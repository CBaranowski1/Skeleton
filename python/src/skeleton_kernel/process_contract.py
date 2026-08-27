"""Fail-closed logical process profiles for the Phase 6 reference kernel."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from types import TracebackType
from typing import Any, BinaryIO, Mapping, Sequence

from .authority_protocol import AuthorityProcessClient
from .canonical import canonicalize, parse_raw_json


PROFILE_SCHEMA_VERSION = "skeleton.process-profiles.v1"
ROLE_PROTOCOL_VERSION = "skeleton.process-role.v1"
MAX_ROLE_MESSAGE_BYTES = 16 * 1024
ROLE_NAMES = (
    "reference-authority",
    "status",
    "cognition-simulator",
    "advisory",
    "owner-ui",
)
ROLE_PERMISSIONS: Mapping[str, tuple[str, ...]] = {
    "reference-authority": ("authority.read", "authority.write"),
    "status": ("authority.health.read", "status.publish"),
    "cognition-simulator": ("advisory.emit",),
    "advisory": ("advisory.read",),
    "owner-ui": ("status.read",),
}
REQUIRED_ROLES = frozenset({"reference-authority", "status"})
OPTIONAL_ROLES = frozenset(set(ROLE_NAMES) - REQUIRED_ROLES)
WRITER_ROLE = "reference-authority"


@dataclass(slots=True)
class ProcessProfileRejection(ValueError):
    """Stable configuration/runtime failure that never echoes untrusted input."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class RoleContract:
    name: str
    required: bool
    permissions: tuple[str, ...]
    health_timeout_ms: int
    shutdown_timeout_ms: int
    authority_writer: bool


@dataclass(frozen=True, slots=True)
class ProcessGroup:
    process_id: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProcessProfile:
    name: str
    roles: Mapping[str, RoleContract]
    process_groups: tuple[ProcessGroup, ...]
    writer_owner: str


@dataclass(frozen=True, slots=True)
class RoleHealth:
    state: str
    required: bool
    pid: int | None


@dataclass(frozen=True, slots=True)
class ProfileStatus:
    profile: str
    ready: bool
    authority_available: bool
    roles: Mapping[str, RoleHealth]

    def as_wire_value(self) -> dict[str, Any]:
        return {
            "schema_version": "skeleton.process-profile.status.v1",
            "profile": self.profile,
            "ready": self.ready,
            "authority_available": self.authority_available,
            "roles": {
                name: {
                    "state": health.state,
                    "required": health.required,
                    "pid": health.pid,
                }
                for name, health in sorted(self.roles.items())
            },
        }


def _default_roles() -> dict[str, RoleContract]:
    return {
        name: RoleContract(
            name=name,
            required=name in REQUIRED_ROLES,
            permissions=ROLE_PERMISSIONS[name],
            health_timeout_ms=400,
            shutdown_timeout_ms=2000,
            authority_writer=name == WRITER_ROLE,
        )
        for name in ROLE_NAMES
    }


def _tracer_profile() -> ProcessProfile:
    return ProcessProfile(
        name="separated",
        roles=_default_roles(),
        process_groups=tuple(
            ProcessGroup(process_id=name, roles=(name,)) for name in ROLE_NAMES
        ),
        writer_owner=WRITER_ROLE,
    )


def load_process_profiles(path: Path) -> dict[str, ProcessProfile]:
    """Load the complete compact/separated contract without permissive defaults."""

    try:
        raw = path.resolve(strict=True).read_bytes()
        value = parse_raw_json(raw)
    except Exception as error:
        raise ProcessProfileRejection("process_profile_configuration_invalid") from error
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "roles",
        "profiles",
        "writer_owner",
    }:
        raise ProcessProfileRejection("process_profile_configuration_invalid")
    if (
        value["schema_version"] != PROFILE_SCHEMA_VERSION
        or value["writer_owner"] != WRITER_ROLE
        or not isinstance(value["roles"], dict)
        or set(value["roles"]) != set(ROLE_NAMES)
        or not isinstance(value["profiles"], dict)
        or set(value["profiles"]) != {"compact", "separated"}
    ):
        raise ProcessProfileRejection("process_profile_configuration_invalid")

    roles: dict[str, RoleContract] = {}
    for name in ROLE_NAMES:
        candidate = value["roles"][name]
        if not isinstance(candidate, dict) or set(candidate) != {
            "required",
            "permissions",
            "health_timeout_ms",
            "shutdown_timeout_ms",
            "authority_writer",
        }:
            raise ProcessProfileRejection("process_profile_role_invalid")
        permissions = candidate["permissions"]
        health_timeout = candidate["health_timeout_ms"]
        shutdown_timeout = candidate["shutdown_timeout_ms"]
        if (
            type(candidate["required"]) is not bool
            or candidate["required"] != (name in REQUIRED_ROLES)
            or not isinstance(permissions, list)
            or tuple(permissions) != ROLE_PERMISSIONS[name]
            or type(health_timeout) is not int
            or not 50 <= health_timeout <= 5000
            or type(shutdown_timeout) is not int
            or not 100 <= shutdown_timeout <= 10000
            or type(candidate["authority_writer"]) is not bool
            or candidate["authority_writer"] != (name == WRITER_ROLE)
        ):
            raise ProcessProfileRejection("process_profile_role_invalid")
        roles[name] = RoleContract(
            name=name,
            required=candidate["required"],
            permissions=tuple(permissions),
            health_timeout_ms=health_timeout,
            shutdown_timeout_ms=shutdown_timeout,
            authority_writer=candidate["authority_writer"],
        )
    writers = [role.name for role in roles.values() if role.authority_writer]
    if writers != [WRITER_ROLE]:
        raise ProcessProfileRejection("process_profile_writer_invalid")
    for name, role in roles.items():
        if name != WRITER_ROLE and "authority.write" in role.permissions:
            raise ProcessProfileRejection("process_profile_writer_invalid")

    profiles: dict[str, ProcessProfile] = {}
    for profile_name in ("compact", "separated"):
        raw_profile = value["profiles"][profile_name]
        if not isinstance(raw_profile, dict) or set(raw_profile) != {
            "process_groups"
        }:
            raise ProcessProfileRejection("process_profile_layout_invalid")
        groups_value = raw_profile["process_groups"]
        if not isinstance(groups_value, list) or not groups_value:
            raise ProcessProfileRejection("process_profile_layout_invalid")
        groups: list[ProcessGroup] = []
        seen: list[str] = []
        process_ids: set[str] = set()
        for group_value in groups_value:
            if not isinstance(group_value, dict) or set(group_value) != {
                "process_id",
                "roles",
            }:
                raise ProcessProfileRejection("process_profile_layout_invalid")
            process_id = group_value["process_id"]
            group_roles = group_value["roles"]
            if (
                not isinstance(process_id, str)
                or not process_id
                or process_id in process_ids
                or not isinstance(group_roles, list)
                or not group_roles
                or any(not isinstance(role, str) for role in group_roles)
                or any(role not in roles for role in group_roles)
                or len(set(group_roles)) != len(group_roles)
            ):
                raise ProcessProfileRejection("process_profile_layout_invalid")
            if WRITER_ROLE in group_roles and tuple(group_roles) != (WRITER_ROLE,):
                raise ProcessProfileRejection("process_profile_writer_invalid")
            process_ids.add(process_id)
            seen.extend(group_roles)
            groups.append(ProcessGroup(process_id, tuple(group_roles)))
        if sorted(seen) != sorted(ROLE_NAMES) or len(seen) != len(set(seen)):
            raise ProcessProfileRejection("process_profile_layout_invalid")
        if profile_name == "separated" and any(
            len(group.roles) != 1 for group in groups
        ):
            raise ProcessProfileRejection("process_profile_layout_invalid")
        profiles[profile_name] = ProcessProfile(
            name=profile_name,
            roles=roles,
            process_groups=tuple(groups),
            writer_owner=WRITER_ROLE,
        )
    return profiles


class _RoleGroup:
    __slots__ = (
        "_process",
        "_responses",
        "_roles",
        "_shutdown_timeout",
        "_stdout_thread",
    )

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        roles: tuple[str, ...],
        shutdown_timeout: float,
    ) -> None:
        self._process = process
        self._roles = roles
        self._shutdown_timeout = shutdown_timeout
        self._responses: queue.Queue[bytes | None] = queue.Queue()
        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            name=f"phase06-role-reader-{process.pid}",
            daemon=True,
        )
        self._stdout_thread.start()

    @classmethod
    def launch(
        cls,
        *,
        python_executable: Path,
        python_source_root: Path,
        roles: tuple[str, ...],
        shutdown_timeout: float,
    ) -> "_RoleGroup":
        arguments = [
            str(python_executable.resolve(strict=True)),
            "-m",
            "skeleton_kernel.process_contract",
            "--child-roles",
            ",".join(roles),
        ]
        startupinfo = None
        creationflags = 0
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW
        process = subprocess.Popen(
            arguments,
            cwd=python_source_root.resolve(strict=True),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ.copy(),
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        group = cls(
            process=process,
            roles=roles,
            shutdown_timeout=shutdown_timeout,
        )
        ready = group._receive(timeout=2.0)
        if ready != {
            "schema_version": ROLE_PROTOCOL_VERSION,
            "kind": "ready",
            "roles": list(roles),
        }:
            group.close()
            raise ProcessProfileRejection("process_role_not_ready")
        return group

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def exited(self) -> bool:
        return self._process.poll() is not None

    def probe(self, role: str, *, timeout: float) -> str:
        if role not in self._roles or self.exited:
            return "failed"
        try:
            self._send({"op": "probe", "role": role})
            response = self._receive(timeout=timeout)
        except ProcessProfileRejection as error:
            if error.code == "process_role_timeout":
                return "timed_out"
            return "failed"
        if response == {
            "schema_version": ROLE_PROTOCOL_VERSION,
            "kind": "health",
            "role": role,
            "state": "ready",
        }:
            return "ready"
        if (
            response.get("schema_version") == ROLE_PROTOCOL_VERSION
            and response.get("kind") == "health"
            and response.get("role") == role
            and response.get("state") in {"failed", "timed_out"}
        ):
            return str(response["state"])
        return "failed"

    def saturate(self, role: str, *, timeout: float) -> None:
        self._send({"op": "saturate", "role": role})
        response = self._receive(timeout=timeout)
        if response != {
            "schema_version": ROLE_PROTOCOL_VERSION,
            "kind": "saturating",
            "role": role,
        }:
            raise ProcessProfileRejection("process_role_control_failed")

    def terminate(self) -> None:
        if self.exited:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=self._shutdown_timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=self._shutdown_timeout)

    def close(self) -> None:
        if self.exited:
            return
        if self._process.stdin is not None:
            try:
                self._send({"op": "shutdown"})
                self._process.stdin.close()
            except (BrokenPipeError, OSError, ProcessProfileRejection):
                pass
        try:
            self._process.wait(timeout=self._shutdown_timeout)
        except subprocess.TimeoutExpired:
            self._process.terminate()
            try:
                self._process.wait(timeout=self._shutdown_timeout)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=self._shutdown_timeout)

    def _read_stdout(self) -> None:
        stream = self._process.stdout
        if stream is None:
            self._responses.put(None)
            return
        while True:
            raw = stream.readline(MAX_ROLE_MESSAGE_BYTES + 2)
            if not raw:
                self._responses.put(None)
                return
            self._responses.put(raw)

    def _send(self, value: Mapping[str, Any]) -> None:
        if self.exited or self._process.stdin is None:
            raise ProcessProfileRejection("process_role_unavailable")
        raw = canonicalize(value)
        try:
            self._process.stdin.write(raw + b"\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise ProcessProfileRejection("process_role_unavailable") from error

    def _receive(self, *, timeout: float) -> dict[str, Any]:
        try:
            raw = self._responses.get(timeout=timeout)
        except queue.Empty as error:
            raise ProcessProfileRejection("process_role_timeout") from error
        if raw is None:
            raise ProcessProfileRejection("process_role_unavailable")
        value = _parse_role_line(raw)
        return value


class ProcessProfileRunner:
    """Own and reap one executable profile without transferring writer authority."""

    __slots__ = (
        "_closed",
        "_groups",
        "_profile",
        "_role_groups",
        "authority",
        "database_path",
    )

    def __init__(
        self,
        *,
        profile: ProcessProfile,
        database_path: Path,
        authority: AuthorityProcessClient,
        groups: list[_RoleGroup],
        role_groups: Mapping[str, _RoleGroup],
    ) -> None:
        self._profile = profile
        self.database_path = database_path
        self.authority = authority
        self._groups = groups
        self._role_groups = dict(role_groups)
        self._closed = False

    @classmethod
    def launch(
        cls,
        *,
        profile_name: str,
        profiles_path: Path | None,
        python_executable: Path,
        python_source_root: Path,
        database_path: Path,
        ddl_path: Path,
        contracts_root: Path,
        authority_domains_path: Path,
        result_signing_seed_path: Path,
        optional_roles: frozenset[str] = frozenset(),
        authority_test_now: str | None = None,
        authority_test_lease_seconds: int | None = None,
    ) -> "ProcessProfileRunner":
        if not isinstance(optional_roles, frozenset) or not optional_roles <= OPTIONAL_ROLES:
            raise ProcessProfileRejection("process_profile_optional_roles_invalid")
        if profiles_path is None:
            if profile_name != "separated":
                raise ProcessProfileRejection("process_profile_unknown")
            profile = _tracer_profile()
        else:
            profiles = load_process_profiles(profiles_path)
            try:
                profile = profiles[profile_name]
            except KeyError as error:
                raise ProcessProfileRejection("process_profile_unknown") from error

        old_environment = {
            name: os.environ.get(name)
            for name in (
                "SKELETON_AUTHORITY_TEST_MODE",
                "SKELETON_AUTHORITY_TEST_NOW",
                "SKELETON_AUTHORITY_TEST_LEASE_SECONDS",
            )
        }
        if (authority_test_now is None) != (authority_test_lease_seconds is None):
            raise ProcessProfileRejection("process_profile_test_configuration_invalid")
        if authority_test_now is not None:
            if (
                type(authority_test_lease_seconds) is not int
                or not 1 <= authority_test_lease_seconds <= 300
            ):
                raise ProcessProfileRejection(
                    "process_profile_test_configuration_invalid"
                )
            os.environ["SKELETON_AUTHORITY_TEST_MODE"] = "1"
            os.environ["SKELETON_AUTHORITY_TEST_NOW"] = authority_test_now
            os.environ["SKELETON_AUTHORITY_TEST_LEASE_SECONDS"] = str(
                authority_test_lease_seconds
            )
        authority: AuthorityProcessClient | None = None
        groups: list[_RoleGroup] = []
        try:
            authority = AuthorityProcessClient.launch(
                python_executable=python_executable,
                python_source_root=python_source_root,
                database_path=database_path,
                ddl_path=ddl_path,
                contracts_root=contracts_root,
                authority_domains_path=authority_domains_path,
                result_signing_seed_path=result_signing_seed_path,
            )
        finally:
            for name, previous in old_environment.items():
                if previous is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = previous

        role_groups: dict[str, _RoleGroup] = {}
        enabled_roles = REQUIRED_ROLES | optional_roles
        try:
            for group_spec in profile.process_groups:
                selected = tuple(
                    role for role in group_spec.roles if role in enabled_roles
                )
                if not selected or WRITER_ROLE in selected:
                    continue
                shutdown_timeout = max(
                    profile.roles[role].shutdown_timeout_ms for role in selected
                ) / 1000.0
                group = _RoleGroup.launch(
                    python_executable=python_executable,
                    python_source_root=python_source_root,
                    roles=selected,
                    shutdown_timeout=shutdown_timeout,
                )
                groups.append(group)
                for role in selected:
                    role_groups[role] = group
        except BaseException:
            for group in reversed(groups):
                group.close()
            authority.close()
            raise
        return cls(
            profile=profile,
            database_path=database_path.resolve(strict=True),
            authority=authority,
            groups=groups,
            role_groups=role_groups,
        )

    def __enter__(self) -> "ProcessProfileRunner":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def pids(self) -> dict[str, int]:
        result = {"reference-authority": self.authority.pid}
        result.update(
            {
                role: group.pid
                for role, group in self._role_groups.items()
            }
        )
        return result

    @property
    def all_children_reaped(self) -> bool:
        return (
            self._closed
            and all(group.exited for group in self._groups)
            and self.authority.wait_for_exit(timeout=0.1) == 0
        )

    def status(self) -> ProfileStatus:
        roles: dict[str, RoleHealth] = {}
        try:
            self.authority.wait_for_exit(timeout=0)
        except Exception as error:
            authority_state = (
                "ready"
                if getattr(error, "code", None) == "authority_process_still_running"
                else "failed"
            )
        else:
            authority_state = "failed"
        roles[WRITER_ROLE] = RoleHealth(
            state=authority_state,
            required=True,
            pid=self.authority.pid,
        )
        for name in ROLE_NAMES:
            if name == WRITER_ROLE:
                continue
            contract = self._profile.roles[name]
            group = self._role_groups.get(name)
            if group is None:
                state = "absent"
                pid = None
            else:
                state = group.probe(
                    name,
                    timeout=contract.health_timeout_ms / 1000.0,
                )
                pid = group.pid
            roles[name] = RoleHealth(
                state=state,
                required=contract.required,
                pid=pid,
            )
        ready = all(
            roles[name].state == "ready"
            for name in REQUIRED_ROLES
        )
        return ProfileStatus(
            profile=self._profile.name,
            ready=ready,
            authority_available=authority_state == "ready",
            roles=roles,
        )

    def terminate_role(self, role: str) -> None:
        if role == WRITER_ROLE:
            raise ProcessProfileRejection("writer_control_forbidden")
        group = self._role_groups.get(role)
        if group is None:
            raise ProcessProfileRejection("process_role_absent")
        group.terminate()

    def saturate_role(self, role: str) -> None:
        if role != "cognition-simulator":
            raise ProcessProfileRejection("process_role_control_forbidden")
        group = self._role_groups.get(role)
        if group is None:
            raise ProcessProfileRejection("process_role_absent")
        timeout = self._profile.roles[role].health_timeout_ms / 1000.0
        group.saturate(role, timeout=timeout)

    def close(self) -> None:
        if self._closed:
            return
        for group in reversed(self._groups):
            group.close()
        self.authority.close()
        self._closed = True


def _parse_role_line(raw: bytes) -> dict[str, Any]:
    if (
        not raw
        or len(raw) > MAX_ROLE_MESSAGE_BYTES + 1
        or not raw.endswith(b"\n")
        or b"\r" in raw
    ):
        raise ProcessProfileRejection("process_role_response_invalid")
    try:
        value = parse_raw_json(raw[:-1])
    except Exception as error:
        raise ProcessProfileRejection("process_role_response_invalid") from error
    if not isinstance(value, dict) or canonicalize(value) != raw[:-1]:
        raise ProcessProfileRejection("process_role_response_invalid")
    return value


def _write_role(value: Mapping[str, Any]) -> None:
    sys.stdout.buffer.write(canonicalize(value) + b"\n")
    sys.stdout.buffer.flush()


def _child(roles_text: str) -> int:
    roles = tuple(roles_text.split(","))
    if (
        not roles
        or any(role not in ROLE_NAMES or role == WRITER_ROLE for role in roles)
        or len(set(roles)) != len(roles)
    ):
        return 2
    states = {role: "ready" for role in roles}
    _write_role(
        {
            "schema_version": ROLE_PROTOCOL_VERSION,
            "kind": "ready",
            "roles": list(roles),
        }
    )
    while True:
        raw = sys.stdin.buffer.readline(MAX_ROLE_MESSAGE_BYTES + 2)
        if raw == b"":
            return 0
        try:
            request = _parse_role_line(raw)
        except ProcessProfileRejection:
            return 2
        if set(request) == {"op"} and request["op"] == "shutdown":
            return 0
        if set(request) != {"op", "role"} or request["role"] not in states:
            return 2
        role = str(request["role"])
        if request["op"] == "probe":
            _write_role(
                {
                    "schema_version": ROLE_PROTOCOL_VERSION,
                    "kind": "health",
                    "role": role,
                    "state": states[role],
                }
            )
        elif request["op"] == "saturate" and role == "cognition-simulator":
            _write_role(
                {
                    "schema_version": ROLE_PROTOCOL_VERSION,
                    "kind": "saturating",
                    "role": role,
                }
            )
            if len(roles) == 1:
                while True:
                    time.sleep(60)
            states[role] = "timed_out"
        else:
            return 2


def _arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--child-roles")
    parser.add_argument("--run-profile")
    parser.add_argument("--profiles")
    parser.add_argument("--database")
    parser.add_argument("--ddl")
    parser.add_argument("--contracts")
    parser.add_argument("--authority-domains")
    parser.add_argument("--result-signing-seed")
    parser.add_argument("--optional-role", action="append", default=[])
    parser.add_argument("--once", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(sys.argv[1:] if argv is None else argv)
    if arguments.child_roles is not None:
        if any(
            value is not None
            for value in (
                arguments.run_profile,
                arguments.profiles,
                arguments.database,
                arguments.ddl,
                arguments.contracts,
                arguments.authority_domains,
                arguments.result_signing_seed,
            )
        ) or arguments.optional_role or arguments.once:
            return 2
        return _child(arguments.child_roles)
    required = (
        arguments.run_profile,
        arguments.profiles,
        arguments.database,
        arguments.ddl,
        arguments.contracts,
        arguments.authority_domains,
        arguments.result_signing_seed,
    )
    if any(value is None for value in required):
        return 2
    try:
        with ProcessProfileRunner.launch(
            profile_name=arguments.run_profile,
            profiles_path=Path(arguments.profiles),
            python_executable=Path(sys.executable),
            python_source_root=Path.cwd(),
            database_path=Path(arguments.database),
            ddl_path=Path(arguments.ddl),
            contracts_root=Path(arguments.contracts),
            authority_domains_path=Path(arguments.authority_domains),
            result_signing_seed_path=Path(arguments.result_signing_seed),
            optional_roles=frozenset(arguments.optional_role),
        ) as runtime:
            while True:
                sys.stdout.buffer.write(
                    canonicalize(runtime.status().as_wire_value()) + b"\n"
                )
                sys.stdout.buffer.flush()
                if arguments.once:
                    return 0
                time.sleep(1)
    except (OSError, ProcessProfileRejection):
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
