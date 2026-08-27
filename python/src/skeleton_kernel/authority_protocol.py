"""Bounded typed client/process protocol for the reference authority."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sqlite3
import subprocess
from typing import Any, BinaryIO, Mapping

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .constitution import (
    ConstitutionRejection,
    verify_current_signer,
    verify_historical_signer,
)
from .schema_registry import SchemaRegistry
from .store import KernelStore


AUTHORITY_COMMAND_SCHEMA_ID = (
    "https://schemas.skeleton.local/v1/authority-command.schema.json"
)
AUTHORITY_RESULT_SCHEMA_ID = (
    "https://schemas.skeleton.local/v1/authority-result.schema.json"
)
AUTHORITY_RESULT_CLASS = "authority_result"
AUTHORITY_RESULT_DOMAIN = "skeleton.authority-result.v1"
AUTHORITY_RESULT_CLASS_TAG = 0x04
MAX_PROTOCOL_LINE_BYTES = 64 * 1024


@dataclass(slots=True)
class AuthorityProtocolRejection(ValueError):
    """Closed process-boundary rejection that never echoes submitted bytes."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class AuthorityCommand:
    authority_domain: str
    command_id: str
    expected_state_sha256: str
    lifecycle_effect: str
    authorization_id: str
    requested_at: str
    payload_sha256: str
    wire_bytes: bytes

    @classmethod
    def from_wire(
        cls,
        raw: bytes,
        *,
        registry: SchemaRegistry,
    ) -> "AuthorityCommand":
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_PROTOCOL_LINE_BYTES:
            raise AuthorityProtocolRejection("authority_command_length_invalid")
        try:
            validated = registry.validate_raw(raw, AUTHORITY_COMMAND_SCHEMA_ID)
        except Exception as error:
            raise AuthorityProtocolRejection("authority_command_invalid") from error
        if validated.canonical_bytes != raw:
            raise AuthorityProtocolRejection("authority_command_noncanonical")
        value = validated.value
        if not isinstance(value, dict):
            raise AuthorityProtocolRejection("authority_command_invalid")
        return cls(
            authority_domain=str(value["authority_domain"]),
            command_id=str(value["command_id"]),
            expected_state_sha256=str(value["expected_state_sha256"]),
            lifecycle_effect=str(value["lifecycle_effect"]),
            authorization_id=str(value["authorization_id"]),
            requested_at=str(value["requested_at"]),
            payload_sha256=sha256_hex(raw),
            wire_bytes=raw,
        )


@dataclass(frozen=True, slots=True)
class AuthorityProcessReady:
    authority_domain: str
    fence_token: int
    semantic_state_sha256: str
    journal_state_sha256: str
    authority_snapshot_sha256: str


@dataclass(frozen=True, slots=True)
class AuthorityResult:
    wire_bytes: bytes
    signer_key_id: str
    signer_set_epoch: str
    body: Mapping[str, Any]

    @classmethod
    def from_wire(
        cls,
        raw: bytes,
        *,
        registry: SchemaRegistry,
        database_path: Path,
    ) -> "AuthorityResult":
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_PROTOCOL_LINE_BYTES:
            raise AuthorityProtocolRejection("authority_result_length_invalid")
        try:
            validated = registry.validate_raw(raw, AUTHORITY_RESULT_SCHEMA_ID)
        except Exception as error:
            raise AuthorityProtocolRejection("authority_result_invalid") from error
        if validated.canonical_bytes != raw:
            raise AuthorityProtocolRejection("authority_result_noncanonical")
        value = validated.value
        if not isinstance(value, dict) or not isinstance(value.get("body"), dict):
            raise AuthorityProtocolRejection("authority_result_invalid")
        connection = sqlite3.connect(
            f"{database_path.resolve(strict=True).as_uri()}?mode=ro",
            uri=True,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        store = KernelStore(connection, database_path)
        try:
            if value["signer_set_epoch"] == store.current_signer_epoch():
                verify_current_signer(
                    value,
                    store,
                    expected_object_class=AUTHORITY_RESULT_CLASS,
                    expected_domain=AUTHORITY_RESULT_DOMAIN,
                    class_tag=AUTHORITY_RESULT_CLASS_TAG,
                )
            else:
                body = value["body"]
                digest = sha256_hex(raw)
                row = connection.execute(
                    """
                    SELECT r.result_bytes, r.result_sha256,
                           j.result_sha256 AS journal_result_sha256,
                           j.journal_state
                    FROM authority_command_journal AS j
                    JOIN command_results AS r
                      USING(authority_domain, command_id)
                    WHERE j.authority_domain = ? AND j.command_id = ?
                    """,
                    (body.get("authority_domain"), body.get("command_id")),
                ).fetchone()
                if (
                    row is None
                    or row["journal_state"] != "RESULT_COMMITTED"
                    or bytes(row["result_bytes"]) != raw
                    or row["result_sha256"] != digest
                    or row["journal_result_sha256"] != digest
                ):
                    raise ConstitutionRejection("signer_epoch_mismatch")
                verify_historical_signer(
                    value,
                    store,
                    expected_object_class=AUTHORITY_RESULT_CLASS,
                    expected_domain=AUTHORITY_RESULT_DOMAIN,
                    class_tag=AUTHORITY_RESULT_CLASS_TAG,
                )
        except ConstitutionRejection as error:
            raise AuthorityProtocolRejection(error.code) from error
        finally:
            connection.close()
        return cls(
            wire_bytes=raw,
            signer_key_id=str(value["signer_key_id"]),
            signer_set_epoch=str(value["signer_set_epoch"]),
            body=dict(value["body"]),
        )


class AuthorityProcessClient:
    """One bounded binary-line channel to the sole writer subprocess."""

    __slots__ = (
        "_database_path",
        "_process",
        "_registry",
        "ready",
    )

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        database_path: Path,
        registry: SchemaRegistry,
        ready: AuthorityProcessReady,
    ) -> None:
        self._process = process
        self._database_path = database_path
        self._registry = registry
        self.ready = ready

    @classmethod
    def launch(
        cls,
        *,
        python_executable: Path,
        python_source_root: Path,
        database_path: Path,
        ddl_path: Path,
        contracts_root: Path,
        authority_domains_path: Path,
        result_signing_seed_path: Path,
    ) -> "AuthorityProcessClient":
        executable = python_executable.resolve(strict=True)
        source_root = python_source_root.resolve(strict=True)
        database = database_path.resolve(strict=True)
        arguments = [
            str(executable),
            "-m",
            "skeleton_kernel.authority_process",
            "--database",
            str(database),
            "--ddl",
            str(ddl_path.resolve(strict=True)),
            "--contracts",
            str(contracts_root.resolve(strict=True)),
            "--authority-domains",
            str(authority_domains_path.resolve(strict=True)),
            "--result-signing-seed",
            str(result_signing_seed_path.resolve(strict=True)),
        ]
        startupinfo = None
        creationflags = 0
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW
        process = subprocess.Popen(
            arguments,
            cwd=source_root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ.copy(),
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        assert process.stdout is not None
        first = _read_line(process.stdout)
        value = _parse_message(first)
        if value.get("schema_version") == "skeleton.authority-process.rejection.v1":
            process.wait(timeout=5)
            raise AuthorityProtocolRejection(str(value["rejection_code"]))
        expected = {
            "schema_version",
            "authority_domain",
            "fence_token",
            "semantic_state_sha256",
            "journal_state_sha256",
            "authority_snapshot_sha256",
        }
        if (
            set(value) != expected
            or value["schema_version"] != "skeleton.authority-process.ready.v1"
            or not isinstance(value["fence_token"], int)
            or value["fence_token"] < 1
        ):
            process.terminate()
            process.wait(timeout=5)
            raise AuthorityProtocolRejection("authority_process_not_ready")
        registry = SchemaRegistry(contracts_root)
        return cls(
            process,
            database_path=database,
            registry=registry,
            ready=AuthorityProcessReady(
                authority_domain=str(value["authority_domain"]),
                fence_token=int(value["fence_token"]),
                semantic_state_sha256=str(value["semantic_state_sha256"]),
                journal_state_sha256=str(value["journal_state_sha256"]),
                authority_snapshot_sha256=str(value["authority_snapshot_sha256"]),
            ),
        )

    @property
    def pid(self) -> int:
        return self._process.pid

    def submit(self, raw: bytes) -> AuthorityResult:
        if (
            self._process.poll() is not None
            or self._process.stdin is None
            or self._process.stdout is None
        ):
            raise AuthorityProtocolRejection("authority_process_unavailable")
        if (
            not isinstance(raw, bytes)
            or not raw
            or len(raw) > MAX_PROTOCOL_LINE_BYTES
            or b"\n" in raw
            or b"\r" in raw
        ):
            raise AuthorityProtocolRejection("authority_command_length_invalid")
        try:
            self._process.stdin.write(raw + b"\n")
            self._process.stdin.flush()
            response = _read_line(self._process.stdout)
        except (BrokenPipeError, OSError) as error:
            raise AuthorityProtocolRejection("authority_process_unavailable") from error
        value = _parse_message(response)
        if value.get("schema_version") == "skeleton.authority-process.rejection.v1":
            raise AuthorityProtocolRejection(str(value["rejection_code"]))
        return AuthorityResult.from_wire(
            response,
            registry=self._registry,
            database_path=self._database_path,
        )

    def close(self) -> None:
        if self._process.poll() is not None:
            return
        if self._process.stdin is not None:
            try:
                self._process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.terminate()
            self._process.wait(timeout=5)

    def wait_for_exit(self, *, timeout: float) -> int:
        try:
            return int(self._process.wait(timeout=timeout))
        except subprocess.TimeoutExpired as error:
            raise AuthorityProtocolRejection("authority_process_still_running") from error


def rejection_wire(code: str) -> bytes:
    if (
        not isinstance(code, str)
        or not code
        or len(code) > 128
        or not code.replace("_", "").isascii()
        or not code.replace("_", "").isalnum()
    ):
        code = "authority_internal_error"
    return canonicalize(
        {
            "schema_version": "skeleton.authority-process.rejection.v1",
            "rejection_code": code,
        }
    )


def _read_line(stream: BinaryIO) -> bytes:
    raw = stream.readline(MAX_PROTOCOL_LINE_BYTES + 2)
    if not raw:
        raise AuthorityProtocolRejection("authority_process_unavailable")
    if len(raw) > MAX_PROTOCOL_LINE_BYTES + 1 or not raw.endswith(b"\n"):
        raise AuthorityProtocolRejection("authority_process_response_invalid")
    value = raw[:-1]
    if not value or b"\r" in value or b"\n" in value:
        raise AuthorityProtocolRejection("authority_process_response_invalid")
    return value


def _parse_message(raw: bytes) -> dict[str, Any]:
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise AuthorityProtocolRejection("authority_process_response_invalid") from error
    if not isinstance(value, dict) or canonicalize(value) != raw:
        raise AuthorityProtocolRejection("authority_process_response_invalid")
    return value
