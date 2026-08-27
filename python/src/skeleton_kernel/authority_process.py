"""Long-lived local subprocess entrypoint for the reference authority writer."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import tempfile

from .authority_protocol import (
    MAX_PROTOCOL_LINE_BYTES,
    AuthorityCommand,
    AuthorityProtocolRejection,
    rejection_wire,
)
from .canonical import canonicalize
from .reference_authority import AuthorityRejection, ReferenceAuthority
from .schema_registry import SchemaRegistry


CRASH_POINTS = frozenset(
    {
        "after_accept_commit",
        "after_apply_commit",
        "after_finalize_commit_before_send",
    }
)
CRASH_EXIT_CODE = 86


@dataclass(frozen=True, slots=True)
class _ProcessSettings:
    now: str
    lease_seconds: int
    crash_point: str | None


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--database", required=True)
    parser.add_argument("--ddl", required=True)
    parser.add_argument("--contracts", required=True)
    parser.add_argument("--authority-domains", required=True)
    parser.add_argument("--result-signing-seed", required=True)
    return parser.parse_args()


def _write(raw: bytes) -> None:
    sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()


def _contained_under(path: Path, root: Path) -> bool:
    resolved = path.resolve(strict=True)
    expected = root.resolve(strict=True)
    return resolved == expected or expected in resolved.parents


def _settings(database: Path, seed: Path) -> _ProcessSettings:
    test_mode = os.environ.get("SKELETON_AUTHORITY_TEST_MODE") == "1"
    if not test_mode:
        return _ProcessSettings(
            now=datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            lease_seconds=30,
            crash_point=None,
        )
    temporary_root = Path(tempfile.gettempdir())
    if not _contained_under(database, temporary_root) or not _contained_under(
        seed, temporary_root
    ):
        raise AuthorityRejection("authority_test_path_outside_temporary_root")
    now = os.environ.get("SKELETON_AUTHORITY_TEST_NOW")
    seconds = os.environ.get("SKELETON_AUTHORITY_TEST_LEASE_SECONDS")
    if now is None or seconds is None or not seconds.isascii() or not seconds.isdecimal():
        raise AuthorityRejection("authority_test_configuration_invalid")
    crash_point = os.environ.get("SKELETON_AUTHORITY_TEST_CRASH_POINT")
    if crash_point is not None and crash_point not in CRASH_POINTS:
        raise AuthorityRejection("authority_test_configuration_invalid")
    return _ProcessSettings(
        now=now,
        lease_seconds=int(seconds),
        crash_point=crash_point,
    )


def _after_commit(settings: _ProcessSettings, point: str) -> None:
    if settings.crash_point == point:
        os._exit(CRASH_EXIT_CODE)


def main() -> int:
    authority: ReferenceAuthority | None = None
    try:
        arguments = _arguments()
        database = Path(arguments.database).resolve(strict=True)
        ddl = Path(arguments.ddl).resolve(strict=True)
        contracts = Path(arguments.contracts).resolve(strict=True)
        domains = Path(arguments.authority_domains).resolve(strict=True)
        seed = Path(arguments.result_signing_seed).resolve(strict=True)
        if not ddl.is_file() or ddl.name != "kernel-store.sql":
            raise AuthorityRejection("authority_store_schema_missing")
        settings = _settings(database, seed)
        registry = SchemaRegistry(contracts)
        authority = ReferenceAuthority(
            database_path=database,
            authority_domains_path=domains,
            registry=registry,
            result_signing_seed_path=seed,
            lease_now=settings.now,
            lease_seconds=settings.lease_seconds,
            after_commit=lambda point: _after_commit(settings, point),
        )
        hashes = authority.hashes()
        _write(
            canonicalize(
                {
                    "schema_version": "skeleton.authority-process.ready.v1",
                    "authority_domain": authority.authority_domain,
                    "fence_token": authority.fence_token,
                    "semantic_state_sha256": hashes.semantic_state_sha256,
                    "journal_state_sha256": hashes.journal_state_sha256,
                    "authority_snapshot_sha256": hashes.authority_snapshot_sha256,
                }
            )
        )
        while True:
            raw = sys.stdin.buffer.readline(MAX_PROTOCOL_LINE_BYTES + 2)
            if raw == b"":
                return 0
            if (
                len(raw) > MAX_PROTOCOL_LINE_BYTES + 1
                or not raw.endswith(b"\n")
                or b"\r" in raw
            ):
                _write(rejection_wire("authority_command_length_invalid"))
                return 2
            command_raw = raw[:-1]
            try:
                command = AuthorityCommand.from_wire(
                    command_raw,
                    registry=registry,
                )
                _write(authority.execute(command))
            except (AuthorityProtocolRejection, AuthorityRejection) as error:
                _write(rejection_wire(error.code))
    except AuthorityRejection as error:
        _write(rejection_wire(error.code))
        return 2
    except BaseException:
        _write(rejection_wire("authority_internal_error"))
        return 3
    finally:
        if authority is not None:
            authority.close()


if __name__ == "__main__":
    raise SystemExit(main())
