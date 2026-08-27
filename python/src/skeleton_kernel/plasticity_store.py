"""Sole-writer append-only persistence for Phase 13 fast synaptic plasticity.

This module owns two closed surfaces:

``PlasticityMigrations``
    A ``MetabolismMigrations``-style runner for the mirrored migration
    ``0014-fast-plasticity``: exact pinned source bytes, exact ordered
    0007-0013 predecessor ledger authentication, ``BEGIN IMMEDIATE``
    application, live object-SQL verification on idempotent reapply, and
    rollback on every declared fault point.

``PlasticityStore``
    A narrow typed facade over one spawned SQLite owner process, mirroring
    ``metabolism_store.py``: a closed authorizer naming only the twelve
    plasticity tables (no authority, credential, policy, promotion, memory,
    or metabolism table — D-20), fixed typed operations only, fenced
    generation-accounted appends, apply/reverse delta-application events as
    separate append-only rows with monotonic ordinals (never mutations), an
    idempotent operation ledger, and a replay surface proving byte-equality
    of every appended record.  Placeholder appends are pressure-exempt by
    construction: appending a ``pending_owner_hardware`` row never consults
    homeostasis state and can never be blocked by it (D-18).  Fault
    recovery is explicit: a successor writer resumes by advancing the fence
    generation (``acquire_fence``) under which abandoned in-flight work is
    re-recorded fail-closed.

Every ``recorded_at``/``acquired_at`` value is caller-provided canonical
UTC text; this module never reads a wall clock for row content.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from fractions import Fraction
from hashlib import sha256
from functools import lru_cache
from importlib.resources import files
import multiprocessing
from multiprocessing.connection import Connection
import os
from pathlib import Path
import re
import sqlite3
from struct import pack
import tempfile
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import metabolism_store as _metabolism_store
from .bootstrap_trust import load_release_root_anchor
from .canonical import canonicalize, parse_raw_json, sha256_hex
from .plasticity_homeostasis import (
    HOMEOSTASIS_ADMISSION_BUDGETS,
    HOMEOSTASIS_PROFILE_ID,
    HomeostasisRejection,
    budget_cap,
    derive_homeostasis_decision,
)
from .plasticity_kernel import (
    PlasticityKernelRejection,
    payload_from_bytes,
    tensor_payload_root,
)
from .plasticity_contracts import (
    PlasticityContractRejection,
    PlasticityContractSurface,
)
from .plasticity_types import (
    ChangeKind,
    EvaluationBasis,
    GENESIS_SHA256,
    HomeostasisAction,
    HomeostasisAppendClass,
    HomeostasisBudgetKind,
    PlasticityTypeRejection,
    PressureBand,
    ProbeKind,
    ProbeStatus,
    SAFE_INTEGER_MAX,
    ScopeRegistryKind,
    channel_update_from_raw,
    compute_phase13_identity,
    delta_from_raw,
    gradient_from_raw,
    placeholder_from_raw,
)


AUTHORITY_DOMAIN = "skeleton.phase13.provider-owner-authority.v1"
AUTHORITY_PROTOCOL_VERSION = 1
CAPABILITY_SCHEMA_VERSION = "skeleton.provider-owner-capability.v1"
OWNER_OPERATIONS = frozenset({"training", "load", "unload"})
_AUTHORITY_MAGIC = b"SKELETON-PHASE13-PROVIDER-OWNER-AUTHORITY\x00"
_OWNER_CAPABILITY_TOKEN = object()


class PlasticityAuthorityRejection(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _authority_reject(code: str) -> None:
    raise PlasticityAuthorityRejection(code)


def _authority_identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _authority_reject(code)
    return value


def _load_authority_root() -> tuple[bytes, str]:
    try:
        root = load_release_root_anchor()
    except Exception as error:
        raise PlasticityAuthorityRejection(
            "provider_authority_root_unavailable"
        ) from error
    public_key = root.root_public_key
    fingerprint = root.root_fingerprint_sha256
    if sha256(public_key).hexdigest() != fingerprint:
        _authority_reject("provider_authority_root_mismatch")
    return public_key, fingerprint


def owner_capability_body(
    *,
    operation: str,
    operation_id: str,
    provider_snapshot_id: str,
    subject_root: str,
    attempt_ordinal: int,
) -> Mapping[str, Any]:
    if operation not in OWNER_OPERATIONS:
        _authority_reject("provider_authority_operation_invalid")
    if type(attempt_ordinal) is not int or attempt_ordinal < 1:
        _authority_reject("provider_authority_ordinal_invalid")
    return {
        "attempt_ordinal": attempt_ordinal,
        "operation": operation,
        "operation_id": _authority_identity(
            operation_id, "provider_authority_operation_id_invalid"
        ),
        "provider_snapshot_id": _authority_identity(
            provider_snapshot_id, "provider_authority_snapshot_invalid"
        ),
        "schema_version": CAPABILITY_SCHEMA_VERSION,
        "subject_root": _authority_identity(
            subject_root, "provider_authority_subject_invalid"
        ),
    }


def authority_preimage(body: Mapping[str, Any]) -> bytes:
    domain = AUTHORITY_DOMAIN.encode("ascii")
    body_bytes = canonicalize(body)
    return b"".join(
        (
            _AUTHORITY_MAGIC,
            pack(">H", AUTHORITY_PROTOCOL_VERSION),
            pack(">H", len(domain)),
            domain,
            pack(">Q", len(body_bytes)),
            body_bytes,
        )
    )


class VerifiedOwnerCapability:
    """Opaque authenticated authorization for exactly one provider operation."""

    __slots__ = ("_body", "_raw", "_raw_sha256")

    def __init__(
        self,
        body: Mapping[str, Any],
        raw: bytes,
        raw_sha256: str,
        token: object,
    ) -> None:
        if token is not _OWNER_CAPABILITY_TOKEN:
            raise TypeError(
                "verified owner capabilities require signature verification"
            )
        self._body = dict(body)
        self._raw = raw
        self._raw_sha256 = raw_sha256

    @property
    def operation(self) -> str:
        return str(self._body["operation"])

    @property
    def operation_id(self) -> str:
        return str(self._body["operation_id"])

    @property
    def provider_snapshot_id(self) -> str:
        return str(self._body["provider_snapshot_id"])

    @property
    def subject_root(self) -> str:
        return str(self._body["subject_root"])

    @property
    def attempt_ordinal(self) -> int:
        return int(self._body["attempt_ordinal"])

    @property
    def capability_sha256(self) -> str:
        return self._raw_sha256

    @property
    def canonical_bytes(self) -> bytes:
        return self._raw


def verify_owner_capability(
    raw: bytes,
    *,
    operation: str,
    operation_id: str,
    provider_snapshot_id: str,
    subject_root: str,
    attempt_ordinal: int,
) -> VerifiedOwnerCapability:
    if not isinstance(raw, bytes):
        _authority_reject("provider_authority_bytes_required")
    try:
        value = parse_raw_json(raw)
    except (TypeError, ValueError) as error:
        raise PlasticityAuthorityRejection(
            "provider_authority_parse_invalid"
        ) from error
    if not isinstance(value, dict) or canonicalize(value) != raw:
        _authority_reject("provider_authority_noncanonical")
    if set(value) != {
        "body",
        "signature",
        "signature_domain",
        "signature_protocol_version",
        "signer_key_id",
    }:
        _authority_reject("provider_authority_shape_invalid")
    expected = owner_capability_body(
        operation=operation,
        operation_id=operation_id,
        provider_snapshot_id=provider_snapshot_id,
        subject_root=subject_root,
        attempt_ordinal=attempt_ordinal,
    )
    body = value.get("body")
    public_key, fingerprint = _load_authority_root()
    if (
        not isinstance(body, dict)
        or canonicalize(body) != canonicalize(expected)
        or value.get("signature_domain") != AUTHORITY_DOMAIN
        or value.get("signature_protocol_version") != AUTHORITY_PROTOCOL_VERSION
        or value.get("signer_key_id") != fingerprint
    ):
        _authority_reject("provider_authority_binding_invalid")
    signature = value.get("signature")
    if (
        not isinstance(signature, str)
        or len(signature) != 128
        or any(character not in "0123456789abcdef" for character in signature)
    ):
        _authority_reject("provider_authority_signature_invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(signature), authority_preimage(body)
        )
    except (InvalidSignature, ValueError) as error:
        raise PlasticityAuthorityRejection(
            "provider_authority_signature_invalid"
        ) from error
    return VerifiedOwnerCapability(
        expected,
        raw,
        sha256(raw).hexdigest(),
        _OWNER_CAPABILITY_TOKEN,
    )


PLASTICITY_MIGRATION_ID = "0014-fast-plasticity"
MIGRATION_0014_SHA256 = (
    "925a62f1801178758d15e5ffec47e4e7891d1f5e17ae6fad2f3da3441b02fca4"
)
PLASTICITY_SCHEMA_ROOT = (
    "ad5dcdb8560d3f31e15a9275f3509cf91aa462b8819bab27dd2d147cc4cbaf01"
)
PLASTICITY_TABLES = (
    "admission_receipts",
    "candidate_versions",
    "channel_updates",
    "delta_applications",
    "experience_gradients",
    "homeostasis_events",
    "invocation_receipts",
    "learning_attempts",
    "mixture_records",
    "parameter_deltas",
    "pending_owner_hardware",
    "plasticity_fences",
    "plasticity_operation_ledger",
    "plasticity_scopes",
    "probe_batteries",
    "probe_receipts",
    "provider_lifecycle_receipts",
)
PLASTICITY_INDEXES = ("delta_applications_one_ordinal",)
FAULT_POINTS = frozenset(
    {"after_ledger", "after_table", "after_index", "after_trigger", "before_commit"}
)
ZERO_SHA256 = "0" * 64
NONE_SENTINEL = "none"
GLOBAL_SCOPE_SENTINEL = "global"
APPLY_EVENT = "apply"
REVERSE_EVENT = "reverse"
APPLICATION_EVENTS = (APPLY_EVENT, REVERSE_EVENT)
RESERVED_SCOPE_NAMES = frozenset(
    {"kernel", "identity", "coding", "trading", "research"}
)

_OPERATION_DOMAIN = b"SKELETON_PHASE13_PLASTICITY_OPERATION_V1"
_STATE_DOMAIN = b"SKELETON_PHASE13_PLASTICITY_STATE_V1"
_LEARNING_ATTEMPT_DOMAIN = b"SKELETON_PHASE13_LEARNING_ATTEMPT_V1"
_ROW_DOMAINS = MappingProxyType(
    {
        "fence": b"SKELETON_PHASE13_FENCE_ROW_V1",
        "admission": b"SKELETON_PHASE13_ADMISSION_RECEIPT_V1",
        "scope": b"SKELETON_PHASE13_SCOPE_ROW_V1",
        "delta_application": b"SKELETON_PHASE13_DELTA_APPLICATION_ROW_V1",
        "probe_receipt": b"SKELETON_PHASE13_PROBE_RECEIPT_ROW_V1",
        "probe_battery": b"SKELETON_PHASE13_PROBE_BATTERY_V1",
        "homeostasis_event": b"SKELETON_PHASE13_HOMEOSTASIS_EVENT_ROW_V1",
        "invocation": b"SKELETON_PHASE13_INVOCATION_RECEIPT_V1",
        "mixture": b"SKELETON_PHASE13_MIXTURE_ROW_V1",
        "candidate_version": b"SKELETON_PHASE13_CANDIDATE_VERSION_ROW_V1",
        "provider_lifecycle": b"SKELETON_PHASE13_PROVIDER_LIFECYCLE_ROW_V1",
    }
)
_READ_TABLES = frozenset(
    (*PLASTICITY_TABLES, "schema_migrations", "sqlite_master")
)
_OBJECT_PATTERN = re.compile(
    r"^CREATE\s+(TABLE|TRIGGER|UNIQUE\s+INDEX)\s+([a-z0-9_]+)\b", re.IGNORECASE
)
_SCOPE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_APPLICATION_CAPABILITY_TOKEN = object()
_HOMEOSTASIS_SET_DOMAIN = b"SKELETON_PHASE13_HOMEOSTASIS_DECISION_SET_V1"


@dataclass(frozen=True, slots=True)
class PlasticityMigrationResult:
    status: str
    migration_id: str
    sql_sha256: str


@dataclass(slots=True)
class PlasticityMigrationRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(slots=True)
class PlasticityStoreRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise PlasticityStoreRejection(code)


@lru_cache(maxsize=1)
def _contract_surface() -> PlasticityContractSurface:
    try:
        return PlasticityContractSurface.from_contracts_root(
            Path(__file__).resolve().parents[3] / "contracts" / "v1"
        )
    except (OSError, PlasticityContractRejection) as error:
        raise PlasticityStoreRejection("plasticity_contract_surface_unavailable") from error


def _contract_document(raw: bytes, validator: str, code: str) -> object:
    try:
        return getattr(_contract_surface(), validator)(raw)
    except PlasticityContractRejection as error:
        raise PlasticityStoreRejection(code) from error


def _same(actual: object, expected: object, code: str) -> None:
    if actual != expected:
        _reject(code)


class PlasticityMigrations:
    """Apply reviewed migration 0014 through one injected SQLite connection."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise PlasticityMigrationRejection("writer_connection_required")
        self._connection = connection

    @property
    def table_names(self) -> tuple[str, ...]:
        return PLASTICITY_TABLES

    def apply_0014(self) -> PlasticityMigrationResult:
        return self._apply_0014(failure_point=None)

    def apply_0014_for_test(self, *, failure_point: str) -> PlasticityMigrationResult:
        if failure_point not in FAULT_POINTS:
            raise PlasticityMigrationRejection("unknown_failure_point")
        return self._apply_0014(failure_point=failure_point)

    def _apply_0014(self, *, failure_point: str | None) -> PlasticityMigrationResult:
        connection = self._connection
        if connection.in_transaction:
            raise PlasticityMigrationRejection("nested_transaction")
        raw = _migration_bytes()
        digest = sha256(raw).hexdigest()
        if digest != MIGRATION_0014_SHA256:
            raise PlasticityMigrationRejection("migration_sql_identity_mismatch")
        statements = tuple(_sql_statements(raw.decode("utf-8")))
        objects = _declared_objects(statements)
        table_names = tuple(
            sorted(name for kind, name, _statement in objects if kind == "table")
        )
        if table_names != PLASTICITY_TABLES:
            raise PlasticityMigrationRejection("migration_sql_incomplete")
        index_names = tuple(
            sorted(name for kind, name, _statement in objects if kind == "index")
        )
        if index_names != PLASTICITY_INDEXES:
            raise PlasticityMigrationRejection("migration_sql_incomplete")
        expected_triggers = {
            ("trigger", f"{table_name}_no_{operation}")
            for table_name in PLASTICITY_TABLES
            for operation in ("update", "delete")
        }
        if {
            (kind, name) for kind, name, _statement in objects if kind == "trigger"
        } != expected_triggers:
            raise PlasticityMigrationRejection("migration_sql_incomplete")

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        try:
            _require_prerequisite_chain(connection)
            existing = _migration_row(connection)
            if existing is not None:
                if existing != digest:
                    raise PlasticityMigrationRejection(
                        "migration_ledger_identity_mismatch"
                    )
                _require_schema_identity(connection, objects)
                connection.rollback()
                return PlasticityMigrationResult(
                    "already_applied", PLASTICITY_MIGRATION_ID, digest
                )

            connection.execute(
                "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                (
                    PLASTICITY_MIGRATION_ID,
                    digest,
                    datetime.now(timezone.utc)
                    .isoformat(timespec="microseconds")
                    .replace("+00:00", "Z"),
                ),
            )
            if failure_point == "after_ledger":
                raise PlasticityMigrationRejection("migration_injected_failure")
            first_table = False
            first_index = False
            first_trigger = False
            for statement in statements:
                connection.execute(statement)
                normalized = statement.lstrip().upper()
                if normalized.startswith("CREATE TABLE") and not first_table:
                    first_table = True
                    if failure_point == "after_table":
                        raise PlasticityMigrationRejection(
                            "migration_injected_failure"
                        )
                if normalized.startswith("CREATE UNIQUE INDEX") and not first_index:
                    first_index = True
                    if failure_point == "after_index":
                        raise PlasticityMigrationRejection(
                            "migration_injected_failure"
                        )
                if normalized.startswith("CREATE TRIGGER") and not first_trigger:
                    first_trigger = True
                    if failure_point == "after_trigger":
                        raise PlasticityMigrationRejection(
                            "migration_injected_failure"
                        )
            _require_schema_identity(connection, objects)
            if failure_point == "before_commit":
                raise PlasticityMigrationRejection("migration_injected_failure")
            connection.commit()
        except BaseException as error:
            connection.rollback()
            if isinstance(error, PlasticityMigrationRejection):
                raise
            raise PlasticityMigrationRejection("migration_failed") from error
        return PlasticityMigrationResult("applied", PLASTICITY_MIGRATION_ID, digest)


def apply_plasticity_migrations(
    connection: sqlite3.Connection,
) -> PlasticityMigrationResult:
    """Apply the exact Phase 13 migration through the supplied connection."""

    return PlasticityMigrations(connection).apply_0014()


def _migration_bytes() -> bytes:
    try:
        return files("skeleton_kernel").joinpath(
            "migrations", "0014-fast-plasticity.sql"
        ).read_bytes()
    except (OSError, TypeError) as error:
        raise PlasticityMigrationRejection("migration_sql_unavailable") from error


def _prerequisite_sources() -> tuple[tuple[str, str, bytes], ...]:
    return (
        *_metabolism_store._prerequisite_sources(),
        (
            _metabolism_store.METABOLISM_MIGRATION_ID,
            _metabolism_store.MIGRATION_0013_SHA256,
            _metabolism_store._migration_bytes(),
        ),
    )


def _require_prerequisite_chain(connection: sqlite3.Connection) -> None:
    expected: list[tuple[str, str]] = []
    for migration_id, digest, raw in _prerequisite_sources():
        if sha256(raw).hexdigest() != digest:
            raise PlasticityMigrationRejection("prerequisite_source_identity_mismatch")
        expected.append((migration_id, digest))
    placeholders = ",".join("?" for _item in expected)
    try:
        rows = connection.execute(
            "SELECT migration_id, sql_sha256 FROM schema_migrations "
            f"WHERE migration_id IN ({placeholders}) ORDER BY rowid",
            tuple(migration_id for migration_id, _digest in expected),
        ).fetchall()
    except sqlite3.DatabaseError as error:
        raise PlasticityMigrationRejection("prerequisite_ledger_missing") from error
    observed = tuple((str(migration_id), str(digest)) for migration_id, digest in rows)
    if len(observed) != len(expected):
        raise PlasticityMigrationRejection("prerequisite_ledger_missing")
    if tuple(migration_id for migration_id, _digest in observed) != tuple(
        migration_id for migration_id, _digest in expected
    ):
        raise PlasticityMigrationRejection("prerequisite_ledger_order_mismatch")
    if observed != tuple(expected):
        raise PlasticityMigrationRejection("prerequisite_ledger_identity_mismatch")


def _migration_row(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
        (PLASTICITY_MIGRATION_ID,),
    ).fetchone()
    return None if row is None else str(row[0])


def _normalize_sql(value: str) -> str:
    return " ".join(value.rstrip("; ").split()).lower()


def _schema_identity_root(
    objects: tuple[tuple[str, str, str], ...],
) -> str:
    normalized = sorted(
        [kind, name, _normalize_sql(statement)]
        for kind, name, statement in objects
    )
    return sha256(canonicalize(normalized)).hexdigest()


def _declared_objects(
    statements: tuple[str, ...],
) -> tuple[tuple[str, str, str], ...]:
    objects: list[tuple[str, str, str]] = []
    for statement in statements:
        match = _OBJECT_PATTERN.match(statement.lstrip())
        if match is None:
            raise PlasticityMigrationRejection("migration_sql_incomplete")
        kind = " ".join(match.group(1).lower().split())
        if kind == "unique index":
            kind = "index"
        objects.append((kind, match.group(2), statement))
    if len({(kind, name) for kind, name, _sql in objects}) != len(objects):
        raise PlasticityMigrationRejection("migration_sql_incomplete")
    return tuple(objects)


def _require_schema_identity(
    connection: sqlite3.Connection,
    objects: tuple[tuple[str, str, str], ...],
) -> None:
    expected = {(kind, name): _normalize_sql(sql) for kind, name, sql in objects}
    placeholders = ",".join("?" for _item in expected)
    rows = connection.execute(
        f"SELECT type, name, sql FROM sqlite_master WHERE name IN ({placeholders})",
        tuple(name for _kind, name in expected),
    ).fetchall()
    observed = {
        (str(kind), str(name)): _normalize_sql(str(sql))
        for kind, name, sql in rows
    }
    if observed != expected:
        raise PlasticityMigrationRejection("migration_schema_identity_mismatch")


def _require_live_schema_identity(connection: sqlite3.Connection) -> None:
    """Authenticate the complete live Phase 13 schema before serving requests."""

    try:
        raw = _migration_bytes()
        if sha256(raw).hexdigest() != MIGRATION_0014_SHA256:
            _reject("plasticity_schema_unauthenticated")
        objects = _declared_objects(tuple(_sql_statements(raw.decode("utf-8"))))
        if _schema_identity_root(objects) != PLASTICITY_SCHEMA_ROOT:
            _reject("plasticity_schema_unauthenticated")
        _require_schema_identity(connection, objects)
    except (UnicodeDecodeError, PlasticityMigrationRejection):
        _reject("plasticity_schema_unauthenticated")


def _sql_statements(sql: str) -> Iterator[str]:
    pending = ""
    for line in sql.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            if statement:
                yield statement
            pending = ""
    if pending.strip():
        raise PlasticityMigrationRejection("migration_sql_incomplete")


def _identity(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _nonnegative(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        _reject(code)
    return value


def _positive(value: object, code: str) -> int:
    if type(value) is not int or value < 1:
        _reject(code)
    return value


def _canonical(raw: object, code: str) -> bytes:
    if not isinstance(raw, bytes):
        _reject(code)
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise PlasticityStoreRejection(code) from error
    if canonicalize(value) != raw:
        _reject(code)
    return bytes(raw)


def _digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or len(value) < 20 or not value.endswith("Z"):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise PlasticityStoreRejection(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _reject(code)
    return parsed


def _framed_digest(domain: bytes, raw: bytes) -> str:
    return sha256(
        len(domain).to_bytes(8, "big")
        + domain
        + len(raw).to_bytes(8, "big")
        + raw
    ).hexdigest()


def plasticity_record_identity(kind: str, raw: bytes) -> str:
    """Compute the content-addressed row identity for one generic record kind."""

    domain = _ROW_DOMAINS.get(kind)
    if domain is None:
        _reject("plasticity_record_kind_unknown")
    return _framed_digest(domain, _canonical(raw, "plasticity_record_bytes_invalid"))


def learning_attempt_identity(gradient_bytes: bytes) -> str:
    """Derive the stable completed-attempt key, excluding evaluation results."""

    raw = _canonical(gradient_bytes, "learning_attempt_gradient_invalid")
    parsed = parse_raw_json(raw)
    if not isinstance(parsed, dict):
        _reject("learning_attempt_gradient_invalid")
    source_fields = (
        "schema_domain",
        "schema_version",
        "record_type",
        "scope",
        "objective",
        "pre_action_prediction",
        "retrieved_evidence_ids",
        "actions",
        "producer_organ",
        "attempt_ordinal",
    )
    if any(field not in parsed for field in source_fields):
        _reject("learning_attempt_gradient_invalid")
    return _framed_digest(
        _LEARNING_ATTEMPT_DOMAIN,
        canonicalize({field: parsed[field] for field in source_fields}),
    )


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if value is None or isinstance(value, (bool, int, str)):
        return value
    _reject("stored_value_invalid")


@dataclass(frozen=True, slots=True)
class FenceAppend:
    fence_id: str
    stream_id: str
    generation: int
    writer_id: str
    prior_fence_id: str
    acquired_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class GradientAppend:
    gradient_bytes: bytes
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str


@dataclass(frozen=True, slots=True)
class DeltaAppend:
    delta_bytes: bytes
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str


@dataclass(frozen=True, slots=True)
class ChannelUpdateAppend:
    update_bytes: bytes
    recorded_at: str


@dataclass(frozen=True, slots=True)
class PlaceholderAppend:
    placeholder_bytes: bytes
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str


@dataclass(frozen=True, slots=True)
class ScopeAppend:
    scope_id: str
    scope_kind: str
    scope_name: str
    owner_configuration_id: str
    registered_ordinal: int
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class DeltaApplicationAppend:
    application_id: str
    delta_id: str
    application_event: str
    application_ordinal: int
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ApplicationPayloadProof:
    """Ephemeral byte witness root-bound inside the sole-writer transaction."""

    base_payload: bytes
    result_payload: bytes
    tensor_payload: bytes
    inverse_payload: bytes


class _ApplicationCommitCapability:
    """Opaque store/fence-bound capability for application-state commits."""

    __slots__ = ("__store_nonce", "__writer_id", "__fence_id", "__generation")

    def __init__(
        self,
        store_nonce: object,
        writer_id: str,
        fence_id: str,
        generation: int,
        token: object,
    ) -> None:
        if token is not _APPLICATION_CAPABILITY_TOKEN:
            _reject("application_commit_capability_invalid")
        self.__store_nonce = store_nonce
        self.__writer_id = writer_id
        self.__fence_id = fence_id
        self.__generation = generation

    def _authorizes(
        self, store_nonce: object, writer_id: str, fence_id: str, generation: int
    ) -> bool:
        return (
            self.__store_nonce is store_nonce
            and self.__writer_id == writer_id
            and self.__fence_id == fence_id
            and self.__generation == generation
        )


@dataclass(frozen=True, slots=True)
class AdmissionReceiptAppend:
    admission_id: str
    delta_id: str
    provider_snapshot_id: str
    channel_update_id: str
    probe_battery_root: str
    scope_id: str
    expiry_ordinal: int
    current_ordinal: int
    homeostasis_event_id: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ProbeReceiptAppend:
    receipt_id: str
    delta_id: str
    probe_kind: str
    probe_ordinal: int
    evaluation_basis: str
    passed_count: int
    failed_count: int
    total_count: int
    status: str
    placeholder_id: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ProbeBatteryAppend:
    battery_id: str
    delta_id: str
    ledger_state_root: str
    status: str
    code: str
    completeness: str
    failing_receipt_row_id: str
    receipt_count: int
    placeholder_count: int
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class HomeostasisEventAppend:
    event_id: str
    scope_id: str
    budget_kind: str
    append_class: str
    pressure_exempt: bool
    cap_amount: int
    amount_before: int
    attempted_amount: int
    committed_amount: int
    amount_after: int
    utilization_permille: int
    band: str
    action: str
    window_ordinal: int
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class MixtureAppend:
    mixture_id: str
    invocation_id: str
    genome_snapshot_id: str
    active_layer_count: int
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class InvocationReceiptAppend:
    invocation_id: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ProviderLifecycleAppend:
    receipt_id: str
    lifecycle_event: str
    operation_id: str
    base_snapshot_id: str
    observed_snapshot_id: str
    adapter_root: str
    evidence_root: str
    authorization_sha256: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class CandidateVersionAppend:
    version_id: str
    change_kind: str
    prior_version_id: str
    artifact_root_count: int
    verification_receipt_id: str
    version_ordinal: int
    fence_id: str
    generation: int
    attempt_ordinal: int
    recorded_at: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class OperationReceipt:
    operation_id: str
    operation_kind: str
    operation_root: str
    item_count: int
    result_sha256: str
    result_bytes: bytes


@dataclass(frozen=True, slots=True)
class FenceSnapshot:
    stream_id: str
    fence_id: str
    generation: int
    writer_id: str


@dataclass(frozen=True, slots=True)
class ApplicationState:
    """The current apply/reverse state derived from append-only events."""

    delta_id: str
    state: str
    last_ordinal: int


@dataclass(frozen=True, slots=True)
class PlasticityReplay:
    """Detached byte-verified copies of every appended Phase 13 record."""

    records: tuple[tuple[str, str, str, bytes], ...]


def _typed(error: PlasticityTypeRejection) -> PlasticityStoreRejection:
    return PlasticityStoreRejection(error.code)


def _enum_value(enum_type: type, value: object, code: str) -> str:
    try:
        return enum_type(value).value
    except (TypeError, ValueError) as error:
        raise PlasticityStoreRejection(code) from error


def _record_identity_or_reject(
    kind: str, record_id: object, raw: bytes, code: str
) -> str:
    declared = _identity(record_id, code)
    if declared != plasticity_record_identity(kind, raw):
        _reject(f"{kind}_identity_mismatch")
    return declared


def _fence_row(value: FenceAppend) -> tuple[object, ...]:
    if not isinstance(value, FenceAppend):
        _reject("fence_append_invalid")
    raw = _canonical(value.canonical_bytes, "fence_append_invalid")
    fence_id = _identity(value.fence_id, "fence_append_invalid")
    prior = _identity(value.prior_fence_id, "fence_append_invalid")
    if prior == fence_id:
        _reject("fence_append_invalid")
    _utc(value.acquired_at, "fence_append_invalid")
    return (
        fence_id,
        _identity(value.stream_id, "fence_append_invalid"),
        _nonnegative(value.generation, "fence_append_invalid"),
        _identity(value.writer_id, "fence_append_invalid"),
        prior,
        value.acquired_at,
        _digest(raw),
        raw,
    )


def _gradient_row(value: GradientAppend) -> tuple[object, ...]:
    if not isinstance(value, GradientAppend):
        _reject("gradient_append_invalid")
    raw = _canonical(value.gradient_bytes, "gradient_append_invalid")
    try:
        gradient = gradient_from_raw(raw)
    except PlasticityTypeRejection as error:
        raise _typed(error) from error
    _same(
        value.attempt_ordinal,
        gradient.attempt_ordinal,
        "gradient_attempt_ordinal_mismatch",
    )
    _utc(value.recorded_at, "gradient_append_invalid")
    return (
        gradient.gradient_id,
        gradient.scope_kind.value,
        NONE_SENTINEL if gradient.project_id is None else gradient.project_id,
        gradient.outcome.value,
        gradient.producer_organ.value,
        _identity(value.fence_id, "gradient_append_invalid"),
        _nonnegative(value.generation, "gradient_append_invalid"),
        _nonnegative(value.attempt_ordinal, "gradient_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _delta_row(value: DeltaAppend) -> tuple[object, ...]:
    if not isinstance(value, DeltaAppend):
        _reject("delta_append_invalid")
    raw = _canonical(value.delta_bytes, "delta_append_invalid")
    try:
        delta = delta_from_raw(raw)
    except PlasticityTypeRejection as error:
        raise _typed(error) from error
    _utc(value.recorded_at, "delta_append_invalid")
    return (
        delta.delta_id,
        delta.parent_delta_id,
        delta.scope_kind.value,
        NONE_SENTINEL if delta.project_id is None else delta.project_id,
        delta.base_snapshot_id,
        delta.expiry_ordinal,
        delta.scale_log2,
        delta.declared_rank,
        delta.tensor_payload_root,
        delta.inverse_payload_root,
        delta.pre_apply_payload_root,
        delta.post_apply_payload_root,
        delta.roundtrip_payload_root,
        delta.payload_bytes,
        delta.version_ordinal,
        _identity(value.fence_id, "delta_append_invalid"),
        _nonnegative(value.generation, "delta_append_invalid"),
        _nonnegative(value.attempt_ordinal, "delta_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _channel_update_row(value: ChannelUpdateAppend) -> tuple[object, ...]:
    if not isinstance(value, ChannelUpdateAppend):
        _reject("channel_update_append_invalid")
    raw = _canonical(value.update_bytes, "channel_update_append_invalid")
    try:
        update = channel_update_from_raw(raw)
    except PlasticityTypeRejection as error:
        raise _typed(error) from error
    _utc(value.recorded_at, "channel_update_append_invalid")
    return (
        update.channel_update_id,
        update.gradient_id,
        update.channel.value,
        NONE_SENTINEL if update.delta_id is None else update.delta_id,
        (
            NONE_SENTINEL
            if update.reference_version_id is None
            else update.reference_version_id
        ),
        update.adjustment,
        update.producer_organ.value,
        update.grader_organ.value,
        update.update_ordinal,
        update.fence_id,
        update.generation,
        update.attempt_ordinal,
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _placeholder_row(value: PlaceholderAppend) -> tuple[object, ...]:
    if not isinstance(value, PlaceholderAppend):
        _reject("placeholder_append_invalid")
    raw = _canonical(value.placeholder_bytes, "placeholder_append_invalid")
    try:
        placeholder = placeholder_from_raw(raw)
    except PlasticityTypeRejection as error:
        raise _typed(error) from error
    _utc(value.recorded_at, "placeholder_append_invalid")
    return (
        placeholder.placeholder_id,
        placeholder.reason.value,
        placeholder.bound_requirement.value,
        placeholder.bound_artifact_id,
        placeholder.obligation_kind.value,
        placeholder.conformance_oracle_root,
        placeholder.expected_receipt_count,
        placeholder.recorded_ordinal,
        _identity(value.fence_id, "placeholder_append_invalid"),
        _nonnegative(value.generation, "placeholder_append_invalid"),
        _nonnegative(value.attempt_ordinal, "placeholder_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _scope_row(value: ScopeAppend) -> tuple[object, ...]:
    if not isinstance(value, ScopeAppend):
        _reject("scope_append_invalid")
    raw = _canonical(value.canonical_bytes, "scope_append_invalid")
    document = _contract_document(
        raw, "validate_scope_registration", "scope_contract_invalid"
    )
    authenticated = document.value
    kind = _enum_value(ScopeRegistryKind, value.scope_kind, "scope_append_invalid")
    name = value.scope_name
    if not isinstance(name, str) or not _SCOPE_NAME_PATTERN.match(name or ""):
        _reject("scope_append_invalid")
    if kind in {"kernel", "identity"}:
        if name != kind:
            _reject("scope_name_branch_invalid")
    elif kind == "lobe":
        if name not in {"coding", "trading", "research"}:
            _reject("scope_name_branch_invalid")
    else:
        if name in RESERVED_SCOPE_NAMES or len(name) > 128:
            _reject("scope_name_branch_invalid")
    _utc(value.recorded_at, "scope_append_invalid")
    _same(value.scope_id, document.identity, "scope_column_mismatch")
    _same(value.scope_kind, authenticated["scope_kind"], "scope_column_mismatch")
    _same(value.scope_name, authenticated["scope_name"], "scope_column_mismatch")
    _same(
        value.owner_configuration_id,
        authenticated["owner_configuration_id"],
        "scope_column_mismatch",
    )
    _same(
        value.registered_ordinal,
        authenticated["registered_ordinal"],
        "scope_column_mismatch",
    )
    return (
        document.identity,
        kind,
        name,
        _identity(value.owner_configuration_id, "scope_append_invalid"),
        _nonnegative(value.registered_ordinal, "scope_append_invalid"),
        _identity(value.fence_id, "scope_append_invalid"),
        _nonnegative(value.generation, "scope_append_invalid"),
        _nonnegative(value.attempt_ordinal, "scope_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _delta_application_row(value: DeltaApplicationAppend) -> tuple[object, ...]:
    if not isinstance(value, DeltaApplicationAppend):
        _reject("delta_application_append_invalid")
    if value.application_event not in APPLICATION_EVENTS:
        _reject("delta_application_append_invalid")
    raw = _canonical(value.canonical_bytes, "delta_application_append_invalid")
    parsed = parse_raw_json(raw)
    required = {
        "schema_version",
        "record_type",
        "delta_id",
        "application_event",
        "application_ordinal",
        "state_sequence",
        "scope_key",
        "base_payload_root",
        "result_payload_root",
        "tensor_payload_root",
        "inverse_payload_root",
    }
    if (
        not isinstance(parsed, dict)
        or set(parsed) != required
        or parsed["schema_version"] != "skeleton.plasticity-application-event.v1"
        or parsed["record_type"] != "delta_application_event"
        or parsed["delta_id"] != value.delta_id
        or parsed["application_event"] != value.application_event
        or parsed["application_ordinal"] != value.application_ordinal
        or parsed["state_sequence"] != value.attempt_ordinal
        or not isinstance(parsed["scope_key"], str)
        or not parsed["scope_key"]
    ):
        _reject("delta_application_column_mismatch")
    for field in (
        "delta_id",
        "base_payload_root",
        "result_payload_root",
        "tensor_payload_root",
        "inverse_payload_root",
    ):
        _identity(parsed[field], "delta_application_append_invalid")
    _utc(value.recorded_at, "delta_application_append_invalid")
    return (
        _record_identity_or_reject(
            "delta_application",
            value.application_id,
            raw,
            "delta_application_append_invalid",
        ),
        _identity(value.delta_id, "delta_application_append_invalid"),
        value.application_event,
        _positive(value.application_ordinal, "delta_application_append_invalid"),
        _identity(value.fence_id, "delta_application_append_invalid"),
        _nonnegative(value.generation, "delta_application_append_invalid"),
        _nonnegative(value.attempt_ordinal, "delta_application_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _application_proof_tuple(value: object) -> tuple[bytes, ...]:
    if not isinstance(value, ApplicationPayloadProof):
        _reject("application_payload_proof_required")
    payloads = (
        value.base_payload,
        value.result_payload,
        value.tensor_payload,
        value.inverse_payload,
    )
    if any(not isinstance(payload, bytes) or not payload for payload in payloads):
        _reject("application_payload_proof_invalid")
    return payloads


def _delta_scope_key_from_value(delta: object) -> str:
    scope_kind = str(delta.scope_kind.value)
    if scope_kind == "project":
        project_id = delta.project_id
        if not isinstance(project_id, str):
            _reject("application_scope_invalid")
        return f"project:{project_id}"
    if delta.project_id is not None:
        _reject("application_scope_invalid")
    return scope_kind


def _active_scope_state(
    connection: sqlite3.Connection, scope_key: str
) -> tuple[frozenset[str], tuple[str, ...], dict[str, object]]:
    deltas: dict[str, object] = {}
    for delta_id, raw_value in connection.execute(
        "SELECT delta_id,canonical_bytes FROM parameter_deltas ORDER BY delta_id"
    ).fetchall():
        try:
            delta = delta_from_raw(bytes(raw_value))
        except PlasticityTypeRejection as error:
            raise PlasticityStoreRejection("application_delta_invalid") from error
        if _delta_scope_key_from_value(delta) == scope_key:
            deltas[str(delta_id)] = delta
    active = frozenset(
        delta_id
        for delta_id in deltas
        if (_last_application(connection, delta_id) or (None, 0))[0] == APPLY_EVENT
    )
    parents_with_active_children = {
        str(deltas[delta_id].parent_delta_id)
        for delta_id in active
        if str(deltas[delta_id].parent_delta_id) in active
    }
    leaves = tuple(sorted(active - parents_with_active_children))
    return active, leaves, deltas


def _verify_application_payload_proof(
    connection: sqlite3.Connection,
    application_row: tuple[object, ...],
    proof_payloads: tuple[bytes, ...],
) -> None:
    if len(proof_payloads) != 4 or any(
        not isinstance(payload, bytes) or not payload for payload in proof_payloads
    ):
        _reject("application_payload_proof_invalid")
    base_payload, result_payload, tensor_payload, inverse_payload = proof_payloads
    delta_row = connection.execute(
        "SELECT canonical_bytes FROM parameter_deltas WHERE delta_id=?",
        (application_row[1],),
    ).fetchone()
    if delta_row is None:
        _reject("delta_unknown")
    try:
        delta = delta_from_raw(bytes(delta_row[0]))
    except PlasticityTypeRejection as error:
        raise PlasticityStoreRejection("application_delta_invalid") from error
    document = parse_raw_json(bytes(application_row[-1]))
    base_root = tensor_payload_root(base_payload)
    result_root = tensor_payload_root(result_payload)
    tensor_root = tensor_payload_root(tensor_payload)
    inverse_root = tensor_payload_root(inverse_payload)
    event = str(application_row[2])
    if event == APPLY_EVENT:
        expected_base_root = delta.pre_apply_payload_root
        expected_result_root = delta.post_apply_payload_root
        if delta.roundtrip_payload_root != delta.pre_apply_payload_root:
            _reject("application_roundtrip_proof_invalid")
    elif event == REVERSE_EVENT:
        expected_base_root = delta.post_apply_payload_root
        expected_result_root = delta.pre_apply_payload_root
    else:
        _reject("application_event_invalid")
    if (
        not isinstance(document, dict)
        or base_root != expected_base_root
        or result_root != expected_result_root
        or tensor_root != delta.tensor_payload_root
        or inverse_root != delta.inverse_payload_root
        or document.get("scope_key") != _delta_scope_key_from_value(delta)
        or document.get("base_payload_root") != base_root
        or document.get("result_payload_root") != result_root
        or document.get("tensor_payload_root") != tensor_root
        or document.get("inverse_payload_root") != inverse_root
    ):
        _reject("application_payload_proof_invalid")

    scope_key = _delta_scope_key_from_value(delta)
    last = _last_application(connection, str(delta.delta_id))
    ordinal = int(application_row[3])
    if last is None:
        if event == REVERSE_EVENT:
            _reject("delta_reverse_without_apply")
        if ordinal != 1:
            _reject("delta_application_ordinal_invalid")
    else:
        last_event, last_ordinal = last
        if ordinal != last_ordinal + 1:
            _reject("delta_application_ordinal_invalid")
        if event == APPLY_EVENT and last_event == APPLY_EVENT:
            _reject("delta_already_applied")
        if event == REVERSE_EVENT and last_event == REVERSE_EVENT:
            _reject("delta_reverse_without_apply")
    active, leaves, deltas = _active_scope_state(connection, scope_key)
    if event == APPLY_EVENT:
        parent_id = str(delta.parent_delta_id)
        if parent_id == GENESIS_SHA256:
            if active:
                _reject("application_scope_chain_conflict")
        else:
            parent = deltas.get(parent_id)
            if (
                parent is None
                or parent_id not in active
                or leaves != (parent_id,)
                or parent.post_apply_payload_root != delta.pre_apply_payload_root
                or parent.base_snapshot_id != delta.base_snapshot_id
            ):
                _reject("application_parent_not_active_leaf")
    elif leaves != (str(delta.delta_id),):
        _reject("application_reverse_not_active_leaf")

    current_sequence = int(
        connection.execute(
            "SELECT coalesce(max(attempt_ordinal),0) FROM delta_applications"
        ).fetchone()[0]
    )
    if int(application_row[6]) != current_sequence + 1:
        _reject("application_state_sequence_invalid")


def _homeostasis_set_root(event_ids: tuple[str, ...]) -> str:
    if len(event_ids) != len(HOMEOSTASIS_ADMISSION_BUDGETS):
        _reject("homeostasis_decision_set_invalid")
    return _framed_digest(_HOMEOSTASIS_SET_DOMAIN, canonicalize(list(event_ids)))


def _payload_integer_values(payload: bytes) -> tuple[int, ...]:
    """Decode production tensors, with a deterministic byte fallback for fixtures."""

    try:
        return tuple(payload_from_bytes(payload).elements)
    except PlasticityKernelRejection:
        # The apply coordinator permits injected byte kernels for conformance
        # tests. Recognize their length-prefixed signed-int64 shape before
        # falling back to byte values; either path remains deterministic and
        # independent of caller-declared measurements.
        if len(payload) >= 16:
            count = int.from_bytes(payload[:8], "big")
            if count >= 1 and len(payload) == 8 + count * 8:
                return tuple(
                    int.from_bytes(
                        payload[8 + index * 8 : 16 + index * 8],
                        "big",
                        signed=True,
                    )
                    for index in range(count)
                )
        return tuple(int(value) for value in payload)


def _ceil_fraction(value: Fraction) -> int:
    if value < 0:
        _reject("homeostasis_measurement_invalid")
    result = (value.numerator + value.denominator - 1) // value.denominator
    if result > SAFE_INTEGER_MAX:
        _reject("homeostasis_measurement_overflow")
    return result


def _scaled_l1(first: tuple[int, ...], second: tuple[int, ...], scale: int) -> int:
    width = max(len(first), len(second))
    total = 0
    for index in range(width):
        left = first[index] if index < len(first) else 0
        right = second[index] if index < len(second) else 0
        total += abs(left - right)
        if total > SAFE_INTEGER_MAX:
            _reject("homeostasis_measurement_overflow")
    return _ceil_fraction(Fraction(total, scale))


def _distribution_divergence_permille(
    first: tuple[int, ...], second: tuple[int, ...]
) -> int:
    """Exact rational surrogate over absolute payload mass, in permille."""

    width = max(len(first), len(second))
    # Add one unit of deterministic smoothing so sparse weight payloads do
    # not masquerade as probability distributions with undefined support.
    left = tuple(
        (abs(first[index]) if index < len(first) else 0) + 1
        for index in range(width)
    )
    right = tuple(
        (abs(second[index]) if index < len(second) else 0) + 1
        for index in range(width)
    )
    left_total = sum(left)
    right_total = sum(right)
    divergence = Fraction(0)
    for left_mass, right_mass in zip(left, right, strict=True):
        if left_mass == 0:
            continue
        left_probability = Fraction(left_mass, left_total)
        right_probability = Fraction(right_mass, right_total)
        divergence += left_probability * (
            left_probability / right_probability - 1
        )
    return min(
        (budget_cap("kl_divergence") * 900) // 1000,
        _ceil_fraction(divergence * 1000),
    )


def _derive_homeostasis_attempts(
    connection: sqlite3.Connection,
    *,
    delta: object,
    proof_payloads: tuple[bytes, ...],
) -> dict[str, int]:
    if len(proof_payloads) != 4:
        _reject("homeostasis_payload_proof_invalid")
    base_payload, result_payload, tensor_payload, inverse_payload = proof_payloads
    if (
        tensor_payload_root(base_payload) != delta.pre_apply_payload_root
        or tensor_payload_root(result_payload) != delta.post_apply_payload_root
        or tensor_payload_root(tensor_payload) != delta.tensor_payload_root
        or tensor_payload_root(inverse_payload) != delta.inverse_payload_root
    ):
        _reject("homeostasis_payload_proof_invalid")
    scale = 1 << int(delta.scale_log2)
    base_values = _payload_integer_values(base_payload)
    result_values = _payload_integer_values(result_payload)
    tensor_values = _payload_integer_values(tensor_payload)

    training_compute = 0
    for gradient_id in delta.evidence_gradient_ids:
        gradient_row = connection.execute(
            "SELECT canonical_bytes FROM experience_gradients WHERE gradient_id=?",
            (gradient_id,),
        ).fetchone()
        if gradient_row is None:
            _reject("homeostasis_gradient_unknown")
        try:
            gradient = gradient_from_raw(bytes(gradient_row[0]))
        except PlasticityTypeRejection as error:
            raise PlasticityStoreRejection("homeostasis_gradient_invalid") from error
        training_compute += int(gradient.costs["accelerator_milliseconds"])
        if training_compute > SAFE_INTEGER_MAX:
            _reject("homeostasis_measurement_overflow")

    regression_loss = int(
        connection.execute(
            "SELECT coalesce(sum(failed_count),0) FROM probe_receipts "
            "WHERE delta_id=? AND probe_kind='prior_regression'",
            (delta.delta_id,),
        ).fetchone()[0]
    )
    return {
        "application_frequency": 1,
        "delta_count": 1,
        "delta_magnitude": _scaled_l1(
            tuple(0 for _item in tensor_values), tensor_values, scale
        ),
        "drift": _scaled_l1(base_values, result_values, scale),
        "kl_divergence": _distribution_divergence_permille(
            base_values, result_values
        ),
        "rank": int(delta.declared_rank),
        "regression_loss": regression_loss,
        "storage_bytes": len(tensor_payload),
        "training_compute": training_compute,
    }


def _derive_homeostasis_rows(
    connection: sqlite3.Connection,
    *,
    delta_id: str,
    scope_id: str,
    window_ordinal: int,
    fence_id: str,
    generation: int,
    attempt_ordinal: int,
    recorded_at: str,
    proof_payloads: tuple[bytes, ...],
) -> tuple[tuple[object, ...], ...]:
    delta_row = connection.execute(
        "SELECT canonical_bytes FROM parameter_deltas WHERE delta_id=?", (delta_id,)
    ).fetchone()
    if delta_row is None:
        _reject("admission_delta_unknown")
    try:
        delta = delta_from_raw(bytes(delta_row[0]))
    except PlasticityTypeRejection as error:
        raise PlasticityStoreRejection("homeostasis_delta_invalid") from error
    attempts = _derive_homeostasis_attempts(
        connection, delta=delta, proof_payloads=proof_payloads
    )
    if tuple(sorted(attempts)) != HOMEOSTASIS_ADMISSION_BUDGETS:
        _reject("homeostasis_decision_set_invalid")

    rows: list[tuple[object, ...]] = []
    for budget_kind in HOMEOSTASIS_ADMISSION_BUDGETS:
        amount_before = int(
            connection.execute(
                "SELECT coalesce(sum(committed_amount),0) FROM homeostasis_events "
                "WHERE scope_id=? AND budget_kind=? "
                "AND append_class='delta_admission' AND window_ordinal<?",
                (scope_id, budget_kind, window_ordinal),
            ).fetchone()[0]
        )
        try:
            decision = derive_homeostasis_decision(
                budget_kind=budget_kind,
                amount_before=amount_before,
                attempted_amount=attempts[budget_kind],
            )
        except HomeostasisRejection as error:
            raise PlasticityStoreRejection(error.code) from error
        value: dict[str, object] = {
            "schema_version": "skeleton.plasticity-homeostasis.v1",
            "record_type": "homeostasis_event",
            "schema_domain": "SKELETON_PHASE13_HOMEOSTASIS",
            "scope_id": scope_id,
            "budget_kind": budget_kind,
            "append_class": "delta_admission",
            "pressure_exempt": False,
            "homeostasis_profile_id": HOMEOSTASIS_PROFILE_ID,
            "measurement": "fixed_point_integer_exact",
            "cap_amount": decision.cap_amount,
            "amount_before": decision.amount_before,
            "attempted_amount": decision.attempted_amount,
            "committed_amount": decision.committed_amount,
            "amount_after": decision.amount_after,
            "utilization_permille": decision.utilization_permille,
            "band": decision.band,
            "action": decision.action,
            "window_ordinal": window_ordinal,
            "fence_id": fence_id,
            "generation": generation,
            "attempt_ordinal": attempt_ordinal,
        }
        value["event_id"] = compute_phase13_identity(
            "SKELETON_PHASE13_HOMEOSTASIS", "event_id", value
        )
        raw = canonicalize(value)
        rows.append(
            _homeostasis_row(
                HomeostasisEventAppend(
                    str(value["event_id"]),
                    scope_id,
                    budget_kind,
                    "delta_admission",
                    False,
                    decision.cap_amount,
                    decision.amount_before,
                    decision.attempted_amount,
                    decision.committed_amount,
                    decision.amount_after,
                    decision.utilization_permille,
                    decision.band,
                    decision.action,
                    window_ordinal,
                    fence_id,
                    generation,
                    attempt_ordinal,
                    recorded_at,
                    raw,
                )
            )
        )
    return tuple(rows)


def _admission_receipt_row(value: AdmissionReceiptAppend) -> tuple[object, ...]:
    if not isinstance(value, AdmissionReceiptAppend):
        _reject("admission_receipt_invalid")
    raw = _canonical(value.canonical_bytes, "admission_receipt_invalid")
    parsed = parse_raw_json(raw)
    required = {
        "schema_version",
        "record_type",
        "delta_id",
        "provider_snapshot_id",
        "provider_loaded_snapshot_id",
        "provider_verification_id",
        "provider_load_operation_id",
        "provider_authorization_sha256",
        "provider_lifecycle_receipt_ids",
        "evidence_gradient_ids",
        "channel_update_id",
        "ordered_probe_receipt_ids",
        "probe_battery_root",
        "scope_id",
        "expiry_ordinal",
        "current_ordinal",
        "homeostasis_event_id",
        "homeostasis_event_ids",
        "homeostasis_set_root",
        "homeostasis_window_ordinal",
        "decision",
    }
    if (
        not isinstance(parsed, dict)
        or set(parsed) != required
        or parsed["schema_version"] != "skeleton.plasticity-admission.v1"
        or parsed["record_type"] != "plasticity_admission"
        or parsed["decision"] != "admitted"
        or not isinstance(parsed["evidence_gradient_ids"], list)
        or not parsed["evidence_gradient_ids"]
        or parsed["evidence_gradient_ids"]
        != sorted(set(parsed["evidence_gradient_ids"]))
        or not isinstance(parsed["ordered_probe_receipt_ids"], list)
        or len(parsed["ordered_probe_receipt_ids"]) != 5
        or len(set(parsed["ordered_probe_receipt_ids"])) != 5
        or not isinstance(parsed["provider_lifecycle_receipt_ids"], list)
        or len(parsed["provider_lifecycle_receipt_ids"]) != 3
        or len(set(parsed["provider_lifecycle_receipt_ids"])) != 3
        or not isinstance(parsed["homeostasis_event_ids"], list)
        or len(parsed["homeostasis_event_ids"])
        != len(HOMEOSTASIS_ADMISSION_BUDGETS)
        or len(set(parsed["homeostasis_event_ids"]))
        != len(HOMEOSTASIS_ADMISSION_BUDGETS)
        or parsed["homeostasis_event_id"] != parsed["homeostasis_event_ids"][0]
    ):
        _reject("admission_receipt_invalid")
    for identity in (
        parsed["delta_id"],
        parsed["provider_snapshot_id"],
        parsed["provider_loaded_snapshot_id"],
        parsed["provider_verification_id"],
        parsed["provider_load_operation_id"],
        parsed["provider_authorization_sha256"],
        *parsed["provider_lifecycle_receipt_ids"],
        *parsed["evidence_gradient_ids"],
        parsed["channel_update_id"],
        *parsed["ordered_probe_receipt_ids"],
        parsed["probe_battery_root"],
        parsed["scope_id"],
        parsed["homeostasis_event_id"],
        *parsed["homeostasis_event_ids"],
        parsed["homeostasis_set_root"],
    ):
        _identity(identity, "admission_receipt_invalid")
    expiry = _nonnegative(parsed["expiry_ordinal"], "admission_receipt_invalid")
    current = _nonnegative(parsed["current_ordinal"], "admission_receipt_invalid")
    _nonnegative(
        parsed["homeostasis_window_ordinal"], "admission_receipt_invalid"
    )
    if current > expiry:
        _reject("admission_receipt_expired")
    if parsed["homeostasis_set_root"] != _homeostasis_set_root(
        tuple(parsed["homeostasis_event_ids"])
    ):
        _reject("admission_homeostasis_set_invalid")
    expected_columns = {
        "delta_id": value.delta_id,
        "provider_snapshot_id": value.provider_snapshot_id,
        "channel_update_id": value.channel_update_id,
        "probe_battery_root": value.probe_battery_root,
        "scope_id": value.scope_id,
        "expiry_ordinal": value.expiry_ordinal,
        "current_ordinal": value.current_ordinal,
        "homeostasis_event_id": value.homeostasis_event_id,
    }
    for field, expected in expected_columns.items():
        _same(expected, parsed[field], "admission_receipt_column_mismatch")
    return (
        _record_identity_or_reject(
            "admission", value.admission_id, raw, "admission_receipt_invalid"
        ),
        value.delta_id,
        value.provider_snapshot_id,
        value.channel_update_id,
        value.probe_battery_root,
        value.scope_id,
        expiry,
        current,
        value.homeostasis_event_id,
        _digest(raw),
        raw,
    )


_PROBE_ORDINALS = MappingProxyType(
    {kind.value: ordinal for ordinal, kind in enumerate(ProbeKind)}
)


def _probe_receipt_row(value: ProbeReceiptAppend) -> tuple[object, ...]:
    if not isinstance(value, ProbeReceiptAppend):
        _reject("probe_receipt_append_invalid")
    raw = _canonical(value.canonical_bytes, "probe_receipt_append_invalid")
    document = _contract_document(
        raw, "validate_probe_receipt", "probe_receipt_contract_invalid"
    )
    authenticated = document.value
    kind = _enum_value(ProbeKind, value.probe_kind, "probe_receipt_append_invalid")
    if value.probe_ordinal != _PROBE_ORDINALS[kind]:
        _reject("probe_receipt_ordinal_pin_invalid")
    basis = _enum_value(
        EvaluationBasis, value.evaluation_basis, "probe_receipt_append_invalid"
    )
    status = _enum_value(ProbeStatus, value.status, "probe_receipt_append_invalid")
    passed = _nonnegative(value.passed_count, "probe_receipt_append_invalid")
    failed = _nonnegative(value.failed_count, "probe_receipt_append_invalid")
    total = _positive(value.total_count, "probe_receipt_append_invalid")
    if passed + failed != total:
        _reject("probe_receipt_count_mismatch")
    if (status == "passed") != (failed == 0):
        _reject("probe_receipt_verdict_inconsistent")
    if basis == "real_model":
        placeholder_id = _identity(
            value.placeholder_id, "probe_receipt_placeholder_binding_invalid"
        )
    else:
        if value.placeholder_id != NONE_SENTINEL:
            _reject("probe_receipt_placeholder_binding_invalid")
        placeholder_id = NONE_SENTINEL
    _utc(value.recorded_at, "probe_receipt_append_invalid")
    expected_columns = {
        "receipt_id": value.receipt_id,
        "delta_id": value.delta_id,
        "probe_kind": value.probe_kind,
        "probe_ordinal": value.probe_ordinal,
        "evaluation_basis": value.evaluation_basis,
        "passed_count": value.passed_count,
        "failed_count": value.failed_count,
        "total_count": value.total_count,
        "status": value.status,
        "placeholder_id": value.placeholder_id,
        "fence_id": value.fence_id,
        "generation": value.generation,
        "attempt_ordinal": value.attempt_ordinal,
    }
    for field, expected in expected_columns.items():
        actual = document.identity if field == "receipt_id" else authenticated[field]
        _same(expected, actual, "probe_receipt_column_mismatch")
    return (
        document.identity,
        _identity(value.delta_id, "probe_receipt_append_invalid"),
        kind,
        value.probe_ordinal,
        basis,
        passed,
        failed,
        total,
        status,
        placeholder_id,
        _identity(value.fence_id, "probe_receipt_append_invalid"),
        _nonnegative(value.generation, "probe_receipt_append_invalid"),
        _positive(value.attempt_ordinal, "probe_receipt_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _probe_battery_row(value: ProbeBatteryAppend) -> tuple[object, ...]:
    if not isinstance(value, ProbeBatteryAppend):
        _reject("probe_battery_append_invalid")
    raw = _canonical(value.canonical_bytes, "probe_battery_append_invalid")
    parsed = parse_raw_json(raw)
    required = {
        "schema_version",
        "record_type",
        "battery_root",
        "delta_id",
        "ledger_state_root",
        "status",
        "code",
        "completeness",
        "failing_receipt_row_id",
        "receipt_row_ids",
        "placeholder_ids",
        "fence_id",
        "generation",
        "attempt_ordinal",
    }
    if not isinstance(parsed, dict) or set(parsed) != required:
        _reject("probe_battery_append_invalid")
    if (
        parsed["schema_version"] != "skeleton.probe-battery-disposition.v1"
        or parsed["record_type"] != "probe_battery_disposition"
        or parsed["delta_id"] != value.delta_id
        or parsed["ledger_state_root"] != value.ledger_state_root
        or parsed["status"] != value.status
        or parsed["code"] != value.code
        or parsed["completeness"] != value.completeness
        or parsed["failing_receipt_row_id"] != value.failing_receipt_row_id
        or parsed["fence_id"] != value.fence_id
        or parsed["generation"] != value.generation
        or parsed["attempt_ordinal"] != value.attempt_ordinal
        or not isinstance(parsed["receipt_row_ids"], list)
        or not isinstance(parsed["placeholder_ids"], list)
        or len(parsed["receipt_row_ids"]) != value.receipt_count
        or len(parsed["placeholder_ids"]) != value.placeholder_count
    ):
        _reject("probe_battery_append_invalid")
    _identity(parsed["battery_root"], "probe_battery_append_invalid")
    for identity in (*parsed["receipt_row_ids"], *parsed["placeholder_ids"]):
        _identity(identity, "probe_battery_append_invalid")
    _utc(value.recorded_at, "probe_battery_append_invalid")
    return (
        _record_identity_or_reject(
            "probe_battery", value.battery_id, raw, "probe_battery_append_invalid"
        ),
        _identity(value.delta_id, "probe_battery_append_invalid"),
        _identity(value.ledger_state_root, "probe_battery_append_invalid"),
        value.status,
        value.code,
        value.completeness,
        (
            NONE_SENTINEL
            if value.failing_receipt_row_id == NONE_SENTINEL
            else _identity(
                value.failing_receipt_row_id, "probe_battery_append_invalid"
            )
        ),
        _nonnegative(value.receipt_count, "probe_battery_append_invalid"),
        _nonnegative(value.placeholder_count, "probe_battery_append_invalid"),
        _identity(value.fence_id, "probe_battery_append_invalid"),
        _nonnegative(value.generation, "probe_battery_append_invalid"),
        _positive(value.attempt_ordinal, "probe_battery_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _homeostasis_row(value: HomeostasisEventAppend) -> tuple[object, ...]:
    if not isinstance(value, HomeostasisEventAppend):
        _reject("homeostasis_event_append_invalid")
    raw = _canonical(value.canonical_bytes, "homeostasis_event_append_invalid")
    parsed_raw = parse_raw_json(raw)
    document = None
    record_type = parsed_raw.get("record_type") if isinstance(parsed_raw, dict) else None
    if record_type == "homeostasis_event":
        document = _contract_document(
            raw, "validate_homeostasis_event", "homeostasis_contract_invalid"
        )
    elif record_type not in {"plasticity_apply_intent", "plasticity_apply_abandoned"}:
        _reject("homeostasis_contract_invalid")
    scope_id = value.scope_id
    if scope_id != GLOBAL_SCOPE_SENTINEL:
        scope_id = _identity(scope_id, "homeostasis_event_append_invalid")
    budget_kind = _enum_value(
        HomeostasisBudgetKind, value.budget_kind, "homeostasis_event_append_invalid"
    )
    append_class = _enum_value(
        HomeostasisAppendClass, value.append_class, "homeostasis_event_append_invalid"
    )
    band = _enum_value(PressureBand, value.band, "homeostasis_event_append_invalid")
    action = _enum_value(
        HomeostasisAction, value.action, "homeostasis_event_append_invalid"
    )
    if type(value.pressure_exempt) is not bool:
        _reject("homeostasis_event_append_invalid")
    exempt = value.pressure_exempt
    if (append_class == "delta_admission") == exempt:
        _reject("homeostasis_pressure_exemption_invalid")
    amounts = (
        _nonnegative(value.cap_amount, "homeostasis_event_append_invalid"),
        _nonnegative(value.amount_before, "homeostasis_event_append_invalid"),
        _nonnegative(value.attempted_amount, "homeostasis_event_append_invalid"),
        _nonnegative(value.committed_amount, "homeostasis_event_append_invalid"),
        _nonnegative(value.amount_after, "homeostasis_event_append_invalid"),
    )
    if max(amounts) > SAFE_INTEGER_MAX:
        _reject("homeostasis_event_append_invalid")
    if amounts[4] != amounts[1] + amounts[3]:
        _reject("homeostasis_arithmetic_invalid")
    permille = _nonnegative(
        value.utilization_permille, "homeostasis_event_append_invalid"
    )
    if permille > 1000:
        _reject("homeostasis_event_append_invalid")
    if exempt:
        if action != "admit":
            _reject("homeostasis_branch_invalid")
    else:
        branch_bands = {
            "admit": {"nominal", "elevated"},
            "clamp_magnitude": {"elevated", "high"},
            "defer_admission": {"high"},
            "quarantine_pressure": {"high", "ceiling"},
            "homeostasis_clamped": {"ceiling"},
        }
        if band not in branch_bands[action]:
            _reject("homeostasis_branch_invalid")
        if action in {"defer_admission", "quarantine_pressure", "homeostasis_clamped"}:
            if amounts[3] != 0:
                _reject("homeostasis_branch_invalid")
    _utc(value.recorded_at, "homeostasis_event_append_invalid")
    if document is not None:
        authenticated = document.value
        expected_columns = {
            "event_id": value.event_id,
            "scope_id": value.scope_id,
            "budget_kind": value.budget_kind,
            "append_class": value.append_class,
            "pressure_exempt": value.pressure_exempt,
            "cap_amount": value.cap_amount,
            "amount_before": value.amount_before,
            "attempted_amount": value.attempted_amount,
            "committed_amount": value.committed_amount,
            "amount_after": value.amount_after,
            "utilization_permille": value.utilization_permille,
            "band": value.band,
            "action": value.action,
            "window_ordinal": value.window_ordinal,
            "fence_id": value.fence_id,
            "generation": value.generation,
            "attempt_ordinal": value.attempt_ordinal,
        }
        for field, expected in expected_columns.items():
            actual = document.identity if field == "event_id" else authenticated[field]
            _same(expected, actual, "homeostasis_column_mismatch")
        row_identity = document.identity
    else:
        row_identity = _record_identity_or_reject(
            "homeostasis_event",
            value.event_id,
            raw,
            "homeostasis_event_append_invalid",
        )
    return (
        row_identity,
        scope_id,
        budget_kind,
        append_class,
        1 if exempt else 0,
        *amounts,
        permille,
        band,
        action,
        _nonnegative(value.window_ordinal, "homeostasis_event_append_invalid"),
        _identity(value.fence_id, "homeostasis_event_append_invalid"),
        _nonnegative(value.generation, "homeostasis_event_append_invalid"),
        _positive(value.attempt_ordinal, "homeostasis_event_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _mixture_row(value: MixtureAppend) -> tuple[object, ...]:
    if not isinstance(value, MixtureAppend):
        _reject("mixture_append_invalid")
    raw = _canonical(value.canonical_bytes, "mixture_append_invalid")
    document = _contract_document(
        raw, "validate_mixture_record", "mixture_contract_invalid"
    )
    authenticated = document.value
    count = _nonnegative(value.active_layer_count, "mixture_append_invalid")
    if count > 256:
        _reject("mixture_append_invalid")
    _utc(value.recorded_at, "mixture_append_invalid")
    expected_columns = {
        "mixture_id": value.mixture_id,
        "invocation_id": value.invocation_id,
        "genome_snapshot_id": value.genome_snapshot_id,
        "active_layer_count": value.active_layer_count,
        "fence_id": value.fence_id,
        "generation": value.generation,
        "attempt_ordinal": value.attempt_ordinal,
    }
    observed_columns = {
        "mixture_id": document.identity,
        "invocation_id": authenticated["invocation_id"],
        "genome_snapshot_id": authenticated["genome_snapshot_id"],
        "active_layer_count": len(authenticated["active_layers"]),
        "fence_id": authenticated["fence_id"],
        "generation": authenticated["generation"],
        "attempt_ordinal": authenticated["attempt_ordinal"],
    }
    for field, expected in expected_columns.items():
        _same(expected, observed_columns[field], "mixture_column_mismatch")
    return (
        document.identity,
        _identity(value.invocation_id, "mixture_append_invalid"),
        _identity(value.genome_snapshot_id, "mixture_append_invalid"),
        count,
        _identity(value.fence_id, "mixture_append_invalid"),
        _nonnegative(value.generation, "mixture_append_invalid"),
        _positive(value.attempt_ordinal, "mixture_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _invocation_receipt_row(value: InvocationReceiptAppend) -> tuple[object, ...]:
    if not isinstance(value, InvocationReceiptAppend):
        _reject("invocation_receipt_append_invalid")
    raw = _canonical(value.canonical_bytes, "invocation_receipt_append_invalid")
    parsed = parse_raw_json(raw)
    required = {
        "schema_version",
        "record_type",
        "fence_id",
        "generation",
        "attempt_ordinal",
    }
    if (
        not isinstance(parsed, dict)
        or set(parsed) != required
        or parsed["schema_version"] != "skeleton.invocation-receipt.v1"
        or parsed["record_type"] != "invocation_receipt"
        or parsed["fence_id"] != value.fence_id
        or parsed["generation"] != value.generation
        or parsed["attempt_ordinal"] != value.attempt_ordinal
    ):
        _reject("invocation_receipt_append_invalid")
    _utc(value.recorded_at, "invocation_receipt_append_invalid")
    return (
        _record_identity_or_reject(
            "invocation",
            value.invocation_id,
            raw,
            "invocation_receipt_append_invalid",
        ),
        _identity(value.fence_id, "invocation_receipt_append_invalid"),
        _nonnegative(value.generation, "invocation_receipt_append_invalid"),
        _positive(value.attempt_ordinal, "invocation_receipt_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _verify_provider_lifecycle_authority(document: dict[str, object]) -> None:
    """Verify the embedded owner signature against the fixed release root."""

    owner_capability = document["owner_capability"]
    if not isinstance(owner_capability, dict):
        _reject("provider_lifecycle_authorization_invalid")
    owner_capability_raw = canonicalize(owner_capability)
    event = str(document["lifecycle_event"])
    required_operation = (
        "training"
        if event == "training"
        else "load"
        if event in {"stage", "verification", "activation"}
        else "load"
        if event == "restoration"
        and document["observed_snapshot_id"] == document["base_snapshot_id"]
        else "unload"
    )
    expected_snapshot = (
        document["observed_snapshot_id"]
        if required_operation == "unload"
        else document["base_snapshot_id"]
    )
    expected_subject = (
        document["evidence_root"]
        if required_operation == "training"
        else document["observed_snapshot_id"]
        if required_operation == "unload"
        else document["adapter_root"]
    )
    try:
        verified_authorization = verify_owner_capability(
            owner_capability_raw,
            operation=required_operation,
            operation_id=document["operation_id"],
            provider_snapshot_id=expected_snapshot,
            subject_root=expected_subject,
            attempt_ordinal=document["attempt_ordinal"],
        )
    except PlasticityAuthorityRejection as error:
        raise PlasticityStoreRejection(
            "provider_lifecycle_authorization_invalid"
        ) from error
    if (
        verified_authorization.capability_sha256
        != document["authorization_sha256"]
    ):
        _reject("provider_lifecycle_authorization_invalid")


def _provider_lifecycle_row(
    value: ProviderLifecycleAppend, *, verify_authority: bool = True
) -> tuple[object, ...]:
    if not isinstance(value, ProviderLifecycleAppend):
        _reject("provider_lifecycle_append_invalid")
    raw = _canonical(value.canonical_bytes, "provider_lifecycle_append_invalid")
    document = parse_raw_json(raw)
    required = {
        "adapter_root",
        "attempt_ordinal",
        "authorization_sha256",
        "base_snapshot_id",
        "evidence_root",
        "fence_id",
        "generation",
        "lifecycle_event",
        "observed_snapshot_id",
        "operation_id",
        "owner_capability",
        "record_type",
        "schema_version",
    }
    if (
        not isinstance(document, dict)
        or set(document) != required
        or document["schema_version"] != "skeleton.provider-lifecycle-receipt.v1"
        or document["record_type"] != "provider_lifecycle_receipt"
        or document["lifecycle_event"]
        not in {
            "training",
            "stage",
            "verification",
            "activation",
            "unload",
            "restoration",
        }
    ):
        _reject("provider_lifecycle_append_invalid")
    for field in (
        "operation_id",
        "base_snapshot_id",
        "observed_snapshot_id",
        "adapter_root",
        "evidence_root",
        "authorization_sha256",
        "fence_id",
    ):
        _identity(document[field], "provider_lifecycle_append_invalid")
    if verify_authority:
        _verify_provider_lifecycle_authority(document)
    generation = _nonnegative(
        document["generation"], "provider_lifecycle_append_invalid"
    )
    attempt = _positive(
        document["attempt_ordinal"], "provider_lifecycle_append_invalid"
    )
    expected = {
        "lifecycle_event": value.lifecycle_event,
        "operation_id": value.operation_id,
        "base_snapshot_id": value.base_snapshot_id,
        "observed_snapshot_id": value.observed_snapshot_id,
        "adapter_root": value.adapter_root,
        "evidence_root": value.evidence_root,
        "authorization_sha256": value.authorization_sha256,
        "fence_id": value.fence_id,
        "generation": value.generation,
        "attempt_ordinal": value.attempt_ordinal,
    }
    if any(document[field] != declared for field, declared in expected.items()):
        _reject("provider_lifecycle_column_mismatch")
    _utc(value.recorded_at, "provider_lifecycle_append_invalid")
    return (
        _record_identity_or_reject(
            "provider_lifecycle",
            value.receipt_id,
            raw,
            "provider_lifecycle_append_invalid",
        ),
        value.lifecycle_event,
        value.operation_id,
        value.base_snapshot_id,
        value.observed_snapshot_id,
        value.adapter_root,
        value.evidence_root,
        value.authorization_sha256,
        value.fence_id,
        generation,
        attempt,
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _candidate_version_row(value: CandidateVersionAppend) -> tuple[object, ...]:
    if not isinstance(value, CandidateVersionAppend):
        _reject("candidate_version_append_invalid")
    raw = _canonical(value.canonical_bytes, "candidate_version_append_invalid")
    document = _contract_document(
        raw, "validate_candidate_version", "candidate_version_contract_invalid"
    )
    authenticated = document.value
    _utc(value.recorded_at, "candidate_version_append_invalid")
    expected_columns = {
        "version_id": value.version_id,
        "change_kind": value.change_kind,
        "prior_version_id": value.prior_version_id,
        "artifact_root_count": value.artifact_root_count,
        "verification_receipt_id": value.verification_receipt_id,
        "version_ordinal": value.version_ordinal,
    }
    observed_columns = {
        "version_id": document.identity,
        "change_kind": authenticated["change_kind"],
        "prior_version_id": authenticated["prior_version_id"],
        "artifact_root_count": len(authenticated["artifact_roots"]),
        "verification_receipt_id": authenticated["verification_receipt_id"],
        "version_ordinal": authenticated["version_ordinal"],
    }
    for field, expected in expected_columns.items():
        _same(expected, observed_columns[field], "candidate_version_column_mismatch")
    return (
        document.identity,
        _enum_value(ChangeKind, value.change_kind, "candidate_version_append_invalid"),
        _identity(value.prior_version_id, "candidate_version_append_invalid"),
        _positive(value.artifact_root_count, "candidate_version_append_invalid"),
        _identity(
            value.verification_receipt_id, "candidate_version_append_invalid"
        ),
        _nonnegative(value.version_ordinal, "candidate_version_append_invalid"),
        _identity(value.fence_id, "candidate_version_append_invalid"),
        _nonnegative(value.generation, "candidate_version_append_invalid"),
        _nonnegative(value.attempt_ordinal, "candidate_version_append_invalid"),
        value.recorded_at,
        _digest(raw),
        raw,
    )


def _sqlite_authorizer(
    action: int,
    arg1: str | None,
    arg2: str | None,
    database: str | None,
    trigger: str | None,
) -> int:
    del database, trigger
    if action in {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_TRANSACTION,
        getattr(sqlite3, "SQLITE_RECURSIVE", -1),
        getattr(sqlite3, "SQLITE_SAVEPOINT", -2),
    }:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        return sqlite3.SQLITE_OK if arg1 in _READ_TABLES else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION:
        return (
            sqlite3.SQLITE_DENY
            if str(arg2).lower() == "load_extension"
            else sqlite3.SQLITE_OK
        )
    if action == sqlite3.SQLITE_INSERT and arg1 in PLASTICITY_TABLES:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and str(arg1).lower() in {
        "foreign_key_check",
        "foreign_keys",
        "integrity_check",
        "quick_check",
        "table_info",
    }:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _table_root(
    connection: sqlite3.Connection, tables: tuple[str, ...], domain: bytes
) -> str:
    material: list[dict[str, object]] = []
    for table in tables:
        columns = tuple(
            str(row[1])
            for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        )
        if not columns:
            _reject("plasticity_table_missing")
        order = ", ".join(f'"{column}"' for column in columns)
        rows = connection.execute(
            f'SELECT * FROM "{table}" ORDER BY {order}'
        ).fetchall()
        material.append(
            {
                "table": table,
                "columns": list(columns),
                "rows": [[_jsonable(item) for item in row] for row in rows],
            }
        )
    return _framed_digest(domain, canonicalize(material))


def _request_bytes(operation: str, rows: tuple[tuple[object, ...], ...]) -> bytes:
    return canonicalize(
        {
            "operation": operation,
            "rows": [[_jsonable(item) for item in row] for row in rows],
        }
    )


def _receipt_tuple(
    operation_id: str,
    operation_kind: str,
    request_sha256: str,
    item_count: int,
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    operation_root = _framed_digest(_OPERATION_DOMAIN, bytes.fromhex(request_sha256))
    result_bytes = canonicalize(
        {
            "item_count": item_count,
            "operation_id": operation_id,
            "operation_kind": operation_kind,
            "operation_root": operation_root,
        }
    )
    result_sha256 = _digest(result_bytes)
    ledger = (
        operation_id,
        operation_kind,
        request_sha256,
        operation_root,
        item_count,
        result_sha256,
        result_bytes,
    )
    return ledger, (
        operation_id,
        operation_kind,
        operation_root,
        item_count,
        result_sha256,
        result_bytes,
    )


def _existing_operation(
    connection: sqlite3.Connection,
    operation_id: str,
    operation_kind: str,
    request_sha256: str,
) -> tuple[object, ...] | None:
    row = connection.execute(
        "SELECT operation_kind,request_sha256,operation_root,item_count,"
        "result_sha256,result_bytes FROM plasticity_operation_ledger "
        "WHERE operation_id=?",
        (operation_id,),
    ).fetchone()
    if row is None:
        return None
    if tuple(row[:2]) != (operation_kind, request_sha256):
        _reject("plasticity_operation_replay_mismatch")
    return (operation_id, str(row[0]), *tuple(row[2:]))


def _insert_or_require_exact(
    connection: sqlite3.Connection,
    table: str,
    key: str,
    row: tuple[object, ...],
) -> bool:
    existing = connection.execute(
        f'SELECT * FROM "{table}" WHERE "{key}"=?', (row[0],)
    ).fetchone()
    if existing is not None:
        if tuple(existing) != row:
            _reject("plasticity_fact_replay_mismatch")
        return False
    placeholders = ",".join("?" for _item in row)
    connection.execute(f'INSERT INTO "{table}" VALUES ({placeholders})', row)
    return True


def _current_fence(
    connection: sqlite3.Connection, stream_id: str
) -> tuple[object, ...] | None:
    return connection.execute(
        "SELECT fence_id,generation,writer_id FROM plasticity_fences "
        "WHERE stream_id=? ORDER BY generation DESC LIMIT 1",
        (stream_id,),
    ).fetchone()


def _require_current_fence(
    connection: sqlite3.Connection,
    fence_id: str,
    generation: int,
    writer_id: str,
) -> None:
    fence = connection.execute(
        "SELECT stream_id,generation,writer_id FROM plasticity_fences "
        "WHERE fence_id=?",
        (fence_id,),
    ).fetchone()
    if fence is None:
        _reject("plasticity_fence_unknown")
    if int(fence[1]) != int(generation):
        _reject("plasticity_generation_mismatch")
    if str(fence[2]) != writer_id:
        _reject("plasticity_writer_mismatch")
    current = _current_fence(connection, str(fence[0]))
    if current is None or str(current[0]) != fence_id:
        _reject("stale_plasticity_fence")


def _write_operation(
    connection: sqlite3.Connection,
    *,
    operation_id: str,
    operation_kind: str,
    request_rows: tuple[tuple[object, ...], ...],
    action: Callable[[], int],
) -> tuple[object, ...]:
    if connection.in_transaction:
        _reject("nested_transaction")
    operation_id = _identity(operation_id, "operation_identity_invalid")
    request_sha256 = _digest(_request_bytes(operation_kind, request_rows))
    connection.execute("BEGIN IMMEDIATE")
    try:
        existing = _existing_operation(
            connection, operation_id, operation_kind, request_sha256
        )
        if existing is not None:
            connection.rollback()
            return existing
        item_count = action()
        ledger, receipt = _receipt_tuple(
            operation_id, operation_kind, request_sha256, item_count
        )
        connection.execute(
            "INSERT INTO plasticity_operation_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
            ledger,
        )
        connection.commit()
        return receipt
    except BaseException:
        connection.rollback()
        raise


def _append_fence(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    operation_id: str,
) -> tuple[object, ...]:
    def action() -> int:
        current = _current_fence(connection, str(row[1]))
        if current is None:
            if int(row[2]) != 0 or str(row[4]) != ZERO_SHA256:
                _reject("fence_generation_invalid")
        elif int(row[2]) != int(current[1]) + 1 or str(row[4]) != str(current[0]):
            _reject("fence_generation_invalid")
        connection.execute(
            "INSERT INTO plasticity_fences VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row
        )
        return 1

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind="fence",
        request_rows=(row,),
        action=action,
    )


def _append_record(
    connection: sqlite3.Connection,
    *,
    table: str,
    key: str,
    row: tuple[object, ...],
    operation_kind: str,
    writer_id: str,
    operation_id: str,
    extra_check: Callable[[], None] | None = None,
) -> tuple[object, ...]:
    def action() -> int:
        _require_current_fence(connection, str(row[-6]), int(row[-5]), writer_id)
        if extra_check is not None:
            extra_check()
        return int(_insert_or_require_exact(connection, table, key, row))

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind=operation_kind,
        request_rows=(row,),
        action=action,
    )


def _append_channel_update(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    def extra_check() -> None:
        existing = connection.execute(
            "SELECT channel_update_id FROM channel_updates WHERE gradient_id=?",
            (row[1],),
        ).fetchone()
        if existing is not None and str(existing[0]) != str(row[0]):
            _reject("gradient_channel_update_exists")

    return _append_record(
        connection,
        table="channel_updates",
        key="channel_update_id",
        row=row,
        operation_kind="channel_update",
        writer_id=writer_id,
        operation_id=operation_id,
        extra_check=extra_check,
    )


def _commit_learning_attempt(
    connection: sqlite3.Connection,
    attempt_id: str,
    gradient_row: tuple[object, ...],
    update_row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    """Commit the exactly-one gradient/update pair for one stable attempt."""

    if str(update_row[1]) != str(gradient_row[0]):
        _reject("learning_attempt_gradient_mismatch")
    if (
        str(update_row[9]) != str(gradient_row[5])
        or int(update_row[10]) != int(gradient_row[6])
        or int(update_row[11]) != int(gradient_row[7])
    ):
        _reject("learning_attempt_fence_mismatch")
    derived_attempt_id = learning_attempt_identity(bytes(gradient_row[-1]))
    if attempt_id != derived_attempt_id:
        _reject("learning_attempt_identity_mismatch")

    def action() -> int:
        _require_current_fence(
            connection, str(gradient_row[5]), int(gradient_row[6]), writer_id
        )
        existing = connection.execute(
            "SELECT gradient_id,channel_update_id FROM learning_attempts "
            "WHERE attempt_id=?",
            (attempt_id,),
        ).fetchone()
        pair = (str(gradient_row[0]), str(update_row[0]))
        if existing is not None:
            if tuple(str(value) for value in existing) != pair:
                _reject("learning_attempt_already_committed")
            return 0
        if str(update_row[2]) == "fast_weights":
            delta_id = str(update_row[3])
            durable_delta = connection.execute(
                "SELECT 1 FROM parameter_deltas WHERE delta_id=?",
                (delta_id,),
            ).fetchone()
            if durable_delta is None:
                _reject("learning_attempt_delta_unknown")
            existing_delta_update = connection.execute(
                "SELECT channel_update_id FROM channel_updates "
                "WHERE channel='fast_weights' AND delta_id=?",
                (delta_id,),
            ).fetchone()
            if existing_delta_update is not None:
                _reject("learning_attempt_delta_update_exists")
        inserted = int(
            _insert_or_require_exact(
                connection, "experience_gradients", "gradient_id", gradient_row
            )
        )
        inserted += int(
            _insert_or_require_exact(
                connection, "channel_updates", "channel_update_id", update_row
            )
        )
        inserted += int(
            _insert_or_require_exact(
                connection,
                "learning_attempts",
                "attempt_id",
                (attempt_id, *pair),
            )
        )
        return inserted

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind="learning_attempt",
        request_rows=((attempt_id,), gradient_row, update_row),
        action=action,
    )


def _append_mixture(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    def extra_check() -> None:
        existing = connection.execute(
            "SELECT mixture_id FROM mixture_records WHERE invocation_id=?",
            (row[1],),
        ).fetchone()
        if existing is not None and str(existing[0]) != str(row[0]):
            _reject("mixture_invocation_exists")

    return _append_record(
        connection,
        table="mixture_records",
        key="mixture_id",
        row=row,
        operation_kind="mixture",
        writer_id=writer_id,
        operation_id=operation_id,
        extra_check=extra_check,
    )


def _commit_invocation_mixture(
    connection: sqlite3.Connection,
    invocation_row: tuple[object, ...],
    mixture_row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    if str(mixture_row[1]) != str(invocation_row[0]):
        _reject("invocation_mixture_identity_mismatch")
    if (
        str(mixture_row[4]) != str(invocation_row[1])
        or int(mixture_row[5]) != int(invocation_row[2])
        or int(mixture_row[6]) != int(invocation_row[3])
    ):
        _reject("invocation_mixture_fence_mismatch")

    def action() -> int:
        _require_current_fence(
            connection, str(invocation_row[1]), int(invocation_row[2]), writer_id
        )
        existing = connection.execute(
            "SELECT mixture_id FROM mixture_records WHERE invocation_id=?",
            (invocation_row[0],),
        ).fetchone()
        if existing is not None and str(existing[0]) != str(mixture_row[0]):
            _reject("mixture_invocation_exists")
        inserted = int(
            _insert_or_require_exact(
                connection,
                "invocation_receipts",
                "invocation_id",
                invocation_row,
            )
        )
        inserted += int(
            _insert_or_require_exact(
                connection, "mixture_records", "mixture_id", mixture_row
            )
        )
        return inserted

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind="invocation_mixture",
        request_rows=(invocation_row, mixture_row),
        action=action,
    )


def _append_probe_receipt(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    def extra_check() -> None:
        existing = connection.execute(
            "SELECT receipt_id FROM probe_receipts "
            "WHERE delta_id=? AND probe_kind=?",
            (row[1], row[2]),
        ).fetchone()
        if existing is not None and str(existing[0]) != str(row[0]):
            _reject("probe_receipt_exists")

    return _append_record(
        connection,
        table="probe_receipts",
        key="receipt_id",
        row=row,
        operation_kind="probe_receipt",
        writer_id=writer_id,
        operation_id=operation_id,
        extra_check=extra_check,
    )


def _append_homeostasis_event(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    def extra_check() -> None:
        append_class = str(row[3])
        if append_class != "delta_admission":
            return
        scope_id = str(row[1])
        budget_kind = str(row[2])
        window_ordinal = int(row[13])
        current = int(
            connection.execute(
                "SELECT coalesce(sum(committed_amount),0) FROM homeostasis_events "
                "WHERE scope_id=? AND budget_kind=? AND window_ordinal=? "
                "AND append_class='delta_admission'",
                (scope_id, budget_kind, window_ordinal),
            ).fetchone()[0]
        )
        try:
            decision = derive_homeostasis_decision(
                budget_kind=budget_kind,
                amount_before=current,
                attempted_amount=int(row[7]),
            )
        except HomeostasisRejection as error:
            raise PlasticityStoreRejection(error.code) from error
        declared = (
            int(row[5]),
            int(row[6]),
            int(row[7]),
            int(row[8]),
            int(row[9]),
            int(row[10]),
            str(row[11]),
            str(row[12]),
        )
        expected = (
            decision.cap_amount,
            decision.amount_before,
            decision.attempted_amount,
            decision.committed_amount,
            decision.amount_after,
            decision.utilization_permille,
            decision.band,
            decision.action,
        )
        if declared != expected:
            _reject("homeostasis_decision_mismatch")

    return _append_record(
        connection,
        table="homeostasis_events",
        key="event_id",
        row=row,
        operation_kind="homeostasis_event",
        writer_id=writer_id,
        operation_id=operation_id,
        extra_check=extra_check,
    )


def _commit_probe_battery(
    connection: sqlite3.Connection,
    placeholder_rows: tuple[tuple[object, ...], ...],
    receipt_rows: tuple[tuple[object, ...], ...],
    battery_row: tuple[object, ...],
    writer_id: str,
    operation_id: str,
    failure_after_row: int,
) -> tuple[object, ...]:
    def action() -> int:
        inserted = 0
        boundary = 0
        delta_id = str(battery_row[1])
        if connection.execute(
            "SELECT 1 FROM parameter_deltas WHERE delta_id=?", (delta_id,)
        ).fetchone() is None:
            _reject("probe_battery_delta_unknown")
        if any(str(row[1]) != delta_id for row in receipt_rows):
            _reject("probe_battery_delta_mismatch")

        def fault() -> None:
            nonlocal boundary
            boundary += 1
            if failure_after_row == boundary:
                _reject("probe_battery_injected_failure")

        for row in placeholder_rows:
            _require_current_fence(
                connection, str(row[-6]), int(row[-5]), writer_id
            )
            inserted += int(
                _insert_or_require_exact(
                    connection, "pending_owner_hardware", "placeholder_id", row
                )
            )
            fault()
        for row in receipt_rows:
            _require_current_fence(
                connection, str(row[-6]), int(row[-5]), writer_id
            )
            duplicate = connection.execute(
                "SELECT receipt_id FROM probe_receipts "
                "WHERE delta_id=? AND probe_kind=?",
                (row[1], row[2]),
            ).fetchone()
            if duplicate is not None and str(duplicate[0]) != str(row[0]):
                _reject("probe_receipt_exists")
            if str(row[9]) != NONE_SENTINEL:
                placeholder = connection.execute(
                    "SELECT placeholder_id FROM pending_owner_hardware "
                    "WHERE placeholder_id=?",
                    (row[9],),
                ).fetchone()
                if placeholder is None:
                    _reject("probe_receipt_placeholder_unknown")
            inserted += int(
                _insert_or_require_exact(
                    connection, "probe_receipts", "receipt_id", row
                )
            )
            fault()
        _require_current_fence(
            connection, str(battery_row[-6]), int(battery_row[-5]), writer_id
        )
        disposition = parse_raw_json(bytes(battery_row[-1]))
        receipt_ids = tuple(str(value) for value in disposition["receipt_row_ids"])
        placeholder_ids = tuple(str(value) for value in disposition["placeholder_ids"])
        if receipt_ids != tuple(str(row[0]) for row in receipt_rows):
            _reject("probe_battery_membership_invalid")
        if placeholder_ids != tuple(str(row[0]) for row in placeholder_rows):
            _reject("probe_battery_membership_invalid")
        inserted += int(
            _insert_or_require_exact(
                connection, "probe_batteries", "battery_id", battery_row
            )
        )
        fault()
        return inserted

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind="probe_receipt",
        request_rows=(*placeholder_rows, *receipt_rows, battery_row),
        action=action,
    )


def _last_application(
    connection: sqlite3.Connection, delta_id: str
) -> tuple[str, int] | None:
    row = connection.execute(
        "SELECT application_event,application_ordinal FROM delta_applications "
        "WHERE delta_id=? ORDER BY application_ordinal DESC LIMIT 1",
        (delta_id,),
    ).fetchone()
    return None if row is None else (str(row[0]), int(row[1]))


def _insert_delta_application_row(
    connection: sqlite3.Connection, row: tuple[object, ...]
) -> int:
    existing = connection.execute(
        "SELECT * FROM delta_applications WHERE application_id=?", (row[0],)
    ).fetchone()
    if existing is not None:
        if tuple(existing) != row:
            _reject("plasticity_fact_replay_mismatch")
        return 0
    delta = connection.execute(
        "SELECT delta_id FROM parameter_deltas WHERE delta_id=?", (row[1],)
    ).fetchone()
    if delta is None:
        _reject("delta_unknown")
    event = str(row[2])
    ordinal = int(row[3])
    last = _last_application(connection, str(row[1]))
    if last is None:
        if event != APPLY_EVENT:
            _reject("delta_reverse_without_apply")
        if ordinal != 1:
            _reject("delta_application_ordinal_invalid")
    else:
        last_event, last_ordinal = last
        if ordinal != last_ordinal + 1:
            _reject("delta_application_ordinal_invalid")
        if event == APPLY_EVENT and last_event == APPLY_EVENT:
            _reject("delta_already_applied")
        if event == REVERSE_EVENT and last_event == REVERSE_EVENT:
            _reject("delta_reverse_without_apply")
    placeholders = ",".join("?" for _item in row)
    connection.execute(
        f"INSERT INTO delta_applications VALUES ({placeholders})", row
    )
    return 1


def _append_delta_application(
    connection: sqlite3.Connection,
    row: tuple[object, ...],
    proof_payloads: tuple[bytes, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    def action() -> int:
        _require_current_fence(connection, str(row[-6]), int(row[-5]), writer_id)
        _verify_application_payload_proof(connection, row, proof_payloads)
        return _insert_delta_application_row(connection, row)

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind="delta_application",
        request_rows=(row,),
        action=action,
    )


def _commit_admission_application(
    connection: sqlite3.Connection,
    admission_row: tuple[object, ...],
    application_row: tuple[object, ...],
    homeostasis_rows: tuple[tuple[object, ...], ...],
    proof_payloads: tuple[bytes, ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    if str(application_row[1]) != str(admission_row[1]):
        _reject("admission_application_delta_mismatch")
    if str(application_row[2]) != APPLY_EVENT:
        _reject("admission_application_event_invalid")

    def action() -> int:
        _require_current_fence(
            connection,
            str(application_row[-6]),
            int(application_row[-5]),
            writer_id,
        )
        _verify_application_payload_proof(
            connection, application_row, proof_payloads
        )
        delta_row = connection.execute(
            "SELECT base_snapshot_id,expiry_ordinal,canonical_bytes "
            "FROM parameter_deltas WHERE delta_id=?",
            (admission_row[1],),
        ).fetchone()
        if delta_row is None:
            _reject("admission_delta_unknown")
        admission = parse_raw_json(bytes(admission_row[-1]))
        delta = parse_raw_json(bytes(delta_row[2]))
        if (
            not isinstance(admission, dict)
            or not isinstance(delta, dict)
            or admission["provider_snapshot_id"] != str(delta_row[0])
            or admission["expiry_ordinal"] != int(delta_row[1])
            or admission["evidence_gradient_ids"]
            != delta.get("evidence_gradient_ids")
        ):
            _reject("admission_delta_binding_mismatch")
        durable_gradient_ids = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT gradient_id FROM experience_gradients WHERE gradient_id IN ("
                + ",".join("?" for _item in admission["evidence_gradient_ids"])
                + ") ORDER BY gradient_id",
                tuple(admission["evidence_gradient_ids"]),
            ).fetchall()
        )
        if durable_gradient_ids != tuple(admission["evidence_gradient_ids"]):
            _reject("admission_gradient_unknown")
        update = connection.execute(
            "SELECT gradient_id,channel,delta_id FROM channel_updates "
            "WHERE channel_update_id=?",
            (admission["channel_update_id"],),
        ).fetchone()
        if (
            update is None
            or str(update[0]) not in durable_gradient_ids
            or str(update[1]) != "fast_weights"
            or str(update[2]) != str(admission_row[1])
        ):
            _reject("admission_channel_update_invalid")
        fast_updates = tuple(
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                "SELECT channel_update_id,gradient_id FROM channel_updates "
                "WHERE channel='fast_weights' AND delta_id=? "
                "ORDER BY channel_update_id",
                (admission_row[1],),
            ).fetchall()
        )
        if fast_updates != (
            (str(admission["channel_update_id"]), str(update[0])),
        ):
            _reject("admission_channel_update_not_unique")
        battery = None
        for candidate in connection.execute(
            "SELECT status,completeness,receipt_count,canonical_bytes "
            "FROM probe_batteries WHERE delta_id=?",
            (admission_row[1],),
        ).fetchall():
            parsed_battery = parse_raw_json(bytes(candidate[3]))
            if (
                isinstance(parsed_battery, dict)
                and parsed_battery.get("battery_root")
                == admission["probe_battery_root"]
            ):
                battery = (*candidate[:3], parsed_battery)
                break
        if (
            battery is None
            or str(battery[0]) != "cpu_battery_passed_with_placeholders"
            or str(battery[1]) != "complete"
            or int(battery[2]) != 5
            or tuple(battery[3]["receipt_row_ids"])
            != tuple(admission["ordered_probe_receipt_ids"])
        ):
            _reject("admission_probe_battery_invalid")
        probe_rows = connection.execute(
            "SELECT receipt_id,probe_kind,status FROM probe_receipts "
            "WHERE delta_id=? ORDER BY probe_ordinal",
            (admission_row[1],),
        ).fetchall()
        if (
            tuple(str(row[0]) for row in probe_rows)
            != tuple(admission["ordered_probe_receipt_ids"])
            or tuple(str(row[1]) for row in probe_rows)
            != tuple(kind.value for kind in ProbeKind)
            or any(str(row[2]) != "passed" for row in probe_rows)
        ):
            _reject("admission_probe_receipt_invalid")
        scope = connection.execute(
            "SELECT scope_kind,scope_name FROM plasticity_scopes WHERE scope_id=?",
            (admission["scope_id"],),
        ).fetchone()
        delta_scope = str(delta.get("scope", {}).get("scope_kind", ""))
        actual_scope = None if scope is None else tuple(str(item) for item in scope)
        if delta_scope.startswith("lobe_"):
            scope_valid = actual_scope == (
                "lobe",
                delta_scope.removeprefix("lobe_"),
            )
        elif delta_scope == "project":
            scope_valid = actual_scope == (
                "project",
                str(delta.get("scope", {}).get("project_id", "")),
            )
        else:
            scope_valid = actual_scope == (delta_scope, delta_scope)
        if not scope_valid:
            _reject("admission_scope_invalid")
        lifecycle_ids = tuple(admission["provider_lifecycle_receipt_ids"])
        lifecycle_rows = connection.execute(
            "SELECT receipt_id,lifecycle_event,operation_id,base_snapshot_id,"
            "observed_snapshot_id,adapter_root,evidence_root,authorization_sha256 "
            "FROM provider_lifecycle_receipts WHERE receipt_id IN (?,?,?) "
            "ORDER BY CASE lifecycle_event WHEN 'stage' THEN 1 "
            "WHEN 'verification' THEN 2 WHEN 'activation' THEN 3 END",
            lifecycle_ids,
        ).fetchall()
        if (
            tuple(str(row[0]) for row in lifecycle_rows) != lifecycle_ids
            or tuple(str(row[1]) for row in lifecycle_rows)
            != ("stage", "verification", "activation")
            or any(
                str(row[2]) != admission["provider_load_operation_id"]
                or str(row[3]) != admission["provider_snapshot_id"]
                or str(row[5]) != delta["tensor_payload_root"]
                or str(row[7]) != admission["provider_authorization_sha256"]
                for row in lifecycle_rows
            )
            or str(lifecycle_rows[1][6]) != admission["provider_verification_id"]
            or str(lifecycle_rows[2][4])
            != admission["provider_loaded_snapshot_id"]
            or str(lifecycle_rows[2][6])
            != admission["provider_loaded_snapshot_id"]
        ):
            _reject("admission_provider_lifecycle_invalid")
        scope_key = _delta_scope_key_from_value(delta_from_raw(bytes(delta_row[2])))
        _active, _leaves, scoped_deltas = _active_scope_state(connection, scope_key)
        durable_current = max(
            (int(item.version_ordinal) for item in scoped_deltas.values()), default=0
        )
        if int(admission["current_ordinal"]) != durable_current:
            _reject("admission_current_ordinal_invalid")
        expected_homeostasis_rows = _derive_homeostasis_rows(
            connection,
            delta_id=str(admission_row[1]),
            scope_id=str(admission["scope_id"]),
            window_ordinal=int(application_row[6]),
            fence_id=str(application_row[-6]),
            generation=int(application_row[-5]),
            attempt_ordinal=int(application_row[6]),
            recorded_at=str(application_row[7]),
            proof_payloads=proof_payloads,
        )
        if homeostasis_rows != expected_homeostasis_rows:
            _reject("admission_homeostasis_decision_mismatch")
        event_ids = tuple(str(row[0]) for row in expected_homeostasis_rows)
        if tuple(str(row[2]) for row in expected_homeostasis_rows) != (
            HOMEOSTASIS_ADMISSION_BUDGETS
        ):
            _reject("admission_homeostasis_incomplete")
        if any(
            str(row[12]) not in {"admit", "clamp_magnitude"}
            for row in expected_homeostasis_rows
        ):
            _reject("admission_homeostasis_pressure_rejected")
        if (
            tuple(admission["homeostasis_event_ids"]) != event_ids
            or admission["homeostasis_event_id"] != event_ids[0]
            or admission["homeostasis_set_root"]
            != _homeostasis_set_root(event_ids)
            or admission["homeostasis_window_ordinal"] != int(application_row[6])
        ):
            _reject("admission_homeostasis_binding_invalid")
        inserted = 0
        for row in expected_homeostasis_rows:
            _require_current_fence(
                connection, str(row[-6]), int(row[-5]), writer_id
            )
            inserted += int(
                _insert_or_require_exact(
                    connection, "homeostasis_events", "event_id", row
                )
            )
        for existing_admission_id, existing_raw in connection.execute(
            "SELECT admission_id,canonical_bytes FROM admission_receipts "
            "WHERE delta_id=?",
            (admission_row[1],),
        ).fetchall():
            existing_admission = parse_raw_json(bytes(existing_raw))
            if (
                isinstance(existing_admission, dict)
                and existing_admission.get("homeostasis_window_ordinal")
                == admission["homeostasis_window_ordinal"]
                and str(existing_admission_id) != str(admission_row[0])
            ):
                _reject("homeostasis_admission_already_decided")
        inserted += int(
            _insert_or_require_exact(
                connection,
                "admission_receipts",
                "admission_id",
                admission_row,
            )
        )
        inserted += _insert_delta_application_row(connection, application_row)
        return inserted

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind="admission_application",
        request_rows=(*homeostasis_rows, admission_row, application_row),
        action=action,
    )


def _append_application_batch(
    connection: sqlite3.Connection,
    intent_rows: tuple[tuple[object, ...], ...],
    application_rows: tuple[tuple[object, ...], ...],
    proof_payloads: tuple[tuple[bytes, ...], ...],
    writer_id: str,
    operation_id: str,
) -> tuple[object, ...]:
    if (
        not intent_rows
        or len(intent_rows) != len(application_rows)
        or len(application_rows) != len(proof_payloads)
    ):
        _reject("application_batch_invalid")

    def action() -> int:
        inserted = 0
        for row in intent_rows:
            _require_current_fence(
                connection, str(row[-6]), int(row[-5]), writer_id
            )
            inserted += int(
                _insert_or_require_exact(
                    connection, "homeostasis_events", "event_id", row
                )
            )
        for row, proof in zip(application_rows, proof_payloads, strict=True):
            _require_current_fence(
                connection, str(row[-6]), int(row[-5]), writer_id
            )
            _verify_application_payload_proof(connection, row, proof)
            inserted += _insert_delta_application_row(connection, row)
        return inserted

    return _write_operation(
        connection,
        operation_id=operation_id,
        operation_kind="delta_application",
        request_rows=(*intent_rows, *application_rows),
        action=action,
    )


_RECORD_TABLES = MappingProxyType(
    {
        "gradient": ("experience_gradients", "gradient_id"),
        "delta": ("parameter_deltas", "delta_id"),
        "scope": ("plasticity_scopes", "scope_id"),
        "placeholder": ("pending_owner_hardware", "placeholder_id"),
        "candidate_version": ("candidate_versions", "version_id"),
        "provider_lifecycle": (
            "provider_lifecycle_receipts",
            "receipt_id",
        ),
    }
)

_REPLAY_TABLES = (
    ("admission_receipts", "admission_id"),
    ("candidate_versions", "version_id"),
    ("channel_updates", "channel_update_id"),
    ("delta_applications", "application_id"),
    ("experience_gradients", "gradient_id"),
    ("homeostasis_events", "event_id"),
    ("invocation_receipts", "invocation_id"),
    ("mixture_records", "mixture_id"),
    ("parameter_deltas", "delta_id"),
    ("pending_owner_hardware", "placeholder_id"),
    ("plasticity_fences", "fence_id"),
    ("plasticity_scopes", "scope_id"),
    ("provider_lifecycle_receipts", "receipt_id"),
    ("probe_batteries", "battery_id"),
    ("probe_receipts", "receipt_id"),
)


def _rebuild_replay_row(
    table: str, row: tuple[object, ...], raw: bytes
) -> tuple[object, ...]:
    """Rebuild one complete stored projection through its append validator."""

    if table == "admission_receipts":
        return _admission_receipt_row(
            AdmissionReceiptAppend(*row[0:9], raw)  # type: ignore[arg-type]
        )
    if table == "candidate_versions":
        return _candidate_version_row(
            CandidateVersionAppend(*row[0:10], raw)  # type: ignore[arg-type]
        )
    if table == "channel_updates":
        return _channel_update_row(ChannelUpdateAppend(raw, str(row[12])))
    if table == "delta_applications":
        return _delta_application_row(
            DeltaApplicationAppend(*row[0:8], raw)  # type: ignore[arg-type]
        )
    if table == "experience_gradients":
        return _gradient_row(
            GradientAppend(raw, str(row[5]), int(row[6]), int(row[7]), str(row[8]))
        )
    if table == "homeostasis_events":
        return _homeostasis_row(
            HomeostasisEventAppend(
                *row[0:4],  # type: ignore[arg-type]
                bool(row[4]),
                *row[5:17],  # type: ignore[arg-type]
                str(row[17]),
                raw,
            )
        )
    if table == "invocation_receipts":
        return _invocation_receipt_row(
            InvocationReceiptAppend(*row[0:5], raw)  # type: ignore[arg-type]
        )
    if table == "mixture_records":
        return _mixture_row(MixtureAppend(*row[0:8], raw))  # type: ignore[arg-type]
    if table == "parameter_deltas":
        return _delta_row(
            DeltaAppend(
                raw, str(row[15]), int(row[16]), int(row[17]), str(row[18])
            )
        )
    if table == "pending_owner_hardware":
        return _placeholder_row(
            PlaceholderAppend(
                raw, str(row[8]), int(row[9]), int(row[10]), str(row[11])
            )
        )
    if table == "plasticity_fences":
        return _fence_row(FenceAppend(*row[0:6], raw))  # type: ignore[arg-type]
    if table == "plasticity_scopes":
        return _scope_row(ScopeAppend(*row[0:9], raw))  # type: ignore[arg-type]
    if table == "provider_lifecycle_receipts":
        return _provider_lifecycle_row(
            ProviderLifecycleAppend(*row[0:12], raw),  # type: ignore[arg-type]
            verify_authority=False,
        )
    if table == "probe_batteries":
        return _probe_battery_row(
            ProbeBatteryAppend(*row[0:13], raw)  # type: ignore[arg-type]
        )
    if table == "probe_receipts":
        return _probe_receipt_row(
            ProbeReceiptAppend(*row[0:14], raw)  # type: ignore[arg-type]
        )
    _reject("plasticity_replay_table_unknown")


def _authenticate_replay_record(
    table: str, record_id: str, raw: bytes, row: tuple[object, ...]
) -> None:
    """Rebuild every full row through the same validator used at append."""

    try:
        rebuilt = _rebuild_replay_row(table, row, raw)
    except (
        PlasticityStoreRejection,
        PlasticityContractRejection,
        PlasticityTypeRejection,
    ) as error:
        raise PlasticityStoreRejection(
            "plasticity_replay_denormalized_mismatch"
        ) from error
    if rebuilt != row or str(rebuilt[0]) != record_id:
        _reject("plasticity_replay_denormalized_mismatch")


def _verify_replay_operation_ledger(connection: sqlite3.Connection) -> None:
    for row in connection.execute(
        "SELECT operation_id,operation_kind,request_sha256,operation_root,"
        "item_count,result_sha256,result_bytes FROM plasticity_operation_ledger "
        "ORDER BY operation_id"
    ).fetchall():
        operation_id, operation_kind, request_sha256, operation_root = (
            str(row[0]),
            str(row[1]),
            str(row[2]),
            str(row[3]),
        )
        item_count = int(row[4])
        result_sha256 = str(row[5])
        result_raw = bytes(row[6])
        try:
            _identity(operation_id, "plasticity_replay_operation_ledger_invalid")
            _identity(request_sha256, "plasticity_replay_operation_ledger_invalid")
            _identity(operation_root, "plasticity_replay_operation_ledger_invalid")
            _identity(result_sha256, "plasticity_replay_operation_ledger_invalid")
            request_digest = bytes.fromhex(request_sha256)
            result = parse_raw_json(result_raw)
        except (PlasticityStoreRejection, PlasticityTypeRejection, ValueError) as error:
            raise PlasticityStoreRejection(
                "plasticity_replay_operation_ledger_invalid"
            ) from error
        if (
            operation_root
            != _framed_digest(_OPERATION_DOMAIN, request_digest)
            or sha256_hex(result_raw) != result_sha256
            or not isinstance(result, dict)
            or set(result)
            != {"item_count", "operation_id", "operation_kind", "operation_root"}
            or result.get("operation_id") != operation_id
            or result.get("operation_kind") != operation_kind
            or result.get("operation_root") != operation_root
            or result.get("item_count") != item_count
        ):
            _reject("plasticity_replay_operation_ledger_invalid")


def _verify_replay_fence_graph(connection: sqlite3.Connection) -> None:
    prior_by_stream: dict[str, tuple[int, str]] = {}
    for fence_id, stream_id, generation, prior_fence_id in connection.execute(
        "SELECT fence_id,stream_id,generation,prior_fence_id "
        "FROM plasticity_fences ORDER BY stream_id,generation"
    ).fetchall():
        stream = str(stream_id)
        previous = prior_by_stream.get(stream)
        expected_generation = 0 if previous is None else previous[0] + 1
        expected_prior = ZERO_SHA256 if previous is None else previous[1]
        if int(generation) != expected_generation or str(prior_fence_id) != expected_prior:
            _reject("plasticity_replay_fence_graph_open")
        prior_by_stream[stream] = (int(generation), str(fence_id))

    for table in (
        "candidate_versions",
        "channel_updates",
        "delta_applications",
        "experience_gradients",
        "homeostasis_events",
        "mixture_records",
        "invocation_receipts",
        "parameter_deltas",
        "pending_owner_hardware",
        "plasticity_scopes",
        "provider_lifecycle_receipts",
        "probe_batteries",
        "probe_receipts",
    ):
        if connection.execute(
            f'SELECT 1 FROM "{table}" AS r LEFT JOIN plasticity_fences AS f '
            "ON f.fence_id=r.fence_id AND f.generation=r.generation "
            "WHERE f.fence_id IS NULL LIMIT 1"
        ).fetchone() is not None:
            _reject("plasticity_replay_fence_graph_open")


def _verify_replay_admission_graph(connection: sqlite3.Connection) -> None:
    bound_homeostasis_ids: set[str] = set()
    decision_keys: set[tuple[str, str, int, str]] = set()
    for admission_id, delta_id, raw_value in connection.execute(
        "SELECT admission_id,delta_id,canonical_bytes FROM admission_receipts "
        "ORDER BY admission_id"
    ).fetchall():
        admission = parse_raw_json(bytes(raw_value))
        delta_row = connection.execute(
            "SELECT base_snapshot_id,expiry_ordinal,canonical_bytes "
            "FROM parameter_deltas WHERE delta_id=?",
            (delta_id,),
        ).fetchone()
        if not isinstance(admission, dict) or delta_row is None:
            _reject("plasticity_replay_admission_graph_open")
        try:
            delta = delta_from_raw(bytes(delta_row[2]))
        except PlasticityTypeRejection as error:
            raise PlasticityStoreRejection(
                "plasticity_replay_admission_graph_open"
            ) from error
        if (
            admission.get("delta_id") != str(delta_id)
            or admission.get("provider_snapshot_id") != str(delta_row[0])
            or admission.get("expiry_ordinal") != int(delta_row[1])
            or tuple(admission.get("evidence_gradient_ids", ()))
            != delta.evidence_gradient_ids
        ):
            _reject("plasticity_replay_admission_graph_open")
        gradient_ids = tuple(admission["evidence_gradient_ids"])
        durable_gradient_ids = tuple(
            str(item[0])
            for item in connection.execute(
                "SELECT gradient_id FROM experience_gradients WHERE gradient_id IN ("
                + ",".join("?" for _item in gradient_ids)
                + ") ORDER BY gradient_id",
                gradient_ids,
            ).fetchall()
        )
        if durable_gradient_ids != gradient_ids:
            _reject("plasticity_replay_admission_graph_open")

        fast_updates = tuple(
            (str(item[0]), str(item[1]))
            for item in connection.execute(
                "SELECT channel_update_id,gradient_id FROM channel_updates "
                "WHERE channel='fast_weights' AND delta_id=? "
                "ORDER BY channel_update_id",
                (delta_id,),
            ).fetchall()
        )
        if (
            len(fast_updates) != 1
            or fast_updates[0][0] != admission.get("channel_update_id")
            or fast_updates[0][1] not in gradient_ids
        ):
            _reject("plasticity_replay_admission_graph_open")

        scope = connection.execute(
            "SELECT scope_kind,scope_name FROM plasticity_scopes WHERE scope_id=?",
            (admission.get("scope_id"),),
        ).fetchone()
        scope_kind = delta.scope_kind.value
        if scope_kind.startswith("lobe_"):
            expected_scope = ("lobe", scope_kind.removeprefix("lobe_"))
        elif scope_kind == "project":
            expected_scope = ("project", delta.project_id)
        else:
            expected_scope = (scope_kind, scope_kind)
        if scope is None or tuple(str(item) for item in scope) != expected_scope:
            _reject("plasticity_replay_admission_graph_open")

        lifecycle_ids = tuple(admission.get("provider_lifecycle_receipt_ids", ()))
        lifecycle_rows = connection.execute(
            "SELECT receipt_id,lifecycle_event,operation_id,base_snapshot_id,"
            "observed_snapshot_id,adapter_root,evidence_root,authorization_sha256 "
            "FROM provider_lifecycle_receipts WHERE receipt_id IN (?,?,?) "
            "ORDER BY CASE lifecycle_event WHEN 'stage' THEN 1 "
            "WHEN 'verification' THEN 2 WHEN 'activation' THEN 3 END",
            lifecycle_ids,
        ).fetchall()
        if (
            tuple(str(row[0]) for row in lifecycle_rows) != lifecycle_ids
            or tuple(str(row[1]) for row in lifecycle_rows)
            != ("stage", "verification", "activation")
            or any(
                str(row[2]) != admission.get("provider_load_operation_id")
                or str(row[3]) != admission.get("provider_snapshot_id")
                or str(row[5]) != delta.tensor_payload_root
                or str(row[7]) != admission.get("provider_authorization_sha256")
                for row in lifecycle_rows
            )
            or str(lifecycle_rows[1][6])
            != admission.get("provider_verification_id")
            or str(lifecycle_rows[2][4])
            != admission.get("provider_loaded_snapshot_id")
            or str(lifecycle_rows[2][6])
            != admission.get("provider_loaded_snapshot_id")
        ):
            _reject("plasticity_replay_admission_graph_open")

        homeostasis_ids = tuple(admission.get("homeostasis_event_ids", ()))
        homeostasis_rows = connection.execute(
            "SELECT event_id,scope_id,window_ordinal,append_class,action,budget_kind "
            "FROM homeostasis_events WHERE event_id IN ("
            + ",".join("?" for _item in homeostasis_ids)
            + ") ORDER BY budget_kind",
            homeostasis_ids,
        ).fetchall()
        if (
            tuple(str(row[0]) for row in homeostasis_rows) != homeostasis_ids
            or tuple(str(row[5]) for row in homeostasis_rows)
            != HOMEOSTASIS_ADMISSION_BUDGETS
            or any(
                str(row[1]) != str(admission.get("scope_id"))
                or int(row[2])
                != int(admission.get("homeostasis_window_ordinal", -1))
                or str(row[3]) != "delta_admission"
                or str(row[4]) not in {"admit", "clamp_magnitude"}
                for row in homeostasis_rows
            )
            or admission.get("homeostasis_event_id") != homeostasis_ids[0]
            or admission.get("homeostasis_set_root")
            != _homeostasis_set_root(homeostasis_ids)
        ):
            _reject("plasticity_replay_admission_graph_open")
        for row in homeostasis_rows:
            event_id = str(row[0])
            decision_key = (
                str(delta_id),
                str(row[1]),
                int(row[2]),
                str(row[5]),
            )
            if event_id in bound_homeostasis_ids or decision_key in decision_keys:
                _reject("plasticity_replay_admission_graph_open")
            bound_homeostasis_ids.add(event_id)
            decision_keys.add(decision_key)

        batteries = []
        for battery_row in connection.execute(
            "SELECT battery_id,canonical_bytes FROM probe_batteries WHERE delta_id=?",
            (delta_id,),
        ).fetchall():
            battery = parse_raw_json(bytes(battery_row[1]))
            if (
                isinstance(battery, dict)
                and battery.get("battery_root") == admission.get("probe_battery_root")
            ):
                batteries.append(battery)
        if len(batteries) != 1 or tuple(batteries[0].get("receipt_row_ids", ())) != (
            tuple(admission.get("ordered_probe_receipt_ids", ()))
        ):
            _reject("plasticity_replay_admission_graph_open")

    if connection.execute(
        "SELECT 1 FROM delta_applications AS a "
        "LEFT JOIN admission_receipts AS r ON r.delta_id=a.delta_id "
        "WHERE a.application_event='apply' AND r.admission_id IS NULL LIMIT 1"
    ).fetchone() is not None:
        _reject("plasticity_replay_admission_graph_open")
    durable_homeostasis_ids = {
        str(row[0])
        for row in connection.execute(
            "SELECT event_id FROM homeostasis_events "
            "WHERE append_class='delta_admission'"
        ).fetchall()
    }
    if durable_homeostasis_ids != bound_homeostasis_ids:
        _reject("plasticity_replay_admission_graph_open")
    application_counts = {
        str(delta_id): int(count)
        for delta_id, count in connection.execute(
            "SELECT delta_id,count(*) FROM delta_applications "
            "WHERE application_event='apply' GROUP BY delta_id"
        ).fetchall()
    }
    admission_counts = {
        str(delta_id): int(count)
        for delta_id, count in connection.execute(
            "SELECT delta_id,count(*) FROM admission_receipts GROUP BY delta_id"
        ).fetchall()
    }
    if application_counts != admission_counts:
        _reject("plasticity_replay_admission_graph_open")


def _verify_replay_provider_graph(connection: sqlite3.Connection) -> None:
    operation_ids = tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT DISTINCT operation_id FROM provider_lifecycle_receipts "
            "ORDER BY operation_id"
        ).fetchall()
    )
    for operation_id in operation_ids:
        rows = connection.execute(
            "SELECT lifecycle_event,base_snapshot_id,observed_snapshot_id,"
            "adapter_root,evidence_root,authorization_sha256,attempt_ordinal "
            "FROM provider_lifecycle_receipts WHERE operation_id=? "
            "ORDER BY CASE lifecycle_event "
            "WHEN 'training' THEN 0 WHEN 'stage' THEN 1 "
            "WHEN 'verification' THEN 2 WHEN 'activation' THEN 3 "
            "WHEN 'unload' THEN 4 WHEN 'restoration' THEN 5 END",
            (operation_id,),
        ).fetchall()
        events = tuple(str(row[0]) for row in rows)
        allowed = {
            ("training",),
            ("stage",),
            ("stage", "verification"),
            ("stage", "verification", "activation"),
            ("stage", "verification", "restoration"),
            ("unload",),
            ("unload", "restoration"),
        }
        if events not in allowed:
            _reject("plasticity_replay_provider_graph_open")
        if len({(str(row[3]), str(row[5]), int(row[6])) for row in rows}) != 1:
            _reject("plasticity_replay_provider_graph_open")
        if len({str(row[1]) for row in rows}) != 1:
            _reject("plasticity_replay_provider_graph_open")
        by_event = {str(row[0]): row for row in rows}
        base = str(rows[0][1])
        if "stage" in by_event and (
            str(by_event["stage"][2]) != base
            or "verification" in by_event
            and str(by_event["verification"][2]) != base
        ):
            _reject("plasticity_replay_provider_graph_open")
        if "activation" in by_event:
            activation = by_event["activation"]
            if str(activation[2]) == base or str(activation[4]) != str(activation[2]):
                _reject("plasticity_replay_provider_graph_open")
        if "restoration" in by_event and str(by_event["restoration"][4]) != base:
            _reject("plasticity_replay_provider_graph_open")


def _replay_rows(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    material: list[tuple[object, ...]] = []
    for table, key in _REPLAY_TABLES:
        rows = connection.execute(
            f'SELECT * FROM "{table}" ORDER BY "{key}"'
        ).fetchall()
        for row in rows:
            record_id = row[0]
            declared = row[-2]
            raw_value = row[-1]
            raw = bytes(raw_value)
            if sha256_hex(raw) != str(declared):
                _reject("plasticity_replay_divergent")
            _authenticate_replay_record(table, str(record_id), raw, tuple(row))
            material.append((table, str(record_id), str(declared), raw))
    _verify_replay_operation_ledger(connection)
    _verify_replay_fence_graph(connection)
    _verify_replay_admission_graph(connection)
    _verify_replay_provider_graph(connection)
    dangling_checks = (
        (
            "SELECT 1 FROM channel_updates c LEFT JOIN experience_gradients g "
            "ON g.gradient_id=c.gradient_id WHERE g.gradient_id IS NULL LIMIT 1",
            "plasticity_replay_graph_open",
        ),
        (
            "SELECT 1 FROM channel_updates c LEFT JOIN parameter_deltas d "
            "ON d.delta_id=c.delta_id WHERE c.channel='fast_weights' "
            "AND d.delta_id IS NULL LIMIT 1",
            "plasticity_replay_graph_open",
        ),
        (
            "SELECT 1 FROM delta_applications a LEFT JOIN parameter_deltas d "
            "ON d.delta_id=a.delta_id WHERE d.delta_id IS NULL LIMIT 1",
            "plasticity_replay_graph_open",
        ),
        (
            "SELECT 1 FROM mixture_records m LEFT JOIN invocation_receipts i "
            "ON i.invocation_id=m.invocation_id WHERE i.invocation_id IS NULL LIMIT 1",
            "plasticity_replay_graph_open",
        ),
        (
            "SELECT 1 FROM probe_receipts p LEFT JOIN parameter_deltas d "
            "ON d.delta_id=p.delta_id WHERE d.delta_id IS NULL LIMIT 1",
            "plasticity_replay_graph_open",
        ),
        (
            "SELECT 1 FROM probe_batteries b LEFT JOIN parameter_deltas d "
            "ON d.delta_id=b.delta_id WHERE d.delta_id IS NULL LIMIT 1",
            "plasticity_replay_graph_open",
        ),
    )
    for statement, code in dangling_checks:
        if connection.execute(statement).fetchone() is not None:
            _reject(code)
    for battery_id, delta_id, raw_value in connection.execute(
        "SELECT battery_id,delta_id,canonical_bytes FROM probe_batteries"
    ).fetchall():
        parsed = parse_raw_json(bytes(raw_value))
        if not isinstance(parsed, dict):
            _reject("plasticity_replay_contract_invalid")
        receipt_ids = tuple(parsed.get("receipt_row_ids", ()))
        placeholder_ids = tuple(parsed.get("placeholder_ids", ()))
        durable_receipts = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT receipt_id FROM probe_receipts WHERE delta_id=? "
                "ORDER BY probe_ordinal",
                (delta_id,),
            ).fetchall()
        )
        if durable_receipts != receipt_ids:
            _reject("plasticity_replay_graph_open")
        if placeholder_ids:
            durable_placeholders = frozenset(
                str(row[0])
                for row in connection.execute(
                    "SELECT placeholder_id FROM pending_owner_hardware "
                    "WHERE placeholder_id IN ("
                    + ",".join("?" for _item in placeholder_ids)
                    + ")",
                    placeholder_ids,
                ).fetchall()
            )
            if durable_placeholders != frozenset(placeholder_ids):
                _reject("plasticity_replay_graph_open")
    for attempt_id, gradient_id, channel_update_id in connection.execute(
        "SELECT attempt_id,gradient_id,channel_update_id FROM learning_attempts "
        "ORDER BY attempt_id"
    ).fetchall():
        pair = connection.execute(
            "SELECT c.gradient_id FROM channel_updates c "
            "JOIN experience_gradients g ON g.gradient_id=c.gradient_id "
            "WHERE c.channel_update_id=? AND g.gradient_id=?",
            (channel_update_id, gradient_id),
        ).fetchone()
        if pair is None:
            _reject("plasticity_replay_graph_open")
        raw = canonicalize(
            {
                "attempt_id": str(attempt_id),
                "gradient_id": str(gradient_id),
                "channel_update_id": str(channel_update_id),
                "record_type": "learning_attempt",
                "schema_version": "skeleton.learning-attempt.v1",
            }
        )
        material.append(
            ("learning_attempts", str(attempt_id), sha256_hex(raw), raw)
        )
    rows = connection.execute(
        "SELECT operation_id,result_sha256,result_bytes FROM "
        "plasticity_operation_ledger ORDER BY operation_id"
    ).fetchall()
    for operation_id, declared, raw_value in rows:
        raw = bytes(raw_value)
        if sha256_hex(raw) != str(declared):
            _reject("plasticity_replay_divergent")
        material.append(
            ("plasticity_operation_ledger", str(operation_id), str(declared), raw)
        )
    return tuple(material)


def _dispatch_operation(
    connection: sqlite3.Connection, operation: str, arguments: tuple[object, ...]
) -> object:
    if operation == "row_counts" and not arguments:
        return tuple(
            (
                table,
                int(
                    connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                ),
            )
            for table in PLASTICITY_TABLES
        )
    if operation == "integrity_check" and not arguments:
        return str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    if operation == "state_root" and not arguments:
        return _table_root(connection, PLASTICITY_TABLES, _STATE_DOMAIN)
    if operation == "fence_snapshot" and len(arguments) == 1:
        return _current_fence(connection, str(arguments[0]))
    if operation == "application_state" and len(arguments) == 1:
        return _last_application(connection, str(arguments[0]))
    if operation == "homeostasis_totals" and len(arguments) == 2:
        scope_id = str(arguments[0])
        window_ordinal = int(arguments[1])
        return tuple(
            (
                kind.value,
                int(
                    connection.execute(
                        "SELECT coalesce(sum(committed_amount),0) "
                        "FROM homeostasis_events WHERE budget_kind=? "
                        "AND scope_id=? AND window_ordinal=?",
                        (kind.value, scope_id, window_ordinal),
                    ).fetchone()[0]
                ),
            )
            for kind in sorted(HomeostasisBudgetKind, key=lambda item: item.value)
        )
    if operation == "prepare_homeostasis_admission" and len(arguments) == 9:
        _require_current_fence(
            connection, str(arguments[4]), int(arguments[5]), str(arguments[8])
        )
        return _derive_homeostasis_rows(
            connection,
            delta_id=str(arguments[0]),
            scope_id=str(arguments[1]),
            window_ordinal=int(arguments[2]),
            proof_payloads=tuple(arguments[3]),
            fence_id=str(arguments[4]),
            generation=int(arguments[5]),
            attempt_ordinal=int(arguments[6]),
            recorded_at=str(arguments[7]),
        )
    if operation == "replay" and not arguments:
        return _replay_rows(connection)
    if operation == "fence" and len(arguments) == 2:
        return _append_fence(connection, arguments[0], str(arguments[1]))
    if operation == "channel_update" and len(arguments) == 3:
        return _append_channel_update(
            connection, arguments[0], str(arguments[1]), str(arguments[2])
        )
    if operation == "learning_attempt" and len(arguments) == 5:
        return _commit_learning_attempt(
            connection,
            str(arguments[0]),
            arguments[1],
            arguments[2],
            str(arguments[3]),
            str(arguments[4]),
        )
    if operation == "invocation_mixture" and len(arguments) == 4:
        return _commit_invocation_mixture(
            connection,
            arguments[0],
            arguments[1],
            str(arguments[2]),
            str(arguments[3]),
        )
    if operation == "probe_receipt" and len(arguments) == 3:
        return _append_probe_receipt(
            connection, arguments[0], str(arguments[1]), str(arguments[2])
        )
    if operation == "probe_battery" and len(arguments) == 6:
        return _commit_probe_battery(
            connection,
            tuple(arguments[0]),
            tuple(arguments[1]),
            arguments[2],
            str(arguments[3]),
            str(arguments[4]),
            int(arguments[5]),
        )
    if operation == "homeostasis_event" and len(arguments) == 3:
        return _append_homeostasis_event(
            connection, arguments[0], str(arguments[1]), str(arguments[2])
        )
    if operation == "delta_application" and len(arguments) == 4:
        return _append_delta_application(
            connection,
            arguments[0],
            tuple(arguments[1]),
            str(arguments[2]),
            str(arguments[3]),
        )
    if operation == "admission_application" and len(arguments) == 6:
        return _commit_admission_application(
            connection,
            arguments[0],
            arguments[1],
            tuple(arguments[2]),
            tuple(arguments[3]),
            str(arguments[4]),
            str(arguments[5]),
        )
    if operation == "application_batch" and len(arguments) == 5:
        return _append_application_batch(
            connection,
            tuple(arguments[0]),
            tuple(arguments[1]),
            tuple(tuple(proof) for proof in arguments[2]),
            str(arguments[3]),
            str(arguments[4]),
        )
    if operation in _RECORD_TABLES and len(arguments) == 3:
        table, key = _RECORD_TABLES[operation]
        return _append_record(
            connection,
            table=table,
            key=key,
            row=arguments[0],
            operation_kind=operation,
            writer_id=str(arguments[1]),
            operation_id=str(arguments[2]),
        )
    _reject("plasticity_operation_forbidden")


def _serve_worker(connection: sqlite3.Connection, channel: Connection) -> None:
    while True:
        try:
            request = channel.recv()
        except EOFError:
            return
        if (
            not isinstance(request, tuple)
            or len(request) != 3
            or not isinstance(request[0], int)
            or not isinstance(request[1], str)
            or not isinstance(request[2], tuple)
        ):
            channel.send((-1, "error", "plasticity_worker_protocol_invalid"))
            continue
        sequence, operation, arguments = request
        if operation == "close" and not arguments:
            if connection.in_transaction:
                connection.rollback()
            channel.send((sequence, "ok", None))
            return
        try:
            result = _dispatch_operation(connection, operation, arguments)
            channel.send((sequence, "ok", result))
        except BaseException as error:
            if connection.in_transaction:
                connection.rollback()
            if isinstance(error, PlasticityStoreRejection):
                code = error.code
            elif isinstance(error, sqlite3.OperationalError) and any(
                word in str(error).lower() for word in ("locked", "busy")
            ):
                code = "plasticity_writer_busy"
            else:
                code = "plasticity_operation_failed"
            channel.send((sequence, "error", code))


def _sqlite_worker(path: str, channel: Connection) -> None:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, timeout=0.0)
        connection.execute("PRAGMA foreign_keys=ON")
        if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
            _reject("foreign_keys_unavailable")
        row = connection.execute(
            "SELECT sql_sha256 FROM schema_migrations WHERE migration_id=?",
            (PLASTICITY_MIGRATION_ID,),
        ).fetchone()
        if row != (MIGRATION_0014_SHA256,):
            _reject("plasticity_schema_unauthenticated")
        _require_live_schema_identity(connection)
        connection.execute("PRAGMA locking_mode=EXCLUSIVE")
        connection.set_authorizer(_sqlite_authorizer)
        connection.execute("BEGIN EXCLUSIVE")
        connection.commit()
        channel.send(("ready", None))
        _serve_worker(connection, channel)
    except BaseException as error:
        if isinstance(error, PlasticityStoreRejection):
            code = error.code
        elif isinstance(error, sqlite3.OperationalError) and any(
            word in str(error).lower() for word in ("locked", "busy")
        ):
            code = "plasticity_writer_busy"
        else:
            code = "plasticity_worker_start_failed"
        try:
            channel.send(("startup_error", code))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        if connection is not None:
            try:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()
            except sqlite3.Error:
                pass
        channel.close()


class _PlasticityProcessOwner:
    __slots__ = (
        "_channel",
        "_closed",
        "_operation_timeout_seconds",
        "_process",
        "_sequence",
    )

    def __init__(self, path: Path) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(
            target=_sqlite_worker,
            args=(str(path), child),
            daemon=True,
            name="skeleton-phase13-plasticity-owner",
        )
        process.start()
        child.close()
        self._channel = parent
        self._process = process
        self._sequence = 0
        self._closed = False
        self._operation_timeout_seconds = 5.0
        if not parent.poll(10.0):
            process.terminate()
            process.join(5.0)
            parent.close()
            _reject("plasticity_worker_unavailable")
        response = parent.recv()
        if response != ("ready", None):
            process.join(5.0)
            parent.close()
            code = (
                response[1]
                if isinstance(response, tuple)
                and len(response) == 2
                and response[0] == "startup_error"
                else "plasticity_worker_start_failed"
            )
            _reject(str(code))

    def _request(self, operation: str, *arguments: object) -> object:
        if self._closed or not self._process.is_alive():
            _reject("plasticity_worker_unavailable")
        self._sequence += 1
        sequence = self._sequence
        try:
            self._channel.send((sequence, operation, tuple(arguments)))
            if not self._channel.poll(self._operation_timeout_seconds):
                alive = self._process.is_alive()
                if alive:
                    self._process.terminate()
                self._process.join(5.0)
                self._channel.close()
                self._closed = True
                _reject(
                    "plasticity_worker_timeout"
                    if alive
                    else "plasticity_worker_unavailable"
                )
            response = self._channel.recv()
        except (BrokenPipeError, EOFError, OSError) as error:
            raise PlasticityStoreRejection("plasticity_worker_unavailable") from error
        if (
            not isinstance(response, tuple)
            or len(response) != 3
            or response[0] != sequence
            or response[1] not in {"ok", "error"}
        ):
            _reject("plasticity_worker_protocol_invalid")
        if response[1] == "error":
            _reject(str(response[2]))
        return response[2]

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._process.is_alive():
                self._request("close")
        finally:
            self._closed = True
            self._channel.close()
            self._process.join(5.0)
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(5.0)


def _is_reparse(path: Path) -> bool:
    return path.is_symlink() or bool(
        hasattr(os.path, "isjunction") and os.path.isjunction(path)
    )


def _reject_reparse_components(path: Path, code: str) -> None:
    """Reject caller-supplied aliases before any resolving can erase them."""

    unresolved = path if path.is_absolute() else Path.cwd() / path
    current = Path(unresolved.anchor)
    for part in unresolved.parts[1:]:
        if part == "..":
            _reject(code)
        current /= part
        if _is_reparse(current):
            _reject(code)


def _receipt(value: object) -> OperationReceipt:
    if not isinstance(value, tuple) or len(value) != 6:
        _reject("plasticity_worker_protocol_invalid")
    return OperationReceipt(
        str(value[0]),
        str(value[1]),
        str(value[2]),
        int(value[3]),
        str(value[4]),
        bytes(value[5]),
    )


def _homeostasis_append_from_row(row: object) -> HomeostasisEventAppend:
    if not isinstance(row, tuple) or len(row) != 20:
        _reject("plasticity_worker_protocol_invalid")
    return HomeostasisEventAppend(
        str(row[0]),
        str(row[1]),
        str(row[2]),
        str(row[3]),
        bool(row[4]),
        *(int(value) for value in row[5:11]),
        str(row[11]),
        str(row[12]),
        int(row[13]),
        str(row[14]),
        int(row[15]),
        int(row[16]),
        str(row[17]),
        bytes(row[19]),
    )


class PlasticityStore:
    """Narrow typed facade over the sole Phase 13 SQLite owner process."""

    __slots__ = ("__application_nonce", "__owner", "_closed")

    def __init__(
        self,
        *,
        database_path: Path | str,
        temporary_root: Path | str | None = None,
        durable_root: Path | str | None = None,
    ) -> None:
        if (temporary_root is None) == (durable_root is None):
            _reject("plasticity_storage_root_ambiguous")
        selected_root = temporary_root if temporary_root is not None else durable_root
        assert selected_root is not None
        unresolved_root = Path(selected_root)
        _reject_reparse_components(unresolved_root, "plasticity_storage_root_invalid")
        root = unresolved_root.resolve(strict=True)
        if not root.is_dir():
            _reject("plasticity_storage_root_invalid")
        if temporary_root is not None:
            system_temp = Path(tempfile.gettempdir()).resolve(strict=True)
            if root != system_temp and system_temp not in root.parents:
                _reject("plasticity_temporary_root_invalid")
        unresolved_path = Path(database_path)
        _reject_reparse_components(unresolved_path, "plasticity_database_outside_root")
        path = unresolved_path.resolve(strict=True)
        if not path.is_file() or root not in path.parents:
            _reject("plasticity_database_outside_root")
        self.__owner = _PlasticityProcessOwner(path)
        self.__application_nonce = object()
        self._closed = False

    def _issue_application_commit_capability(
        self, *, writer_id: str, fence_id: str, generation: int
    ) -> _ApplicationCommitCapability:
        """Mint one opaque capability bound to this store and exact fence."""

        writer = _identity(writer_id, "writer_identity_invalid")
        fence = _identity(fence_id, "fence_identity_invalid")
        generation_value = _nonnegative(generation, "fence_generation_invalid")
        return _ApplicationCommitCapability(
            self.__application_nonce,
            writer,
            fence,
            generation_value,
            _APPLICATION_CAPABILITY_TOKEN,
        )

    def _require_application_commit_capability(
        self,
        capability: object,
        *,
        writer_id: str,
        fence_id: str,
        generation: int,
    ) -> None:
        if not isinstance(capability, _ApplicationCommitCapability) or not (
            capability._authorizes(
                self.__application_nonce, writer_id, fence_id, generation
            )
        ):
            _reject("application_commit_capability_required")

    def close(self) -> None:
        if not self._closed:
            self.__owner.close()
            self._closed = True

    def __enter__(self) -> "PlasticityStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def row_counts(self) -> dict[str, int]:
        return {
            str(name): int(count)
            for name, count in self.__owner._request("row_counts")
        }

    def integrity_check(self) -> str:
        return str(self.__owner._request("integrity_check"))

    def state_root(self) -> str:
        return str(self.__owner._request("state_root"))

    def fence_snapshot(self, stream_id: str) -> FenceSnapshot:
        """Read the current fence for one stream to resume after a fault."""

        value = self.__owner._request(
            "fence_snapshot", _identity(stream_id, "fence_stream_invalid")
        )
        if value is None:
            _reject("plasticity_fence_unknown")
        if not isinstance(value, tuple) or len(value) != 3:
            _reject("plasticity_worker_protocol_invalid")
        return FenceSnapshot(stream_id, str(value[0]), int(value[1]), str(value[2]))

    def application_state(self, delta_id: str) -> ApplicationState:
        """Derive one delta's current application state from apply/reverse rows."""

        value = self.__owner._request(
            "application_state", _identity(delta_id, "delta_identity_invalid")
        )
        if value is None:
            return ApplicationState(delta_id, "never_applied", 0)
        if not isinstance(value, tuple) or len(value) != 2:
            _reject("plasticity_worker_protocol_invalid")
        event = str(value[0])
        if event not in APPLICATION_EVENTS:
            _reject("plasticity_worker_protocol_invalid")
        state = "applied" if event == APPLY_EVENT else "reversed"
        return ApplicationState(delta_id, state, int(value[1]))

    def homeostasis_totals(
        self, *, scope_id: str = GLOBAL_SCOPE_SENTINEL, window_ordinal: int = 0
    ) -> dict[str, int]:
        """Exact totals for one isolated scope/window accumulator."""

        if scope_id != GLOBAL_SCOPE_SENTINEL:
            scope_id = _identity(scope_id, "homeostasis_scope_invalid")
        window = _nonnegative(window_ordinal, "homeostasis_window_invalid")
        return {
            str(kind): int(total)
            for kind, total in self.__owner._request(
                "homeostasis_totals", scope_id, window
            )
        }

    @staticmethod
    def homeostasis_set_root(event_ids: tuple[str, ...]) -> str:
        """Authenticate the exact budget-ordered admission decision set."""

        for event_id in event_ids:
            _identity(event_id, "homeostasis_decision_set_invalid")
        return _homeostasis_set_root(event_ids)

    def _prepare_homeostasis_admission(
        self,
        *,
        delta_id: str,
        scope_id: str,
        window_ordinal: int,
        proof: ApplicationPayloadProof,
        fence_id: str,
        generation: int,
        attempt_ordinal: int,
        recorded_at: str,
        writer_id: str,
    ) -> tuple[HomeostasisEventAppend, ...]:
        """Derive a preview which the commit transaction independently rechecks."""

        _utc(recorded_at, "homeostasis_event_append_invalid")
        value = self.__owner._request(
            "prepare_homeostasis_admission",
            _identity(delta_id, "delta_identity_invalid"),
            _identity(scope_id, "homeostasis_scope_invalid"),
            _nonnegative(window_ordinal, "homeostasis_window_invalid"),
            _application_proof_tuple(proof),
            _identity(fence_id, "fence_identity_invalid"),
            _nonnegative(generation, "fence_generation_invalid"),
            _positive(attempt_ordinal, "homeostasis_event_append_invalid"),
            recorded_at,
            _identity(writer_id, "writer_identity_invalid"),
        )
        if not isinstance(value, tuple):
            _reject("plasticity_worker_protocol_invalid")
        return tuple(_homeostasis_append_from_row(row) for row in value)

    def replay_verify(self) -> PlasticityReplay:
        """Return every appended record with its byte identity re-proven.

        The worker verifies each stored ``canonical_sha256`` against its
        stored bytes, and this facade independently re-verifies the detached
        copies, so a divergent byte anywhere rejects instead of replaying.
        """

        value = self.__owner._request("replay")
        if not isinstance(value, tuple):
            _reject("plasticity_worker_protocol_invalid")
        records: list[tuple[str, str, str, bytes]] = []
        for entry in value:
            if not isinstance(entry, tuple) or len(entry) != 4:
                _reject("plasticity_worker_protocol_invalid")
            table, record_id, declared, raw_value = entry
            raw = bytes(raw_value)
            if sha256_hex(raw) != str(declared):
                _reject("plasticity_replay_divergent")
            if str(table) == "provider_lifecycle_receipts":
                document = parse_raw_json(raw)
                if not isinstance(document, dict):
                    _reject("plasticity_replay_provider_authorization_invalid")
                try:
                    _verify_provider_lifecycle_authority(document)
                except PlasticityStoreRejection as error:
                    raise PlasticityStoreRejection(
                        "plasticity_replay_provider_authorization_invalid"
                    ) from error
            records.append((str(table), str(record_id), str(declared), raw))
        return PlasticityReplay(tuple(records))

    def acquire_fence(
        self, item: FenceAppend, *, operation_id: str
    ) -> OperationReceipt:
        """Acquire the genesis fence or advance one generation (resume)."""

        return _receipt(
            self.__owner._request(
                "fence",
                _fence_row(item),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_scope(
        self, item: ScopeAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "scope",
                _scope_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_gradient(
        self, item: GradientAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        _gradient_row(item)
        _identity(writer_id, "writer_identity_invalid")
        _identity(operation_id, "operation_identity_invalid")
        _reject("learning_attempt_transaction_required")

    def append_channel_update(
        self, item: ChannelUpdateAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        _channel_update_row(item)
        _identity(writer_id, "writer_identity_invalid")
        _identity(operation_id, "operation_identity_invalid")
        _reject("learning_attempt_transaction_required")

    def commit_learning_attempt(
        self,
        *,
        attempt_id: str,
        gradient: GradientAppend,
        update: ChannelUpdateAppend,
        writer_id: str,
        operation_id: str,
    ) -> OperationReceipt:
        """Atomically persist one completed-attempt gradient/update pair."""

        return _receipt(
            self.__owner._request(
                "learning_attempt",
                _identity(attempt_id, "learning_attempt_identity_invalid"),
                _gradient_row(gradient),
                _channel_update_row(update),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_delta(
        self, item: DeltaAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "delta",
                _delta_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_delta_application(
        self,
        item: DeltaApplicationAppend,
        *,
        proof: ApplicationPayloadProof | None = None,
        capability: object | None = None,
        writer_id: str,
        operation_id: str,
    ) -> OperationReceipt:
        """Append one apply or reverse event row — never a mutation.

        Reverse is representable only after an apply at the immediately
        preceding ordinal; a second terminal event of the same kind rejects
        typed, and re-apply after reverse is a new monotonic ordinal.
        """

        row = _delta_application_row(item)
        if item.application_event == APPLY_EVENT:
            _reject("application_admission_required")
        writer = _identity(writer_id, "writer_identity_invalid")
        self._require_application_commit_capability(
            capability,
            writer_id=writer,
            fence_id=item.fence_id,
            generation=item.generation,
        )
        return _receipt(
            self.__owner._request(
                "delta_application",
                row,
                _application_proof_tuple(proof),
                writer,
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def _commit_admission_application(
        self,
        *,
        admission: AdmissionReceiptAppend,
        application: DeltaApplicationAppend,
        homeostasis: tuple[HomeostasisEventAppend, ...],
        provider_evidence: object,
        proof: ApplicationPayloadProof | None = None,
        capability: object | None = None,
        writer_id: str,
        operation_id: str,
    ) -> OperationReceipt:
        """Coordinator-only atomic admission receipt plus activation."""

        writer = _identity(writer_id, "writer_identity_invalid")
        self._require_application_commit_capability(
            capability,
            writer_id=writer,
            fence_id=application.fence_id,
            generation=application.generation,
        )
        if len(homeostasis) != len(HOMEOSTASIS_ADMISSION_BUDGETS):
            _reject("homeostasis_decision_set_invalid")
        admission_document = parse_raw_json(admission.canonical_bytes)
        authorize_live = getattr(
            provider_evidence, "_authorizes_live_activation", None
        )
        try:
            provider_fields_valid = (
                isinstance(admission_document, dict)
                and callable(authorize_live)
                and authorize_live(
                    base_snapshot_id=admission.provider_snapshot_id,
                    adapter_digest=str(
                        delta_from_raw(
                            next(
                                raw
                                for table, record_id, _digest, raw in self.replay_verify().records
                                if table == "parameter_deltas"
                                and record_id == admission.delta_id
                            )
                        ).tensor_payload_root
                    ),
                )
                and provider_evidence.loaded_snapshot_id
                == admission_document["provider_loaded_snapshot_id"]
                and provider_evidence.verification_id
                == admission_document["provider_verification_id"]
                and provider_evidence.operation_id
                == admission_document["provider_load_operation_id"]
                and provider_evidence.authorization_sha256
                == admission_document["provider_authorization_sha256"]
                and list(provider_evidence.lifecycle_receipt_ids)
                == admission_document["provider_lifecycle_receipt_ids"]
            )
        except (AttributeError, PlasticityTypeRejection, StopIteration):
            provider_fields_valid = False
        if not provider_fields_valid:
            _reject("provider_verified_load_required")
        return _receipt(
            self.__owner._request(
                "admission_application",
                _admission_receipt_row(admission),
                _delta_application_row(application),
                tuple(_homeostasis_row(item) for item in homeostasis),
                _application_proof_tuple(proof),
                writer,
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def _append_application_batch(
        self,
        intents: tuple[HomeostasisEventAppend, ...],
        applications: tuple[DeltaApplicationAppend, ...],
        proofs: tuple[ApplicationPayloadProof, ...],
        *,
        capability: object | None = None,
        writer_id: str,
        operation_id: str,
    ) -> OperationReceipt:
        """Internal all-or-nothing apply/reverse journal transaction."""

        if (
            not intents
            or len(intents) != len(applications)
            or len(applications) != len(proofs)
        ):
            _reject("application_batch_invalid")
        writer = _identity(writer_id, "writer_identity_invalid")
        for application in applications:
            self._require_application_commit_capability(
                capability,
                writer_id=writer,
                fence_id=application.fence_id,
                generation=application.generation,
            )
        return _receipt(
            self.__owner._request(
                "application_batch",
                tuple(_homeostasis_row(item) for item in intents),
                tuple(_delta_application_row(item) for item in applications),
                tuple(_application_proof_tuple(proof) for proof in proofs),
                writer,
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_probe_receipt(
        self, item: ProbeReceiptAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        _probe_receipt_row(item)
        _identity(writer_id, "writer_identity_invalid")
        _identity(operation_id, "operation_identity_invalid")
        _reject("probe_battery_transaction_required")

    def commit_probe_battery(
        self,
        *,
        placeholders: tuple[PlaceholderAppend, ...],
        receipts: tuple[ProbeReceiptAppend, ...],
        disposition: ProbeBatteryAppend,
        writer_id: str,
        operation_id: str,
        failure_after_row: int = 0,
    ) -> OperationReceipt:
        """Persist a complete battery and disposition in one transaction."""

        if type(failure_after_row) is not int or failure_after_row < 0:
            _reject("probe_battery_failure_point_invalid")
        return _receipt(
            self.__owner._request(
                "probe_battery",
                tuple(_placeholder_row(item) for item in placeholders),
                tuple(_probe_receipt_row(item) for item in receipts),
                _probe_battery_row(disposition),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
                failure_after_row,
            )
        )

    def append_homeostasis_event(
        self, item: HomeostasisEventAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        row = _homeostasis_row(item)
        if str(row[3]) == "delta_admission":
            _reject("homeostasis_admission_transaction_required")
        return _receipt(
            self.__owner._request(
                "homeostasis_event",
                row,
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_placeholder(
        self, item: PlaceholderAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        """Append one hardware-honesty placeholder row.

        Placeholder appends are pressure-exempt by construction: this path
        never reads homeostasis state, so no pressure band, ceiling, or
        clamped budget can ever block it (D-18).
        """

        _placeholder_row(item)
        _identity(writer_id, "writer_identity_invalid")
        _identity(operation_id, "operation_identity_invalid")
        _reject("probe_battery_transaction_required")

    def append_mixture(
        self, item: MixtureAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        _mixture_row(item)
        _identity(writer_id, "writer_identity_invalid")
        _identity(operation_id, "operation_identity_invalid")
        _reject("mixture_requires_invocation_transaction")

    def commit_invocation_mixture(
        self,
        *,
        invocation: InvocationReceiptAppend,
        mixture: MixtureAppend,
        writer_id: str,
        operation_id: str,
    ) -> OperationReceipt:
        """Append the invocation receipt and its exhaustive mixture together."""

        return _receipt(
            self.__owner._request(
                "invocation_mixture",
                _invocation_receipt_row(invocation),
                _mixture_row(mixture),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def append_candidate_version(
        self, item: CandidateVersionAppend, *, writer_id: str, operation_id: str
    ) -> OperationReceipt:
        return _receipt(
            self.__owner._request(
                "candidate_version",
                _candidate_version_row(item),
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )

    def _append_provider_lifecycle(
        self,
        item: ProviderLifecycleAppend,
        *,
        authorization: VerifiedOwnerCapability,
        writer_id: str,
        operation_id: str,
    ) -> OperationReceipt:
        """Persist one owner-authorized provider lifecycle transition."""

        row = _provider_lifecycle_row(item)
        event = item.lifecycle_event
        required_operation = (
            "training"
            if event == "training"
            else "load"
            if event in {"stage", "verification", "activation"}
            else authorization.operation
            if event == "restoration"
            else "unload"
        )
        if required_operation not in {"training", "load", "unload"}:
            _reject("provider_lifecycle_authorization_invalid")
        expected_snapshot = (
            item.observed_snapshot_id
            if required_operation == "unload"
            else item.base_snapshot_id
        )
        expected_subject = (
            item.evidence_root
            if required_operation == "training"
            else item.observed_snapshot_id
            if required_operation == "unload"
            else item.adapter_root
        )
        if (
            not isinstance(authorization, VerifiedOwnerCapability)
            or authorization.operation != required_operation
            or authorization.operation_id != item.operation_id
            or authorization.provider_snapshot_id != expected_snapshot
            or authorization.subject_root != expected_subject
            or authorization.attempt_ordinal != item.attempt_ordinal
            or authorization.capability_sha256 != item.authorization_sha256
        ):
            _reject("provider_lifecycle_authorization_invalid")
        return _receipt(
            self.__owner._request(
                "provider_lifecycle",
                row,
                _identity(writer_id, "writer_identity_invalid"),
                _identity(operation_id, "operation_identity_invalid"),
            )
        )


__all__ = [
    "APPLICATION_EVENTS",
    "AUTHORITY_DOMAIN",
    "AUTHORITY_PROTOCOL_VERSION",
    "CAPABILITY_SCHEMA_VERSION",
    "AdmissionReceiptAppend",
    "ApplicationPayloadProof",
    "ApplicationState",
    "CandidateVersionAppend",
    "ChannelUpdateAppend",
    "DeltaAppend",
    "DeltaApplicationAppend",
    "FAULT_POINTS",
    "FenceAppend",
    "FenceSnapshot",
    "GradientAppend",
    "HomeostasisEventAppend",
    "InvocationReceiptAppend",
    "MIGRATION_0014_SHA256",
    "PLASTICITY_SCHEMA_ROOT",
    "MixtureAppend",
    "OperationReceipt",
    "OWNER_OPERATIONS",
    "PLASTICITY_INDEXES",
    "PLASTICITY_MIGRATION_ID",
    "PLASTICITY_TABLES",
    "PlaceholderAppend",
    "PlasticityMigrationRejection",
    "PlasticityMigrationResult",
    "PlasticityMigrations",
    "PlasticityReplay",
    "PlasticityStore",
    "PlasticityStoreRejection",
    "PlasticityAuthorityRejection",
    "ProbeBatteryAppend",
    "ProbeReceiptAppend",
    "ProviderLifecycleAppend",
    "ScopeAppend",
    "VerifiedOwnerCapability",
    "ZERO_SHA256",
    "apply_plasticity_migrations",
    "authority_preimage",
    "plasticity_record_identity",
    "learning_attempt_identity",
    "owner_capability_body",
    "verify_owner_capability",
]
