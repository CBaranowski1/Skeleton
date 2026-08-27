"""Truthful immutable status assembled from existing read-only owners."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import stat
import struct
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .process_contract import ProfileStatus, ROLE_NAMES
from .reference_authority import AuthorityEvidence, inspect_authority_database
from .schema_registry import SchemaRegistry


KERNEL_STATUS_SCHEMA_ID = (
    "https://schemas.skeleton.local/v1/kernel-status.schema.json"
)
STATUS_SCHEMA_VERSION = "skeleton.kernel-status.v1"
PRODUCT_IDENTITY = "skeleton.private-single-owner"
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_ROLE_STATES = frozenset({"ready", "absent", "failed", "timed_out"})


@dataclass(slots=True)
class StatusRejection(ValueError):
    """Stable status rejection that never echoes paths or evidence bytes."""

    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class ComponentDisposition:
    """Read-only verification disposition retained outside the frozen wire schema."""

    state: str
    evidence_sha256: str | None
    observed_at: str | None


@dataclass(frozen=True, slots=True)
class KernelStatusSnapshot:
    """One immutable, schema-validated status response."""

    canonical_bytes: bytes
    etag: str
    readiness: str
    components: Mapping[str, ComponentDisposition]
    authority: AuthorityEvidence


@dataclass(frozen=True, slots=True)
class MarketActivationPointer:
    activation_id: str
    dossier_sha256: str
    adapter_identity_sha256: str
    state: str
    blockers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class KernelStatusV3:
    schema_version: str
    kernel_status_v1_sha256: str
    kernel_status_v2_sha256: str
    market_activation: MarketActivationPointer
    observed_at: str
    canonical_bytes: bytes
    etag: str


@dataclass(frozen=True, slots=True)
class StatusSnapshotProvider:
    """Read-only bounded inputs used to rebuild current status per observation."""

    registry: SchemaRegistry
    database_path: Path
    authority_domain: str
    process_status_provider: Callable[[], ProfileStatus]
    rust_evidence_path: Path
    typescript_evidence_path: Path
    observed_at_provider: Callable[[], datetime]
    evidence_max_age: timedelta = timedelta(hours=24)
    evidence_health_provider: object | None = None

    def snapshot(self) -> KernelStatusSnapshot:
        return build_status_snapshot(
            registry=self.registry,
            database_path=self.database_path,
            authority_domain=self.authority_domain,
            process_status=self.process_status_provider(),
            rust_evidence_path=self.rust_evidence_path,
            typescript_evidence_path=self.typescript_evidence_path,
            observed_at=self.observed_at_provider(),
            evidence_max_age=self.evidence_max_age,
        )

    def snapshot_v2(self, evidence_health: object) -> object:
        """Compose additive v2 while leaving the frozen v1 path byte-exact."""

        from .evidence_health import build_status_v2

        v1 = self.snapshot()
        return build_status_v2(
            kernel_status_v1_sha256=sha256_hex(v1.canonical_bytes),
            evidence_health=evidence_health,
        )

    def publication_snapshot(self) -> object:
        """Publish additive v2 when durable evidence health is configured."""

        if getattr(self, "evidence_health_provider", None) is None:
            return self.snapshot()
        snapshot_method = getattr(self.evidence_health_provider, "snapshot", None)
        if not callable(snapshot_method):
            raise StatusRejection("evidence_health_provider_invalid")
        return self.snapshot_v2(snapshot_method())

    def snapshot_v3(self, market_activation: object) -> KernelStatusV3:
        """Compose additive market truth without acquiring activation authority."""

        if self.evidence_health_provider is None:
            raise StatusRejection("evidence_health_provider_required")
        health_method = getattr(self.evidence_health_provider, "snapshot", None)
        if not callable(health_method):
            raise StatusRejection("evidence_health_provider_invalid")
        v1 = self.snapshot()
        v2 = self.snapshot_v2(health_method())
        v3 = build_status_v3(
            kernel_status_v1_sha256=sha256_hex(v1.canonical_bytes),
            kernel_status_v2_sha256=sha256_hex(v2.canonical_bytes),
            market_activation=market_activation,
        )
        try:
            validated = self.registry.validate_raw(
                v3.canonical_bytes,
                "https://schemas.skeleton.local/v1/kernel-status-v3.schema.json",
            )
        except Exception as error:
            raise StatusRejection("status_v3_schema_invalid") from error
        if validated.canonical_bytes != v3.canonical_bytes:
            raise StatusRejection("status_v3_not_canonical")
        return v3


def build_status_v3(
    *,
    kernel_status_v1_sha256: str,
    kernel_status_v2_sha256: str,
    market_activation: object,
) -> KernelStatusV3:
    """Build a redacted additive v3 pointer from immutable prior snapshots."""

    from .market_activation import MarketActivationSnapshot

    if _SHA256.fullmatch(kernel_status_v1_sha256) is None or _SHA256.fullmatch(kernel_status_v2_sha256) is None:
        raise StatusRejection("status_v3_parent_identity_invalid")
    if not isinstance(market_activation, MarketActivationSnapshot):
        raise StatusRejection("status_v3_market_snapshot_required")
    market_value = dict(market_activation.as_status_value())
    value = {
        "kernel_status_v1_sha256": kernel_status_v1_sha256,
        "kernel_status_v2_sha256": kernel_status_v2_sha256,
        "market_activation": market_value,
        "observed_at": market_activation.observed_at,
        "schema_version": "skeleton.kernel-status.v3",
    }
    raw = canonicalize(value)
    pointer = MarketActivationPointer(
        activation_id=market_activation.activation_id,
        dossier_sha256=market_activation.dossier_sha256,
        adapter_identity_sha256=market_activation.adapter_identity_sha256,
        state=market_activation.state,
        blockers=market_activation.blockers,
    )
    return KernelStatusV3(
        schema_version="skeleton.kernel-status.v3",
        kernel_status_v1_sha256=kernel_status_v1_sha256,
        kernel_status_v2_sha256=kernel_status_v2_sha256,
        market_activation=pointer,
        observed_at=market_activation.observed_at,
        canonical_bytes=raw,
        etag=f'"{sha256_hex(raw)}"',
    )


def build_status_snapshot(
    *,
    registry: SchemaRegistry,
    database_path: Path,
    authority_domain: str,
    process_status: ProfileStatus,
    rust_evidence_path: Path,
    typescript_evidence_path: Path,
    observed_at: datetime,
    evidence_max_age: timedelta = timedelta(hours=24),
) -> KernelStatusSnapshot:
    """Build one validated snapshot without acquiring any mutation capability."""

    if not isinstance(registry, SchemaRegistry):
        raise TypeError("authenticated SchemaRegistry required")
    observed = _normalized_observed_at(observed_at)
    if (
        not isinstance(evidence_max_age, timedelta)
        or evidence_max_age <= timedelta(0)
    ):
        raise StatusRejection("status_evidence_age_invalid")

    role_health = _validate_process_status(process_status)
    authority = inspect_authority_database(database_path, authority_domain)
    components = {
        "rust-conformance": _read_conformance_evidence(
            "rust",
            rust_evidence_path,
            observed,
            evidence_max_age,
        ),
        "typescript-conformance": _read_conformance_evidence(
            "typescript",
            typescript_evidence_path,
            observed,
            evidence_max_age,
        ),
    }

    value = {
        "schema_version": STATUS_SCHEMA_VERSION,
        "product_identity": PRODUCT_IDENTITY,
        "bundle_sha256": sha256_hex(
            (registry.contracts_root / "bundle-manifest.json").read_bytes()
        ),
        "semantic_state_hash": authority.semantic_state_sha256,
        "journal_state_hash": authority.journal_state_sha256,
        "authority_snapshot_hash": authority.authority_snapshot_sha256,
        "incomplete_journal_disposition": authority.journal_state or "idle",
        "authority_process_health": role_health["reference-authority"],
        "cognition_process_health": role_health["cognition-simulator"],
        "lobe_count": 0,
        "capabilities": [],
        "observed_at": _format_timestamp(observed),
    }
    canonical_bytes = canonicalize(value)
    try:
        validated = registry.validate_raw(
            canonical_bytes,
            KERNEL_STATUS_SCHEMA_ID,
        )
    except Exception as error:
        raise StatusRejection("status_schema_invalid") from error
    if validated.canonical_bytes != canonical_bytes:
        raise StatusRejection("status_not_canonical")

    readiness = _readiness(process_status, role_health, components)
    return KernelStatusSnapshot(
        canonical_bytes=canonical_bytes,
        etag=f'"{sha256_hex(canonical_bytes)}"',
        readiness=readiness,
        components=MappingProxyType(components),
        authority=authority,
    )


def _normalized_observed_at(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise StatusRejection("status_observed_at_invalid")
    normalized = value.astimezone(timezone.utc)
    if normalized.utcoffset() != timedelta(0):
        raise StatusRejection("status_observed_at_invalid")
    return normalized


def _format_timestamp(value: datetime) -> str:
    timespec = "microseconds" if value.microsecond else "seconds"
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def _validate_process_status(status_value: ProfileStatus) -> dict[str, str]:
    if not isinstance(status_value, ProfileStatus):
        raise StatusRejection("status_process_health_invalid")
    if set(status_value.roles) != set(ROLE_NAMES):
        raise StatusRejection("status_process_health_partial")
    for name in ROLE_NAMES:
        role = status_value.roles[name]
        if role.state not in _ROLE_STATES:
            raise StatusRejection("status_process_health_invalid")
        if role.required != (name in {"reference-authority", "status"}):
            raise StatusRejection("status_process_health_invalid")

    authority_state = status_value.roles["reference-authority"].state
    status_state = status_value.roles["status"].state
    expected_authority_available = authority_state == "ready"
    expected_ready = authority_state == "ready" and status_state == "ready"
    if (
        status_value.authority_available != expected_authority_available
        or status_value.ready != expected_ready
    ):
        raise StatusRejection("status_process_health_inconsistent")
    return {
        "reference-authority": _wire_process_health(authority_state),
        "cognition-simulator": _wire_process_health(
            status_value.roles["cognition-simulator"].state
        ),
        "status": _wire_process_health(status_state),
    }


def _wire_process_health(state: str) -> str:
    if state == "ready":
        return "available"
    if state == "timed_out":
        return "degraded"
    return "unavailable"


def _read_conformance_evidence(
    kind: str,
    path: Path,
    observed_at: datetime,
    max_age: timedelta,
) -> ComponentDisposition:
    if not isinstance(path, Path):
        raise StatusRejection(f"status_{kind}_evidence_path_invalid")
    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        return ComponentDisposition(
            state="unknown",
            evidence_sha256=None,
            observed_at=None,
        )
    if (
        stat.S_ISLNK(path_stat.st_mode)
        or not stat.S_ISREG(path_stat.st_mode)
        or path_stat.st_size <= 0
        or path_stat.st_size > MAX_EVIDENCE_BYTES
    ):
        raise StatusRejection(f"status_{kind}_evidence_file_invalid")

    raw = path.read_bytes()
    after_read_stat = path.stat()
    if (
        len(raw) != path_stat.st_size
        or after_read_stat.st_size != path_stat.st_size
        or after_read_stat.st_mtime_ns != path_stat.st_mtime_ns
    ):
        raise StatusRejection(f"status_{kind}_evidence_changed")
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise StatusRejection(f"status_{kind}_evidence_invalid") from error
    if not isinstance(value, dict):
        raise StatusRejection(f"status_{kind}_evidence_partial")
    _validate_conformance_value(kind, value)

    evidence_time = datetime.fromtimestamp(
        path_stat.st_mtime,
        tz=timezone.utc,
    )
    age = observed_at - evidence_time
    state = "ready" if timedelta(0) <= age <= max_age else "degraded"
    return ComponentDisposition(
        state=state,
        evidence_sha256=sha256_hex(raw),
        observed_at=_format_timestamp(evidence_time),
    )


def _validate_conformance_value(kind: str, value: dict[str, Any]) -> None:
    common = (
        "schema_version",
        "source_commit",
        "evidence_digest",
        "file_count",
        "inventory",
        "inventory_sha256",
    )
    if any(name not in value for name in common):
        raise StatusRejection(f"status_{kind}_evidence_partial")
    if (
        not isinstance(value["source_commit"], str)
        or _SOURCE_COMMIT.fullmatch(value["source_commit"]) is None
        or not isinstance(value["evidence_digest"], str)
        or _SHA256.fullmatch(value["evidence_digest"]) is None
        or not isinstance(value["inventory_sha256"], str)
        or _SHA256.fullmatch(value["inventory_sha256"]) is None
        or not isinstance(value["file_count"], int)
        or isinstance(value["file_count"], bool)
        or value["file_count"] <= 0
        or not isinstance(value["inventory"], list)
    ):
        raise StatusRejection(f"status_{kind}_evidence_invalid")
    if len(value["inventory"]) != value["file_count"]:
        raise StatusRejection(f"status_{kind}_evidence_partial")
    _validate_inventory(kind, value["inventory"])
    if value["inventory_sha256"] != _inventory_digest(kind, value["inventory"]):
        raise StatusRejection(f"status_{kind}_evidence_partial")

    if kind == "rust":
        policy = value.get("policy")
        if (
            value["schema_version"]
            != "skeleton.phase06.rust-environment-evidence.v1"
            or not isinstance(policy, dict)
            or policy.get("network_request_count") != 0
            or policy.get("credential_observed") is not False
            or policy.get("frozen") is not True
            or policy.get("offline") is not True
            or value.get("upstream_before_after_equal") is not True
            or value.get("lifecycle_equal") is not True
        ):
            raise StatusRejection("status_rust_evidence_invalid")
        return

    selected = value.get("selected_profile")
    observations = value.get("observations")
    if (
        kind != "typescript"
        or value["schema_version"]
        != "skeleton.phase06.typescript-environment-transfer.v1"
        or not isinstance(selected, dict)
        or selected.get("branches_coexist") is not False
        or not isinstance(selected.get("self_sufficiency"), dict)
        or selected["self_sufficiency"].get("status") != "passed"
        or selected["self_sufficiency"].get("representative_typecheck")
        != "passed"
        or not isinstance(observations, dict)
        or observations.get("network_requests") != 0
        or observations.get("lifecycle_invocations") != 0
        or observations.get("ambient_modules") != 0
        or observations.get("before_after_equal") is not True
    ):
        raise StatusRejection("status_typescript_evidence_invalid")


def _validate_inventory(kind: str, inventory: list[Any]) -> None:
    paths: list[str] = []
    for record in inventory:
        if (
            not isinstance(record, dict)
            or set(record) != {"byte_length", "path", "sha256"}
            or not isinstance(record["byte_length"], int)
            or isinstance(record["byte_length"], bool)
            or record["byte_length"] < 0
            or not isinstance(record["path"], str)
            or not record["path"]
            or "\\" in record["path"]
            or record["path"].startswith("/")
            or ":" in record["path"]
            or any(part in {"", ".", ".."} for part in record["path"].split("/"))
            or not isinstance(record["sha256"], str)
            or _SHA256.fullmatch(record["sha256"]) is None
        ):
            raise StatusRejection(f"status_{kind}_evidence_partial")
        paths.append(record["path"])
    if len(paths) != len(set(paths)):
        raise StatusRejection(f"status_{kind}_evidence_partial")


def _inventory_digest(kind: str, inventory: list[dict[str, Any]]) -> str:
    if kind == "typescript":
        return sha256_hex(canonicalize(inventory))
    frame = bytearray(b"SKELETON_PHASE06_RUST_INVENTORY_V1\x00")
    frame.extend(struct.pack(">I", len(inventory)))
    for record in inventory:
        path_bytes = record["path"].encode("utf-8")
        digest_bytes = record["sha256"].encode("ascii")
        frame.extend(struct.pack(">I", len(path_bytes)))
        frame.extend(path_bytes)
        frame.extend(struct.pack(">Q", record["byte_length"]))
        frame.extend(struct.pack(">I", len(digest_bytes)))
        frame.extend(digest_bytes)
    return hashlib.sha256(frame).hexdigest()


def _readiness(
    process_status: ProfileStatus,
    role_health: Mapping[str, str],
    components: Mapping[str, ComponentDisposition],
) -> str:
    if (
        role_health["reference-authority"] == "unavailable"
        or role_health["status"] == "unavailable"
        or not process_status.ready
    ):
        return "unavailable"
    states = {component.state for component in components.values()}
    if "unknown" in states:
        return "unknown"
    if "degraded" in states or role_health["status"] == "degraded":
        return "degraded"
    return "ready"
