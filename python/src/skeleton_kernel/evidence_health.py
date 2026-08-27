"""Durable redacted evidence-health and additive status-v2 composition."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import sqlite3
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from .canonical import canonicalize, parse_raw_json
from .evidence_store import EvidenceStore


REQUIRED_SIGNALS = (
    "ingest_lag",
    "correction_rate",
    "sequence_gaps",
    "unresolved_identities",
    "exclusions",
    "rights_expiry",
    "deletion_backlog",
    "reproducibility_failures",
    "storage_pressure",
)


@dataclass(slots=True)
class HealthRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class HealthSignal:
    state: str
    value: int | None
    reason_code: str | None

    def as_value(self) -> dict[str, object]:
        return {
            "reason_code": self.reason_code,
            "state": self.state,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class EvidenceHealthSnapshot:
    snapshot_sha256: str
    source_state_sha256: str
    readiness: str
    observed_at: str
    signals: Mapping[str, HealthSignal]
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class EvidenceHealthPointer:
    snapshot_sha256: str
    source_state_sha256: str
    readiness: str
    observed_at: str
    signals: Mapping[str, HealthSignal]


@dataclass(frozen=True, slots=True)
class KernelStatusV2:
    schema_version: str
    kernel_status_v1_sha256: str
    evidence_health: EvidenceHealthPointer
    observed_at: str
    canonical_bytes: bytes
    etag: str

    @property
    def readiness(self) -> str:
        return self.evidence_health.readiness


@dataclass(frozen=True, slots=True)
class HealthHttpResponse:
    status: int
    allow: tuple[str, ...]
    canonical_bytes: bytes | None


class EvidenceHealthProvider:
    """Derive each metric from the injected durable evidence store."""

    def __init__(
        self,
        store: EvidenceStore,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(store, EvidenceStore):
            raise TypeError("durable EvidenceStore required")
        self._store = store
        self._clock = clock

    @classmethod
    def from_fixture_records(
        cls,
        records: Sequence[Mapping[str, Any]],
        *,
        store: EvidenceStore,
        clock: Callable[[], datetime] | None = None,
    ) -> "EvidenceHealthProvider":
        if not records:
            raise HealthRejection("health_fixture_identity_missing")
        return cls(
            store,
            clock=clock or (
                lambda: datetime(2026, 8, 1, 12, 5, tzinfo=timezone.utc)
            ),
        )

    @property
    def store(self) -> EvidenceStore:
        return self._store

    def snapshot(
        self,
        *,
        hostile_detail: str | None = None,
        stored_ids: Mapping[str, str] | None = None,
    ) -> EvidenceHealthSnapshot:
        del hostile_detail
        observed = self._clock()
        observed_at = _timestamp(observed)
        normalized_ids = _stored_ids(stored_ids)
        signals, source = self._derive(observed)
        source["stored_ids"] = normalized_ids
        source_state_sha256 = sha256(canonicalize(source)).hexdigest()
        readiness = _readiness(signals)
        body = {
            "observed_at": observed_at,
            "readiness": readiness,
            "schema_version": "skeleton.evidence-health.v1",
            "signals": {
                name: signals[name].as_value() for name in REQUIRED_SIGNALS
            },
            "source_state_sha256": source_state_sha256,
        }
        snapshot_sha = sha256(canonicalize(body)).hexdigest()
        raw = canonicalize({**body, "snapshot_sha256": snapshot_sha})
        return EvidenceHealthSnapshot(
            snapshot_sha256=snapshot_sha,
            source_state_sha256=source_state_sha256,
            readiness=readiness,
            observed_at=observed_at,
            signals=MappingProxyType(signals),
            canonical_bytes=raw,
        )

    def snapshot_for_stored_ids(
        self,
        stored_ids: Mapping[str, str],
    ) -> EvidenceHealthSnapshot:
        return self.snapshot(stored_ids=stored_ids)

    def _derive(
        self, observed: datetime
    ) -> tuple[dict[str, HealthSignal], dict[str, object]]:
        connection = self._store.connection
        try:
            event_count = _count(connection, "canonical_events")
            if event_count == 0:
                signals = {
                    name: HealthSignal("unknown", None, "evidence_missing")
                    for name in REQUIRED_SIGNALS
                }
                return signals, {
                    "event_count": 0,
                    "metric_source": "durable_sqlite",
                }

            latest_available = str(
                connection.execute(
                    "SELECT max(available_at) FROM canonical_events"
                ).fetchone()[0]
            )
            lag = max(0, int((observed - _parse_time(latest_available)).total_seconds()))
            corrected = int(
                connection.execute(
                    "SELECT count(*) FROM canonical_events "
                    "WHERE correction_of IS NOT NULL"
                ).fetchone()[0]
            )
            correction_rate = (corrected * 1_000_000) // event_count
            sequence_gaps = int(
                connection.execute(
                    "SELECT count(*) FROM canonical_events "
                    "WHERE sequence_state = 'unresolved'"
                ).fetchone()[0]
            )
            unresolved_identities = int(
                connection.execute(
                    "SELECT count(*) FROM stable_identities AS s "
                    "WHERE NOT EXISTS (SELECT 1 FROM identity_alias_facts AS f "
                    "WHERE f.stable_identity_id = s.stable_identity_id)"
                ).fetchone()[0]
            )
            exclusions = _manifest_exclusions(connection)
            active_rights_count, expiry_text = connection.execute(
                "SELECT count(*), min(effective_to) FROM rights_records "
                "WHERE status = 'active'"
            ).fetchone()
            # The contract expresses this signal as a bounded duration.  Active
            # rights with no expiry are healthy, not missing evidence, so use
            # the schema's one-year ceiling as the durable "at least" horizon.
            rights_expiry = (
                0
                if int(active_rights_count) == 0
                else 31_536_000
                if expiry_text is None
                else min(
                    31_536_000,
                    max(
                        0,
                        int(
                            (_parse_time(str(expiry_text)) - observed).total_seconds()
                        ),
                    ),
                )
            )
            deletion_backlog = int(
                connection.execute(
                    "SELECT count(*) FROM deletion_executions "
                    "WHERE execution_state <> 'terminal'"
                ).fetchone()[0]
            )
            reproducibility_failures = int(
                connection.execute(
                    "SELECT count(*) FROM dataset_manifests AS m "
                    "WHERE NOT EXISTS (SELECT 1 FROM dataset_partitions AS p "
                    "WHERE p.dataset_id = m.dataset_id)"
                ).fetchone()[0]
            )
            stored_bytes = int(
                connection.execute(
                    "SELECT coalesce(sum(byte_length), 0) FROM content_objects"
                ).fetchone()[0]
            )
            storage_pressure = min(
                1_000_000, (stored_bytes * 1_000_000) // (16 * 1024 * 1024)
            )
        except (sqlite3.DatabaseError, ValueError, TypeError) as error:
            signals = {
                name: HealthSignal("unavailable", None, "evidence_corrupt")
                for name in REQUIRED_SIGNALS
            }
            return signals, {
                "metric_source": "durable_sqlite",
                "source_error_sha256": sha256(type(error).__name__.encode()).hexdigest(),
            }

        values = {
            "ingest_lag": (lag, lag > 300),
            "correction_rate": (correction_rate, correction_rate > 100_000),
            "sequence_gaps": (sequence_gaps, sequence_gaps > 0),
            "unresolved_identities": (
                unresolved_identities,
                unresolved_identities > 0,
            ),
            "exclusions": (exclusions, exclusions > 0),
            "rights_expiry": (
                rights_expiry,
                rights_expiry is not None and rights_expiry < 86_400,
            ),
            "deletion_backlog": (deletion_backlog, deletion_backlog > 0),
            "reproducibility_failures": (
                reproducibility_failures,
                reproducibility_failures > 0,
            ),
            "storage_pressure": (
                storage_pressure,
                storage_pressure > 900_000,
            ),
        }
        signals: dict[str, HealthSignal] = {}
        for name in REQUIRED_SIGNALS:
            value, exceeded = values[name]
            if value is None:
                signals[name] = HealthSignal(
                    "unknown", None, "evidence_missing"
                )
            elif exceeded:
                signals[name] = HealthSignal(
                    "degraded", value, "threshold_exceeded"
                )
            else:
                signals[name] = HealthSignal("ready", value, None)
        return signals, {
            "active_rights_count": int(active_rights_count),
            "corrected_event_count": corrected,
            "event_count": event_count,
            "exclusion_count": exclusions,
            "latest_available_at": latest_available,
            "metric_source": "durable_sqlite",
            "open_deletion_count": deletion_backlog,
            "reproducibility_failure_count": reproducibility_failures,
            "sequence_gap_count": sequence_gaps,
            "stored_bytes": stored_bytes,
            "unresolved_identity_count": unresolved_identities,
        }


class EvidenceStatusProvider:
    """Read-only GET/HEAD surface with no mutation method or capability."""

    def __init__(self, health: EvidenceHealthProvider) -> None:
        if not isinstance(health, EvidenceHealthProvider):
            raise TypeError("EvidenceHealthProvider required")
        self._health = health

    def request(self, method: str) -> HealthHttpResponse:
        if method not in {"GET", "HEAD"}:
            return HealthHttpResponse(405, ("GET", "HEAD"), None)
        snapshot = self._health.snapshot()
        return HealthHttpResponse(
            200 if snapshot.readiness == "ready" else 503,
            ("GET", "HEAD"),
            b"" if method == "HEAD" else snapshot.canonical_bytes,
        )

    def logical_snapshot(self) -> bytes:
        return canonicalize({"surface": "read_only", "methods": ["GET", "HEAD"]})


def build_status_v2(
    *,
    kernel_status_v1_sha256: str,
    evidence_health: EvidenceHealthSnapshot,
) -> KernelStatusV2:
    if (
        not isinstance(kernel_status_v1_sha256, str)
        or len(kernel_status_v1_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in kernel_status_v1_sha256
        )
    ):
        raise HealthRejection("kernel_status_v1_identity_invalid")
    if not isinstance(evidence_health, EvidenceHealthSnapshot):
        raise HealthRejection("evidence_health_required")
    pointer = EvidenceHealthPointer(
        snapshot_sha256=evidence_health.snapshot_sha256,
        source_state_sha256=evidence_health.source_state_sha256,
        readiness=evidence_health.readiness,
        observed_at=evidence_health.observed_at,
        signals=evidence_health.signals,
    )
    value = {
        "evidence_health": {
            "observed_at": pointer.observed_at,
            "readiness": pointer.readiness,
            "signals": {
                name: pointer.signals[name].as_value()
                for name in REQUIRED_SIGNALS
            },
            "snapshot_sha256": pointer.snapshot_sha256,
            "source_state_sha256": pointer.source_state_sha256,
        },
        "kernel_status_v1_sha256": kernel_status_v1_sha256,
        "observed_at": evidence_health.observed_at,
        "schema_version": "skeleton.kernel-status.v2",
    }
    raw = canonicalize(value)
    return KernelStatusV2(
        schema_version="skeleton.kernel-status.v2",
        kernel_status_v1_sha256=kernel_status_v1_sha256,
        evidence_health=pointer,
        observed_at=evidence_health.observed_at,
        canonical_bytes=raw,
        etag='"' + sha256(raw).hexdigest() + '"',
    )


def _stored_ids(value: Mapping[str, str] | None) -> dict[str, str]:
    if value is None:
        return {}
    if not value:
        raise HealthRejection("health_stored_ids_missing")
    normalized: dict[str, str] = {}
    for name, digest in sorted(value.items()):
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise HealthRejection("health_stored_id_invalid")
        normalized[name] = digest
    return normalized


def _count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute('SELECT count(*) FROM "' + table + '"').fetchone()[0])


def _manifest_exclusions(connection: sqlite3.Connection) -> int:
    total = 0
    for row in connection.execute(
        "SELECT canonical_manifest FROM dataset_manifests ORDER BY manifest_id"
    ):
        value = parse_raw_json(bytes(row[0]))
        if not isinstance(value, dict) or not isinstance(value.get("exclusions"), list):
            raise ValueError("manifest_exclusions_invalid")
        total += len(value["exclusions"])
    return total


def _readiness(signals: Mapping[str, HealthSignal]) -> str:
    states = {signal.state for signal in signals.values()}
    if "unavailable" in states:
        return "unavailable"
    if "degraded" in states or "stale" in states:
        return "degraded"
    if "unknown" in states:
        return "unknown"
    return "ready"


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("timestamp_invalid")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None:
        raise ValueError("timestamp_invalid")
    return parsed.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise HealthRejection("health_clock_invalid")
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(
        timespec="microseconds" if normalized.microsecond else "seconds"
    ).replace("+00:00", "Z")
