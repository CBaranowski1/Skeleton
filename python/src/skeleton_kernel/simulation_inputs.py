"""Capability-limited Phase 9 simulation input and rights resolution.

This module deliberately does not import the stateful authority or rights evaluator.
All runtime values are materialized, authenticated, immutable records.  The resolver
can therefore decide which sealed candidates are lawful for evaluation without a
SQLite connection, store handle, mutable clock, or upstream writer capability.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .evidence_authority import PHASE07_BUNDLE_PROJECTION_SHA256
from .market_contracts import (
    PHASE08_BUNDLE_PROJECTION_SHA256,
    PHASE08_FIXTURE_INDEX_PROJECTION_SHA256,
)
from .simulation_capabilities import (
    SimulationCapabilityRejection,
    verify_authority_envelope,
)
from .simulation_contracts import (
    ARTIFACT_SCHEMA_ID,
    MANIFEST_SCHEMA_ID,
    AllInputsRightsExcluded,
    SimulationContractPublication,
    SimulationContractValue,
    compute_document_identity,
)


RIGHTS_PROJECTION_VERSION = "skeleton.read-only-rights-projection.v1"
_REQUEST_DOMAIN = "SKELETON_PHASE09_EVALUATION_USE_REQUEST_V1"
_RIGHTS_DECISION_DOMAIN = "SKELETON_PHASE09_READ_ONLY_RIGHTS_DECISION_V1"
_EVENT_DOMAIN = "SKELETON_PHASE09_SIMULATION_EVENT_V1"
_RESOLUTION_DOMAIN = "SKELETON_PHASE09_SIMULATION_INPUT_RESOLUTION_V1"
_SNAPSHOT_DOMAIN = "SKELETON_PHASE09_UPSTREAM_READ_ONLY_SNAPSHOT_V1"
_CHECKPOINT_MANIFEST_DOMAIN = "SKELETON_PHASE09_SEALED_CHECKPOINT_MANIFEST_V1"
_AGGREGATE_SUBJECT_DOMAIN = "SKELETON_PHASE09_AGGREGATE_SUBJECT_INVENTORY_V1"
_AGGREGATE_EVIDENCE_DOMAIN = "SKELETON_PHASE09_AGGREGATE_EVIDENCE_INVENTORY_V1"
_HASH_ZERO = "0" * 64
_VIEW_TOKEN = object()

_CHECKPOINT_RECORD_TABLES = MappingProxyType(
    {
        "candidate_records": "sealed_candidate_records",
        "rights_records": "sealed_rights_records",
        "legal_terms": "sealed_legal_terms_records",
        "rights_status_events": "sealed_rights_status_events",
    }
)

_REQUEST_POLICY_FIELDS = (
    "purpose",
    "territory",
    "display",
    "storage",
    "derivation",
    "training",
    "transmission",
    "backup",
    "attribution",
    "retention",
    "deletion",
    "audit",
    "termination",
    "acquisition_method",
)


@dataclass(slots=True)
class SimulationInputRejection(ValueError):
    """Closed, redacted simulation-input failure."""

    code: str
    redacted: bool = True

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise SimulationInputRejection(code)


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    return sha256(
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _hash(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _time(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SimulationInputRejection(code) from error
    if parsed.tzinfo != UTC:
        _reject(code)
    return parsed


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    _reject("forbidden_capability")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def rights_policy_digest(record: Mapping[str, Any]) -> str:
    """Return the complete versioned policy digest used by evaluation manifests."""

    policy = {
        name: record.get(name)
        for name in (
            "rights_record_id",
            "legal_terms_id",
            "version",
            "boundaries",
            "purposes",
            "territories",
            "display",
            "storage",
            "derivation",
            "training",
            "transmission",
            "backup",
            "attribution",
            "retention",
            "deletion",
            "audit",
            "termination",
            "acquisition_methods",
            "processing_destinations",
        )
    }
    return _framed_digest(
        "SKELETON_PHASE09_RIGHTS_POLICY_V1", canonicalize(_plain(policy))
    )


@dataclass(frozen=True, slots=True)
class UpstreamReadOnlySnapshot:
    database_sha256: str
    table_sha256s: tuple[tuple[str, str], ...]
    store_sha256s: tuple[tuple[str, str], ...]
    aggregate_sha256: str

    @classmethod
    def from_material(
        cls,
        *,
        database_bytes: bytes,
        tables: Mapping[str, Any],
        stores: Mapping[str, bytes],
    ) -> "UpstreamReadOnlySnapshot":
        if not isinstance(database_bytes, bytes):
            raise TypeError("database_bytes must be bytes")
        table_sha256s = tuple(
            (name, sha256_hex(canonicalize(_plain(tables[name]))))
            for name in sorted(tables)
        )
        store_sha256s = tuple(
            (name, sha256_hex(stores[name])) for name in sorted(stores)
        )
        value = {
            "database_sha256": sha256_hex(database_bytes),
            "store_sha256s": [list(item) for item in store_sha256s],
            "table_sha256s": [list(item) for item in table_sha256s],
        }
        return cls(
            database_sha256=str(value["database_sha256"]),
            table_sha256s=table_sha256s,
            store_sha256s=store_sha256s,
            aggregate_sha256=_framed_digest(_SNAPSHOT_DOMAIN, canonicalize(value)),
        )

    @classmethod
    def capture(
        cls,
        database_path: Path | str,
        *,
        table_names: Sequence[str],
        store_roots: Mapping[str, Path | str] = MappingProxyType({}),
    ) -> "UpstreamReadOnlySnapshot":
        """Capture exact bytes and ordered rows without retaining a connection."""

        path = Path(database_path).resolve(strict=True)
        if not path.is_file() or path.is_symlink() or _is_junction(path):
            _reject("upstream_database_unavailable")
        for suffix in ("-wal", "-shm"):
            if Path(str(path) + suffix).exists():
                _reject("upstream_database_not_checkpointed")
        rows: dict[str, Any] = {}
        uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True)
        try:
            connection.execute("PRAGMA query_only = ON")
            known = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            }
            for table in sorted(set(table_names)):
                if table not in known or not table.replace("_", "a").isalnum():
                    _reject("upstream_table_unavailable")
                columns = tuple(
                    str(row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table}")')
                )
                if not columns:
                    _reject("upstream_table_unavailable")
                order = ", ".join(f'"{column}"' for column in columns)
                materialized = connection.execute(
                    f'SELECT * FROM "{table}" ORDER BY {order}'
                ).fetchall()
                rows[table] = [
                    [
                        {"bytes_hex": item.hex()} if isinstance(item, bytes) else item
                        for item in row
                    ]
                    for row in materialized
                ]
        finally:
            connection.close()
        stores: dict[str, bytes] = {}
        for label in sorted(store_roots):
            root = Path(store_roots[label]).resolve(strict=True)
            if not root.is_dir() or root.is_symlink() or _is_junction(root):
                _reject("upstream_store_unavailable")
            for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
                if candidate.is_symlink() or _is_junction(candidate):
                    _reject("upstream_store_link_forbidden")
                if candidate.is_file():
                    resolved = candidate.resolve(strict=True)
                    if root not in resolved.parents:
                        _reject("upstream_store_escape")
                    relative = candidate.relative_to(root).as_posix()
                    stores[f"{label}/{relative}"] = candidate.read_bytes()
        return cls.from_material(
            database_bytes=path.read_bytes(), tables=rows, stores=stores
        )

    def assert_equal(self, observed: "UpstreamReadOnlySnapshot") -> None:
        if not isinstance(observed, UpstreamReadOnlySnapshot):
            _reject("upstream_snapshot_required")
        if self != observed:
            _reject("upstream_mutation_detected")


def _is_junction(path: Path) -> bool:
    return bool(hasattr(os.path, "isjunction") and os.path.isjunction(path))


def _snapshot_copy(snapshot: UpstreamReadOnlySnapshot) -> UpstreamReadOnlySnapshot:
    return UpstreamReadOnlySnapshot(
        database_sha256=snapshot.database_sha256,
        table_sha256s=tuple(snapshot.table_sha256s),
        store_sha256s=tuple(snapshot.store_sha256s),
        aggregate_sha256=snapshot.aggregate_sha256,
    )


@dataclass(slots=True)
class _StaticSnapshotRecapture:
    snapshot: UpstreamReadOnlySnapshot

    def capture(self) -> UpstreamReadOnlySnapshot:
        return _snapshot_copy(self.snapshot)


@dataclass(slots=True)
class _SequenceSnapshotRecapture:
    snapshots: tuple[UpstreamReadOnlySnapshot, ...]
    index: int = 0

    def capture(self) -> UpstreamReadOnlySnapshot:
        if self.index >= len(self.snapshots):
            _reject("upstream_recapture_exhausted")
        observed = _snapshot_copy(self.snapshots[self.index])
        self.index += 1
        return observed


@dataclass(frozen=True, slots=True)
class _CheckpointSnapshotRecapture:
    database_path: Path
    table_names: tuple[str, ...]
    store_roots: Mapping[str, Path]

    def capture(self) -> UpstreamReadOnlySnapshot:
        return UpstreamReadOnlySnapshot.capture(
            self.database_path,
            table_names=self.table_names,
            store_roots=self.store_roots,
        )


def _checkpoint_manifest_identity(value: Mapping[str, Any]) -> str:
    body = dict(value)
    body.pop("manifest_id", None)
    return _framed_digest(_CHECKPOINT_MANIFEST_DOMAIN, canonicalize(body))


def _canonical_checkpoint_record(raw: bytes, expected_sha256: str) -> Mapping[str, Any]:
    if sha256_hex(raw) != expected_sha256:
        _reject("checkpoint_record_hash_mismatch")
    parsed = parse_raw_json(raw)
    if not isinstance(parsed, dict) or canonicalize(parsed) != raw:
        _reject("checkpoint_record_not_canonical")
    return _freeze(parsed)


def checkpoint_authority_body(
    *,
    source_manifest_id: str,
    candidate_records: Sequence[Mapping[str, Any]],
    rights_records: Sequence[Mapping[str, Any]],
    legal_terms: Sequence[Mapping[str, Any]],
    rights_status_events: Sequence[Mapping[str, Any]],
    upstream_snapshot_sha256: str,
) -> Mapping[str, Any]:
    return {
        "phase07_bundle_projection_sha256": PHASE07_BUNDLE_PROJECTION_SHA256,
        "phase08_bundle_projection_sha256": PHASE08_BUNDLE_PROJECTION_SHA256,
        "phase08_fixture_index_projection_sha256": PHASE08_FIXTURE_INDEX_PROJECTION_SHA256,
        "record_inventories": {
            "candidate_records": sorted(
                sha256_hex(canonicalize(_plain(item))) for item in candidate_records
            ),
            "legal_terms": sorted(
                sha256_hex(canonicalize(_plain(item))) for item in legal_terms
            ),
            "rights_records": sorted(
                sha256_hex(canonicalize(_plain(item))) for item in rights_records
            ),
            "rights_status_events": sorted(
                sha256_hex(canonicalize(_plain(item))) for item in rights_status_events
            ),
        },
        "source_manifest_id": source_manifest_id,
        "upstream_snapshot_sha256": upstream_snapshot_sha256,
    }


@dataclass(frozen=True, slots=True, init=False)
class SealedEvidenceView:
    publication: SimulationContractPublication
    source_manifest_canonical_bytes: bytes
    source_manifest_id: str
    candidate_records: tuple[Mapping[str, Any], ...]
    rights_records: tuple[Mapping[str, Any], ...]
    legal_terms: tuple[Mapping[str, Any], ...]
    rights_status_events: tuple[Mapping[str, Any], ...]
    upstream_snapshot: UpstreamReadOnlySnapshot
    checkpoint_authority_envelope: bytes
    _recapture: object

    def __init__(
        self,
        *,
        publication: SimulationContractPublication,
        source_manifest_canonical_bytes: bytes,
        source_manifest_id: str,
        candidate_records: tuple[Mapping[str, Any], ...],
        rights_records: tuple[Mapping[str, Any], ...],
        legal_terms: tuple[Mapping[str, Any], ...],
        rights_status_events: tuple[Mapping[str, Any], ...],
        upstream_snapshot: UpstreamReadOnlySnapshot,
        checkpoint_authority_envelope: bytes,
        recapture: object,
        token: object,
    ) -> None:
        if token is not _VIEW_TOKEN:
            raise TypeError("SealedEvidenceView requires authenticated checkpoint capability")
        if not callable(getattr(recapture, "capture", None)):
            raise TypeError("snapshot recapture capability required")
        object.__setattr__(self, "publication", publication)
        object.__setattr__(self, "source_manifest_canonical_bytes", source_manifest_canonical_bytes)
        object.__setattr__(self, "source_manifest_id", source_manifest_id)
        object.__setattr__(self, "candidate_records", candidate_records)
        object.__setattr__(self, "rights_records", rights_records)
        object.__setattr__(self, "legal_terms", legal_terms)
        object.__setattr__(self, "rights_status_events", rights_status_events)
        object.__setattr__(self, "upstream_snapshot", upstream_snapshot)
        object.__setattr__(
            self, "checkpoint_authority_envelope", bytes(checkpoint_authority_envelope)
        )
        object.__setattr__(self, "_recapture", recapture)

    @classmethod
    def from_authorized_records(
        cls,
        *,
        publication: SimulationContractPublication,
        source_manifest_canonical_bytes: bytes,
        source_manifest_id: str,
        candidate_records: Sequence[Mapping[str, Any]],
        rights_records: Sequence[Mapping[str, Any]],
        legal_terms: Sequence[Mapping[str, Any]],
        rights_status_events: Sequence[Mapping[str, Any]],
        upstream_snapshot: UpstreamReadOnlySnapshot,
        checkpoint_authority_envelope: bytes,
        recapture_snapshots: Sequence[UpstreamReadOnlySnapshot] | None = None,
    ) -> "SealedEvidenceView":
        if not isinstance(publication, SimulationContractPublication):
            raise TypeError("authenticated SimulationContractPublication required")
        parsed = parse_raw_json(source_manifest_canonical_bytes)
        if not isinstance(parsed, dict) or canonicalize(parsed) != source_manifest_canonical_bytes:
            _reject("source_manifest_not_canonical")
        manifest_id = _hash(source_manifest_id, "source_manifest_identity_invalid")
        if parsed.get("manifest_id") != manifest_id:
            _reject("source_manifest_identity_mismatch")
        if not isinstance(upstream_snapshot, UpstreamReadOnlySnapshot):
            raise TypeError("UpstreamReadOnlySnapshot required")
        frozen_candidates = tuple(_freeze(dict(item)) for item in candidate_records)
        identifiers = [
            str(item.get("candidate", {}).get("candidate_id", ""))
            for item in frozen_candidates
        ]
        if len(identifiers) != len(set(identifiers)) or any(not item for item in identifiers):
            _reject("candidate_record_inventory_invalid")
        frozen_rights = tuple(_freeze(dict(item)) for item in rights_records)
        frozen_legal = tuple(_freeze(dict(item)) for item in legal_terms)
        frozen_status = tuple(_freeze(dict(item)) for item in rights_status_events)
        try:
            verify_authority_envelope(
                checkpoint_authority_envelope,
                object_class="simulation_checkpoint",
                expected_body=checkpoint_authority_body(
                    source_manifest_id=manifest_id,
                    candidate_records=frozen_candidates,
                    rights_records=frozen_rights,
                    legal_terms=frozen_legal,
                    rights_status_events=frozen_status,
                    upstream_snapshot_sha256=upstream_snapshot.aggregate_sha256,
                ),
            )
        except SimulationCapabilityRejection as error:
            raise SimulationInputRejection("checkpoint_authority_invalid") from error
        runtime_candidates = tuple(
            MappingProxyType(
                {
                    **dict(item),
                    "checkpoint_record_sha256": sha256_hex(
                        canonicalize(_plain(item))
                    ),
                    "checkpoint_record_canonical_bytes": canonicalize(
                        _plain(item)
                    ),
                }
            )
            for item in frozen_candidates
        )
        recapture: object
        if recapture_snapshots is None:
            recapture = _StaticSnapshotRecapture(upstream_snapshot)
        else:
            recapture = _SequenceSnapshotRecapture(tuple(recapture_snapshots))
        return cls(
            publication=publication,
            source_manifest_canonical_bytes=bytes(source_manifest_canonical_bytes),
            source_manifest_id=manifest_id,
            candidate_records=runtime_candidates,
            rights_records=frozen_rights,
            legal_terms=frozen_legal,
            rights_status_events=frozen_status,
            upstream_snapshot=upstream_snapshot,
            checkpoint_authority_envelope=checkpoint_authority_envelope,
            recapture=recapture,
            token=_VIEW_TOKEN,
        )

    @classmethod
    def from_checkpoint(
        cls,
        *,
        publication: SimulationContractPublication,
        database_path: Path | str,
        source_manifest_id: str,
        checkpoint_authority_envelope: bytes,
        store_roots: Mapping[str, Path | str] = MappingProxyType({}),
    ) -> "SealedEvidenceView":
        """Authenticate and detach one exact checkpointed Phase 7/8 projection."""

        if not isinstance(publication, SimulationContractPublication):
            raise TypeError("authenticated SimulationContractPublication required")
        path = Path(database_path).resolve(strict=True)
        if not path.is_file() or path.is_symlink() or _is_junction(path):
            _reject("checkpoint_database_unavailable")
        for suffix in ("-wal", "-shm"):
            if Path(str(path) + suffix).exists():
                _reject("upstream_database_not_checkpointed")
        manifest_id = _hash(source_manifest_id, "source_manifest_identity_invalid")
        table_names = (
            "sealed_evidence_manifests",
            *_CHECKPOINT_RECORD_TABLES.values(),
        )
        resolved_stores = MappingProxyType(
            {
                str(label): Path(root).resolve(strict=True)
                for label, root in sorted(store_roots.items())
            }
        )
        recapture = _CheckpointSnapshotRecapture(
            database_path=path,
            table_names=tuple(table_names),
            store_roots=resolved_stores,
        )
        pre = recapture.capture()
        uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True)
        try:
            connection.execute("PRAGMA query_only = ON")
            known = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            }
            if not set(table_names) <= known:
                _reject("checkpoint_table_inventory_incomplete")
            row = connection.execute(
                "SELECT canonical_manifest FROM sealed_evidence_manifests WHERE manifest_id=?",
                (manifest_id,),
            ).fetchone()
            if row is None:
                _reject("source_manifest_unavailable")
            manifest_raw = bytes(row[0])
            parsed = parse_raw_json(manifest_raw)
            if (
                not isinstance(parsed, dict)
                or canonicalize(parsed) != manifest_raw
                or parsed.get("schema_version")
                != "skeleton.phase09.sealed-evidence-checkpoint.v1"
                or parsed.get("manifest_id") != manifest_id
                or _checkpoint_manifest_identity(parsed) != manifest_id
                or parsed.get("phase07_bundle_projection_sha256")
                != PHASE07_BUNDLE_PROJECTION_SHA256
                or parsed.get("phase08_bundle_projection_sha256")
                != PHASE08_BUNDLE_PROJECTION_SHA256
                or parsed.get("phase08_fixture_index_projection_sha256")
                != PHASE08_FIXTURE_INDEX_PROJECTION_SHA256
            ):
                _reject("checkpoint_manifest_authentication_failed")
            inventories = parsed.get("record_inventories")
            if not isinstance(inventories, dict) or set(inventories) != set(
                _CHECKPOINT_RECORD_TABLES
            ):
                _reject("checkpoint_record_inventory_invalid")
            materialized: dict[str, tuple[Mapping[str, Any], ...]] = {}
            for label, table in _CHECKPOINT_RECORD_TABLES.items():
                expected = inventories.get(label)
                if (
                    not isinstance(expected, list)
                    or expected != sorted(expected)
                    or len(expected) != len(set(expected))
                ):
                    _reject("checkpoint_record_inventory_invalid")
                observed_rows = connection.execute(
                    f'SELECT record_sha256, canonical_record FROM "{table}" ORDER BY record_sha256'
                ).fetchall()
                observed_ids = [str(item[0]) for item in observed_rows]
                if observed_ids != expected:
                    _reject("checkpoint_record_inventory_mismatch")
                materialized[label] = tuple(
                    _canonical_checkpoint_record(bytes(raw), str(digest))
                    for digest, raw in observed_rows
                )
        finally:
            connection.close()
        post = recapture.capture()
        pre.assert_equal(post)
        try:
            verify_authority_envelope(
                checkpoint_authority_envelope,
                object_class="simulation_checkpoint",
                expected_body=checkpoint_authority_body(
                    source_manifest_id=manifest_id,
                    candidate_records=materialized["candidate_records"],
                    rights_records=materialized["rights_records"],
                    legal_terms=materialized["legal_terms"],
                    rights_status_events=materialized["rights_status_events"],
                    upstream_snapshot_sha256=pre.aggregate_sha256,
                ),
            )
        except SimulationCapabilityRejection as error:
            raise SimulationInputRejection("checkpoint_authority_invalid") from error
        candidates = tuple(
            MappingProxyType(
                {
                    **dict(record),
                    "checkpoint_record_sha256": sha256_hex(
                        canonicalize(_plain(record))
                    ),
                    "checkpoint_record_canonical_bytes": canonicalize(
                        _plain(record)
                    ),
                    "source_manifest_id": manifest_id,
                    "raw_authenticated": True,
                    "lineage_closed": True,
                    "phase08_authenticated": True,
                }
            )
            for record in materialized["candidate_records"]
        )
        if any(
            "source_manifest_id" in record
            or "raw_authenticated" in record
            or "lineage_closed" in record
            or "phase08_authenticated" in record
            for record in materialized["candidate_records"]
        ):
            _reject("checkpoint_candidate_claim_forbidden")
        identifiers = [
            str(item.get("candidate", {}).get("candidate_id", ""))
            for item in candidates
        ]
        if len(identifiers) != len(set(identifiers)) or any(not item for item in identifiers):
            _reject("candidate_record_inventory_invalid")
        return cls(
            publication=publication,
            source_manifest_canonical_bytes=manifest_raw,
            source_manifest_id=manifest_id,
            candidate_records=candidates,
            rights_records=materialized["rights_records"],
            legal_terms=materialized["legal_terms"],
            rights_status_events=materialized["rights_status_events"],
            upstream_snapshot=pre,
            checkpoint_authority_envelope=checkpoint_authority_envelope,
            recapture=recapture,
            token=_VIEW_TOKEN,
        )

    def recapture_upstream_snapshot(self) -> UpstreamReadOnlySnapshot:
        observed = self._recapture.capture()  # type: ignore[attr-defined]
        if not isinstance(observed, UpstreamReadOnlySnapshot):
            _reject("upstream_snapshot_required")
        return observed


@dataclass(frozen=True, slots=True)
class ResolvedRightsProjection:
    decision_id: str
    request_id: str
    rights_record_id: str
    legal_terms_id: str
    disposition: str
    reason_code: str


class ReadOnlyRightsResolver:
    """Pure fold over frozen rights rows; intentionally has no evaluator API."""

    __slots__ = ("_artifact_rights", "_rights", "_legal", "_status")

    def __init__(self, view: SealedEvidenceView) -> None:
        if not isinstance(view, SealedEvidenceView):
            raise TypeError("SealedEvidenceView required")
        self._artifact_rights = MappingProxyType(
            {
                str(item["candidate"]["candidate_id"]): item.get(
                    "artifact_rights_record_id"
                )
                for item in view.candidate_records
            }
        )
        self._rights = MappingProxyType(
            {str(item["rights_record_id"]): item for item in view.rights_records}
        )
        self._legal = MappingProxyType(
            {str(item["legal_terms_id"]): item for item in view.legal_terms}
        )
        self._status = tuple(view.rights_status_events)

    def project(
        self,
        candidate: Mapping[str, Any],
        request: Mapping[str, Any],
    ) -> ResolvedRightsProjection:
        candidate_id = _hash(candidate.get("candidate_id"), "candidate_identity_invalid")
        request_id = _hash(request.get("request_id"), "evaluation_request_identity_invalid")
        bound_id = self._artifact_rights.get(candidate_id)
        if request.get("source_rights_record_id") != candidate.get(
            "source_rights_record_id"
        ):
            _reject("evaluation_request_candidate_mismatch")
        if bound_id is None:
            return self._decision(request_id, candidate_id, None, "rights_record_missing")
        if bound_id != candidate.get("source_rights_record_id"):
            _reject("candidate_rights_binding_mismatch")
        record = self._rights.get(str(bound_id))
        if record is None:
            return self._decision(request_id, candidate_id, None, "rights_record_missing")
        if record.get("version") != request.get("rights_record_version"):
            _reject("rights_record_version_invalid")
        legal_id = record.get("legal_terms_id")
        if legal_id != request.get("source_legal_terms_id"):
            _reject("legal_terms_identity_mismatch")
        legal = self._legal.get(str(legal_id))
        if legal is None:
            return self._decision(request_id, candidate_id, record, "legal_terms_unavailable")
        if legal.get("version") != request.get("legal_terms_version"):
            _reject("legal_terms_version_invalid")
        if rights_policy_digest(record) != request.get("policy_digest"):
            _reject("policy_digest_mismatch")

        at = _time(request.get("evaluation_at"), "evaluation_time_invalid")
        status = str(record.get("status", "unknown"))
        visible_events = sorted(
            (
                event
                for event in self._status
                if event.get("rights_record_id") == bound_id
                and _time(event.get("available_at"), "rights_status_event_invalid") <= at
            ),
            key=lambda item: (str(item["available_at"]), str(item.get("status_event_id", ""))),
        )
        for event in visible_events:
            status = str(event.get("status", "unknown"))
        if status != "active":
            reason = {
                "expired": "rights_expired",
                "revoked": "rights_revoked",
                "terminated": "rights_terminated",
                "superseded": "rights_superseded",
                "unknown": "rights_unknown",
            }.get(status, "rights_unknown")
            return self._decision(request_id, candidate_id, record, reason)
        if at < _time(record.get("effective_from"), "rights_record_time_invalid"):
            return self._decision(request_id, candidate_id, record, "rights_not_yet_effective")
        effective_to = record.get("effective_to")
        if effective_to is not None and at >= _time(effective_to, "rights_record_time_invalid"):
            return self._decision(request_id, candidate_id, record, "rights_expired")
        if (
            legal.get("status") != "active"
            or legal.get("applicable") is not True
            or legal.get("resolved") is not True
            or at < _time(legal.get("effective_from"), "legal_terms_time_invalid")
            or (
                legal.get("effective_to") is not None
                and at >= _time(legal.get("effective_to"), "legal_terms_time_invalid")
            )
        ):
            return self._decision(request_id, candidate_id, record, "legal_terms_unavailable")
        if request.get("boundary") != "evaluation" or not dict(record.get("boundaries", {})).get("evaluation", False):
            return self._decision(request_id, candidate_id, record, "rights_incompatible")
        for field in _REQUEST_POLICY_FIELDS:
            record_field = {
                "purpose": "purposes",
                "territory": "territories",
                "acquisition_method": "acquisition_methods",
            }.get(field, field)
            allowed = record.get(record_field)
            if not isinstance(allowed, tuple) or request.get(field) not in allowed:
                return self._decision(request_id, candidate_id, record, "rights_incompatible")
        destinations = record.get("processing_destinations")
        pair = (request.get("processing_boundary"), request.get("destination"))
        if not isinstance(destinations, tuple) or pair not in destinations:
            reason = (
                "external_transmission_not_authorized"
                if "external" in str(pair[0]) or "external" in str(pair[1])
                else "rights_incompatible"
            )
            return self._decision(request_id, candidate_id, record, reason)
        if request.get("acquisition_method") in {"public_viewable", "undocumented_endpoint"} and legal.get("automation_grant") != "exact_recorded_automation":
            return self._decision(request_id, candidate_id, record, "acquisition_not_authorized")
        return self._decision(request_id, candidate_id, record, "terms_and_rights_match", permit=True)

    @staticmethod
    def _decision(
        request_id: str,
        candidate_id: str,
        record: Mapping[str, Any] | None,
        reason: str,
        *,
        permit: bool = False,
    ) -> ResolvedRightsProjection:
        rights_id = str(record.get("rights_record_id", _HASH_ZERO)) if record else _HASH_ZERO
        legal_id = str(record.get("legal_terms_id", _HASH_ZERO)) if record else _HASH_ZERO
        disposition = "permit" if permit else "deny"
        body = {
            "candidate_id": candidate_id,
            "disposition": disposition,
            "legal_terms_id": legal_id,
            "reason_code": reason,
            "request_id": request_id,
            "rights_record_id": rights_id,
            "version": RIGHTS_PROJECTION_VERSION,
        }
        return ResolvedRightsProjection(
            decision_id=_framed_digest(_RIGHTS_DECISION_DOMAIN, canonicalize(body)),
            request_id=request_id,
            rights_record_id=rights_id,
            legal_terms_id=legal_id,
            disposition=disposition,
            reason_code=reason,
        )


@dataclass(frozen=True, slots=True)
class ResolvedSimulationEvent:
    artifact_id: str
    manifest_id: str
    candidate_id: str
    event_id: str
    available_at: str
    effective_at: str
    explicit_sequence: int
    event_class: str
    family: str
    payload_sha256: str
    admission_decision_id: str
    canonical_bytes: bytes
    source_record_canonical_bytes: bytes = b""
    checkpoint_authority_envelope: bytes = b""


def resolved_event_authority_body(event: ResolvedSimulationEvent) -> Mapping[str, object]:
    """Return the complete, canonical event identity used at every dispatch boundary."""

    return {
        "admission_decision_id": event.admission_decision_id,
        "artifact_id": event.artifact_id,
        "available_at": event.available_at,
        "candidate_id": event.candidate_id,
        "canonical_sha256": sha256_hex(event.canonical_bytes),
        "effective_at": event.effective_at,
        "event_class": event.event_class,
        "event_id": event.event_id,
        "explicit_sequence": event.explicit_sequence,
        "family": event.family,
        "manifest_id": event.manifest_id,
        "payload_sha256": event.payload_sha256,
        "source_record_sha256": sha256_hex(event.source_record_canonical_bytes),
    }


@dataclass(frozen=True, slots=True)
class RightsExclusion:
    artifact_id: str
    candidate_id: str
    request_id: str
    rights_record_id: str
    legal_terms_id: str
    reason_code: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ResolvedSimulationInputs:
    artifact_id: str
    manifest_id: str
    resolution_status: str
    candidate_inputs: tuple[str, ...]
    admitted_inputs: tuple[str, ...]
    rights_excluded_inputs: tuple[str, ...]
    events: tuple[ResolvedSimulationEvent, ...]
    exclusions: tuple[RightsExclusion, ...]
    all_excluded: AllInputsRightsExcluded | None
    evaluation_at: str
    counter_algorithm: str
    seed: str
    engine_version: str
    ordering_policy_version: str
    model_profile_ids: tuple[str, ...]
    upstream_pre_sha256: str
    upstream_post_sha256: str
    canonical_bytes: bytes
    checkpoint_authority_envelope: bytes = b""
    resolution_capability_sha256: str = ""

    def _capability_body(self) -> Mapping[str, object]:
        return {
            "admitted_inputs": list(self.admitted_inputs),
            "all_excluded_sha256": (
                sha256_hex(
                    canonicalize(
                        {
                            "admitted_inputs": [],
                            "calibration_eligible": False,
                            "candidate_inputs": list(self.all_excluded.candidate_inputs),
                            "rights_excluded_inputs": list(
                                self.all_excluded.rights_excluded_inputs
                            ),
                            "successful": False,
                            "terminal_code": self.all_excluded.terminal_code,
                        }
                    )
                )
                if self.all_excluded is not None
                else None
            ),
            "artifact_id": self.artifact_id,
            "candidate_inputs": list(self.candidate_inputs),
            "canonical_sha256": sha256_hex(self.canonical_bytes),
            "counter_algorithm": self.counter_algorithm,
            "engine_version": self.engine_version,
            "evaluation_at": self.evaluation_at,
            "events": [resolved_event_authority_body(event) for event in self.events],
            "exclusion_sha256s": [
                sha256_hex(exclusion.canonical_bytes) for exclusion in self.exclusions
            ],
            "manifest_id": self.manifest_id,
            "model_profile_ids": list(self.model_profile_ids),
            "ordering_policy_version": self.ordering_policy_version,
            "resolution_status": self.resolution_status,
            "rights_excluded_inputs": list(self.rights_excluded_inputs),
            "seed": self.seed,
            "upstream_post_sha256": self.upstream_post_sha256,
            "upstream_pre_sha256": self.upstream_pre_sha256,
        }

    def verify_capability(self) -> None:
        try:
            grant = verify_authority_envelope(
                self.checkpoint_authority_envelope,
                object_class="simulation_checkpoint",
            )
        except SimulationCapabilityRejection as error:
            raise SimulationInputRejection("resolution_capability_invalid") from error
        if grant.get("source_manifest_id") is None:
            _reject("resolution_capability_invalid")
        inventories = grant.get("record_inventories")
        if not isinstance(inventories, Mapping):
            _reject("resolution_capability_invalid")
        candidate_hashes = inventories.get("candidate_records")
        if not isinstance(candidate_hashes, list):
            _reject("resolution_capability_invalid")
        if (
            tuple(event.candidate_id for event in self.events) != self.admitted_inputs
            or tuple(exclusion.candidate_id for exclusion in self.exclusions)
            != self.rights_excluded_inputs
            or set(self.candidate_inputs)
            != set(self.admitted_inputs) | set(self.rights_excluded_inputs)
            or set(self.admitted_inputs) & set(self.rights_excluded_inputs)
        ):
            _reject("resolution_capability_invalid")
        for event in self.events:
            raw = event.source_record_canonical_bytes
            if (
                not raw
                or sha256_hex(raw) not in candidate_hashes
                or event.checkpoint_authority_envelope
                != self.checkpoint_authority_envelope
            ):
                _reject("resolved_event_capability_invalid")
            parsed = parse_raw_json(raw)
            if not isinstance(parsed, dict) or canonicalize(parsed) != raw:
                _reject("resolved_event_capability_invalid")
            candidate = parsed.get("candidate")
            if not isinstance(candidate, dict):
                _reject("resolved_event_capability_invalid")
            if (
                candidate.get("candidate_id") != event.candidate_id
                or candidate.get("family") != event.family
                or candidate.get("evidence_sha256") != event.payload_sha256
                or candidate.get("available_at") != event.available_at
                or candidate.get("effective_at") != event.effective_at
                or candidate.get("explicit_sequence") != event.explicit_sequence
                or candidate.get("event_class") != event.event_class
                or parsed.get("source_event_id") != event.event_id
            ):
                _reject("resolved_event_capability_invalid")
            expected_event = {
                "admission_decision_id": event.admission_decision_id,
                "artifact_id": _HASH_ZERO,
                "artifact_type": "simulation_event",
                "available_at": event.available_at,
                "candidate_id": event.candidate_id,
                "effective_at": event.effective_at,
                "event_class": event.event_class,
                "event_id": event.event_id,
                "explicit_sequence": event.explicit_sequence,
                "family": event.family,
                "manifest_id": event.manifest_id,
                "payload_sha256": event.payload_sha256,
                "schema_version": "skeleton.simulation-artifact.v1",
            }
            expected_event["artifact_id"] = compute_document_identity(
                ARTIFACT_SCHEMA_ID, expected_event
            )
            if (
                event.artifact_id != expected_event["artifact_id"]
                or event.canonical_bytes != canonicalize(expected_event)
            ):
                _reject("resolved_event_capability_invalid")
        for exclusion in self.exclusions:
            expected_exclusion = {
                "artifact_id": _HASH_ZERO,
                "artifact_type": "simulation_rights_exclusion",
                "candidate_id": exclusion.candidate_id,
                "legal_terms_id": exclusion.legal_terms_id,
                "manifest_id": self.manifest_id,
                "reason_code": exclusion.reason_code,
                "request_id": exclusion.request_id,
                "rights_record_id": exclusion.rights_record_id,
                "schema_version": "skeleton.simulation-artifact.v1",
            }
            expected_exclusion["artifact_id"] = compute_document_identity(
                ARTIFACT_SCHEMA_ID, expected_exclusion
            )
            if (
                exclusion.artifact_id != expected_exclusion["artifact_id"]
                or exclusion.canonical_bytes != canonicalize(expected_exclusion)
            ):
                _reject("resolution_capability_invalid")
        expected_resolution = {
            "admitted_inputs": list(self.admitted_inputs),
            "artifact_id": _HASH_ZERO,
            "artifact_type": "simulation_input_resolution",
            "candidate_inputs": list(self.candidate_inputs),
            "manifest_id": self.manifest_id,
            "resolution_status": self.resolution_status,
            "rights_excluded_inputs": list(self.rights_excluded_inputs),
            "schema_version": "skeleton.simulation-artifact.v1",
        }
        expected_resolution["artifact_id"] = compute_document_identity(
            ARTIFACT_SCHEMA_ID, expected_resolution
        )
        if (
            self.artifact_id != expected_resolution["artifact_id"]
            or self.canonical_bytes != canonicalize(expected_resolution)
        ):
            _reject("resolution_capability_invalid")
        expected = _framed_digest(
            "SKELETON_PHASE09_RESOLUTION_CAPABILITY_V2",
            canonicalize(self._capability_body()),
        )
        if self.resolution_capability_sha256 != expected:
            _reject("resolution_capability_invalid")


class SimulationInputResolver:
    """Resolve an authenticated manifest using only one frozen sealed view."""

    __slots__ = ("_view", "_rights")

    def __init__(self, view: SealedEvidenceView) -> None:
        if not isinstance(view, SealedEvidenceView):
            raise TypeError("SealedEvidenceView required")
        self._view = view
        self._rights = ReadOnlyRightsResolver(view)

    def resolve(self, manifest: SimulationContractValue | Mapping[str, Any]) -> ResolvedSimulationInputs:
        if isinstance(manifest, Mapping):
            submitted = manifest.get("candidate_inputs")
            if submitted is None:
                _reject("simulation_events_null")
            if isinstance(submitted, (list, tuple)) and not submitted:
                _reject("simulation_event_stream_empty")
            _reject("simulation_manifest_required")
        if not isinstance(manifest, SimulationContractValue) or manifest.schema_id != MANIFEST_SCHEMA_ID:
            _reject("simulation_manifest_required")
        value = manifest.value
        submitted = value.get("candidate_inputs")
        if submitted is None:
            _reject("simulation_events_null")
        if not isinstance(submitted, tuple) or not submitted:
            _reject("simulation_event_stream_empty")
        if value.get("source_evidence_manifest_id") != self._view.source_manifest_id:
            _reject("source_manifest_identity_mismatch")
        if value.get("phase07_bundle_projection_sha256") != PHASE07_BUNDLE_PROJECTION_SHA256:
            _reject("phase07_projection_mismatch")
        if value.get("phase08_bundle_projection_sha256") != PHASE08_BUNDLE_PROJECTION_SHA256:
            _reject("phase08_projection_mismatch")
        if value.get("phase08_fixture_index_projection_sha256") != PHASE08_FIXTURE_INDEX_PROJECTION_SHA256:
            _reject("phase08_projection_mismatch")
        request = value.get("evaluation_request")
        if not isinstance(request, Mapping):
            _reject("evaluation_request_invalid")
        self._validate_request(request, submitted)

        pre = self._view.recapture_upstream_snapshot()
        records = {
            str(record["candidate"]["candidate_id"]): record
            for record in self._view.candidate_records
        }
        events: list[ResolvedSimulationEvent] = []
        exclusions: list[RightsExclusion] = []
        candidate_ids = tuple(sorted(str(candidate["candidate_id"]) for candidate in submitted))
        if len(candidate_ids) != len(set(candidate_ids)):
            _reject("resolution_inventory_invalid")
        for candidate in sorted(submitted, key=lambda item: str(item["candidate_id"])):
            candidate_id = str(candidate["candidate_id"])
            record = records.get(candidate_id)
            if record is None:
                _reject("candidate_record_missing")
            if _plain(record.get("candidate")) != _plain(candidate):
                _reject("candidate_identity_mismatch")
            if record.get("source_manifest_id") != self._view.source_manifest_id:
                _reject("candidate_manifest_mismatch")
            if record.get("raw_authenticated") is not True:
                _reject("candidate_raw_unauthenticated")
            if record.get("lineage_closed") is not True:
                _reject("candidate_lineage_unverified")
            if record.get("phase08_authenticated") is not True:
                _reject("candidate_phase08_unauthenticated")
            if record.get("payload_sha256") != candidate.get("evidence_sha256"):
                _reject("candidate_payload_identity_mismatch")
            projection = self._rights.project(candidate, request)
            if projection.disposition == "permit":
                event_value = {
                    "schema_version": "skeleton.simulation-artifact.v1",
                    "artifact_type": "simulation_event",
                    "artifact_id": _HASH_ZERO,
                    "manifest_id": manifest.identity,
                    "candidate_id": candidate_id,
                    "event_id": _hash(record.get("source_event_id"), "candidate_event_identity_invalid"),
                    "available_at": candidate["available_at"],
                    "effective_at": candidate["effective_at"],
                    "explicit_sequence": candidate["explicit_sequence"],
                    "event_class": candidate["event_class"],
                    "family": candidate["family"],
                    "payload_sha256": candidate["evidence_sha256"],
                    "admission_decision_id": projection.decision_id,
                }
                event_value["artifact_id"] = compute_document_identity(ARTIFACT_SCHEMA_ID, event_value)
                raw = canonicalize(event_value)
                events.append(
                    ResolvedSimulationEvent(
                        artifact_id=str(event_value["artifact_id"]),
                        manifest_id=manifest.identity,
                        candidate_id=candidate_id,
                        event_id=str(event_value["event_id"]),
                        available_at=str(event_value["available_at"]),
                        effective_at=str(event_value["effective_at"]),
                        explicit_sequence=int(event_value["explicit_sequence"]),
                        event_class=str(event_value["event_class"]),
                        family=str(event_value["family"]),
                        payload_sha256=str(event_value["payload_sha256"]),
                        admission_decision_id=projection.decision_id,
                        canonical_bytes=raw,
                        source_record_canonical_bytes=bytes(
                            record["checkpoint_record_canonical_bytes"]
                        ),
                        checkpoint_authority_envelope=(
                            self._view.checkpoint_authority_envelope
                        ),
                    )
                )
            else:
                exclusion_value = {
                    "schema_version": "skeleton.simulation-artifact.v1",
                    "artifact_type": "simulation_rights_exclusion",
                    "artifact_id": _HASH_ZERO,
                    "manifest_id": manifest.identity,
                    "candidate_id": candidate_id,
                    "request_id": projection.request_id,
                    "rights_record_id": projection.rights_record_id,
                    "legal_terms_id": projection.legal_terms_id,
                    "reason_code": projection.reason_code,
                }
                exclusion_value["artifact_id"] = compute_document_identity(ARTIFACT_SCHEMA_ID, exclusion_value)
                raw = canonicalize(exclusion_value)
                exclusions.append(
                    RightsExclusion(
                        artifact_id=str(exclusion_value["artifact_id"]),
                        candidate_id=candidate_id,
                        request_id=projection.request_id,
                        rights_record_id=projection.rights_record_id,
                        legal_terms_id=projection.legal_terms_id,
                        reason_code=projection.reason_code,
                        canonical_bytes=raw,
                    )
                )

        admitted = tuple(event.candidate_id for event in events)
        excluded = tuple(item.candidate_id for item in exclusions)
        if set(admitted) & set(excluded) or set(candidate_ids) != set(admitted) | set(excluded):
            _reject("resolution_inventory_overlap")
        status = "all_excluded" if not admitted else "mixed" if excluded else "admitted"
        resolution_value = {
            "schema_version": "skeleton.simulation-artifact.v1",
            "artifact_type": "simulation_input_resolution",
            "artifact_id": _HASH_ZERO,
            "manifest_id": manifest.identity,
            "candidate_inputs": list(candidate_ids),
            "admitted_inputs": list(admitted),
            "rights_excluded_inputs": list(excluded),
            "resolution_status": status,
        }
        resolution_value["artifact_id"] = compute_document_identity(ARTIFACT_SCHEMA_ID, resolution_value)
        resolution_raw = canonicalize(resolution_value)
        all_excluded: AllInputsRightsExcluded | None = None
        if status == "all_excluded":
            abstention_value = {
                "schema_version": "skeleton.simulation-artifact.v1",
                "artifact_type": "simulation_all_inputs_rights_excluded",
                "artifact_id": _HASH_ZERO,
                "manifest_id": manifest.identity,
                "terminal_code": "simulation_all_inputs_rights_excluded",
                "successful": False,
                "calibration_eligible": False,
                "candidate_inputs": list(candidate_ids),
                "admitted_inputs": [],
                "rights_excluded_inputs": list(excluded),
                "events": [],
                "fills": [],
                "costs": [],
                "settlements": [],
                "success_labels": [],
            }
            abstention_value["artifact_id"] = compute_document_identity(ARTIFACT_SCHEMA_ID, abstention_value)
            contract = self._view.publication.validate_contract(
                canonicalize(abstention_value), ARTIFACT_SCHEMA_ID
            )
            all_excluded = AllInputsRightsExcluded.from_contract(contract)
        post = self._view.recapture_upstream_snapshot()
        pre.assert_equal(post)
        resolved_value = ResolvedSimulationInputs(
            artifact_id=str(resolution_value["artifact_id"]),
            manifest_id=manifest.identity,
            resolution_status=status,
            candidate_inputs=candidate_ids,
            admitted_inputs=admitted,
            rights_excluded_inputs=excluded,
            events=tuple(events),
            exclusions=tuple(exclusions),
            all_excluded=all_excluded,
            evaluation_at=str(request["evaluation_at"]),
            counter_algorithm=str(value["counter_algorithm"]),
            seed=str(value["seed"]),
            engine_version=str(value["engine_version"]),
            ordering_policy_version=str(value["ordering_policy_version"]),
            model_profile_ids=tuple(str(item) for item in value["model_profile_ids"]),
            upstream_pre_sha256=pre.aggregate_sha256,
            upstream_post_sha256=post.aggregate_sha256,
            canonical_bytes=resolution_raw,
            checkpoint_authority_envelope=self._view.checkpoint_authority_envelope,
            resolution_capability_sha256="",
        )
        resolved_value = replace(
            resolved_value,
            resolution_capability_sha256=_framed_digest(
                "SKELETON_PHASE09_RESOLUTION_CAPABILITY_V2",
                canonicalize(resolved_value._capability_body()),
            ),
        )
        resolved_value.verify_capability()
        return resolved_value

    @staticmethod
    def _validate_request(request: Mapping[str, Any], submitted: Sequence[Mapping[str, Any]]) -> None:
        if request.get("boundary") != "evaluation" or request.get("operation") != "deterministic_simulation":
            _reject("evaluation_request_invalid")
        if request.get("evaluator_version") != RIGHTS_PROJECTION_VERSION:
            _reject("evaluation_request_version_invalid")
        body = dict(request)
        observed = body.pop("request_id", None)
        expected = _framed_digest(_REQUEST_DOMAIN, canonicalize(body))
        if observed != expected:
            _reject("evaluation_request_identity_invalid")
        inventory = tuple(
            sorted(
                (
                    str(item.get("candidate_id")),
                    _hash(item.get("subject_sha256"), "candidate_subject_invalid"),
                    _hash(item.get("evidence_sha256"), "candidate_evidence_invalid"),
                    _hash(
                        item.get("source_rights_record_id"),
                        "candidate_rights_identity_invalid",
                    ),
                )
                for item in submitted
            )
        )
        rights_ids = {item[3] for item in inventory}
        if len(rights_ids) != 1:
            _reject("evaluation_request_policy_inventory_ambiguous")
        if len(inventory) == 1:
            expected_subject = inventory[0][1]
            expected_evidence = inventory[0][2]
        else:
            expected_subject = _framed_digest(
                _AGGREGATE_SUBJECT_DOMAIN,
                canonicalize(
                    [
                        {"candidate_id": item[0], "subject_sha256": item[1]}
                        for item in inventory
                    ]
                ),
            )
            expected_evidence = _framed_digest(
                _AGGREGATE_EVIDENCE_DOMAIN,
                canonicalize(
                    [
                        {"candidate_id": item[0], "evidence_sha256": item[2]}
                        for item in inventory
                    ]
                ),
            )
        if (
            request.get("subject_sha256") != expected_subject
            or request.get("evidence_sha256") != expected_evidence
            or request.get("source_rights_record_id") != next(iter(rights_ids))
        ):
            _reject("evaluation_request_candidate_mismatch")
        if request.get("requested_at") != request.get("evaluation_at"):
            _reject("evaluation_request_time_mismatch")
        _time(request.get("evaluation_at"), "evaluation_time_invalid")
        nonce = request.get("nonce")
        if type(nonce) is not int or nonce < 0:
            _reject("evaluation_request_nonce_invalid")


__all__ = [
    "RIGHTS_PROJECTION_VERSION",
    "ReadOnlyRightsResolver",
    "ResolvedRightsProjection",
    "ResolvedSimulationEvent",
    "ResolvedSimulationInputs",
    "RightsExclusion",
    "SealedEvidenceView",
    "SimulationInputRejection",
    "SimulationInputResolver",
    "UpstreamReadOnlySnapshot",
    "resolved_event_authority_body",
    "rights_policy_digest",
]
