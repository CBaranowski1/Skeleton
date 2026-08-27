"""Detached Phase 10 retrieval boundary for Phase 11 agent organs.

The adapter deliberately accepts values, not retrieval machinery.  It binds the
fixed Phase 10 release anchor, re-authenticates each canonical input, and copies
only whole included envelopes into an immutable packet.  No store, query
predicate, persistence callback, or caller-authored authority projection crosses
this module's public boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .agent_contracts import (
    AgentContractPublication,
    PHASE10_REGISTRY_PAIR_ROOT,
    PHASE10_RELEASE_MANIFEST_SHA256,
    PHASE10_RELEASE_SOURCE_COMMIT,
    PHASE10_RELEASE_SOURCE_ROOT,
)
from .canonical import canonicalize, parse_raw_json, sha256_hex
from .memory_contracts import MemoryContractPublication, compute_document_identity
from .memory_retrieval import (
    CandidateSnapshot,
    IntegritySnapshot,
    RetrievalQuery,
    RetrievalResult,
    RightsSnapshot,
    build_retrieval_query,
    utc_epoch_microseconds,
    verify_retrieval_result,
)
from .memory_safety import scan_memory_document


_CONTRACTS_ROOT = Path(__file__).resolve().parents[3] / "contracts" / "v1"
_ENVELOPE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-envelope.schema.json"
_ZERO = "0" * 64
_QUALITY_ORDER = {
    "verified": 0,
    "corrected": 1,
    "provider_reported": 2,
    "backfilled": 3,
    "synthetic": 4,
    "simulated": 5,
    "contaminated": 6,
    "legacy": 7,
    "unknown": 8,
}


class AgentMemoryRejection(ValueError):
    """Closed rejection that never includes submitted memory material."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise AgentMemoryRejection(code)


def _framed_digest(domain: str, payload: bytes) -> str:
    name = domain.encode("ascii", errors="strict")
    return sha256(
        len(name).to_bytes(8, "big")
        + name
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _object(raw: bytes, code: str) -> Mapping[str, Any]:
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise AgentMemoryRejection(code) from error
    if not isinstance(value, Mapping) or canonicalize(value) != raw:
        _reject(code)
    return value


@dataclass(frozen=True, slots=True)
class Phase10MemoryAnchor:
    release_manifest_sha256: str
    source_commit: str
    source_root_sha256: str
    registry_pair_root_sha256: str


@dataclass(frozen=True, slots=True)
class SealedMemoryRecord:
    memory_id: str
    rank_ordinal: int
    contradiction_set_id: str
    canonical_sha256: str
    canonical_byte_count: int
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class SealedMemoryLedgerItem:
    memory_id: str
    disposition: str
    exclusion_reason: str | None
    rank_ordinal: int | None
    canonical_byte_count: int | None


@dataclass(frozen=True, slots=True)
class SealedMemoryPacket:
    packet_id: str
    anchor: Phase10MemoryAnchor
    retrieval_result_id: str
    retrieval_result_root: str
    query_id: str
    query_root: str
    candidate_snapshot_id: str
    candidate_snapshot_root: str
    integrity_snapshot_id: str
    integrity_snapshot_root: str
    rights_snapshot_id: str
    rights_snapshot_root: str
    operating_mode: str
    records: tuple[SealedMemoryRecord, ...]
    ledger_items: tuple[SealedMemoryLedgerItem, ...]
    candidate_count: int
    included_count: int
    excluded_count: int
    memory_root: str
    ledger_root: str
    canonical_sha256: str
    canonical_bytes: bytes


def _validate_query(query: RetrievalQuery) -> Mapping[str, Any]:
    if not isinstance(query, RetrievalQuery):
        _reject("agent_memory_query_invalid")
    value = _object(query.canonical_bytes, "agent_memory_query_invalid")
    if (
        sha256_hex(query.canonical_bytes) != query.canonical_sha256
        or value.get("query_id") != query.query_id
        or value.get("candidate_snapshot_id") != query.candidate_snapshot_id
        or value.get("integrity_snapshot_id") != query.integrity_snapshot_id
    ):
        _reject("agent_memory_query_invalid")
    try:
        rebuilt = build_retrieval_query(
            **{
                "candidate_snapshot_id": value["candidate_snapshot_id"],
                "decision_at": value["decision_at"],
                "known_at": value["known_at"],
                "world_at": value["world_at"],
                "namespace": value["namespace"],
                "lobe_id": value["lobe_id"],
                "project_id": value["project_id"],
                "purpose": value["purpose"],
                "scope": value["scope"],
                "operating_mode": value["operating_mode"],
                "rights_boundary": value["rights_boundary"],
                "minimum_quality": value["minimum_quality"],
                "accepted_provenance_classes": tuple(value["accepted_provenance_classes"]),
                "model_stage": value["model_stage"],
                "paper_eligible": value["paper_eligible"],
                "item_budget": value["item_budget"],
                "byte_budget": value["byte_budget"],
                "rank_profile_id": value["rank_profile_id"],
                "integrity_snapshot_id": value["integrity_snapshot_id"],
            }
        )
    except Exception as error:
        raise AgentMemoryRejection("agent_memory_query_invalid") from error
    if rebuilt != query:
        _reject("agent_memory_query_invalid")
    return value


def _candidate_value(candidate: object) -> Mapping[str, Any]:
    raw = getattr(candidate, "canonical_bytes", None)
    if not isinstance(raw, bytes):
        _reject("agent_memory_candidate_invalid")
    value = _object(raw, "agent_memory_candidate_invalid")
    try:
        scope = value["scope"]
        scope_kind = str(scope["scope_kind"])
        scope_id = None if scope_kind == "none" else str(scope["scope_id"])
        effective_to = value["effective_to"]
        comparisons = (
            (candidate.memory_id, value["memory_id"]),
            (candidate.memory_kind, value["memory_kind"]),
            (candidate.namespace, value["namespace"]),
            (candidate.lobe_id, value["lobe_id"]),
            (candidate.project_id, value["project_id"]),
            (candidate.scope_kind, scope_kind),
            (candidate.scope_id, scope_id),
            (candidate.evidence_root_ids, tuple(value["evidence_root_ids"])),
            (candidate.lineage_root_ids, tuple(value["lineage_root_ids"])),
            (candidate.rights_decision_id, value["ingest_rights_decision_id"]),
            (candidate.quality_class, value["quality_class"]),
            (candidate.provenance_class, value["provenance_class"]),
            (candidate.quarantine_state, value["initial_quarantine_state"]),
            (candidate.effective_from_us, utc_epoch_microseconds(value["effective_from"])),
            (
                candidate.effective_to_us,
                None if effective_to == "none" else utc_epoch_microseconds(effective_to),
            ),
            (candidate.available_at_us, utc_epoch_microseconds(value["available_at"])),
            (candidate.recorded_at_us, utc_epoch_microseconds(value["recorded_at"])),
            (candidate.operating_mode, value["operating_mode"]),
            (candidate.model_stage, value["model_stage"]),
            (candidate.correction_of, value["correction_of"]),
            (candidate.canonical_sha256, sha256_hex(raw)),
            (candidate.canonical_byte_count, len(raw)),
        )
        payload = value.get("payload")
        contradiction = "none"
        if value["memory_kind"] == "semantic" and isinstance(payload, Mapping):
            contradiction = str(payload.get("contradiction_set_id", "none"))
            if contradiction == _ZERO:
                contradiction = "none"
        comparisons += ((candidate.contradiction_set_id, contradiction),)
    except (KeyError, TypeError, ValueError) as error:
        raise AgentMemoryRejection("agent_memory_candidate_invalid") from error
    if any(left != right for left, right in comparisons):
        _reject("agent_memory_candidate_invalid")
    if compute_document_identity(_ENVELOPE_SCHEMA_ID, value) != candidate.memory_id:
        _reject("agent_memory_candidate_invalid")
    return value


def _validate_candidate_snapshot(snapshot: CandidateSnapshot) -> dict[str, Mapping[str, Any]]:
    if not isinstance(snapshot, CandidateSnapshot) or snapshot.authenticated is not True:
        _reject("agent_memory_candidate_snapshot_invalid")
    candidates = tuple(snapshot.candidates)
    ids = tuple(candidate.memory_id for candidate in candidates)
    if ids != snapshot.candidate_ids or ids != tuple(sorted(set(ids))):
        _reject("agent_memory_candidate_snapshot_invalid")
    publication = MemoryContractPublication.from_registry(_CONTRACTS_ROOT)
    values: dict[str, Mapping[str, Any]] = {}
    for candidate in candidates:
        value = _candidate_value(candidate)
        try:
            wrapped = publication.validate_contract(candidate.canonical_bytes, _ENVELOPE_SCHEMA_ID)
            scan_memory_document(
                value,
                schema_id=_ENVELOPE_SCHEMA_ID,
                source_event_id=candidate.memory_id,
            )
        except Exception as error:
            raise AgentMemoryRejection("agent_memory_candidate_invalid") from error
        if wrapped.identity != candidate.memory_id or wrapped.canonical_bytes != candidate.canonical_bytes:
            _reject("agent_memory_candidate_invalid")
        values[candidate.memory_id] = value
    expected = canonicalize(
        {
            "schema_version": "skeleton.memory-candidate-snapshot.v1",
            "candidates": [
                {
                    "memory_id": candidate.memory_id,
                    "canonical_sha256": candidate.canonical_sha256,
                    "canonical_byte_count": candidate.canonical_byte_count,
                }
                for candidate in candidates
            ],
        }
    )
    if (
        snapshot.canonical_bytes != expected
        or snapshot.canonical_sha256 != sha256_hex(expected)
        or snapshot.snapshot_id
        != _framed_digest("SKELETON_PHASE10_CANDIDATE_SNAPSHOT_V1", expected)
    ):
        _reject("agent_memory_candidate_snapshot_invalid")
    if any(child not in values or parent not in values for child, parent in snapshot.correction_edges.items()):
        _reject("agent_memory_candidate_snapshot_invalid")
    return values


def _validate_integrity(snapshot: IntegritySnapshot, candidate_ids: tuple[str, ...]) -> None:
    if not isinstance(snapshot, IntegritySnapshot) or snapshot.authenticated is not True:
        _reject("agent_memory_integrity_invalid")
    findings = [
        {"memory_id": identity, "status": snapshot.statuses[identity]}
        for identity in candidate_ids
    ]
    expected = canonicalize(
        {
            "schema_version": "skeleton.memory-integrity-snapshot.v1",
            "complete": snapshot.complete,
            "resolved_evidence_ids": list(snapshot.resolved_evidence_ids),
            "resolved_lineage_ids": list(snapshot.resolved_lineage_ids),
            "findings": findings,
        }
    )
    if (
        snapshot.complete is not True
        or snapshot.candidate_ids != candidate_ids
        or snapshot.canonical_bytes != expected
        or snapshot.canonical_sha256 != sha256_hex(expected)
        or snapshot.snapshot_id
        != _framed_digest("SKELETON_PHASE10_INTEGRITY_SNAPSHOT_V1", expected)
    ):
        _reject("agent_memory_integrity_invalid")


def _validate_rights(snapshot: RightsSnapshot) -> None:
    if not isinstance(snapshot, RightsSnapshot) or snapshot.authenticated is not True:
        _reject("agent_memory_rights_invalid")
    expected = canonicalize(
        {
            "schema_version": "skeleton.memory-rights-snapshot.v1",
            "decisions": [
                {"decision_id": identity, "status": snapshot.decisions[identity]}
                for identity in sorted(snapshot.decisions)
            ],
        }
    )
    if (
        snapshot.canonical_bytes != expected
        or snapshot.canonical_sha256 != sha256_hex(expected)
        or snapshot.snapshot_id
        != _framed_digest("SKELETON_PHASE10_RIGHTS_SNAPSHOT_V1", expected)
    ):
        _reject("agent_memory_rights_invalid")


def _included_is_compatible(
    value: Mapping[str, Any],
    query: RetrievalQuery,
    integrity: IntegritySnapshot,
    rights: RightsSnapshot,
) -> bool:
    scope = value["scope"]
    candidate_id = str(value["memory_id"])
    effective_to = value["effective_to"]
    status = integrity.statuses[candidate_id]
    if (
        value["initial_quarantine_state"] != "clean"
        or status not in {"healthy", "contradiction_member"}
        or value["namespace"] != query.namespace
        or value["lobe_id"] != query.lobe_id
        or value["project_id"] != query.project_id
        or value["operating_mode"] != query.operating_mode
        or value["model_stage"] != query.model_stage
        or value["provenance_class"] not in query.accepted_provenance_classes
        or _QUALITY_ORDER[str(value["quality_class"])] > _QUALITY_ORDER[query.minimum_quality]
        or rights.decisions.get(str(value["ingest_rights_decision_id"])) != "active"
        or utc_epoch_microseconds(str(value["available_at"])) > query.known_at_us
        or utc_epoch_microseconds(str(value["recorded_at"])) > query.known_at_us
        or utc_epoch_microseconds(str(value["effective_from"])) > query.world_at_us
        or (
            effective_to != "none"
            and utc_epoch_microseconds(str(effective_to)) <= query.world_at_us
        )
        or scope["scope_kind"] != query.scope_kind
        or (query.scope_kind != "none" and scope["scope_id"] != query.scope_id)
    ):
        return False
    if query.paper_eligible and (
        value["provenance_class"] != "verified_real"
        or status not in {"healthy", "contradiction_member"}
        or not set(value["evidence_root_ids"]).issubset(integrity.resolved_evidence_ids)
        or not set(value["lineage_root_ids"]).issubset(integrity.resolved_lineage_ids)
    ):
        return False
    return True


class SealedMemoryAdapter:
    """Pure public adapter from authenticated Phase 10 values to detached bytes."""

    __slots__ = ("_anchor",)

    def __init__(self) -> None:
        publication = AgentContractPublication.from_registry(_CONTRACTS_ROOT)
        if (
            publication.phase10_release_manifest_sha256
            != PHASE10_RELEASE_MANIFEST_SHA256
            or publication.phase10_registry_pair_root_sha256
            != PHASE10_REGISTRY_PAIR_ROOT
        ):
            _reject("agent_memory_release_anchor_invalid")
        self._anchor = Phase10MemoryAnchor(
            release_manifest_sha256=PHASE10_RELEASE_MANIFEST_SHA256,
            source_commit=PHASE10_RELEASE_SOURCE_COMMIT,
            source_root_sha256=PHASE10_RELEASE_SOURCE_ROOT,
            registry_pair_root_sha256=PHASE10_REGISTRY_PAIR_ROOT,
        )

    def detach(
        self,
        result: RetrievalResult,
        query: RetrievalQuery,
        candidates: CandidateSnapshot,
        integrity: IntegritySnapshot,
        rights: RightsSnapshot,
    ) -> SealedMemoryPacket:
        try:
            verify_retrieval_result(result)
        except Exception as error:
            raise AgentMemoryRejection("agent_memory_result_invalid") from error
        query_value = _validate_query(query)
        candidate_values = _validate_candidate_snapshot(candidates)
        _validate_integrity(integrity, candidates.candidate_ids)
        _validate_rights(rights)
        ledger_value = _object(result.ledger_bytes, "agent_memory_ledger_invalid")
        if (
            result.query_id != query.query_id
            or result.snapshot_id != candidates.snapshot_id
            or result.integrity_snapshot_id != integrity.snapshot_id
            or query.candidate_snapshot_id != candidates.snapshot_id
            or query.integrity_snapshot_id != integrity.snapshot_id
            or ledger_value.get("query_id") != query.query_id
            or ledger_value.get("query_sha256") != query.canonical_sha256
            or ledger_value.get("candidate_snapshot_id") != candidates.snapshot_id
            or ledger_value.get("candidate_snapshot_sha256") != candidates.canonical_sha256
            or ledger_value.get("integrity_snapshot_id") != integrity.snapshot_id
            or ledger_value.get("integrity_snapshot_sha256") != integrity.canonical_sha256
            or ledger_value.get("rights_snapshot_id") != rights.snapshot_id
            or ledger_value.get("rights_snapshot_sha256") != rights.canonical_sha256
            or result.ledger_sha256 != sha256_hex(result.ledger_bytes)
        ):
            _reject("agent_memory_cross_root_mismatch")

        by_id = {candidate.memory_id: candidate for candidate in candidates.candidates}
        ledger_by_id = {item.memory_id: item for item in result.ledger_items}
        if (
            tuple(ledger_by_id) != candidates.candidate_ids
            or set(result.included_ids) != set(result.ranked_included_ids)
            or any(identity not in by_id for identity in result.ranked_included_ids)
        ):
            _reject("agent_memory_accounting_invalid")
        evaluation_by_id = {item.memory_id: item for item in result.evaluations}
        if tuple(evaluation_by_id) != candidates.candidate_ids:
            _reject("agent_memory_evaluation_invalid")

        records: list[SealedMemoryRecord] = []
        rank_ordinals = {
            identity: ordinal
            for ordinal, identity in enumerate(result.ranked_included_ids, start=1)
        }
        for identity in result.ranked_included_ids:
            candidate = by_id[identity]
            item = ledger_by_id[identity]
            evaluation = evaluation_by_id[identity]
            if (
                item.disposition != "included"
                or item.exclusion_reason is not None
                or item.rank_factors is None
                or evaluation.terminal_reason is not None
                or evaluation.rank_factors != item.rank_factors
                or not _included_is_compatible(
                    candidate_values[identity], query, integrity, rights
                )
            ):
                _reject("agent_memory_included_candidate_invalid")
            records.append(
                SealedMemoryRecord(
                    memory_id=identity,
                    rank_ordinal=rank_ordinals[identity],
                    contradiction_set_id=candidate.contradiction_set_id,
                    canonical_sha256=candidate.canonical_sha256,
                    canonical_byte_count=candidate.canonical_byte_count,
                    canonical_bytes=bytes(candidate.canonical_bytes),
                )
            )

        included = frozenset(result.included_ids)
        for child, parent in candidates.correction_edges.items():
            if child in included and parent in included:
                _reject("agent_memory_correction_invalid")
        contradiction_groups: dict[str, set[str]] = {}
        for candidate in candidates.candidates:
            if candidate.contradiction_set_id != "none":
                contradiction_groups.setdefault(candidate.contradiction_set_id, set()).add(
                    candidate.memory_id
                )
        for members in contradiction_groups.values():
            admitted = members.intersection(included)
            if admitted and admitted != members:
                _reject("agent_memory_contradiction_cohort_invalid")

        packet_ledger = tuple(
            SealedMemoryLedgerItem(
                memory_id=item.memory_id,
                disposition=item.disposition,
                exclusion_reason=item.exclusion_reason,
                rank_ordinal=rank_ordinals.get(item.memory_id),
                canonical_byte_count=item.canonical_byte_count,
            )
            for item in result.ledger_items
        )
        memory_inventory = [
            {
                "memory_id": record.memory_id,
                "rank_ordinal": record.rank_ordinal,
                "contradiction_set_id": record.contradiction_set_id,
                "canonical_sha256": record.canonical_sha256,
                "canonical_byte_count": record.canonical_byte_count,
            }
            for record in records
        ]
        memory_root = _framed_digest(
            "SKELETON_PHASE11_DETACHED_MEMORY_INVENTORY_V1",
            canonicalize(memory_inventory),
        )
        body: dict[str, object] = {
            "schema_version": "skeleton.agent-memory-packet.v1",
            "phase10_release_manifest_sha256": self._anchor.release_manifest_sha256,
            "phase10_release_source_commit": self._anchor.source_commit,
            "phase10_release_source_root": self._anchor.source_root_sha256,
            "phase10_registry_pair_root": self._anchor.registry_pair_root_sha256,
            "retrieval_result_id": result.result_id,
            "retrieval_result_root": result.canonical_sha256,
            "query_id": query.query_id,
            "query_root": query.canonical_sha256,
            "candidate_snapshot_id": candidates.snapshot_id,
            "candidate_snapshot_root": candidates.canonical_sha256,
            "integrity_snapshot_id": integrity.snapshot_id,
            "integrity_snapshot_root": integrity.canonical_sha256,
            "rights_snapshot_id": rights.snapshot_id,
            "rights_snapshot_root": rights.canonical_sha256,
            "operating_mode": query_value["operating_mode"],
            "candidate_count": result.candidate_count,
            "included_count": result.included_count,
            "excluded_count": result.excluded_count,
            "memory_root": memory_root,
            "ledger_root": result.ledger_sha256,
            "ranked_records": memory_inventory,
            "considered_items": ledger_value["considered_items"],
        }
        packet_id = _framed_digest(
            "SKELETON_PHASE11_DETACHED_MEMORY_PACKET_V1", canonicalize(body)
        )
        canonical_bytes = canonicalize({**body, "packet_id": packet_id})
        return SealedMemoryPacket(
            packet_id=packet_id,
            anchor=self._anchor,
            retrieval_result_id=result.result_id,
            retrieval_result_root=result.canonical_sha256,
            query_id=query.query_id,
            query_root=query.canonical_sha256,
            candidate_snapshot_id=candidates.snapshot_id,
            candidate_snapshot_root=candidates.canonical_sha256,
            integrity_snapshot_id=integrity.snapshot_id,
            integrity_snapshot_root=integrity.canonical_sha256,
            rights_snapshot_id=rights.snapshot_id,
            rights_snapshot_root=rights.canonical_sha256,
            operating_mode=str(query_value["operating_mode"]),
            records=tuple(records),
            ledger_items=packet_ledger,
            candidate_count=result.candidate_count,
            included_count=result.included_count,
            excluded_count=result.excluded_count,
            memory_root=memory_root,
            ledger_root=result.ledger_sha256,
            canonical_sha256=sha256_hex(canonical_bytes),
            canonical_bytes=canonical_bytes,
        )


__all__ = [
    "AgentMemoryRejection",
    "Phase10MemoryAnchor",
    "SealedMemoryAdapter",
    "SealedMemoryLedgerItem",
    "SealedMemoryPacket",
    "SealedMemoryRecord",
]
