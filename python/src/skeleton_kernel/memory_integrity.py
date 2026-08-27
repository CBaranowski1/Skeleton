"""Deterministic total integrity traversal and append-only quarantine for Phase 10."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from types import MappingProxyType
from typing import Callable, Iterable, Mapping

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .memory_contracts import compute_document_identity
from .memory_retrieval import IntegritySnapshot, _freeze_integrity_snapshot
from .memory_store import (
    IntegrityAppend,
    IntegrityFindingAppend,
    MemoryStore,
    OperationReceipt,
    QuarantineAppend,
)
from .memory_types import MemoryOperationClass


_INTEGRITY_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-integrity.schema.json"
_QUARANTINE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-quarantine.schema.json"
_REFERENCE_KINDS = ("evidence", "rights", "lineage", "procedure", "model", "audit")
_DEFECT_ORDER = (
    "unverifiable_bytes",
    "missing_parent",
    "missing_reference",
    "duplicate_semantic_identity",
    "contradictory_active_fact",
    "invalid_correction_chain",
    "invalid_audit_chain",
    "scope_drift",
    "rights_drift",
    "impossible_time_order",
    "working_set_terminal_invalid",
    "retrieval_ledger_incomplete",
)
_DEFECT_INDEX = {code: ordinal for ordinal, code in enumerate(_DEFECT_ORDER)}
_ZERO = "0" * 64


@dataclass(slots=True)
class IntegrityRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise IntegrityRejection(code)


def _hash(value: object, code: str = "integrity_identity_invalid") -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _framed_digest(domain: str, payload: bytes) -> str:
    label = domain.encode("ascii")
    return sha256(
        len(label).to_bytes(8, "big")
        + label
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject("integrity_time_invalid")
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise IntegrityRejection("integrity_time_invalid") from error
    if instant.tzinfo is None or instant.utcoffset() != timedelta(0):
        _reject("integrity_time_invalid")
    return instant.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    if value.microsecond:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ReferenceBinding:
    reference_id: str
    namespace: str | None = None
    lobe_id: str | None = None
    project_id: str | None = None
    rights_decision_id: str | None = None

    def __post_init__(self) -> None:
        _hash(self.reference_id, "reference_identity_invalid")
        if self.rights_decision_id is not None:
            _hash(self.rights_decision_id, "reference_rights_invalid")
        for value in (self.namespace, self.lobe_id, self.project_id):
            if value is not None and (not isinstance(value, str) or not value):
                _reject("reference_scope_invalid")


@dataclass(frozen=True, slots=True)
class ReferenceManifest:
    reference_kind: str
    bindings: tuple[ReferenceBinding, ...]
    manifest_root: str
    canonical_sha256: str
    canonical_bytes: bytes

    @property
    def by_id(self) -> Mapping[str, ReferenceBinding]:
        return MappingProxyType({binding.reference_id: binding for binding in self.bindings})


def build_reference_manifest(
    reference_kind: str,
    bindings: Iterable[ReferenceBinding],
) -> ReferenceManifest:
    if reference_kind not in _REFERENCE_KINDS:
        _reject("reference_kind_invalid")
    copied = tuple(bindings)
    if any(not isinstance(binding, ReferenceBinding) for binding in copied):
        _reject("reference_binding_invalid")
    ordered = tuple(sorted(copied, key=lambda item: item.reference_id))
    if len({binding.reference_id for binding in ordered}) != len(ordered):
        _reject("reference_manifest_duplicate")
    value = {
        "schema_version": "skeleton.memory-reference-manifest.v1",
        "reference_kind": reference_kind,
        "bindings": [
            {
                "reference_id": binding.reference_id,
                "namespace": binding.namespace,
                "lobe_id": binding.lobe_id,
                "project_id": binding.project_id,
                "rights_decision_id": binding.rights_decision_id,
            }
            for binding in ordered
        ],
    }
    raw = canonicalize(value)
    return ReferenceManifest(
        reference_kind=reference_kind,
        bindings=ordered,
        manifest_root=_framed_digest(
            f"SKELETON_PHASE10_{reference_kind.upper()}_REFERENCE_MANIFEST_V1",
            raw,
        ),
        canonical_sha256=sha256_hex(raw),
        canonical_bytes=raw,
    )


@dataclass(frozen=True, slots=True)
class MemoryManifestEntry:
    subject_id: str
    canonical_sha256: str
    canonical_bytes: bytes
    exact_copy_count: int = 1

    def __post_init__(self) -> None:
        _hash(self.subject_id, "memory_manifest_subject_invalid")
        _hash(self.canonical_sha256, "memory_manifest_digest_invalid")
        if not isinstance(self.canonical_bytes, bytes) or type(self.exact_copy_count) is not int or self.exact_copy_count < 1:
            _reject("memory_manifest_entry_invalid")


@dataclass(frozen=True, slots=True)
class RetrievalLedgerEvidence:
    result_id: str
    candidate_ids: tuple[str, ...]
    ledger_ids: tuple[str, ...]
    sealed: bool

    def __post_init__(self) -> None:
        _hash(self.result_id, "retrieval_evidence_invalid")
        for identity in (*self.candidate_ids, *self.ledger_ids):
            _hash(identity, "retrieval_evidence_invalid")


@dataclass(frozen=True, slots=True)
class IntegrityManifest:
    subjects: tuple[MemoryManifestEntry, ...]
    subject_manifest_root: str
    subject_manifest_sha256: str
    subject_manifest_bytes: bytes
    evidence: ReferenceManifest
    rights: ReferenceManifest
    lineage: ReferenceManifest
    procedure: ReferenceManifest
    model: ReferenceManifest
    audit: ReferenceManifest
    retrieval_ledgers: tuple[RetrievalLedgerEvidence, ...] = ()
    working_terminal_states: Mapping[str, tuple[str, ...]] = MappingProxyType({})

    @property
    def subject_ids(self) -> tuple[str, ...]:
        return tuple(entry.subject_id for entry in self.subjects)


def _memory_entry(value: bytes | MemoryManifestEntry) -> MemoryManifestEntry:
    if isinstance(value, MemoryManifestEntry):
        return value
    if not isinstance(value, bytes):
        _reject("memory_manifest_entry_invalid")
    try:
        parsed = parse_raw_json(value)
        subject_id = _hash(parsed["memory_id"], "memory_manifest_subject_invalid")
    except Exception as error:
        if isinstance(error, IntegrityRejection):
            raise
        raise IntegrityRejection("memory_manifest_subject_invalid") from error
    return MemoryManifestEntry(subject_id, sha256_hex(value), value)


def build_integrity_manifest(
    memories: Iterable[bytes | MemoryManifestEntry],
    *,
    evidence: ReferenceManifest,
    rights: ReferenceManifest,
    lineage: ReferenceManifest,
    procedure: ReferenceManifest,
    model: ReferenceManifest,
    audit: ReferenceManifest,
    retrieval_ledgers: Iterable[RetrievalLedgerEvidence] = (),
    working_terminal_states: Mapping[str, tuple[str, ...]] | None = None,
) -> IntegrityManifest:
    manifests = {
        "evidence": evidence,
        "rights": rights,
        "lineage": lineage,
        "procedure": procedure,
        "model": model,
        "audit": audit,
    }
    if any(
        not isinstance(item, ReferenceManifest) or item.reference_kind != kind
        for kind, item in manifests.items()
    ):
        _reject("reference_manifest_kind_mismatch")
    grouped: dict[str, MemoryManifestEntry] = {}
    for item in memories:
        entry = _memory_entry(item)
        prior = grouped.get(entry.subject_id)
        if prior is None:
            grouped[entry.subject_id] = entry
        elif (
            prior.canonical_sha256 == entry.canonical_sha256
            and prior.canonical_bytes == entry.canonical_bytes
        ):
            grouped[entry.subject_id] = MemoryManifestEntry(
                prior.subject_id,
                prior.canonical_sha256,
                prior.canonical_bytes,
                prior.exact_copy_count + entry.exact_copy_count,
            )
        else:
            _reject("memory_manifest_identity_collision")
    ordered = tuple(grouped[identity] for identity in sorted(grouped))
    if not ordered:
        _reject("memory_manifest_empty")
    terminal_states = {
        _hash(identity, "working_terminal_manifest_invalid"): tuple(states)
        for identity, states in (working_terminal_states or {}).items()
    }
    if any(identity not in grouped for identity in terminal_states):
        _reject("working_terminal_manifest_invalid")
    ledgers = tuple(sorted(retrieval_ledgers, key=lambda item: item.result_id))
    if len({item.result_id for item in ledgers}) != len(ledgers):
        _reject("retrieval_evidence_invalid")
    value = {
        "schema_version": "skeleton.memory-subject-manifest.v1",
        "subjects": [
            {
                "subject_id": entry.subject_id,
                "canonical_sha256": entry.canonical_sha256,
                "canonical_byte_count": len(entry.canonical_bytes),
                "exact_copy_count": entry.exact_copy_count,
            }
            for entry in ordered
        ],
        "reference_manifest_roots": {
            kind: manifests[kind].manifest_root for kind in _REFERENCE_KINDS
        },
        "retrieval_ledger_ids": [item.result_id for item in ledgers],
        "working_terminal_subject_ids": sorted(terminal_states),
    }
    raw = canonicalize(value)
    return IntegrityManifest(
        subjects=ordered,
        subject_manifest_root=_framed_digest(
            "SKELETON_PHASE10_MEMORY_SUBJECT_MANIFEST_V1", raw
        ),
        subject_manifest_sha256=sha256_hex(raw),
        subject_manifest_bytes=raw,
        evidence=evidence,
        rights=rights,
        lineage=lineage,
        procedure=procedure,
        model=model,
        audit=audit,
        retrieval_ledgers=ledgers,
        working_terminal_states=MappingProxyType(terminal_states),
    )


@dataclass(frozen=True, slots=True)
class IntegrityFinding:
    finding_id: str
    finding_sha256: str
    subject_id: str
    terminal_status: str
    defect_code: str | None
    reference_kind: str | None
    reference_id: str | None
    duplicate_of_subject_id: str | None
    contradiction_set_id: str | None
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class QuarantineDecision:
    decision_id: str
    decision_sha256: str
    decision_sequence: int
    previous_decision_id: str
    subject_id: str
    finding_id: str
    integrity_run_id: str
    terminal_disposition: str
    defect_code: str | None
    verified_descendant_id: str | None
    verification_integrity_run_id: str | None
    verification_finding_id: str | None
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class IntegrityRun:
    run_id: str
    canonical_sha256: str
    canonical_bytes: bytes
    findings: tuple[IntegrityFinding, ...]
    quarantine_decisions: tuple[QuarantineDecision, ...]
    integrity_snapshot: IntegritySnapshot
    receipt: OperationReceipt | None
    schedule_evaluation_id: str | None


@dataclass(frozen=True, slots=True)
class IntegritySchedule:
    schedule_id: str
    anchor_at: str
    cadence_seconds: int
    canonical_sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class IntegrityScheduleEvaluation:
    evaluation_id: str
    schedule_id: str
    previous_run_id: str | None
    previous_run_at: str | None
    evaluation_at: str
    next_due_at: str
    due: bool
    missed_run_count: int
    missed_run_fact_id: str | None
    canonical_sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class ScheduledIntegrityResult:
    evaluation: IntegrityScheduleEvaluation
    run: IntegrityRun | None


def build_integrity_schedule(*, anchor_at: str, cadence_seconds: int) -> IntegritySchedule:
    _parse_time(anchor_at)
    if type(cadence_seconds) is not int or cadence_seconds <= 0:
        _reject("integrity_schedule_invalid")
    value = {
        "schema_version": "skeleton.memory-integrity-schedule.v1",
        "anchor_at": anchor_at,
        "cadence_seconds": cadence_seconds,
    }
    raw = canonicalize(value)
    return IntegritySchedule(
        schedule_id=_framed_digest("SKELETON_PHASE10_INTEGRITY_SCHEDULE_V1", raw),
        anchor_at=anchor_at,
        cadence_seconds=cadence_seconds,
        canonical_sha256=sha256_hex(raw),
        canonical_bytes=raw,
    )


def evaluate_integrity_schedule(
    schedule: IntegritySchedule,
    *,
    previous_run_id: str | None,
    previous_run_at: str | None,
    evaluation_at: str,
) -> IntegrityScheduleEvaluation:
    if not isinstance(schedule, IntegritySchedule):
        _reject("integrity_schedule_invalid")
    evaluation_time = _parse_time(evaluation_at)
    anchor = _parse_time(schedule.anchor_at)
    if (previous_run_id is None) != (previous_run_at is None):
        _reject("integrity_schedule_previous_invalid")
    if previous_run_id is None:
        prior_time = None
        next_due = anchor
    else:
        _hash(previous_run_id, "integrity_schedule_previous_invalid")
        prior_time = _parse_time(previous_run_at)  # type: ignore[arg-type]
        if prior_time < anchor or evaluation_time < prior_time:
            _reject("integrity_schedule_previous_invalid")
        next_due = prior_time + timedelta(seconds=schedule.cadence_seconds)
    due = evaluation_time >= next_due
    missed = 0
    if due and prior_time is not None:
        elapsed = int((evaluation_time - prior_time).total_seconds())
        missed = max(0, elapsed // schedule.cadence_seconds - 1)
    missed_value = None
    missed_id = None
    if missed:
        missed_value = {
            "schema_version": "skeleton.memory-integrity-missed-run.v1",
            "schedule_id": schedule.schedule_id,
            "previous_run_id": previous_run_id,
            "previous_run_at": previous_run_at,
            "evaluation_at": evaluation_at,
            "missed_run_count": missed,
        }
        missed_id = _framed_digest(
            "SKELETON_PHASE10_INTEGRITY_MISSED_RUN_V1",
            canonicalize(missed_value),
        )
    value = {
        "schema_version": "skeleton.memory-integrity-schedule-evaluation.v1",
        "schedule_id": schedule.schedule_id,
        "previous_run_id": previous_run_id,
        "previous_run_at": previous_run_at,
        "evaluation_at": evaluation_at,
        "next_due_at": _format_time(next_due),
        "disposition": "due" if due else "not_due",
        "missed_run_count": missed,
        "missed_run_fact_id": missed_id,
        "missed_run_fact": missed_value,
    }
    raw = canonicalize(value)
    return IntegrityScheduleEvaluation(
        evaluation_id=_framed_digest(
            "SKELETON_PHASE10_INTEGRITY_SCHEDULE_EVALUATION_V1", raw
        ),
        schedule_id=schedule.schedule_id,
        previous_run_id=previous_run_id,
        previous_run_at=previous_run_at,
        evaluation_at=evaluation_at,
        next_due_at=_format_time(next_due),
        due=due,
        missed_run_count=missed,
        missed_run_fact_id=missed_id,
        canonical_sha256=sha256_hex(raw),
        canonical_bytes=raw,
    )


def _value(entry: MemoryManifestEntry) -> Mapping[str, object] | None:
    try:
        parsed = parse_raw_json(entry.canonical_bytes)
        if not isinstance(parsed, Mapping):
            return None
        if canonicalize(parsed) != entry.canonical_bytes:
            return None
        if sha256_hex(entry.canonical_bytes) != entry.canonical_sha256:
            return None
        if parsed.get("memory_id") != entry.subject_id:
            return None
        if compute_document_identity(_INTEGRITY_ENVELOPE_SCHEMA_ID, parsed) != entry.subject_id:
            return None
        return parsed
    except Exception:
        return None


_INTEGRITY_ENVELOPE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-envelope.schema.json"


def _first_reference_defect(
    value: Mapping[str, object], manifest: IntegrityManifest
) -> tuple[str, str, str] | None:
    payload = value.get("payload")
    if not isinstance(payload, Mapping):
        return ("missing_reference", "memory", str(value.get("memory_id", _ZERO)))
    required: list[tuple[str, str]] = []
    required.extend(("evidence", str(identity)) for identity in value.get("evidence_root_ids", ()))
    required.extend(("lineage", str(identity)) for identity in value.get("lineage_root_ids", ()))
    required.append(("rights", str(value.get("ingest_rights_decision_id"))))
    procedure_id = str(value.get("producer_procedure_id"))
    if procedure_id != "none":
        required.append(("procedure", procedure_id))
    model_id = str(value.get("producer_model_id"))
    if model_id != "none":
        required.append(("model", model_id))
    kind = str(value.get("memory_kind"))
    if kind == "semantic":
        required.extend(("evidence", str(identity)) for identity in payload.get("source_evidence_ids", ()))
        required.append(("rights", str(payload.get("source_rights_decision_id"))))
    elif kind == "working":
        required.extend(("evidence", str(identity)) for identity in payload.get("admitted_evidence_ids", ()))
        required.extend(("procedure", str(identity)) for identity in payload.get("procedure_ids", ()))
        required.extend(("model", str(identity)) for identity in payload.get("model_ids", ()))
    elif kind == "procedural":
        required.append(("procedure", str(payload.get("procedure_id"))))
    elif kind == "model":
        required.append(("model", str(payload.get("model_id"))))
        required.extend(("model", str(identity)) for identity in payload.get("parent_model_ids", ()))
    elif kind == "audit":
        required.append(("audit", str(payload.get("audit_id"))))
        previous = str(payload.get("previous_audit_id"))
        if previous != _ZERO:
            required.append(("audit", previous))
    manifests = {kind: getattr(manifest, kind) for kind in _REFERENCE_KINDS}
    for reference_kind, reference_id in required:
        try:
            _hash(reference_id)
        except IntegrityRejection:
            return ("missing_reference", reference_kind, _ZERO)
        if reference_id not in manifests[reference_kind].by_id:
            return ("missing_reference", reference_kind, reference_id)
    return None


def _binding_defect(
    value: Mapping[str, object], manifest: IntegrityManifest
) -> tuple[str, str, str] | None:
    subject_scope = (
        str(value.get("namespace")),
        str(value.get("lobe_id")),
        str(value.get("project_id")),
    )
    rights_id = str(value.get("ingest_rights_decision_id"))
    ids_by_kind = {
        "evidence": tuple(str(item) for item in value.get("evidence_root_ids", ())),
        "lineage": tuple(str(item) for item in value.get("lineage_root_ids", ())),
        "procedure": (str(value.get("producer_procedure_id")),),
        "model": (str(value.get("producer_model_id")),),
    }
    for kind, identities in ids_by_kind.items():
        for identity in identities:
            if identity == "none":
                continue
            binding = getattr(manifest, kind).by_id.get(identity)
            if binding is None:
                continue
            bound_scope = (binding.namespace, binding.lobe_id, binding.project_id)
            if any(
                expected is not None and expected != observed
                for expected, observed in zip(bound_scope, subject_scope, strict=True)
            ):
                return ("scope_drift", kind, identity)
            if binding.rights_decision_id is not None and binding.rights_decision_id != rights_id:
                return ("rights_drift", kind, identity)
    return None


def _time_defect(value: Mapping[str, object]) -> bool:
    try:
        effective = _parse_time(str(value["effective_from"]))
        available = _parse_time(str(value["available_at"]))
        recorded = _parse_time(str(value["recorded_at"]))
        effective_to = value["effective_to"]
        if effective_to != "none" and _parse_time(str(effective_to)) <= effective:
            return True
        if available > recorded:
            return True
        payload = value.get("payload")
        if isinstance(payload, Mapping):
            interval = payload.get("effective_interval")
            if isinstance(interval, Mapping) and _parse_time(str(interval["end_exclusive"])) <= _parse_time(str(interval["start_inclusive"])):
                return True
            occurred = payload.get("occurred_at")
            if occurred is not None and _parse_time(str(occurred)) > recorded:
                return True
        return False
    except Exception:
        return True


def _global_statuses(
    entries: tuple[MemoryManifestEntry, ...],
    values: Mapping[str, Mapping[str, object]],
) -> tuple[
    Mapping[str, tuple[str, str | None]],
    frozenset[str],
    frozenset[str],
]:
    semantic_groups: dict[str, list[str]] = {}
    contradictions: dict[str, list[str]] = {}
    corrections: dict[str, str] = {}
    duplicate_status: dict[str, tuple[str, str | None]] = {}
    for entry in entries:
        value = values.get(entry.subject_id)
        if value is None:
            continue
        if entry.exact_copy_count > 1:
            duplicate_status[entry.subject_id] = ("exact_duplicate", entry.subject_id)
        semantic_groups.setdefault(str(value.get("semantic_identity_id")), []).append(entry.subject_id)
        payload = value.get("payload")
        contradiction = (
            str(payload.get("contradiction_set_id", "none"))
            if isinstance(payload, Mapping) and value.get("memory_kind") == "semantic"
            else "none"
        )
        if contradiction == _ZERO:
            contradiction = "none"
        if contradiction != "none":
            contradictions.setdefault(contradiction, []).append(entry.subject_id)
        parent = str(value.get("correction_of", "none"))
        if parent != "none":
            corrections[entry.subject_id] = parent

    for members in semantic_groups.values():
        if len(members) < 2:
            continue
        member_set = set(members)
        roots = [identity for identity in members if identity not in corrections]
        if (
            len(roots) == 1
            and all(
                identity == roots[0] or corrections.get(identity) in member_set
                for identity in members
            )
        ):
            # A persisted correction chain intentionally retains one semantic
            # identity while superseding immutable versions.
            continue
        group_ids = {
            (
                "none"
                if str(values[identity]["payload"].get("contradiction_set_id", "none")) == _ZERO  # type: ignore[union-attr]
                else str(values[identity]["payload"].get("contradiction_set_id", "none"))  # type: ignore[union-attr]
            )
            for identity in members
        }
        if len(group_ids) == 1 and "none" not in group_ids and len(members) >= 2:
            group_id = next(iter(group_ids))
            for identity in members:
                duplicate_status[identity] = ("contradiction_member", group_id)
        elif group_ids == {"none"}:
            for identity in members:
                duplicate_status[identity] = ("duplicate_semantic_identity", None)
        else:
            for identity in members:
                duplicate_status[identity] = ("contradictory_active_fact", None)
    for group_id, members in contradictions.items():
        if len(members) < 2:
            duplicate_status[members[0]] = ("contradictory_active_fact", group_id)
    invalid_corrections: set[str] = set()
    missing_parents: set[str] = set()
    children_by_parent: dict[str, list[str]] = {}
    for child, parent in corrections.items():
        if parent not in values:
            missing_parents.add(child)
        children_by_parent.setdefault(parent, []).append(child)
    for parent, children in children_by_parent.items():
        if len(children) > 1:
            invalid_corrections.update(children)
            if parent in values:
                invalid_corrections.add(parent)
    for start in corrections:
        seen: set[str] = set()
        current = start
        while current in corrections:
            if current in seen:
                invalid_corrections.update(seen)
                break
            seen.add(current)
            current = corrections[current]
    return MappingProxyType(duplicate_status), frozenset(invalid_corrections), frozenset(missing_parents)


def _invalid_audit_subjects(
    entries: tuple[MemoryManifestEntry, ...],
    values: Mapping[str, Mapping[str, object]],
) -> frozenset[str]:
    audits: list[tuple[int, str, str, str]] = []
    for entry in entries:
        value = values.get(entry.subject_id)
        if value is None or value.get("memory_kind") != "audit":
            continue
        payload = value.get("payload")
        if not isinstance(payload, Mapping):
            return frozenset(
                candidate.subject_id
                for candidate in entries
                if values.get(candidate.subject_id, {}).get("memory_kind") == "audit"
            )
        try:
            sequence = int(payload["sequence"])
            audit_id = _hash(payload["audit_id"], "audit_chain_invalid")
            previous = str(payload["previous_audit_id"])
        except (KeyError, TypeError, ValueError, IntegrityRejection):
            return frozenset(
                candidate.subject_id
                for candidate in entries
                if values.get(candidate.subject_id, {}).get("memory_kind") == "audit"
            )
        audits.append((sequence, audit_id, previous, entry.subject_id))
    if not audits:
        return frozenset()
    ordered = sorted(audits)
    valid = len({item[0] for item in ordered}) == len(ordered)
    valid = valid and len({item[1] for item in ordered}) == len(ordered)
    if valid:
        first_sequence, _first_id, first_previous, _first_subject = ordered[0]
        valid = first_sequence == 1 and first_previous == _ZERO
    for prior, current in zip(ordered, ordered[1:]):
        valid = valid and current[0] == prior[0] + 1 and current[2] == prior[1]
    return frozenset() if valid else frozenset(item[3] for item in ordered)


def _incomplete_ledger_subjects(manifest: IntegrityManifest) -> frozenset[str]:
    invalid: set[str] = set()
    subject_ids = set(manifest.subject_ids)
    for ledger in manifest.retrieval_ledgers:
        candidates = ledger.candidate_ids
        items = ledger.ledger_ids
        complete = (
            ledger.sealed
            and candidates == tuple(sorted(set(candidates)))
            and items == tuple(sorted(set(items)))
            and set(candidates) == set(items)
        )
        if not complete:
            referenced = (set(candidates) | set(items)) & subject_ids
            invalid.update(referenced or subject_ids)
    return frozenset(invalid)


def _decision_from_raw(raw: bytes) -> QuarantineDecision:
    value = parse_raw_json(raw)
    if not isinstance(value, Mapping):
        _reject("quarantine_decision_invalid")
    return QuarantineDecision(
        str(value["decision_id"]),
        str(value["decision_sha256"]),
        int(value["decision_sequence"]),
        str(value["previous_decision_id"]),
        str(value["subject_id"]),
        str(value["finding_id"]),
        str(value["integrity_run_id"]),
        str(value["terminal_disposition"]),
        None if "defect_code" not in value else str(value["defect_code"]),
        None if "verified_descendant_id" not in value else str(value["verified_descendant_id"]),
        None if "verification_integrity_run_id" not in value else str(value["verification_integrity_run_id"]),
        None if "verification_finding_id" not in value else str(value["verification_finding_id"]),
        raw,
    )


def _finding(
    *,
    subject_id: str,
    terminal_status: str,
    defect_code: str | None = None,
    reference_kind: str | None = None,
    reference_id: str | None = None,
    duplicate_of_subject_id: str | None = None,
    contradiction_set_id: str | None = None,
) -> IntegrityFinding:
    body: dict[str, object] = {
        "subject_id": subject_id,
        "terminal_status": terminal_status,
    }
    if terminal_status == "quarantined":
        body.update(
            defect_code=defect_code,
            reference_kind=reference_kind,
            reference_id=reference_id,
        )
    elif terminal_status == "exact_duplicate":
        body["duplicate_of_subject_id"] = duplicate_of_subject_id
    elif terminal_status == "contradiction_member":
        body["contradiction_set_id"] = contradiction_set_id
    body_raw = canonicalize(body)
    finding_sha = sha256_hex(body_raw)
    finding_id = _framed_digest("SKELETON_PHASE10_INTEGRITY_FINDING_V1", body_raw)
    value = {"finding_id": finding_id, "finding_sha256": finding_sha, **body}
    raw = canonicalize(value)
    return IntegrityFinding(
        finding_id,
        finding_sha,
        subject_id,
        terminal_status,
        defect_code,
        reference_kind,
        reference_id,
        duplicate_of_subject_id,
        contradiction_set_id,
        raw,
    )


class MemoryIntegrityService:
    """Classify every exact subject, then append the sealed result once."""

    __slots__ = ("_operation_capability_issuer", "_store")

    def __init__(
        self,
        store: MemoryStore | None = None,
        *,
        operation_capability_issuer: Callable[[object, str, str, bytes], bytes]
        | None = None,
    ) -> None:
        if store is not None and not isinstance(store, MemoryStore):
            _reject("integrity_store_invalid")
        self._store = store
        self._operation_capability_issuer = operation_capability_issuer

    def run(
        self,
        manifest: IntegrityManifest,
        *,
        completed_at: str,
        operation_id: str | None = None,
        schedule_evaluation: IntegrityScheduleEvaluation | None = None,
    ) -> IntegrityRun:
        if not isinstance(manifest, IntegrityManifest):
            _reject("integrity_manifest_invalid")
        _parse_time(completed_at)
        if schedule_evaluation is not None and not schedule_evaluation.due:
            _reject("integrity_schedule_not_due")
        state = self._store.integrity_state() if self._store is not None else None
        stored = (
            {item.memory_id: item for item in state.memories}
            if state is not None
            else {}
        )
        parsed = {
            entry.subject_id: value
            for entry in manifest.subjects
            if (value := _value(entry)) is not None
        }
        duplicates, invalid_corrections, missing_parents = _global_statuses(
            manifest.subjects, parsed
        )
        invalid_audits = _invalid_audit_subjects(manifest.subjects, parsed)
        incomplete_ledgers = _incomplete_ledger_subjects(manifest)
        findings: list[IntegrityFinding] = []
        for entry in manifest.subjects:
            value = parsed.get(entry.subject_id)
            defect: tuple[str, str, str] | None = None
            source = stored.get(entry.subject_id)
            if (
                value is None
                or (state is not None and source is None)
                or (
                    source is not None
                    and (
                        source.canonical_sha256 != entry.canonical_sha256
                        or source.canonical_bytes != entry.canonical_bytes
                    )
                )
            ):
                defect = ("unverifiable_bytes", "memory", entry.subject_id)
            elif entry.subject_id in missing_parents:
                parent = str(value.get("correction_of", _ZERO))
                defect = ("missing_parent", "correction", parent)
            else:
                defect = _first_reference_defect(value, manifest)
            duplicate = duplicates.get(entry.subject_id)
            if defect is None and duplicate is not None and duplicate[0] in _DEFECT_INDEX:
                code = duplicate[0]
                defect = (
                    code,
                    "contradiction" if code == "contradictory_active_fact" else "memory",
                    duplicate[1] or entry.subject_id,
                )
            if defect is None and entry.subject_id in invalid_corrections:
                defect = ("invalid_correction_chain", "correction", entry.subject_id)
            if defect is None and entry.subject_id in invalid_audits:
                defect = ("invalid_audit_chain", "audit", entry.subject_id)
            if defect is None:
                defect = _binding_defect(value, manifest)
            if defect is None and _time_defect(value):
                defect = ("impossible_time_order", "memory", entry.subject_id)
            terminal_states = manifest.working_terminal_states.get(entry.subject_id)
            if (
                defect is None
                and terminal_states is not None
                and (
                    len(terminal_states) != 1
                    or terminal_states[0] not in {"sealed", "discarded"}
                )
            ):
                defect = ("working_set_terminal_invalid", "memory", entry.subject_id)
            if defect is None and entry.subject_id in incomplete_ledgers:
                defect = ("retrieval_ledger_incomplete", "retrieval", entry.subject_id)
            if defect is not None:
                findings.append(
                    _finding(
                        subject_id=entry.subject_id,
                        terminal_status="quarantined",
                        defect_code=defect[0],
                        reference_kind=defect[1],
                        reference_id=defect[2],
                    )
                )
            elif duplicate is not None and duplicate[0] == "exact_duplicate":
                findings.append(
                    _finding(
                        subject_id=entry.subject_id,
                        terminal_status="exact_duplicate",
                        duplicate_of_subject_id=duplicate[1],
                    )
                )
            elif duplicate is not None and duplicate[0] == "contradiction_member":
                findings.append(
                    _finding(
                        subject_id=entry.subject_id,
                        terminal_status="contradiction_member",
                        contradiction_set_id=duplicate[1],
                    )
                )
            else:
                findings.append(
                    _finding(subject_id=entry.subject_id, terminal_status="healthy")
                )

        findings_tuple = tuple(findings)
        status_counts = {
            status: sum(item.terminal_status == status for item in findings_tuple)
            for status in (
                "healthy",
                "exact_duplicate",
                "contradiction_member",
                "quarantined",
            )
        }
        run_body = {
            "schema_version": "skeleton.memory-integrity.v1",
            "subject_manifest_id": manifest.subject_manifest_root,
            "subject_manifest_sha256": manifest.subject_manifest_sha256,
            "subject_ids": list(manifest.subject_ids),
            "reference_manifests": {
                f"{kind}_manifest_sha256": getattr(manifest, kind).manifest_root
                for kind in _REFERENCE_KINDS
            },
            "findings": [parse_raw_json(item.canonical_bytes) for item in findings_tuple],
            "subject_count": len(findings_tuple),
            "healthy_count": status_counts["healthy"],
            "exact_duplicate_count": status_counts["exact_duplicate"],
            "contradiction_member_count": status_counts["contradiction_member"],
            "quarantined_count": status_counts["quarantined"],
            "terminal_count": len(findings_tuple),
            "completed_at": completed_at,
        }
        run_sha = sha256_hex(canonicalize(run_body))
        run_value = {**run_body, "integrity_run_sha256": run_sha}
        run_id = compute_document_identity(_INTEGRITY_SCHEMA_ID, run_value)
        run_value["integrity_run_id"] = run_id
        run_raw = canonicalize(run_value)

        prior_decisions: tuple[tuple[object, ...], ...] = (
            state.quarantine_decisions if state is not None else ()
        )
        decisions: list[QuarantineDecision] = []
        existing_for_run = tuple(
            _decision_from_raw(bytes(row[7]))
            for row in prior_decisions
            if str(row[4]) == run_id and str(row[2]) == "quarantined"
        )
        quarantined_findings = tuple(
            finding
            for finding in findings_tuple
            if finding.terminal_status == "quarantined"
        )
        if existing_for_run:
            expected = {
                (finding.subject_id, finding.finding_id)
                for finding in quarantined_findings
            }
            observed = {
                (decision.subject_id, decision.finding_id)
                for decision in existing_for_run
            }
            if expected != observed:
                _reject("integrity_replay_mismatch")
            decisions.extend(existing_for_run)
        sequence = len(prior_decisions)
        previous = str(prior_decisions[-1][0]) if prior_decisions else "none"
        for finding in (() if existing_for_run else quarantined_findings):
            decision_body = {
                "schema_version": "skeleton.memory-quarantine.v1",
                "decision_sequence": sequence,
                "previous_decision_id": previous,
                "subject_id": finding.subject_id,
                "finding_id": finding.finding_id,
                "integrity_run_id": run_id,
                "terminal_disposition": "quarantined",
                "defect_code": finding.defect_code,
                "recorded_at": completed_at,
            }
            decision_sha = sha256_hex(canonicalize(decision_body))
            decision_value = {**decision_body, "decision_sha256": decision_sha}
            decision_id = compute_document_identity(_QUARANTINE_SCHEMA_ID, decision_value)
            decision_value["decision_id"] = decision_id
            decision_raw = canonicalize(decision_value)
            decisions.append(
                QuarantineDecision(
                    decision_id,
                    decision_sha,
                    sequence,
                    previous,
                    finding.subject_id,
                    finding.finding_id,
                    run_id,
                    "quarantined",
                    finding.defect_code,
                    None,
                    None,
                    None,
                    decision_raw,
                )
            )
            previous = decision_id
            sequence += 1
        decisions_tuple = tuple(decisions)

        permanently_quarantined = {
            str(row[1])
            for row in prior_decisions
            if str(row[2]) == "quarantined"
        }
        statuses = {
            finding.subject_id: (
                "quarantined"
                if finding.subject_id in permanently_quarantined
                else finding.terminal_status
            )
            for finding in findings_tuple
        }
        integrity_snapshot = _freeze_integrity_snapshot(
            manifest.subject_ids,
            statuses,
            complete=True,
            resolved_evidence_ids=(binding.reference_id for binding in manifest.evidence.bindings),
            resolved_lineage_ids=(binding.reference_id for binding in manifest.lineage.bindings),
            authenticated=self._store is not None,
        )
        receipt = None
        if self._store is not None:
            if operation_id is None:
                _reject("integrity_operation_identity_required")
            _hash(operation_id, "integrity_operation_identity_invalid")
            if self._operation_capability_issuer is None:
                _reject("integrity_operation_capability_required")
            receipt = self._store.persist_integrity_quarantine(
                IntegrityAppend(
                    run_id=run_id,
                    subject_manifest_root=manifest.subject_manifest_root,
                    canonical_bytes=run_raw,
                    findings=tuple(
                        IntegrityFindingAppend(
                            finding.finding_id,
                            finding.subject_id,
                            finding.terminal_status,
                            finding.defect_code or "none",
                            finding.canonical_bytes,
                        )
                        for finding in findings_tuple
                    ),
                    schedule_evaluation_id=(
                        schedule_evaluation.evaluation_id
                        if schedule_evaluation is not None
                        else None
                    ),
                    schedule_evaluation_bytes=(
                        schedule_evaluation.canonical_bytes
                        if schedule_evaluation is not None
                        else None
                    ),
                ),
                tuple(
                    QuarantineAppend(
                        decision.decision_id,
                        decision.subject_id,
                        decision.terminal_disposition,
                        decision.finding_id,
                        decision.integrity_run_id,
                        None,
                        decision.canonical_bytes,
                    )
                    for decision in decisions_tuple
                ),
                operation_id=operation_id,
                capability_raw=self._operation_capability_issuer(
                    MemoryOperationClass.INTEGRITY,
                    operation_id,
                    run_id,
                    run_raw,
                ),
            )
        return IntegrityRun(
            run_id=run_id,
            canonical_sha256=sha256_hex(run_raw),
            canonical_bytes=run_raw,
            findings=findings_tuple,
            quarantine_decisions=decisions_tuple,
            integrity_snapshot=integrity_snapshot,
            receipt=receipt,
            schedule_evaluation_id=(
                schedule_evaluation.evaluation_id
                if schedule_evaluation is not None
                else None
            ),
        )

    def recover(
        self,
        quarantine: QuarantineDecision,
        *,
        descendant_id: str,
        verification_run: IntegrityRun,
        recorded_at: str,
        operation_id: str,
    ) -> QuarantineDecision:
        """Append recovery for one independently verified correction descendant."""

        if self._store is None:
            _reject("integrity_store_required")
        if (
            not isinstance(quarantine, QuarantineDecision)
            or quarantine.terminal_disposition != "quarantined"
            or not isinstance(verification_run, IntegrityRun)
        ):
            _reject("recovery_quarantine_invalid")
        descendant_id = _hash(descendant_id, "recovery_descendant_invalid")
        _parse_time(recorded_at)
        _hash(operation_id, "integrity_operation_identity_invalid")
        if self._operation_capability_issuer is None:
            _reject("integrity_operation_capability_required")
        verification = next(
            (
                finding
                for finding in verification_run.findings
                if finding.subject_id == descendant_id
                and finding.terminal_status in {
                    "healthy",
                    "exact_duplicate",
                    "contradiction_member",
                }
            ),
            None,
        )
        if verification is None:
            _reject("recovery_descendant_unverified")
        state = self._store.integrity_state()
        sequence = len(state.quarantine_decisions)
        previous = (
            str(state.quarantine_decisions[-1][0])
            if state.quarantine_decisions
            else "none"
        )
        body = {
            "schema_version": "skeleton.memory-quarantine.v1",
            "decision_sequence": sequence,
            "previous_decision_id": previous,
            "subject_id": quarantine.subject_id,
            "finding_id": quarantine.finding_id,
            "integrity_run_id": quarantine.integrity_run_id,
            "terminal_disposition": "recovery_descendant_verified",
            "verified_descendant_id": descendant_id,
            "verification_integrity_run_id": verification_run.run_id,
            "verification_finding_id": verification.finding_id,
            "recorded_at": recorded_at,
        }
        decision_sha = sha256_hex(canonicalize(body))
        value = {**body, "decision_sha256": decision_sha}
        decision_id = compute_document_identity(_QUARANTINE_SCHEMA_ID, value)
        value["decision_id"] = decision_id
        raw = canonicalize(value)
        decision = QuarantineDecision(
            decision_id,
            decision_sha,
            sequence,
            previous,
            quarantine.subject_id,
            quarantine.finding_id,
            quarantine.integrity_run_id,
            "recovery_descendant_verified",
            None,
            descendant_id,
            verification_run.run_id,
            verification.finding_id,
            raw,
        )
        self._store.append_quarantine(
            QuarantineAppend(
                decision.decision_id,
                decision.subject_id,
                decision.terminal_disposition,
                decision.finding_id,
                decision.integrity_run_id,
                descendant_id,
                decision.canonical_bytes,
                verification_run.run_id,
                verification.finding_id,
            ),
            operation_id=operation_id,
            capability_raw=self._operation_capability_issuer(
                MemoryOperationClass.QUARANTINE,
                operation_id,
                decision.decision_id,
                decision.canonical_bytes,
            ),
        )
        return decision

    def run_scheduled(
        self,
        evaluation: IntegrityScheduleEvaluation,
        manifest: IntegrityManifest,
        *,
        operation_id: str,
    ) -> ScheduledIntegrityResult:
        if not isinstance(evaluation, IntegrityScheduleEvaluation):
            _reject("integrity_schedule_invalid")
        if not evaluation.due:
            return ScheduledIntegrityResult(evaluation, None)
        return ScheduledIntegrityResult(
            evaluation,
            self.run(
                manifest,
                completed_at=evaluation.evaluation_at,
                operation_id=operation_id,
                schedule_evaluation=evaluation,
            ),
        )


__all__ = [
    "IntegrityFinding",
    "IntegrityManifest",
    "IntegrityRejection",
    "IntegrityRun",
    "IntegritySchedule",
    "IntegrityScheduleEvaluation",
    "MemoryIntegrityService",
    "MemoryManifestEntry",
    "QuarantineDecision",
    "ReferenceBinding",
    "ReferenceManifest",
    "RetrievalLedgerEvidence",
    "ScheduledIntegrityResult",
    "build_integrity_manifest",
    "build_integrity_schedule",
    "build_reference_manifest",
    "evaluate_integrity_schedule",
]
