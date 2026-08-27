"""Phase 12 Recall Conductor: seven closed lenses over frozen Phase 10 retrieval.

The conductor composes minimal evidence packets through exactly seven typed
lens builders — episodic, semantic, causal, procedural, contradiction,
prospective, ancestral — in one fixed canonical execution order.  Every lens
is a ``build_retrieval_query`` construction plus a deterministic post-hoc
composition over one ``MemoryRetriever`` result that passes
``verify_retrieval_result`` before any field is trusted; no lens constructs
SQL, touches a store handle, or invents a second retrieval engine.  The
conductor receives a ``SealedMemoryAdapter`` surface, never a store.

Packet assembly runs under one immutable Phase 11 seven-counter budget
vector.  Per-lens integer shares are reserved deterministically before any
lens executes, so no early lens can starve a later one; records enter the
packet whole and sealed or not at all; exhaustion mid-walk yields a typed
partial packet naming the exhausted budget family and every unexecuted lens
exactly as the ``recall-packet`` schema requires.  Post-outcome retrieval
regret is an append-only join of one sealed packet identity and one outcome
identity across the four closed regret classes, appended through the sole
Phase 12 writer without mutating any sealed packet or retrieval bytes.

This module reads no wall clock, uses no floats, and rejects fail-closed
with stable typed snake_case codes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType

from .agent_budgets import BudgetVector
from .canonical import canonicalize, sha256_hex
from .memory_retrieval import (
    CandidateSnapshot,
    FrozenCandidate,
    IntegritySnapshot,
    MemoryRetriever,
    RetrievalQuery,
    RetrievalRejection,
    RetrievalResult,
    RightsSnapshot,
    build_retrieval_query,
    verify_retrieval_result,
)
from .metabolism_store import (
    MetabolismStore,
    OperationReceipt,
    RegretAppend,
    metabolism_record_identity,
)
from .metabolism_types import RecallLens, RegretClass, compute_phase12_identity


PACKET_SCHEMA_VERSION = "skeleton.recall-packet.v1"
REGRET_SCHEMA_VERSION = "skeleton.recall-regret.v1"
SKELETON_PHASE12_RECALL_PACKET_V1 = "SKELETON_PHASE12_RECALL_PACKET_V1"
SKELETON_PHASE12_RECALL_REGRET_V1 = "SKELETON_PHASE12_RECALL_REGRET_V1"
RANK_PROFILE_ID = "skeleton.memory-rank.v1"

# Versioned deterministic reservation constant: the closed lens execution
# order and the equal-integer-split rule below are frozen together.  Changing
# either invalidates prior packet replay.
LENS_RESERVATION_TABLE_VERSION = "skeleton.recall-lens-reservation.v1"

# Frozen integer cost model: every lens execution meters exactly one
# retrieval query against the ``tool_calls`` counter before it runs.
LENS_TOOL_CALL_COST = 1

# The closed seven-lens set in fixed canonical execution order (D-21).
LENS_EXECUTION_ORDER: tuple[RecallLens, ...] = tuple(RecallLens)

# Lens-specific query shaping: each lens issues its own frozen-profile
# retrieval query whose ``purpose`` selects the Phase 10 rank ordering that
# serves the lens.  Only non-durable purposes appear here; durable purposes
# would demand store persistence, which the conductor never holds.
LENS_QUERY_PURPOSE: Mapping[RecallLens, str] = MappingProxyType(
    {
        RecallLens.EPISODIC: "research",
        RecallLens.SEMANTIC: "implementation_support",
        RecallLens.CAUSAL: "evaluation",
        RecallLens.PROCEDURAL: "implementation_support",
        RecallLens.CONTRADICTION: "evaluation",
        RecallLens.PROSPECTIVE: "research",
        RecallLens.ANCESTRAL: "evaluation",
    }
)

BUDGET_FAMILIES = (
    "input_tokens",
    "output_tokens",
    "elapsed_milliseconds",
    "memory_items",
    "memory_bytes",
    "tool_calls",
    "accelerator_milliseconds",
)

_NONE = "none"
_LENS_COUNT = len(LENS_EXECUTION_ORDER)
_LENS_INDEX = MappingProxyType(
    {lens: index for index, lens in enumerate(LENS_EXECUTION_ORDER)}
)
_REGRET_CLASS_ORDER: tuple[RegretClass, ...] = tuple(RegretClass)

# Closed mapping from every Phase 10 considered-ledger exclusion reason to
# the packet schema's typed exclusion enum.  An unknown reason rejects.
_EXCLUSION_REASON_MAP: Mapping[str, str] = MappingProxyType(
    {
        "namespace_mismatch": "scope_mismatch",
        "project_mismatch": "scope_mismatch",
        "lobe_mismatch": "scope_mismatch",
        "purpose_kind_incompatible": "scope_mismatch",
        "scope_mismatch": "scope_mismatch",
        "operating_mode_mismatch": "scope_mismatch",
        "model_stage_mismatch": "scope_mismatch",
        "unverifiable_bytes": "quarantined",
        "quarantined": "quarantined",
        "rights_unresolved": "quarantined",
        "rights_revoked": "quarantined",
        "rights_denied": "quarantined",
        "paper_seeded_test": "quarantined",
        "paper_simulated": "quarantined",
        "paper_synthetic": "quarantined",
        "paper_contaminated": "quarantined",
        "contradiction_integrity_invalid": "quarantined",
        "budget_item": "budget_excluded",
        "budget_bytes": "budget_excluded",
        "budget_contradiction_group": "budget_excluded",
        "future_available": "relevance_below_threshold",
        "not_yet_effective": "relevance_below_threshold",
        "expired": "relevance_below_threshold",
        "stale": "relevance_below_threshold",
        "provenance_rejected": "relevance_below_threshold",
        "quality_below_minimum": "relevance_below_threshold",
    }
)

_LENS_STATUS_COMPLETE = "complete"
_LENS_STATUS_PARTIAL_BUDGET = "partial_budget"


class RecallConductorRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise RecallConductorRejection(code)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _sha256_field(value: object, code: str) -> str:
    if not _is_sha256(value):
        _reject(code)
    return str(value)


def _operation_identity(kind: str, subject_id: str) -> str:
    return sha256_hex(
        canonicalize(
            {
                "domain": SKELETON_PHASE12_RECALL_REGRET_V1,
                "operation": kind,
                "subject_id": subject_id,
            }
        )
    )


def _split_evenly(total: int) -> tuple[int, ...]:
    """Split one nonnegative counter into seven deterministic integer shares.

    Shares are reserved per lens before execution and sum exactly to the
    caller's allocation, so no earlier lens can consume a later lens's share.
    Remainder units go to the earliest lenses in canonical order.
    """

    if type(total) is not int or total < 0:
        _reject("recall_budget_counter_invalid")
    base, remainder = divmod(total, _LENS_COUNT)
    return tuple(
        base + (1 if index < remainder else 0) for index in range(_LENS_COUNT)
    )


class SealedMemoryAdapter:
    """The only memory surface a lens may consume: frozen snapshots plus the
    frozen Phase 10 retriever.  A lens that would construct SQL or touch a
    store handle is structurally impossible because no store ever reaches
    the conductor."""

    __slots__ = ("_allow_untrusted", "_integrity", "_retriever", "_rights", "_snapshot")

    def __init__(
        self,
        retriever: MemoryRetriever,
        snapshot: CandidateSnapshot,
        integrity: IntegritySnapshot,
        rights: RightsSnapshot,
    ) -> None:
        self._bind(retriever, snapshot, integrity, rights, allow_untrusted=False)
        if not (
            snapshot.authenticated and integrity.authenticated and rights.authenticated
        ):
            _reject("recall_adapter_authority_required")

    def _bind(
        self,
        retriever: MemoryRetriever,
        snapshot: CandidateSnapshot,
        integrity: IntegritySnapshot,
        rights: RightsSnapshot,
        *,
        allow_untrusted: bool,
    ) -> None:
        if (
            not isinstance(retriever, MemoryRetriever)
            or not isinstance(snapshot, CandidateSnapshot)
            or not isinstance(integrity, IntegritySnapshot)
            or not isinstance(rights, RightsSnapshot)
        ):
            _reject("recall_adapter_surface_invalid")
        self._retriever = retriever
        self._snapshot = snapshot
        self._integrity = integrity
        self._rights = rights
        self._allow_untrusted = allow_untrusted

    @property
    def candidate_snapshot_id(self) -> str:
        return self._snapshot.snapshot_id

    @property
    def integrity_snapshot_id(self) -> str:
        return self._integrity.snapshot_id

    @property
    def candidate_ids(self) -> tuple[str, ...]:
        return self._snapshot.candidate_ids

    @property
    def candidates_by_id(self) -> Mapping[str, FrozenCandidate]:
        return MappingProxyType(
            {candidate.memory_id: candidate for candidate in self._snapshot.candidates}
        )

    @property
    def correction_children(self) -> frozenset[str]:
        return frozenset(self._snapshot.correction_edges)

    @property
    def correction_parents(self) -> frozenset[str]:
        return frozenset(self._snapshot.correction_edges.values())

    @property
    def candidate_count(self) -> int:
        return len(self._snapshot.candidate_ids)

    @property
    def total_candidate_bytes(self) -> int:
        return sum(
            candidate.canonical_byte_count for candidate in self._snapshot.candidates
        )

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        """Issue one frozen-profile retrieval and verify the sealed result."""

        if not isinstance(query, RetrievalQuery):
            _reject("recall_query_invalid")
        try:
            if self._allow_untrusted:
                result = self._retriever._retrieve_for_test(
                    query, self._snapshot, self._integrity, self._rights
                )
            else:
                result = self._retriever.retrieve(
                    query, self._snapshot, self._integrity, self._rights
                )
        except RetrievalRejection as error:
            raise RecallConductorRejection(error.code) from error
        if result.query_id != query.query_id:
            _reject("recall_result_query_mismatch")
        verified_result_root(result)
        return result


def _sealed_memory_adapter_for_test(
    retriever: MemoryRetriever,
    snapshot: CandidateSnapshot,
    integrity: IntegritySnapshot,
    rights: RightsSnapshot,
) -> SealedMemoryAdapter:
    """Adapter over synthetic test snapshots, mirroring ``_retrieve_for_test``."""

    adapter = object.__new__(SealedMemoryAdapter)
    adapter._bind(retriever, snapshot, integrity, rights, allow_untrusted=True)
    return adapter


def verified_result_root(result: RetrievalResult) -> str:
    """Return the verified content-addressed root of one retrieval result.

    Every lens consumes only results that pass ``verify_retrieval_result``;
    a tampered counter, ledger, or seal rejects with a typed code before any
    composition reads a field.
    """

    if not isinstance(result, RetrievalResult):
        _reject("recall_result_invalid")
    try:
        verify_retrieval_result(result)
    except RetrievalRejection as error:
        raise RecallConductorRejection(error.code) from error
    return result.result_id


@dataclass(frozen=True, slots=True)
class RecallFrame:
    """The immutable domain frame shared by all seven lens queries."""

    invocation_id: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    decision_at: str
    known_at: str
    world_at: str
    namespace: str
    lobe_id: str
    project_id: str
    scope: Mapping[str, str]
    operating_mode: str
    minimum_quality: str
    accepted_provenance_classes: tuple[str, ...]
    model_stage: str

    def __post_init__(self) -> None:
        _sha256_field(self.invocation_id, "recall_frame_identity_invalid")
        _sha256_field(self.fence_id, "recall_frame_identity_invalid")
        if type(self.generation) is not int or self.generation < 0:
            _reject("recall_frame_generation_invalid")
        if type(self.attempt_ordinal) is not int or self.attempt_ordinal < 1:
            _reject("recall_frame_attempt_invalid")
        if not isinstance(self.scope, Mapping):
            _reject("recall_frame_scope_invalid")
        object.__setattr__(
            self, "scope", MappingProxyType({str(k): str(v) for k, v in self.scope.items()})
        )
        object.__setattr__(
            self,
            "accepted_provenance_classes",
            tuple(str(item) for item in self.accepted_provenance_classes),
        )


@dataclass(frozen=True, slots=True)
class LensReport:
    """One executed lens: verified evidence root plus its inclusion ledger."""

    lens: RecallLens
    query_id: str
    retrieval_result_root: str
    retrieval_result_sha256: str
    considered_ledger_root: str
    included_record_ids: tuple[str, ...]
    exclusions: tuple[tuple[str, str], ...]
    consumed_items: int
    consumed_bytes: int
    status: str


@dataclass(frozen=True, slots=True)
class RecallPacket:
    """One sealed content-addressed budgeted evidence packet."""

    packet_id: str
    invocation_id: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    completeness: str
    exhausted_counter: str
    unexecuted_lenses: tuple[RecallLens, ...]
    lens_reports: tuple[LensReport, ...]
    allocated: BudgetVector
    reserved: BudgetVector
    consumed: BudgetVector
    candidate_ids: tuple[str, ...]
    canonical_bytes: bytes
    canonical_sha256: str


_MEMORY_REGRET_CLASSES = frozenset(
    {RegretClass.MISSED_RELEVANT, RegretClass.INCLUDED_IRRELEVANT}
)
_LENS_REGRET_CLASSES = frozenset(
    {RegretClass.BUDGET_STARVED, RegretClass.LENS_ABSENT}
)


@dataclass(frozen=True, slots=True)
class RegretEntry:
    """One class-tagged regret attribution: memory ids or lenses, never both.

    ``missed_relevant`` and ``included_irrelevant`` carry sorted unique memory
    identities; ``budget_starved`` and ``lens_absent`` carry canonical-order
    unique lenses.  A mixed or empty attribution rejects fail-closed.
    """

    regret_class: RegretClass
    memory_ids: tuple[str, ...] = ()
    lenses: tuple[RecallLens, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.regret_class, RegretClass):
            _reject("recall_regret_class_invalid")
        object.__setattr__(
            self,
            "memory_ids",
            tuple(
                _sha256_field(item, "recall_regret_memory_invalid")
                for item in self.memory_ids
            ),
        )
        lenses: list[RecallLens] = []
        for item in self.lenses:
            if not isinstance(item, RecallLens):
                _reject("recall_regret_lens_invalid")
            lenses.append(item)
        object.__setattr__(self, "lenses", tuple(lenses))
        if self.regret_class in _MEMORY_REGRET_CLASSES:
            if self.lenses or not self.memory_ids:
                _reject("recall_regret_attribution_invalid")
            if self.memory_ids != tuple(sorted(set(self.memory_ids))):
                _reject("recall_regret_attribution_unsorted")
        else:
            if self.memory_ids or not self.lenses:
                _reject("recall_regret_attribution_invalid")
            ordinals = tuple(_LENS_INDEX[lens] for lens in self.lenses)
            if len(set(ordinals)) != len(ordinals) or ordinals != tuple(sorted(ordinals)):
                _reject("recall_regret_attribution_unsorted")


@dataclass(frozen=True, slots=True)
class RecallRegretRecord:
    """One append-only post-outcome regret join document for one packet."""

    regret_id: str
    store_row_id: str
    packet_id: str
    outcome_id: str
    entries: tuple[RegretEntry, ...]
    canonical_bytes: bytes
    canonical_sha256: str


def _lens_member(
    lens: RecallLens,
    candidate: FrozenCandidate,
    correction_children: frozenset[str],
    correction_parents: frozenset[str],
) -> bool:
    """The deterministic post-hoc membership predicate for one lens."""

    if lens is RecallLens.EPISODIC:
        return candidate.memory_kind == "episodic"
    if lens is RecallLens.SEMANTIC:
        return (
            candidate.memory_kind == "semantic"
            and candidate.contradiction_set_id == _NONE
        )
    if lens is RecallLens.CAUSAL:
        # Correction edges are the recorded changed-belief links: the child
        # record encodes the belief change that falsified its predecessor.
        return candidate.correction_of != _NONE
    if lens is RecallLens.PROCEDURAL:
        return candidate.memory_kind == "procedural"
    if lens is RecallLens.CONTRADICTION:
        return candidate.contradiction_set_id != _NONE
    if lens is RecallLens.PROSPECTIVE:
        # A recorded bounded horizon that has not resolved at retrieval time:
        # the record's ``effective_to`` prediction outcome is still open.
        return candidate.effective_to_us is not None
    if lens is RecallLens.ANCESTRAL:
        return (
            candidate.memory_id in correction_children
            or candidate.memory_id in correction_parents
            or candidate.correction_of != _NONE
        )
    _reject("recall_lens_unknown")
    return False


def _lens_query(
    lens: RecallLens, adapter: SealedMemoryAdapter, frame: RecallFrame
) -> RetrievalQuery:
    try:
        return build_retrieval_query(
            candidate_snapshot_id=adapter.candidate_snapshot_id,
            decision_at=frame.decision_at,
            known_at=frame.known_at,
            world_at=frame.world_at,
            namespace=frame.namespace,
            lobe_id=frame.lobe_id,
            project_id=frame.project_id,
            purpose=LENS_QUERY_PURPOSE[lens],
            scope=dict(frame.scope),
            operating_mode=frame.operating_mode,
            rights_boundary="retrieval",
            minimum_quality=frame.minimum_quality,
            accepted_provenance_classes=frame.accepted_provenance_classes,
            model_stage=frame.model_stage,
            paper_eligible=False,
            item_budget=adapter.candidate_count,
            byte_budget=adapter.total_candidate_bytes,
            rank_profile_id=RANK_PROFILE_ID,
            integrity_snapshot_id=adapter.integrity_snapshot_id,
        )
    except RetrievalRejection as error:
        raise RecallConductorRejection(error.code) from error


def _compose_lens(
    lens: RecallLens,
    query: RetrievalQuery,
    result: RetrievalResult,
    adapter: SealedMemoryAdapter,
    share_items: int,
    share_bytes: int,
    already_included: frozenset[str],
) -> LensReport:
    """Whole-record budget admission over one verified retrieval result.

    Packet minimality is enforced here: a memory identity admitted by an
    earlier lens in the frozen execution order can never be admitted again.
    The first lens wins; every later occurrence is excluded with the typed
    ``duplicate_of_included`` reason and charges no budget.
    """

    by_id = adapter.candidates_by_id
    children = adapter.correction_children
    parents = adapter.correction_parents

    units: list[tuple[str, ...]] = []
    duplicates: set[str] = set()
    seen_groups: set[str] = set()
    for memory_id in result.ranked_included_ids:
        candidate = by_id[memory_id]
        if not _lens_member(lens, candidate, children, parents):
            continue
        if lens is RecallLens.CONTRADICTION:
            group = candidate.contradiction_set_id
            if group in seen_groups:
                continue
            seen_groups.add(group)
            # Every cohort member of any surfaced record enters as one unit;
            # members already carried by an earlier lens stay deduplicated.
            members = tuple(
                included_id
                for included_id in result.ranked_included_ids
                if by_id[included_id].contradiction_set_id == group
            )
            duplicates.update(
                member for member in members if member in already_included
            )
            fresh = tuple(
                member for member in members if member not in already_included
            )
            if fresh:
                units.append(fresh)
        elif memory_id in already_included:
            duplicates.add(memory_id)
        else:
            units.append((memory_id,))

    admitted: list[str] = []
    budget_excluded: set[str] = set()
    items_used = 0
    bytes_used = 0
    exhausted = False
    for unit in units:
        unit_items = len(unit)
        unit_bytes = sum(by_id[member].canonical_byte_count for member in unit)
        if (
            exhausted
            or items_used + unit_items > share_items
            or bytes_used + unit_bytes > share_bytes
        ):
            # Records enter whole and sealed or not at all: the unit is
            # excluded intact and the lens closes over its remaining rank.
            exhausted = True
            budget_excluded.update(unit)
        else:
            items_used += unit_items
            bytes_used += unit_bytes
            admitted.extend(unit)

    admitted_set = frozenset(admitted)
    exclusions: list[tuple[str, str]] = []
    for item in result.ledger_items:
        if item.memory_id in admitted_set:
            continue
        if item.memory_id in duplicates:
            reason = "duplicate_of_included"
        elif item.disposition == "excluded":
            assert item.exclusion_reason is not None
            reason = _EXCLUSION_REASON_MAP.get(item.exclusion_reason)
            if reason is None:
                _reject("recall_exclusion_reason_unknown")
        elif item.memory_id in budget_excluded:
            reason = "budget_excluded"
        else:
            reason = "relevance_below_threshold"
        exclusions.append((item.memory_id, reason))
    exclusions.sort(key=lambda entry: entry[0])

    return LensReport(
        lens=lens,
        query_id=query.query_id,
        retrieval_result_root=result.result_id,
        retrieval_result_sha256=result.canonical_sha256,
        considered_ledger_root=result.ledger_sha256,
        included_record_ids=tuple(sorted(admitted)),
        exclusions=tuple(exclusions),
        consumed_items=items_used,
        consumed_bytes=bytes_used,
        status=_LENS_STATUS_PARTIAL_BUDGET if budget_excluded else _LENS_STATUS_COMPLETE,
    )


class RecallConductor:
    """Assemble sealed budgeted recall packets and their post-outcome regret."""

    __slots__ = ("_packets",)

    def __init__(self) -> None:
        self._packets: dict[str, RecallPacket] = {}

    @property
    def sealed_packet_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._packets))

    def sealed_packet(self, packet_id: str) -> RecallPacket:
        packet = self._packets.get(_sha256_field(packet_id, "recall_packet_identity_invalid"))
        if packet is None:
            _reject("recall_packet_unknown")
        return packet

    def assemble_packet(
        self,
        adapter: SealedMemoryAdapter,
        frame: RecallFrame,
        allocated: BudgetVector,
    ) -> RecallPacket:
        if not isinstance(adapter, SealedMemoryAdapter):
            _reject("recall_adapter_surface_invalid")
        if not isinstance(frame, RecallFrame):
            _reject("recall_frame_invalid")
        if not isinstance(allocated, BudgetVector):
            _reject("recall_budget_vector_invalid")

        item_shares = _split_evenly(allocated.memory_items)
        byte_shares = _split_evenly(allocated.memory_bytes)

        reports: list[LensReport] = []
        unexecuted: list[RecallLens] = []
        exhausted_counter = _NONE
        consumed_tool_calls = 0
        consumed_items = 0
        consumed_bytes = 0
        included_so_far: set[str] = set()
        for index, lens in enumerate(LENS_EXECUTION_ORDER):
            if exhausted_counter != _NONE:
                unexecuted.append(lens)
                continue
            if consumed_tool_calls + LENS_TOOL_CALL_COST > allocated.tool_calls:
                # One retrieval query per lens is the fixed metered cost; the
                # walk halts typed, naming the exhausted budget family.
                exhausted_counter = "tool_calls"
                unexecuted.append(lens)
                continue
            query = _lens_query(lens, adapter, frame)
            result = adapter.retrieve(query)
            consumed_tool_calls += LENS_TOOL_CALL_COST
            report = _compose_lens(
                lens,
                query,
                result,
                adapter,
                item_shares[index],
                byte_shares[index],
                frozenset(included_so_far),
            )
            included_so_far.update(report.included_record_ids)
            consumed_items += report.consumed_items
            consumed_bytes += report.consumed_bytes
            reports.append(report)

        completeness = "complete" if exhausted_counter == _NONE else "partial"
        reserved = BudgetVector(
            memory_items=allocated.memory_items,
            memory_bytes=allocated.memory_bytes,
            tool_calls=min(allocated.tool_calls, _LENS_COUNT),
        )
        consumed = BudgetVector(
            memory_items=consumed_items,
            memory_bytes=consumed_bytes,
            tool_calls=consumed_tool_calls,
        )
        value: dict[str, object] = {
            "schema_version": PACKET_SCHEMA_VERSION,
            "record_type": "conductor_packet",
            "invocation_id": frame.invocation_id,
            "fence_id": frame.fence_id,
            "generation": frame.generation,
            "attempt_ordinal": frame.attempt_ordinal,
            "lens_entries": [
                {
                    "lens": report.lens.value,
                    "retrieval_result_root": report.retrieval_result_root,
                    "included_record_ids": list(report.included_record_ids),
                    "exclusions": [
                        {"memory_id": memory_id, "exclusion_reason": reason}
                        for memory_id, reason in report.exclusions
                    ],
                }
                for report in reports
            ],
            "budget": {
                "allocated": allocated.as_mapping(),
                "reserved": reserved.as_mapping(),
                "consumed": consumed.as_mapping(),
            },
            "completeness": completeness,
            "exhausted_counter": exhausted_counter,
            "unexecuted_lenses": [lens.value for lens in unexecuted],
        }
        packet_id = compute_phase12_identity(
            SKELETON_PHASE12_RECALL_PACKET_V1, "packet_id", value
        )
        value["packet_id"] = packet_id
        raw = canonicalize(value)
        packet = RecallPacket(
            packet_id=packet_id,
            invocation_id=frame.invocation_id,
            fence_id=frame.fence_id,
            generation=frame.generation,
            attempt_ordinal=frame.attempt_ordinal,
            completeness=completeness,
            exhausted_counter=exhausted_counter,
            unexecuted_lenses=tuple(unexecuted),
            lens_reports=tuple(reports),
            allocated=allocated,
            reserved=reserved,
            consumed=consumed,
            candidate_ids=adapter.candidate_ids,
            canonical_bytes=raw,
            canonical_sha256=sha256_hex(raw),
        )
        self._packets[packet_id] = packet
        return packet

    def build_regret_document(
        self,
        *,
        packet_id: str,
        outcome_root: str,
        entries: Iterable[RegretEntry],
    ) -> RecallRegretRecord:
        """Build the sealed post-outcome regret join document for one packet.

        The join never mutates, re-seals, or re-ranks the packet: it reads
        only the sealed packet identity frame and the caller's class-tagged
        attributions.  At most one entry per closed class, in canonical class
        order; an empty attribution set is a valid (regret-free) join.
        """

        packet = self.sealed_packet(packet_id)
        outcome = _sha256_field(outcome_root, "recall_outcome_identity_invalid")
        typed = tuple(entries)
        for entry in typed:
            if not isinstance(entry, RegretEntry):
                _reject("recall_regret_entry_invalid")
        ordinals = tuple(
            _REGRET_CLASS_ORDER.index(entry.regret_class) for entry in typed
        )
        if len(set(ordinals)) != len(ordinals):
            _reject("recall_regret_class_duplicate")
        ordered = tuple(
            entry for _ordinal, entry in sorted(zip(ordinals, typed, strict=True))
        )
        value: dict[str, object] = {
            "schema_version": REGRET_SCHEMA_VERSION,
            "record_type": "recall_regret",
            "packet_id": packet.packet_id,
            "outcome_id": outcome,
            "fence_id": packet.fence_id,
            "generation": packet.generation,
            "attempt_ordinal": packet.attempt_ordinal,
            "regret_entries": [
                (
                    {
                        "regret_class": entry.regret_class.value,
                        "memory_ids": list(entry.memory_ids),
                    }
                    if entry.regret_class in _MEMORY_REGRET_CLASSES
                    else {
                        "regret_class": entry.regret_class.value,
                        "lenses": [lens.value for lens in entry.lenses],
                    }
                )
                for entry in ordered
            ],
        }
        regret_id = compute_phase12_identity(
            SKELETON_PHASE12_RECALL_REGRET_V1, "regret_id", value
        )
        value["regret_id"] = regret_id
        raw = canonicalize(value)
        return RecallRegretRecord(
            regret_id=regret_id,
            store_row_id=metabolism_record_identity("recall_regret", raw),
            packet_id=packet.packet_id,
            outcome_id=outcome,
            entries=ordered,
            canonical_bytes=raw,
            canonical_sha256=sha256_hex(raw),
        )

    def record_regret(
        self,
        store: MetabolismStore,
        *,
        packet_id: str,
        outcome_root: str,
        entries: Iterable[RegretEntry],
        writer_id: str,
        recorded_at: str,
    ) -> tuple[RecallRegretRecord, OperationReceipt]:
        """Append one post-outcome regret join through the sole Phase 12 writer.

        The append is idempotent for identical content: re-recording the same
        join replays the committed operation receipt.  The row's class and
        lens columns are deterministic projections of the sealed document —
        the first entry's class in canonical order (``missed_relevant`` for a
        regret-free join) and the first attributed lens (canonical first lens
        when no lens attribution exists); the sealed document bytes remain
        the sole authoritative content.
        """

        if not isinstance(store, MetabolismStore):
            _reject("recall_regret_store_invalid")
        record = self.build_regret_document(
            packet_id=packet_id, outcome_root=outcome_root, entries=entries
        )
        packet = self.sealed_packet(packet_id)
        row_class = (
            record.entries[0].regret_class
            if record.entries
            else _REGRET_CLASS_ORDER[0]
        )
        row_lens = LENS_EXECUTION_ORDER[0]
        for entry in record.entries:
            if entry.lenses:
                row_lens = entry.lenses[0]
                break
        receipt = store.append_regret(
            RegretAppend(
                record.store_row_id,
                record.packet_id,
                row_class.value,
                row_lens.value,
                packet.fence_id,
                packet.generation,
                packet.attempt_ordinal,
                recorded_at,
                record.canonical_bytes,
            ),
            writer_id=writer_id,
            operation_id=_operation_identity("append", record.store_row_id),
        )
        return record, receipt


def regret_aggregate(
    records: Iterable[RecallRegretRecord],
) -> Mapping[str, int]:
    """Deterministic integer counts of attributions per closed regret class."""

    counts = {regret_class.value: 0 for regret_class in _REGRET_CLASS_ORDER}
    for record in records:
        if not isinstance(record, RecallRegretRecord):
            _reject("recall_regret_record_invalid")
        for entry in record.entries:
            counts[entry.regret_class.value] += len(entry.memory_ids) + len(
                entry.lenses
            )
    return MappingProxyType(counts)


__all__ = [
    "BUDGET_FAMILIES",
    "LENS_EXECUTION_ORDER",
    "LENS_QUERY_PURPOSE",
    "LENS_RESERVATION_TABLE_VERSION",
    "LENS_TOOL_CALL_COST",
    "PACKET_SCHEMA_VERSION",
    "RANK_PROFILE_ID",
    "REGRET_SCHEMA_VERSION",
    "RecallConductor",
    "RecallConductorRejection",
    "RecallFrame",
    "RecallPacket",
    "RecallRegretRecord",
    "RegretEntry",
    "LensReport",
    "SKELETON_PHASE12_RECALL_PACKET_V1",
    "SKELETON_PHASE12_RECALL_REGRET_V1",
    "SealedMemoryAdapter",
    "regret_aggregate",
    "verified_result_root",
]
