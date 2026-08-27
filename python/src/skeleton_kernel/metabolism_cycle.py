"""Metabolism cycle identity and generation-fenced resume (Phase 12, plan 12-08).

``MetabolismCycle`` is the single coordinator for one nightly metabolism
cycle over the 12-06 ``MetabolismStore`` substrate:

* Cycle identity is content-addressed: a length-framed domain digest over
  the cycle ordinal plus the cycle input snapshot root.  No wall-clock
  value enters any sealed cycle or stage record; every ``recorded_at``
  written through this module is the coordinator-supplied fence timestamp.
* The cycle input snapshot folds the byte-verified capsule inventory
  (``capsule_id``, ``canonical_sha256`` pairs in strict identity order)
  and the exact integer per-tier quota totals into one deterministic root,
  so any admitted capsule or quota event changes the root.
* The six pipeline stages run in the frozen ``METABOLISM_STAGE_ORDER``.
  Each stage commits exactly one schema-shaped stage receipt chained to
  the predecessor receipt identity, with the stage-0 genesis sentinel
  exactly as the published ``metabolism-stage-receipt`` schema pins it.
* Resume is receipt-driven and generation-fenced, mirroring the Phase 11
  coordinator discipline (``agent_orchestration._advance_fence`` /
  ``_append_abandoned``): a successor acquires the advanced fence, reads
  the committed receipt chain, re-derives the input root, and either
  continues from the first missing stage (attempt ordinal incremented) or
  terminally abandons the cycle with a typed ``disposition_deferred``
  record — never re-running a committed stage.  Stale-generation writers
  reject through the store's ``stale_metabolism_fence`` path.
* Stage executors are injected typed callables.  The real stage
  implementations arrive in plans 12-09..12-13; this module ships a
  closed deterministic passthrough executor set so the walker is fully
  testable today.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from types import MappingProxyType
from typing import Callable

from .canonical import canonicalize, parse_raw_json
from .metabolism_store import (
    DispositionAppend,
    FenceAppend,
    FenceSnapshot,
    MetabolismStore,
    MetabolismStoreRejection,
    StageReceiptAppend,
    metabolism_record_identity,
)
from .metabolism_types import (
    DeferralReason,
    DispositionKind,
    SAFE_INTEGER_MAX,
    StageKind,
    compute_disposition_identity,
    compute_phase12_identity,
)


ZERO_SHA256 = "0" * 64
GENESIS_RECEIPT_ID = ZERO_SHA256
NONE_SENTINEL = "none"

STAGE_RECEIPT_SCHEMA_VERSION = "skeleton.metabolism-stage-receipt.v1"
DISPOSITION_SCHEMA_VERSION = "skeleton.memory-disposition.v1"

SKELETON_PHASE12_CYCLE_V1 = "SKELETON_PHASE12_CYCLE_V1"
SKELETON_PHASE12_CYCLE_INPUT_V1 = "SKELETON_PHASE12_CYCLE_INPUT_V1"
SKELETON_PHASE12_CYCLE_STREAM_V1 = "SKELETON_PHASE12_CYCLE_STREAM_V1"
SKELETON_PHASE12_CYCLE_ABANDON_V1 = "SKELETON_PHASE12_CYCLE_ABANDON_V1"
SKELETON_PHASE12_CYCLE_OPERATION_V1 = "SKELETON_PHASE12_CYCLE_OPERATION_V1"
SKELETON_PHASE12_STAGE_RECEIPT_V1 = "SKELETON_PHASE12_STAGE_RECEIPT_V1"
SKELETON_PHASE12_STAGE_PASSTHROUGH_V1 = "SKELETON_PHASE12_STAGE_PASSTHROUGH_V1"

# Frozen six-stage pipeline order; must match the 0013 stage CHECK enum and
# the published metabolism-stage-receipt schema's pinned stage/ordinal pairs.
METABOLISM_STAGE_ORDER: tuple[str, ...] = (
    "lossless_deduplication",
    "semantic_delta_encoding",
    "prototype_exception_clustering",
    "crystallization",
    "retention_scoring",
    "pressure_pruning",
)
assert METABOLISM_STAGE_ORDER == tuple(stage.value for stage in StageKind)
METABOLISM_STAGE_COUNT = len(METABOLISM_STAGE_ORDER)


class MetabolismCycleRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise MetabolismCycleRejection(code)


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _identity(value: object, code: str) -> str:
    if not _is_sha256(value):
        _reject(code)
    return str(value)


def _count(value: object, code: str) -> int:
    if type(value) is not int or not 0 <= value <= SAFE_INTEGER_MAX:
        _reject(code)
    return value


def _utc_text(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) < 20 or not value.endswith("Z"):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise MetabolismCycleRejection(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _reject(code)
    return value


METABOLISM_CYCLE_STREAM_ID = _framed_digest(
    SKELETON_PHASE12_CYCLE_STREAM_V1,
    canonicalize({"stream": "metabolism-cycle"}),
)


def derive_cycle_input_root(
    capsule_inventory: tuple[tuple[str, str], ...],
    quota_totals: Mapping[str, int],
) -> str:
    """Fold the identity-ordered capsule inventory and quota state to one root."""

    pairs = tuple(
        (
            _identity(capsule_id, "cycle_input_inventory_invalid"),
            _identity(canonical_sha256, "cycle_input_inventory_invalid"),
        )
        for capsule_id, canonical_sha256 in capsule_inventory
    )
    if pairs != tuple(sorted(pairs)) or len({pair[0] for pair in pairs}) != len(pairs):
        _reject("cycle_input_inventory_invalid")
    totals = {
        str(tier): _count(total, "cycle_input_quota_invalid")
        for tier, total in quota_totals.items()
    }
    return _framed_digest(
        SKELETON_PHASE12_CYCLE_INPUT_V1,
        canonicalize(
            {
                "capsules": [
                    {"capsule_id": capsule_id, "canonical_sha256": canonical_sha256}
                    for capsule_id, canonical_sha256 in pairs
                ],
                "quota_totals": totals,
                "schema_version": "skeleton.metabolism-cycle-input.v1",
            }
        ),
    )


def derive_cycle_identity(cycle_ordinal: int, input_root: str) -> str:
    """Content-addressed cycle identity: ordinal plus input root, never a clock."""

    return _framed_digest(
        SKELETON_PHASE12_CYCLE_V1,
        canonicalize(
            {
                "cycle_ordinal": _count(cycle_ordinal, "cycle_ordinal_invalid"),
                "input_root": _identity(input_root, "cycle_input_root_invalid"),
                "schema_version": "skeleton.metabolism-cycle-identity.v1",
            }
        ),
    )


def abandonment_encounter_id(cycle_ordinal: int) -> str:
    """Deterministic encounter identity binding one cycle-level abandonment."""

    return _framed_digest(
        SKELETON_PHASE12_CYCLE_ABANDON_V1,
        canonicalize(
            {
                "cycle_ordinal": _count(cycle_ordinal, "cycle_ordinal_invalid"),
                "schema_version": "skeleton.metabolism-cycle-abandonment.v1",
            }
        ),
    )


def _operation_id(**values: object) -> str:
    return _framed_digest(SKELETON_PHASE12_CYCLE_OPERATION_V1, canonicalize(values))


@dataclass(frozen=True, slots=True)
class CycleIdentity:
    """Ordinal-plus-input-root cycle key; byte-identical across replays."""

    cycle_ordinal: int
    input_root: str
    cycle_id: str


@dataclass(frozen=True, slots=True)
class CycleInputSnapshot:
    """Deterministic snapshot of cycle inputs read through the sole writer."""

    capsule_inventory: tuple[tuple[str, str], ...]
    quota_totals: Mapping[str, int]
    input_root: str

    @property
    def item_count(self) -> int:
        return len(self.capsule_inventory)


@dataclass(frozen=True, slots=True)
class StageRequest:
    """Typed input handed to one injected stage executor."""

    cycle_ordinal: int
    cycle_input_root: str
    stage: StageKind
    stage_ordinal: int
    input_root: str
    input_item_count: int


@dataclass(frozen=True, slots=True)
class StageResult:
    """Typed output an executor must return for one stage."""

    output_root: str
    output_item_count: int


StageExecutor = Callable[[StageRequest], StageResult]


@dataclass(frozen=True, slots=True)
class StageReceiptView:
    """One authenticated committed stage receipt read back from the store."""

    receipt_id: str
    row_id: str
    cycle_ordinal: int
    cycle_input_root: str
    fence_id: str
    generation: int
    attempt_ordinal: int
    stage: StageKind
    stage_ordinal: int
    prior_receipt_id: str
    input_root: str
    output_root: str
    input_item_count: int
    output_item_count: int
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class CycleCompleted:
    """Terminal success: one linear six-receipt chain for one cycle."""

    identity: CycleIdentity
    receipts: tuple[StageReceiptView, ...]
    resumed_from_stage_ordinal: int | None
    attempt_ordinal: int


@dataclass(frozen=True, slots=True)
class CycleAbandoned:
    """Terminal typed abandonment: a fence-stamped deferred disposition."""

    cycle_ordinal: int
    input_root: str
    disposition_id: str
    encounter_id: str
    reason: DeferralReason
    fence_id: str
    generation: int
    attempt_ordinal: int


def _passthrough(request: StageRequest) -> StageResult:
    """Deterministic no-op stage: content-addressed root, unchanged count."""

    return StageResult(
        output_root=_framed_digest(
            SKELETON_PHASE12_STAGE_PASSTHROUGH_V1,
            canonicalize(
                {
                    "input_item_count": request.input_item_count,
                    "input_root": request.input_root,
                    "stage": request.stage.value,
                }
            ),
        ),
        output_item_count=request.input_item_count,
    )


def passthrough_stage_executors() -> Mapping[StageKind, StageExecutor]:
    """The closed no-op executor set covering exactly the six frozen stages."""

    return MappingProxyType({stage: _passthrough for stage in StageKind})


def build_stage_receipt_document(
    *,
    cycle_ordinal: int,
    cycle_input_root: str,
    fence_id: str,
    generation: int,
    attempt_ordinal: int,
    stage_ordinal: int,
    prior_receipt_id: str,
    input_root: str,
    output_root: str,
    input_item_count: int,
    output_item_count: int,
) -> tuple[str, bytes]:
    """Build one schema-shaped stage receipt; returns (identity, canonical bytes).

    Enforces the published schema's pinned stage/ordinal branches and the
    stage-0 genesis sentinel: only stage ordinal 0 may (and must) carry the
    all-zero ``prior_receipt_id``.
    """

    if type(stage_ordinal) is not int or not 0 <= stage_ordinal < METABOLISM_STAGE_COUNT:
        _reject("stage_ordinal_invalid")
    prior = _identity(prior_receipt_id, "stage_receipt_prior_invalid")
    if stage_ordinal == 0:
        if prior != GENESIS_RECEIPT_ID:
            _reject("stage_receipt_genesis_invalid")
    elif prior == GENESIS_RECEIPT_ID:
        _reject("stage_receipt_genesis_invalid")
    if type(attempt_ordinal) is not int or not 1 <= attempt_ordinal <= SAFE_INTEGER_MAX:
        _reject("stage_receipt_attempt_invalid")
    value: dict[str, object] = {
        "schema_version": STAGE_RECEIPT_SCHEMA_VERSION,
        "record_type": "stage_receipt",
        "stage_receipt_id": ZERO_SHA256,
        "cycle_ordinal": _count(cycle_ordinal, "cycle_ordinal_invalid"),
        "cycle_input_root": _identity(cycle_input_root, "cycle_input_root_invalid"),
        "fence_id": _identity(fence_id, "stage_receipt_fence_invalid"),
        "generation": _count(generation, "stage_receipt_generation_invalid"),
        "attempt_ordinal": attempt_ordinal,
        "stage": METABOLISM_STAGE_ORDER[stage_ordinal],
        "stage_ordinal": stage_ordinal,
        "prior_receipt_id": prior,
        "input_root": _identity(input_root, "stage_receipt_root_invalid"),
        "output_root": _identity(output_root, "stage_receipt_root_invalid"),
        "input_item_count": _count(input_item_count, "stage_receipt_count_invalid"),
        "output_item_count": _count(output_item_count, "stage_receipt_count_invalid"),
    }
    identity = compute_phase12_identity(
        SKELETON_PHASE12_STAGE_RECEIPT_V1, "stage_receipt_id", value
    )
    value["stage_receipt_id"] = identity
    return identity, canonicalize(value)


def _receipt_view(row_id: str, raw: bytes) -> StageReceiptView:
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise MetabolismCycleRejection("cycle_receipt_chain_invalid") from error
    if not isinstance(value, dict):
        _reject("cycle_receipt_chain_invalid")
    if (
        value.get("schema_version") != STAGE_RECEIPT_SCHEMA_VERSION
        or value.get("record_type") != "stage_receipt"
    ):
        _reject("cycle_receipt_chain_invalid")
    declared = _identity(value.get("stage_receipt_id"), "cycle_receipt_chain_invalid")
    expected = compute_phase12_identity(
        SKELETON_PHASE12_STAGE_RECEIPT_V1, "stage_receipt_id", value
    )
    if declared != expected:
        _reject("cycle_receipt_chain_invalid")
    stage_ordinal = value.get("stage_ordinal")
    if type(stage_ordinal) is not int or not 0 <= stage_ordinal < METABOLISM_STAGE_COUNT:
        _reject("cycle_receipt_chain_invalid")
    stage_name = value.get("stage")
    if stage_name != METABOLISM_STAGE_ORDER[stage_ordinal]:
        _reject("cycle_stage_order_invalid")
    attempt = value.get("attempt_ordinal")
    if type(attempt) is not int or attempt < 1:
        _reject("cycle_receipt_chain_invalid")
    return StageReceiptView(
        receipt_id=declared,
        row_id=row_id,
        cycle_ordinal=_count(value.get("cycle_ordinal"), "cycle_receipt_chain_invalid"),
        cycle_input_root=_identity(
            value.get("cycle_input_root"), "cycle_receipt_chain_invalid"
        ),
        fence_id=_identity(value.get("fence_id"), "cycle_receipt_chain_invalid"),
        generation=_count(value.get("generation"), "cycle_receipt_chain_invalid"),
        attempt_ordinal=attempt,
        stage=StageKind(str(stage_name)),
        stage_ordinal=stage_ordinal,
        prior_receipt_id=_identity(
            value.get("prior_receipt_id"), "cycle_receipt_chain_invalid"
        ),
        input_root=_identity(value.get("input_root"), "cycle_receipt_chain_invalid"),
        output_root=_identity(value.get("output_root"), "cycle_receipt_chain_invalid"),
        input_item_count=_count(
            value.get("input_item_count"), "cycle_receipt_chain_invalid"
        ),
        output_item_count=_count(
            value.get("output_item_count"), "cycle_receipt_chain_invalid"
        ),
        canonical_bytes=bytes(raw),
    )


def _verify_chain(
    cycle_ordinal: int, receipts: tuple[StageReceiptView, ...]
) -> None:
    """Require one linear genesis-anchored chain with exactly-linked roots."""

    for index, receipt in enumerate(receipts):
        if receipt.cycle_ordinal != cycle_ordinal:
            _reject("cycle_receipt_foreign")
        if receipt.stage_ordinal != index:
            _reject("cycle_receipt_chain_invalid")
        if receipt.cycle_input_root != receipts[0].cycle_input_root:
            _reject("cycle_receipt_chain_invalid")
        if index == 0:
            if receipt.prior_receipt_id != GENESIS_RECEIPT_ID:
                _reject("stage_receipt_genesis_invalid")
            if receipt.input_root != receipt.cycle_input_root:
                _reject("cycle_receipt_chain_invalid")
        else:
            if receipt.prior_receipt_id != receipts[index - 1].receipt_id:
                _reject("cycle_receipt_chain_invalid")
            if receipt.input_root != receipts[index - 1].output_root:
                _reject("cycle_receipt_chain_invalid")
            if receipt.input_item_count != receipts[index - 1].output_item_count:
                _reject("cycle_receipt_chain_invalid")


@dataclass(frozen=True, slots=True)
class _CycleLedger:
    receipts_by_cycle: Mapping[int, tuple[StageReceiptView, ...]]
    abandoned_by_cycle: Mapping[int, str]
    capsule_inventory: tuple[tuple[str, str], ...]

    def snapshot(self, quota_totals: Mapping[str, int]) -> CycleInputSnapshot:
        totals = MappingProxyType(
            {str(tier): int(total) for tier, total in quota_totals.items()}
        )
        return CycleInputSnapshot(
            capsule_inventory=self.capsule_inventory,
            quota_totals=totals,
            input_root=derive_cycle_input_root(self.capsule_inventory, totals),
        )


class MetabolismCycle:
    """Generation-fenced coordinator for one metabolism cycle lifecycle."""

    __slots__ = (
        "_executors",
        "_fence_id",
        "_generation",
        "_recorded_at",
        "_store",
        "_writer_id",
    )

    def __init__(
        self,
        *,
        store: MetabolismStore,
        writer_id: str,
        acquired_at: str,
        executors: Mapping[StageKind, StageExecutor],
    ) -> None:
        if not isinstance(store, MetabolismStore):
            _reject("cycle_store_invalid")
        self._store = store
        self._writer_id = _identity(writer_id, "cycle_writer_invalid")
        # The sole timestamp this coordinator may stamp into rows: supplied
        # by the caller at construction, never read from a clock here.
        self._recorded_at = _utc_text(acquired_at, "cycle_recorded_at_invalid")
        if not isinstance(executors, Mapping):
            _reject("cycle_executor_set_invalid")
        closed = dict(executors)
        if set(closed) != set(StageKind):
            _reject("cycle_executor_set_invalid")
        for stage in StageKind:
            if not callable(closed[stage]):
                _reject("cycle_executor_invalid")
        self._executors = MappingProxyType(closed)
        self._fence_id: str | None = None
        self._generation: int | None = None

    @property
    def fence_id(self) -> str | None:
        return self._fence_id

    @property
    def generation(self) -> int | None:
        return self._generation

    def acquire_fence(self) -> FenceSnapshot:
        """Acquire the genesis fence or the advanced successor generation.

        Mirrors ``agent_orchestration._advance_fence``: the new fence binds
        generation ``current + 1`` (or 0 at genesis) to this writer, so any
        writer still holding the prior fence rejects typed on its next append.
        """

        if self._fence_id is not None:
            _reject("cycle_fence_already_acquired")
        try:
            current = self._store.fence_snapshot(METABOLISM_CYCLE_STREAM_ID)
        except MetabolismStoreRejection as error:
            if error.code != "metabolism_fence_unknown":
                raise
            current = None
        generation = 0 if current is None else current.generation + 1
        prior_fence_id = ZERO_SHA256 if current is None else current.fence_id
        fence_value = {
            "acquired_at": self._recorded_at,
            "generation": generation,
            "prior_fence_id": prior_fence_id,
            "schema_version": "skeleton.metabolism-cycle-fence.v1",
            "stream_id": METABOLISM_CYCLE_STREAM_ID,
            "writer_id": self._writer_id,
        }
        raw = canonicalize(fence_value)
        fence_id = metabolism_record_identity("fence", raw)
        self._store.acquire_fence(
            FenceAppend(
                fence_id,
                METABOLISM_CYCLE_STREAM_ID,
                generation,
                self._writer_id,
                prior_fence_id,
                self._recorded_at,
                raw,
            ),
            operation_id=_operation_id(
                generation=generation,
                operation="fence",
                stream_id=METABOLISM_CYCLE_STREAM_ID,
                writer_id=self._writer_id,
            ),
        )
        self._fence_id = fence_id
        self._generation = generation
        return FenceSnapshot(
            METABOLISM_CYCLE_STREAM_ID, fence_id, generation, self._writer_id
        )

    def snapshot_inputs(self) -> CycleInputSnapshot:
        """Snapshot capsule inventory plus quota state into one exact root."""

        return self._read_ledger().snapshot(self._store.quota_totals())

    def run_cycle(self, cycle_ordinal: int) -> CycleCompleted:
        """Walk all six stages of one fresh cycle under the current fence."""

        ordinal = _count(cycle_ordinal, "cycle_ordinal_invalid")
        self._require_fence()
        ledger = self._read_ledger()
        self._require_fresh_ordinal(ordinal, ledger)
        snapshot = ledger.snapshot(self._store.quota_totals())
        return self._walk(ordinal, snapshot, (), attempt_ordinal=1)

    def resume_cycle(self, cycle_ordinal: int) -> CycleCompleted | CycleAbandoned:
        """Resume from the last committed stage receipt or abandon typed.

        A committed stage never re-runs: the walk continues from the first
        missing stage.  If the re-derived input root no longer matches the
        committed ``cycle_input_root``, the cycle terminally abandons with a
        typed, fence-stamped deferred disposition instead of silently
        continuing against changed inputs.
        """

        ordinal = _count(cycle_ordinal, "cycle_ordinal_invalid")
        self._require_fence()
        ledger = self._read_ledger()
        if ordinal in ledger.abandoned_by_cycle:
            _reject("cycle_abandoned_terminal")
        committed = ledger.receipts_by_cycle.get(ordinal, ())
        if not committed:
            self._require_fresh_ordinal(ordinal, ledger)
            snapshot = ledger.snapshot(self._store.quota_totals())
            return self._walk(ordinal, snapshot, (), attempt_ordinal=1)
        _verify_chain(ordinal, committed)
        snapshot = ledger.snapshot(self._store.quota_totals())
        if len(committed) == METABOLISM_STAGE_COUNT:
            return CycleCompleted(
                identity=CycleIdentity(
                    ordinal,
                    committed[0].cycle_input_root,
                    derive_cycle_identity(ordinal, committed[0].cycle_input_root),
                ),
                receipts=committed,
                resumed_from_stage_ordinal=None,
                attempt_ordinal=max(item.attempt_ordinal for item in committed),
            )
        attempt = max(item.attempt_ordinal for item in committed) + 1
        if snapshot.input_root != committed[0].cycle_input_root:
            return self._abandon(
                ordinal,
                snapshot.input_root,
                DeferralReason.STAGE_TIMEOUT,
                attempt_ordinal=attempt,
            )
        return self._walk(ordinal, snapshot, committed, attempt_ordinal=attempt)

    def abandon_cycle(
        self, cycle_ordinal: int, reason: DeferralReason
    ) -> CycleAbandoned:
        """Explicitly and terminally abandon one unfinished cycle, typed."""

        ordinal = _count(cycle_ordinal, "cycle_ordinal_invalid")
        self._require_fence()
        if not isinstance(reason, DeferralReason):
            _reject("cycle_abandon_reason_invalid")
        ledger = self._read_ledger()
        if ordinal in ledger.abandoned_by_cycle:
            _reject("cycle_abandoned_terminal")
        committed = ledger.receipts_by_cycle.get(ordinal, ())
        if len(committed) == METABOLISM_STAGE_COUNT:
            _reject("cycle_already_complete")
        snapshot = ledger.snapshot(self._store.quota_totals())
        attempt = (
            max(item.attempt_ordinal for item in committed) + 1 if committed else 1
        )
        return self._abandon(
            ordinal, snapshot.input_root, reason, attempt_ordinal=attempt
        )

    def _require_fence(self) -> tuple[str, int]:
        if self._fence_id is None or self._generation is None:
            _reject("cycle_fence_missing")
        return self._fence_id, self._generation

    def _require_fresh_ordinal(self, ordinal: int, ledger: _CycleLedger) -> None:
        resolved: set[int] = set(ledger.abandoned_by_cycle)
        partial: set[int] = set()
        highest = -1
        for existing, receipts in ledger.receipts_by_cycle.items():
            highest = max(highest, existing)
            if len(receipts) == METABOLISM_STAGE_COUNT:
                resolved.add(existing)
            elif existing not in ledger.abandoned_by_cycle:
                partial.add(existing)
        highest = max((highest, *ledger.abandoned_by_cycle), default=highest)
        if ordinal in partial:
            _reject("cycle_resume_required")
        if ordinal in resolved:
            _reject("cycle_ordinal_duplicate")
        if partial:
            _reject("cycle_resume_required")
        expected = highest + 1
        if ordinal < expected:
            _reject("cycle_ordinal_duplicate")
        if ordinal > expected:
            _reject("cycle_ordinal_gap")

    def _read_ledger(self) -> _CycleLedger:
        receipts: dict[int, list[StageReceiptView]] = {}
        abandoned: dict[int, str] = {}
        inventory: list[tuple[str, str]] = []
        for table, record_id, declared_sha256, raw in self._store.replay_verify().records:
            if table == "memory_capsules":
                inventory.append((str(record_id), str(declared_sha256)))
            elif table == "metabolism_stage_receipts":
                view = _receipt_view(str(record_id), raw)
                receipts.setdefault(view.cycle_ordinal, []).append(view)
            elif table == "memory_dispositions":
                try:
                    value = parse_raw_json(raw)
                except Exception as error:
                    raise MetabolismCycleRejection(
                        "cycle_ledger_invalid"
                    ) from error
                if (
                    isinstance(value, dict)
                    and value.get("disposition")
                    == DispositionKind.DISPOSITION_DEFERRED.value
                    and type(value.get("cycle_ordinal")) is int
                    and value.get("encounter_id")
                    == abandonment_encounter_id(int(value["cycle_ordinal"]))
                ):
                    abandoned[int(value["cycle_ordinal"])] = str(
                        value.get("disposition_id")
                    )
        ordered = {
            ordinal: tuple(sorted(views, key=lambda view: view.stage_ordinal))
            for ordinal, views in receipts.items()
        }
        for ordinal, views in ordered.items():
            if len({view.stage_ordinal for view in views}) != len(views):
                _reject("cycle_receipt_chain_invalid")
        return _CycleLedger(
            receipts_by_cycle=MappingProxyType(ordered),
            abandoned_by_cycle=MappingProxyType(abandoned),
            capsule_inventory=tuple(sorted(inventory)),
        )

    def _walk(
        self,
        ordinal: int,
        snapshot: CycleInputSnapshot,
        committed: tuple[StageReceiptView, ...],
        *,
        attempt_ordinal: int,
    ) -> CycleCompleted:
        fence_id, generation = self._require_fence()
        views = list(committed)
        if views:
            prior_receipt_id = views[-1].receipt_id
            input_root = views[-1].output_root
            input_item_count = views[-1].output_item_count
        else:
            prior_receipt_id = GENESIS_RECEIPT_ID
            input_root = snapshot.input_root
            input_item_count = snapshot.item_count
        for stage_ordinal in range(len(views), METABOLISM_STAGE_COUNT):
            stage = StageKind(METABOLISM_STAGE_ORDER[stage_ordinal])
            request = StageRequest(
                cycle_ordinal=ordinal,
                cycle_input_root=snapshot.input_root,
                stage=stage,
                stage_ordinal=stage_ordinal,
                input_root=input_root,
                input_item_count=input_item_count,
            )
            try:
                result = self._executors[stage](request)
            except MetabolismCycleRejection:
                raise
            except BaseException as error:
                raise MetabolismCycleRejection("stage_executor_failed") from error
            if not isinstance(result, StageResult):
                _reject("stage_executor_output_invalid")
            output_root = _identity(
                result.output_root, "stage_executor_output_invalid"
            )
            output_item_count = _count(
                result.output_item_count, "stage_executor_output_invalid"
            )
            receipt_id, raw = build_stage_receipt_document(
                cycle_ordinal=ordinal,
                cycle_input_root=snapshot.input_root,
                fence_id=fence_id,
                generation=generation,
                attempt_ordinal=attempt_ordinal,
                stage_ordinal=stage_ordinal,
                prior_receipt_id=prior_receipt_id,
                input_root=input_root,
                output_root=output_root,
                input_item_count=input_item_count,
                output_item_count=output_item_count,
            )
            row_id = metabolism_record_identity("stage_receipt", raw)
            self._store.append_stage_receipt(
                StageReceiptAppend(
                    row_id,
                    ordinal,
                    stage.value,
                    input_root,
                    output_root,
                    fence_id,
                    generation,
                    attempt_ordinal,
                    self._recorded_at,
                    raw,
                ),
                writer_id=self._writer_id,
                operation_id=_operation_id(
                    attempt_ordinal=attempt_ordinal,
                    cycle_ordinal=ordinal,
                    generation=generation,
                    operation="stage_receipt",
                    stage=stage.value,
                ),
            )
            views.append(_receipt_view(row_id, raw))
            prior_receipt_id = receipt_id
            input_root = output_root
            input_item_count = output_item_count
        receipts = tuple(views)
        _verify_chain(ordinal, receipts)
        return CycleCompleted(
            identity=CycleIdentity(
                ordinal,
                snapshot.input_root,
                derive_cycle_identity(ordinal, snapshot.input_root),
            ),
            receipts=receipts,
            resumed_from_stage_ordinal=len(committed) if committed else None,
            attempt_ordinal=attempt_ordinal,
        )

    def _abandon(
        self,
        ordinal: int,
        input_root: str,
        reason: DeferralReason,
        *,
        attempt_ordinal: int,
    ) -> CycleAbandoned:
        fence_id, generation = self._require_fence()
        encounter_id = abandonment_encounter_id(ordinal)
        value: dict[str, object] = {
            "schema_version": DISPOSITION_SCHEMA_VERSION,
            "record_type": "encounter_disposition",
            "disposition_id": ZERO_SHA256,
            "encounter_id": encounter_id,
            "cycle_ordinal": ordinal,
            "cycle_input_root": input_root,
            "fence_id": fence_id,
            "generation": generation,
            "attempt_ordinal": attempt_ordinal,
            "disposition": DispositionKind.DISPOSITION_DEFERRED.value,
            "capsule_id": NONE_SENTINEL,
            "artifact_id": NONE_SENTINEL,
            "gate_receipt_id": NONE_SENTINEL,
            "residue_snapshot_id": NONE_SENTINEL,
            "erasure_decision_id": NONE_SENTINEL,
            "deferral_reason": reason.value,
        }
        disposition_id = compute_disposition_identity(value)
        value["disposition_id"] = disposition_id
        self._store.append_disposition(
            DispositionAppend(canonicalize(value), self._recorded_at),
            writer_id=self._writer_id,
            operation_id=_operation_id(
                cycle_ordinal=ordinal,
                generation=generation,
                operation="cycle_abandon",
                reason=reason.value,
            ),
        )
        return CycleAbandoned(
            cycle_ordinal=ordinal,
            input_root=input_root,
            disposition_id=disposition_id,
            encounter_id=encounter_id,
            reason=reason,
            fence_id=fence_id,
            generation=generation,
            attempt_ordinal=attempt_ordinal,
        )


__all__ = [
    "CycleAbandoned",
    "CycleCompleted",
    "CycleIdentity",
    "CycleInputSnapshot",
    "GENESIS_RECEIPT_ID",
    "METABOLISM_CYCLE_STREAM_ID",
    "METABOLISM_STAGE_COUNT",
    "METABOLISM_STAGE_ORDER",
    "MetabolismCycle",
    "MetabolismCycleRejection",
    "StageExecutor",
    "StageReceiptView",
    "StageRequest",
    "StageResult",
    "abandonment_encounter_id",
    "build_stage_receipt_document",
    "derive_cycle_identity",
    "derive_cycle_input_root",
    "passthrough_stage_executors",
]
