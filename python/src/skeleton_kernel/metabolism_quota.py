"""Retention scoring, quota tiers, the pressure ladder, and gate-guarded
pruning for Phase 12 memory metabolism (Plan 12-11; MEM-15, MEM-18).

This module owns three closed deterministic surfaces:

``retention_score`` / ``rank_retention``
    The versioned pure scoring function ``skeleton.memory-retention.v1``
    over a closed integer feature tuple (recency ordinal supplied by the
    cycle — never a wall clock — retrieval-hit count, surprise presence,
    provenance-class weight) combined with frozen module-constant
    :class:`fractions.Fraction` weights into one exact ``Fraction`` score.
    A ``compression_exempt`` or ``pinned`` capsule scores infinite
    retention.  Ordering is the total order ``(score, capsule_id)``: equal
    scores break on content identity, so ties are impossible for distinct
    capsules and permuted inputs rank byte-identically.

``QuotaLadder``
    Exact integer per-tier byte accounting over writer-measured store
    quota events under the frozen per-tier quotas and the const total
    ceiling ``274877906944``.  Utilization is exact integer per-mille,
    mapped through the frozen ``PRESSURE_BAND_FLOORS_PER_MILLE`` table to
    the closed pressure actions: ``none -> admit``,
    ``soft -> schedule_metabolize_first`` (a schema-valid quota event with
    zero committed delta), ``hard -> prune_lowest_retention`` (a bounded
    batch), ``ceiling -> reject admission`` typed
    ``quota_ceiling_exceeded``.  Accounting, disposition, and audit
    appends are structurally ``pressure_exempt`` per the published
    ``memory-quota`` schema and are never rejected for pressure — only
    exact arithmetic bounds (a negative tier total, a crossed tier quota
    or total ceiling) can reject them.

``plan_prune``
    Deterministic lowest-retention-first pruning decisions, bounded by an
    integer batch limit.  Each decision either routes a capsule to residue
    eviction (a fossil-tier ``residue_eviction`` quota event plus the
    ``statistical_residue`` disposition, exactly the accountant's
    ``DISPOSITION_QUOTA_BINDING``) or skips typed when the capsule is
    ``compression_exempt`` or ``pinned``.  A decision that would touch a
    capsule whose replacement lacks a complete all-pass gate receipt is
    rejected typed ``gate_receipt_required``.  This module never deletes,
    tombstones, or writes a row: it emits append-only quota-event values
    and typed decision records the caller executes through the sole
    writer and the 12-07 accountant.

Storage pressure changes retention, never correctness.  Deterministic and
typed throughout: no wall clock, no float, no randomness, no unsorted
iteration; every rejection carries a closed snake_case code.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from fractions import Fraction
from types import MappingProxyType
from typing import Any

from .canonical import canonicalize
from .memory_types import ProvenanceClass
from .metabolism_accounting import DISPOSITION_QUOTA_BINDING
from .metabolism_store import QuotaEventAppend, metabolism_record_identity
from .metabolism_types import (
    DispositionKind,
    QuotaCause,
    QuotaTier,
    SAFE_INTEGER_MAX,
    compute_phase12_identity,
)


# ---------------------------------------------------------------------------
# Frozen retention profile ``skeleton.memory-retention.v1``
# ---------------------------------------------------------------------------

RETENTION_PROFILE_ID = "skeleton.memory-retention.v1"
RETENTION_INFINITE = "infinite"

# Frozen exact Fraction weights.  Changing any value is a new profile
# version, never an in-place edit: scores are sealed evidence.
RETENTION_WEIGHT_RECENCY = Fraction(3, 2)
RETENTION_WEIGHT_RETRIEVAL_HIT = Fraction(5, 2)
RETENTION_WEIGHT_SURPRISE = Fraction(7, 1)
RETENTION_PROVENANCE_WEIGHTS: Mapping[ProvenanceClass, Fraction] = MappingProxyType(
    {
        ProvenanceClass.VERIFIED_REAL: Fraction(21, 1),
        ProvenanceClass.DERIVED_REAL: Fraction(13, 1),
        ProvenanceClass.OWNER_ASSERTED: Fraction(8, 1),
        ProvenanceClass.SEEDED_TEST: Fraction(5, 1),
        ProvenanceClass.FIXTURE: Fraction(3, 1),
        ProvenanceClass.SIMULATED: Fraction(2, 1),
        ProvenanceClass.SYNTHETIC: Fraction(1, 1),
        ProvenanceClass.UNKNOWN: Fraction(0, 1),
    }
)

# ---------------------------------------------------------------------------
# Frozen quota tiers, per-tier quotas, and the const total ceiling
# ---------------------------------------------------------------------------

QUOTA_SCHEMA_VERSION = "skeleton.memory-quota.v1"
SKELETON_PHASE12_QUOTA_V1 = "SKELETON_PHASE12_QUOTA_V1"
QUOTA_MEASUREMENT = "canonical_blob_length_in_transaction"

TOTAL_CEILING_BYTES = 274_877_906_944  # const per the published schema

# Frozen per-tier byte quotas partitioning the total ceiling exactly.
QUOTA_TIER_QUOTA_BYTES: Mapping[QuotaTier, int] = MappingProxyType(
    {
        QuotaTier.HOT: 137_438_953_472,
        QuotaTier.WARM: 68_719_476_736,
        QuotaTier.ADAPTER: 34_359_738_368,
        QuotaTier.FOSSIL: 34_359_738_368,
    }
)
assert sum(QUOTA_TIER_QUOTA_BYTES.values()) == TOTAL_CEILING_BYTES

# New content admission is a low-tier event; adapter and fossil bytes
# arrive only through compression, demotion, and eviction accounting.
LOW_QUOTA_TIERS = (QuotaTier.HOT, QuotaTier.WARM)

CONTENT_ADMISSION_APPEND_CLASS = "content_admission"
PRESSURE_EXEMPT_APPEND_CLASSES = (
    "accounting_append",
    "disposition_append",
    "audit_append",
)

OUTCOME_APPLIED = "applied"
OUTCOME_METABOLIZE_FIRST = "metabolize_first"


class PressureBand(StrEnum):
    """The four closed utilization bands of the pressure ladder."""

    NONE = "none"
    SOFT = "soft"
    HARD = "hard"
    CEILING = "ceiling"


class PressureAction(StrEnum):
    """The closed action each pressure band selects."""

    ADMIT = "admit"
    SCHEDULE_METABOLIZE_FIRST = "schedule_metabolize_first"
    PRUNE_LOWEST_RETENTION = "prune_lowest_retention"
    REJECT_ADMISSION = "reject_admission"


# Frozen inclusive per-mille lower bounds, ascending.
PRESSURE_BAND_FLOORS_PER_MILLE: Mapping[PressureBand, int] = MappingProxyType(
    {
        PressureBand.NONE: 0,
        PressureBand.SOFT: 700,
        PressureBand.HARD: 850,
        PressureBand.CEILING: 1000,
    }
)
PRESSURE_BAND_ACTIONS: Mapping[PressureBand, PressureAction] = MappingProxyType(
    {
        PressureBand.NONE: PressureAction.ADMIT,
        PressureBand.SOFT: PressureAction.SCHEDULE_METABOLIZE_FIRST,
        PressureBand.HARD: PressureAction.PRUNE_LOWEST_RETENTION,
        PressureBand.CEILING: PressureAction.REJECT_ADMISSION,
    }
)
# Frozen demotion-threshold rows: rising utilization raises the cutoff a
# finite score must clear to stay resident, so more content metabolizes
# sooner.  Pressure moves these thresholds — never correctness.
RETENTION_THRESHOLD_ROWS: Mapping[PressureBand, Fraction] = MappingProxyType(
    {
        PressureBand.NONE: Fraction(0, 1),
        PressureBand.SOFT: Fraction(5, 2),
        PressureBand.HARD: Fraction(15, 2),
        PressureBand.CEILING: Fraction(45, 2),
    }
)

# The accountant's disposition/quota binding for residue eviction: the
# ``statistical_residue`` disposition accounts into the fossil tier under
# the ``residue_eviction`` cause (D-17).
EVICTION_DISPOSITION = DispositionKind.STATISTICAL_RESIDUE
EVICTION_TIER, EVICTION_CAUSE = DISPOSITION_QUOTA_BINDING[EVICTION_DISPOSITION]
assert (EVICTION_TIER, EVICTION_CAUSE) == ("fossil", "residue_eviction")

GATE_COMPLETENESS_COMPLETE = "complete"
GATE_COMPLETENESS_PARTIAL = "partial"

# Prune decision kinds and their closed typed codes.
PRUNE_DECISION_EVICT = "evict_to_residue"
PRUNE_DECISION_SKIP = "skip"
PRUNE_DECISION_REJECT = "reject"
CLOSED_PRUNE_DECISION_KINDS = (
    PRUNE_DECISION_EVICT,
    PRUNE_DECISION_REJECT,
    PRUNE_DECISION_SKIP,
)
PRUNE_CODE_SCHEDULED = "residue_eviction_scheduled"
PRUNE_CODE_SKIP_EXEMPT = "prune_skip_compression_exempt"
PRUNE_CODE_SKIP_PINNED = "prune_skip_pinned"
PRUNE_CODE_GATE_RECEIPT_REQUIRED = "gate_receipt_required"
CLOSED_PRUNE_DECISION_CODES = (
    PRUNE_CODE_GATE_RECEIPT_REQUIRED,
    PRUNE_CODE_SKIP_EXEMPT,
    PRUNE_CODE_SKIP_PINNED,
    PRUNE_CODE_SCHEDULED,
)

CLOSED_QUOTA_REJECTION_CODES = (
    "prune_batch_limit_invalid",
    "prune_candidates_invalid",
    "prune_decision_invalid",
    "prune_gate_evidence_invalid",
    "quota_admission_tier_invalid",
    "quota_append_class_invalid",
    "quota_cause_unknown",
    "quota_ceiling_exceeded",
    "quota_context_invalid",
    "quota_delta_float_forbidden",
    "quota_delta_invalid",
    "quota_delta_negative",
    "quota_tier_quota_exceeded",
    "quota_tier_unknown",
    "quota_total_negative",
    "quota_totals_invalid",
    "quota_utilization_invalid",
    "retention_duplicate_capsule",
    "retention_input_bounds_exceeded",
    "retention_input_float_forbidden",
    "retention_input_negative",
    "retention_input_type_invalid",
    "retention_provenance_unknown",
    "retention_view_invalid",
)


class MetabolismQuotaRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise MetabolismQuotaRejection(code)


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


def _exact_nonnegative(value: object, code: str) -> int:
    if type(value) is not int or not 0 <= value <= SAFE_INTEGER_MAX:
        _reject(code)
    return int(value)


# ---------------------------------------------------------------------------
# Retention scoring
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CapsuleRetentionView:
    """The closed per-capsule feature tuple the cycle supplies for scoring.

    ``recency_ordinal`` is a cycle-supplied ordinal (higher is more
    recent); no wall-clock value ever enters a score.
    """

    capsule_id: str
    recency_ordinal: int
    retrieval_hits: int
    surprise_present: bool
    provenance_class: ProvenanceClass | str
    compression_exempt: bool
    pinned: bool


@dataclass(frozen=True, slots=True)
class RetentionScore:
    """One sealed exact score with its total-order sort key."""

    capsule_id: str
    profile_id: str
    infinite: bool
    score: Fraction

    @property
    def sort_key(self) -> tuple[int, Fraction, str]:
        """Ascending retention order; ``capsule_id`` makes ties impossible."""

        return (1 if self.infinite else 0, self.score, self.capsule_id)

    @property
    def serialized(self) -> str:
        """Exact fraction-string serialization; no float representation."""

        if self.infinite:
            return RETENTION_INFINITE
        return f"{self.score.numerator}/{self.score.denominator}"


def _retention_feature(value: object, code_prefix: str = "retention_input") -> int:
    if isinstance(value, bool):
        _reject(f"{code_prefix}_type_invalid")
    if isinstance(value, float):
        _reject(f"{code_prefix}_float_forbidden")
    if type(value) is not int:
        _reject(f"{code_prefix}_type_invalid")
    if value < 0:
        _reject(f"{code_prefix}_negative")
    if value > SAFE_INTEGER_MAX:
        _reject(f"{code_prefix}_bounds_exceeded")
    return int(value)


def _retention_flag(value: object) -> bool:
    if not isinstance(value, bool):
        _reject("retention_input_type_invalid")
    return bool(value)


def retention_score(capsule_view: CapsuleRetentionView) -> RetentionScore:
    """Score one capsule under the frozen ``skeleton.memory-retention.v1``.

    Pure and exact: integer features combined with frozen ``Fraction``
    weights.  A ``compression_exempt`` or ``pinned`` capsule scores
    infinite retention and can never be selected for pruning.
    """

    if not isinstance(capsule_view, CapsuleRetentionView):
        _reject("retention_view_invalid")
    capsule_id = _identity(capsule_view.capsule_id, "retention_view_invalid")
    recency = _retention_feature(capsule_view.recency_ordinal)
    hits = _retention_feature(capsule_view.retrieval_hits)
    surprise = _retention_flag(capsule_view.surprise_present)
    exempt = _retention_flag(capsule_view.compression_exempt)
    pinned = _retention_flag(capsule_view.pinned)
    try:
        provenance = ProvenanceClass(capsule_view.provenance_class)
    except (TypeError, ValueError) as error:
        raise MetabolismQuotaRejection("retention_provenance_unknown") from error

    if exempt or pinned:
        return RetentionScore(
            capsule_id=capsule_id,
            profile_id=RETENTION_PROFILE_ID,
            infinite=True,
            score=Fraction(0, 1),
        )
    score = (
        RETENTION_WEIGHT_RECENCY * recency
        + RETENTION_WEIGHT_RETRIEVAL_HIT * hits
        + RETENTION_WEIGHT_SURPRISE * (1 if surprise else 0)
        + RETENTION_PROVENANCE_WEIGHTS[provenance]
    )
    return RetentionScore(
        capsule_id=capsule_id,
        profile_id=RETENTION_PROFILE_ID,
        infinite=False,
        score=score,
    )


def rank_retention(
    capsule_views: Sequence[CapsuleRetentionView],
) -> tuple[RetentionScore, ...]:
    """Rank views ascending by ``(score, capsule_id)`` — a total order.

    Duplicate capsule identities reject typed, so ties are structurally
    impossible and any permutation of the input ranks identically.
    """

    if not isinstance(capsule_views, (list, tuple)):
        _reject("retention_view_invalid")
    scores = tuple(retention_score(view) for view in capsule_views)
    seen: set[str] = set()
    for score in scores:
        if score.capsule_id in seen:
            _reject("retention_duplicate_capsule")
        seen.add(score.capsule_id)
    return tuple(sorted(scores, key=lambda item: item.sort_key))


# ---------------------------------------------------------------------------
# Pressure bands
# ---------------------------------------------------------------------------


def band_for_utilization(per_mille: object) -> PressureBand:
    """Map exact per-mille utilization through the frozen band floors."""

    if isinstance(per_mille, bool) or type(per_mille) is not int:
        _reject("quota_utilization_invalid")
    if not 0 <= per_mille <= 1000:
        _reject("quota_utilization_invalid")
    selected = PressureBand.NONE
    for band, floor in PRESSURE_BAND_FLOORS_PER_MILLE.items():
        if per_mille >= floor:
            selected = band
    return selected


# ---------------------------------------------------------------------------
# Quota events and the ladder
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QuotaEventRecord:
    """One sealed schema-valid ``skeleton.memory-quota.v1`` event.

    ``quota_event_id`` is the document's domain-framed content identity;
    ``row_id`` is the sole-writer store row identity for the same bytes.
    """

    quota_event_id: str
    row_id: str
    tier: QuotaTier
    cause: QuotaCause
    append_class: str
    pressure_exempt: bool
    outcome: str
    attempted_delta_bytes: int
    committed_delta_bytes: int
    utilization_per_mille: int
    band: PressureBand
    value: Mapping[str, Any]
    canonical_bytes: bytes


def quota_event_append(
    record: QuotaEventRecord, *, recorded_at: str
) -> QuotaEventAppend:
    """Build the sole-writer append row for one sealed quota event."""

    if not isinstance(record, QuotaEventRecord):
        _reject("prune_decision_invalid")
    return QuotaEventAppend(
        quota_event_id=record.row_id,
        tier=record.tier.value,
        cause=record.cause.value,
        byte_delta=record.committed_delta_bytes,
        fence_id=str(record.value["fence_id"]),
        generation=int(record.value["generation"]),
        attempt_ordinal=int(record.value["attempt_ordinal"]),
        recorded_at=recorded_at,
        canonical_bytes=record.canonical_bytes,
    )


def _delta(value: object, *, allow_negative: bool, allow_zero: bool) -> int:
    if isinstance(value, bool):
        _reject("quota_delta_invalid")
    if isinstance(value, float):
        _reject("quota_delta_float_forbidden")
    if type(value) is not int:
        _reject("quota_delta_invalid")
    if value < 0 and not allow_negative:
        _reject("quota_delta_negative")
    if value == 0 and not allow_zero:
        _reject("quota_delta_invalid")
    if not -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX:
        _reject("quota_delta_invalid")
    return int(value)


class QuotaLadder:
    """Exact per-tier accounting plus the deterministic pressure ladder.

    The ladder is bound to one cycle context and seeded from
    writer-measured store totals (``MetabolismStore.quota_totals``).  It
    emits sealed schema-valid quota-event values; it never writes a row
    itself — the caller appends each event through the sole writer.
    """

    __slots__ = (
        "_attempt_ordinal",
        "_cycle_input_root",
        "_cycle_ordinal",
        "_fence_id",
        "_generation",
        "_totals",
    )

    def __init__(
        self,
        *,
        cycle_ordinal: int,
        cycle_input_root: str,
        fence_id: str,
        generation: int,
        attempt_ordinal: int,
        tier_totals: Mapping[str, int] | None = None,
    ) -> None:
        self._cycle_ordinal = _exact_nonnegative(cycle_ordinal, "quota_context_invalid")
        self._cycle_input_root = _identity(cycle_input_root, "quota_context_invalid")
        self._fence_id = _identity(fence_id, "quota_context_invalid")
        self._generation = _exact_nonnegative(generation, "quota_context_invalid")
        attempt = _exact_nonnegative(attempt_ordinal, "quota_context_invalid")
        if attempt < 1:
            _reject("quota_context_invalid")
        self._attempt_ordinal = attempt
        self._totals = self._validated_totals(tier_totals)

    @staticmethod
    def _validated_totals(
        tier_totals: Mapping[str, int] | None,
    ) -> dict[QuotaTier, int]:
        if tier_totals is None:
            return {tier: 0 for tier in QuotaTier}
        if not isinstance(tier_totals, Mapping):
            _reject("quota_totals_invalid")
        keys = set()
        for key in tier_totals:
            try:
                keys.add(QuotaTier(key))
            except (TypeError, ValueError) as error:
                raise MetabolismQuotaRejection("quota_totals_invalid") from error
        if keys != set(QuotaTier) or len(tier_totals) != len(QuotaTier):
            _reject("quota_totals_invalid")
        totals: dict[QuotaTier, int] = {}
        for tier in QuotaTier:
            observed = tier_totals[tier.value if tier.value in tier_totals else tier]
            amount = _exact_nonnegative(observed, "quota_totals_invalid")
            if amount > QUOTA_TIER_QUOTA_BYTES[tier]:
                _reject("quota_totals_invalid")
            totals[tier] = amount
        if sum(totals.values()) > TOTAL_CEILING_BYTES:
            _reject("quota_totals_invalid")
        return totals

    # -- read surface -----------------------------------------------------

    def tier_totals(self) -> dict[str, int]:
        return {tier.value: self._totals[tier] for tier in QuotaTier}

    def total_bytes(self) -> int:
        return sum(self._totals.values())

    def utilization_per_mille(self) -> int:
        return (self.total_bytes() * 1000) // TOTAL_CEILING_BYTES

    def pressure_band(self) -> PressureBand:
        return band_for_utilization(self.utilization_per_mille())

    def pressure_action(self) -> PressureAction:
        return PRESSURE_BAND_ACTIONS[self.pressure_band()]

    def retention_threshold(self) -> Fraction:
        return RETENTION_THRESHOLD_ROWS[self.pressure_band()]

    # -- event authoring --------------------------------------------------

    def admit(self, *, tier: QuotaTier | str, attempted_delta_bytes: object) -> QuotaEventRecord:
        """Attempt one new low-tier content admission under pressure.

        ``none`` band admits with a committed ``applied`` event; ``soft``
        and ``hard`` bands fail closed to a typed ``metabolize_first``
        event with zero committed delta; the ``ceiling`` band — and any
        delta that would cross the total ceiling — rejects typed
        ``quota_ceiling_exceeded``.  Nothing ever grows past the ceiling
        and nothing is silently dropped or truncated.
        """

        selected = self._tier(tier)
        if selected not in LOW_QUOTA_TIERS:
            _reject("quota_admission_tier_invalid")
        delta = _delta(attempted_delta_bytes, allow_negative=False, allow_zero=False)
        band = self.pressure_band()
        if band is PressureBand.CEILING:
            _reject("quota_ceiling_exceeded")
        if self.total_bytes() + delta > TOTAL_CEILING_BYTES:
            _reject("quota_ceiling_exceeded")
        if band in (PressureBand.SOFT, PressureBand.HARD):
            return self._sealed_event(
                tier=selected,
                cause=QuotaCause.ADMISSION,
                append_class=CONTENT_ADMISSION_APPEND_CLASS,
                pressure_exempt=False,
                attempted_delta_bytes=delta,
                committed_delta_bytes=0,
                outcome=OUTCOME_METABOLIZE_FIRST,
                band=band,
            )
        if self._totals[selected] + delta > QUOTA_TIER_QUOTA_BYTES[selected]:
            _reject("quota_tier_quota_exceeded")
        return self._sealed_event(
            tier=selected,
            cause=QuotaCause.ADMISSION,
            append_class=CONTENT_ADMISSION_APPEND_CLASS,
            pressure_exempt=False,
            attempted_delta_bytes=delta,
            committed_delta_bytes=delta,
            outcome=OUTCOME_APPLIED,
            band=band,
        )

    def append_exempt(
        self,
        *,
        tier: QuotaTier | str,
        cause: QuotaCause | str,
        append_class: str,
        delta_bytes: object,
    ) -> QuotaEventRecord:
        """Author one pressure-exempt accounting/disposition/audit event.

        The pressure band is never consulted: at 1000 per-mille these
        appends still commit.  Only exact arithmetic bounds reject — a
        tier total below zero, a crossed tier quota, or a crossed total
        ceiling — and those are correctness bounds, not pressure.
        """

        selected = self._tier(tier)
        try:
            typed_cause = QuotaCause(cause)
        except (TypeError, ValueError) as error:
            raise MetabolismQuotaRejection("quota_cause_unknown") from error
        if append_class not in PRESSURE_EXEMPT_APPEND_CLASSES:
            _reject("quota_append_class_invalid")
        delta = _delta(delta_bytes, allow_negative=True, allow_zero=True)
        tier_after = self._totals[selected] + delta
        if tier_after < 0:
            _reject("quota_total_negative")
        if tier_after > QUOTA_TIER_QUOTA_BYTES[selected]:
            _reject("quota_tier_quota_exceeded")
        if self.total_bytes() + delta > TOTAL_CEILING_BYTES:
            _reject("quota_ceiling_exceeded")
        return self._sealed_event(
            tier=selected,
            cause=typed_cause,
            append_class=append_class,
            pressure_exempt=True,
            attempted_delta_bytes=delta,
            committed_delta_bytes=delta,
            outcome=OUTCOME_APPLIED,
            band=self.pressure_band(),
        )

    def record_eviction(self, decision: "PruneDecision") -> QuotaEventRecord:
        """Account one executed eviction decision as a fossil quota event.

        Uses the accountant binding for ``statistical_residue`` — fossil
        tier, ``residue_eviction`` cause — as a pressure-exempt
        disposition append.  The caller still appends the disposition
        itself through the 12-07 accountant; nothing is deleted here.
        """

        if (
            not isinstance(decision, PruneDecision)
            or decision.decision != PRUNE_DECISION_EVICT
            or decision.byte_count is None
        ):
            _reject("prune_decision_invalid")
        return self.append_exempt(
            tier=EVICTION_TIER,
            cause=EVICTION_CAUSE,
            append_class="disposition_append",
            delta_bytes=decision.byte_count,
        )

    # -- internals --------------------------------------------------------

    @staticmethod
    def _tier(tier: QuotaTier | str) -> QuotaTier:
        try:
            return QuotaTier(tier)
        except (TypeError, ValueError) as error:
            raise MetabolismQuotaRejection("quota_tier_unknown") from error

    def _sealed_event(
        self,
        *,
        tier: QuotaTier,
        cause: QuotaCause,
        append_class: str,
        pressure_exempt: bool,
        attempted_delta_bytes: int,
        committed_delta_bytes: int,
        outcome: str,
        band: PressureBand,
    ) -> QuotaEventRecord:
        tier_before = self._totals[tier]
        total_before = self.total_bytes()
        tier_after = tier_before + committed_delta_bytes
        total_after = total_before + committed_delta_bytes
        value: dict[str, Any] = {
            "schema_version": QUOTA_SCHEMA_VERSION,
            "record_type": "quota_event",
            "cycle_ordinal": self._cycle_ordinal,
            "cycle_input_root": self._cycle_input_root,
            "fence_id": self._fence_id,
            "generation": self._generation,
            "attempt_ordinal": self._attempt_ordinal,
            "tier": tier.value,
            "cause": cause.value,
            "append_class": append_class,
            "pressure_exempt": pressure_exempt,
            "measurement": QUOTA_MEASUREMENT,
            "tier_quota_bytes": QUOTA_TIER_QUOTA_BYTES[tier],
            "total_ceiling_bytes": TOTAL_CEILING_BYTES,
            "attempted_delta_bytes": attempted_delta_bytes,
            "committed_delta_bytes": committed_delta_bytes,
            "tier_bytes_before": tier_before,
            "tier_bytes_after": tier_after,
            "total_bytes_before": total_before,
            "total_bytes_after": total_after,
            "utilization_per_mille": (total_after * 1000) // TOTAL_CEILING_BYTES,
            "retention_threshold_version": RETENTION_PROFILE_ID,
            "outcome": outcome,
        }
        quota_event_id = compute_phase12_identity(
            SKELETON_PHASE12_QUOTA_V1, "quota_event_id", value
        )
        value["quota_event_id"] = quota_event_id
        raw = canonicalize(value)
        self._totals[tier] = tier_after
        return QuotaEventRecord(
            quota_event_id=quota_event_id,
            row_id=metabolism_record_identity("quota_event", raw),
            tier=tier,
            cause=cause,
            append_class=append_class,
            pressure_exempt=pressure_exempt,
            outcome=outcome,
            attempted_delta_bytes=attempted_delta_bytes,
            committed_delta_bytes=committed_delta_bytes,
            utilization_per_mille=int(value["utilization_per_mille"]),
            band=band,
            value=MappingProxyType(dict(value)),
            canonical_bytes=raw,
        )


# ---------------------------------------------------------------------------
# Gate-guarded pruning decisions
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PruneCandidate:
    """One capsule offered for pruning with its writer-measured bytes."""

    view: CapsuleRetentionView
    byte_count: int


@dataclass(frozen=True, slots=True)
class ReplacementGateEvidence:
    """The caller-supplied 12-12 replacement gate receipt for one capsule.

    Only a ``complete`` receipt whose five gates all passed and whose
    sampled/source coverage includes the capsule identity authorizes a
    pruning decision to touch that capsule.
    """

    gate_receipt_id: str
    artifact_id: str
    completeness: str
    all_gates_passed: bool
    covered_capsule_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PruneDecision:
    """One typed append-only pruning decision record.

    The caller executes eviction decisions through the sole writer and
    the accountant; skip and reject decisions execute nothing.  This
    module never deletes, tombstones, or overwrites a row.
    """

    decision: str
    code: str
    capsule_id: str
    retention_score: str
    tier: str | None
    cause: str | None
    disposition: str | None
    byte_count: int | None
    gate_receipt_id: str | None


def _validated_gate_evidence(
    gate_evidence: Mapping[str, ReplacementGateEvidence] | None,
) -> dict[str, ReplacementGateEvidence]:
    if gate_evidence is None:
        return {}
    if not isinstance(gate_evidence, Mapping):
        _reject("prune_gate_evidence_invalid")
    validated: dict[str, ReplacementGateEvidence] = {}
    for capsule_id, evidence in gate_evidence.items():
        key = _identity(capsule_id, "prune_gate_evidence_invalid")
        if not isinstance(evidence, ReplacementGateEvidence):
            _reject("prune_gate_evidence_invalid")
        _identity(evidence.gate_receipt_id, "prune_gate_evidence_invalid")
        _identity(evidence.artifact_id, "prune_gate_evidence_invalid")
        if evidence.completeness not in (
            GATE_COMPLETENESS_COMPLETE,
            GATE_COMPLETENESS_PARTIAL,
        ):
            _reject("prune_gate_evidence_invalid")
        if not isinstance(evidence.all_gates_passed, bool):
            _reject("prune_gate_evidence_invalid")
        if not isinstance(evidence.covered_capsule_ids, tuple) or not all(
            _is_sha256(item) for item in evidence.covered_capsule_ids
        ):
            _reject("prune_gate_evidence_invalid")
        validated[key] = evidence
    return validated


def _gate_receipt_authorizes(
    evidence: ReplacementGateEvidence | None, capsule_id: str
) -> bool:
    return (
        evidence is not None
        and evidence.completeness == GATE_COMPLETENESS_COMPLETE
        and evidence.all_gates_passed is True
        and capsule_id in evidence.covered_capsule_ids
    )


def plan_prune(
    candidates: Sequence[PruneCandidate],
    *,
    batch_limit: object,
    gate_evidence: Mapping[str, ReplacementGateEvidence] | None = None,
) -> tuple[PruneDecision, ...]:
    """Select lowest-retention capsules deterministically for demotion.

    Candidates are ranked ascending by ``(score, capsule_id)`` — a total
    order, so permuted inputs plan identically.  Walking that order:

    * a ``compression_exempt`` or ``pinned`` capsule (infinite retention)
      yields a typed skip decision and is never selected;
    * a capsule whose replacement carries a complete all-pass gate
      receipt covering it yields an eviction decision (fossil-tier
      ``residue_eviction`` accounting plus the ``statistical_residue``
      disposition, executed by the caller);
    * a capsule whose replacement lacks such a receipt — absent, partial,
      failed, or covering a different capsule — is rejected typed
      ``gate_receipt_required`` with nothing executed.

    The walk stops once ``batch_limit`` eviction decisions exist, so a
    prune batch is always bounded.
    """

    if isinstance(batch_limit, bool) or type(batch_limit) is not int:
        _reject("prune_batch_limit_invalid")
    if not 1 <= batch_limit <= SAFE_INTEGER_MAX:
        _reject("prune_batch_limit_invalid")
    if not isinstance(candidates, (list, tuple)):
        _reject("prune_candidates_invalid")
    evidence_by_capsule = _validated_gate_evidence(gate_evidence)

    scored: list[tuple[RetentionScore, PruneCandidate]] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not isinstance(candidate, PruneCandidate):
            _reject("prune_candidates_invalid")
        score = retention_score(candidate.view)
        if isinstance(candidate.byte_count, bool):
            _reject("prune_candidates_invalid")
        if isinstance(candidate.byte_count, float):
            _reject("quota_delta_float_forbidden")
        if type(candidate.byte_count) is not int:
            _reject("prune_candidates_invalid")
        if candidate.byte_count < 0:
            _reject("quota_delta_negative")
        if candidate.byte_count > SAFE_INTEGER_MAX:
            _reject("prune_candidates_invalid")
        if score.capsule_id in seen:
            _reject("retention_duplicate_capsule")
        seen.add(score.capsule_id)
        scored.append((score, candidate))
    scored.sort(key=lambda item: item[0].sort_key)

    decisions: list[PruneDecision] = []
    evictions = 0
    for score, candidate in scored:
        if evictions >= batch_limit:
            break
        view = candidate.view
        if score.infinite:
            code = (
                PRUNE_CODE_SKIP_EXEMPT
                if view.compression_exempt is True
                else PRUNE_CODE_SKIP_PINNED
            )
            decisions.append(
                PruneDecision(
                    decision=PRUNE_DECISION_SKIP,
                    code=code,
                    capsule_id=score.capsule_id,
                    retention_score=score.serialized,
                    tier=None,
                    cause=None,
                    disposition=None,
                    byte_count=None,
                    gate_receipt_id=None,
                )
            )
            continue
        evidence = evidence_by_capsule.get(score.capsule_id)
        if not _gate_receipt_authorizes(evidence, score.capsule_id):
            decisions.append(
                PruneDecision(
                    decision=PRUNE_DECISION_REJECT,
                    code=PRUNE_CODE_GATE_RECEIPT_REQUIRED,
                    capsule_id=score.capsule_id,
                    retention_score=score.serialized,
                    tier=None,
                    cause=None,
                    disposition=None,
                    byte_count=None,
                    gate_receipt_id=None,
                )
            )
            continue
        assert evidence is not None
        decisions.append(
            PruneDecision(
                decision=PRUNE_DECISION_EVICT,
                code=PRUNE_CODE_SCHEDULED,
                capsule_id=score.capsule_id,
                retention_score=score.serialized,
                tier=EVICTION_TIER,
                cause=EVICTION_CAUSE,
                disposition=EVICTION_DISPOSITION.value,
                byte_count=candidate.byte_count,
                gate_receipt_id=evidence.gate_receipt_id,
            )
        )
        evictions += 1
    return tuple(decisions)


__all__ = [
    "CLOSED_PRUNE_DECISION_CODES",
    "CLOSED_PRUNE_DECISION_KINDS",
    "CLOSED_QUOTA_REJECTION_CODES",
    "CONTENT_ADMISSION_APPEND_CLASS",
    "CapsuleRetentionView",
    "EVICTION_CAUSE",
    "EVICTION_DISPOSITION",
    "EVICTION_TIER",
    "GATE_COMPLETENESS_COMPLETE",
    "GATE_COMPLETENESS_PARTIAL",
    "LOW_QUOTA_TIERS",
    "MetabolismQuotaRejection",
    "OUTCOME_APPLIED",
    "OUTCOME_METABOLIZE_FIRST",
    "PRESSURE_BAND_ACTIONS",
    "PRESSURE_BAND_FLOORS_PER_MILLE",
    "PRESSURE_EXEMPT_APPEND_CLASSES",
    "PRUNE_CODE_GATE_RECEIPT_REQUIRED",
    "PRUNE_CODE_SCHEDULED",
    "PRUNE_CODE_SKIP_EXEMPT",
    "PRUNE_CODE_SKIP_PINNED",
    "PRUNE_DECISION_EVICT",
    "PRUNE_DECISION_REJECT",
    "PRUNE_DECISION_SKIP",
    "PressureAction",
    "PressureBand",
    "PruneCandidate",
    "PruneDecision",
    "QUOTA_MEASUREMENT",
    "QUOTA_SCHEMA_VERSION",
    "QUOTA_TIER_QUOTA_BYTES",
    "QuotaEventRecord",
    "QuotaLadder",
    "RETENTION_INFINITE",
    "RETENTION_PROFILE_ID",
    "RETENTION_PROVENANCE_WEIGHTS",
    "RETENTION_THRESHOLD_ROWS",
    "RETENTION_WEIGHT_RECENCY",
    "RETENTION_WEIGHT_RETRIEVAL_HIT",
    "RETENTION_WEIGHT_SURPRISE",
    "ReplacementGateEvidence",
    "RetentionScore",
    "SKELETON_PHASE12_QUOTA_V1",
    "TOTAL_CEILING_BYTES",
    "band_for_utilization",
    "plan_prune",
    "quota_event_append",
    "rank_retention",
    "retention_score",
]
