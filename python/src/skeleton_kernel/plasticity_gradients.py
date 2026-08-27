"""Gradient emission and the evaluated-effort gate for Phase 13 (PLT-02/03).

This module owns two closed surfaces over the sole-writer
``PlasticityStore`` append path:

``GradientEmitter``
    Builds one schema-valid ``ExperienceGradient`` document from typed
    evaluated-effort inputs (``EvaluatedEffortView``: organ invocation
    results, verifier verdicts, prediction/outcome, seven-counter integer
    budget costs) and appends it under the emitter's fence binding.  The
    emitting producer organ is recorded in the document, every listed
    verifier result must come from an organ other than the producer
    (``gradient_self_grading_forbidden`` — the structural D-08 inequality
    the published schema annotates), a resolved outcome requires at least
    one independent verifier result, an unresolved outcome structurally
    cannot permit the ``fast_weights`` learning target, and causal credit
    may name only action ordinals listed in the gradient's action
    inventory (``gradient_credit_unlisted_action``).  Emission is
    deterministic and idempotent: the operation identity is derived from
    the gradient identity, so replaying the same view appends nothing new.

``EvaluatedEffortGate``
    Derives exactly one ``ChannelUpdate`` per gradient.  The gate binds
    producer and grader organ identities (the grader is the canonically
    first ``FALSIFICATION`` or ``OUTCOME_JUDGMENT`` verifier result that
    actually evaluated), re-rejects ``producer == grader`` structurally,
    prechecks exactly-one at the gate layer
    (``gradient_already_channeled``) with the store's
    ``UNIQUE(gradient_id)`` constraint as the SQL backstop, and selects
    the channel by the frozen decision table below.  ``fast_weights``
    updates carry a delta identity reference only when the gradient's
    resolved branch permits it; the four non-factual channels carry a
    versioned-table reference plus one exact integer adjustment and can
    never carry a delta reference (``channel_update_delta_ref_forbidden``).

Frozen channel decision table (D-09, PLT-03)
--------------------------------------------

The channel is the FIRST entry of the outcome's priority row that is a
member of the gradient's ``permitted_learning_targets``; membership is the
only input, so any permutation of the same permitted set selects the same
channel.  The table is closed and frozen; an empty intersection is the
typed failure ``gradient_channel_unroutable``.

===========  ==============================================================
outcome      priority row (first permitted member wins)
===========  ==============================================================
success      fast_weights, retrieval, routing, experiment_selection,
             uncertainty
failure      fast_weights, uncertainty, retrieval, routing,
             experiment_selection
unresolved   uncertainty, retrieval, routing, experiment_selection
             (``fast_weights`` is unrepresentable in this row; an
             unresolved gradient that permits it is the typed failure
             ``gradient_unresolved_forbids_fast_weights``)
===========  ==============================================================

All appends flow through the injected ``PlasticityStore`` under the bound
fence/generation/writer accounting; a stale fence rejects typed at the
store layer.  This module reads no wall clock: ``recorded_at`` is
caller-provided canonical UTC text, and every rejection carries a closed
snake_case code.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType

from .agent_types import AgentOrgan
from .canonical import canonicalize
from .plasticity_store import (
    ChannelUpdateAppend,
    GradientAppend,
    OperationReceipt,
    PlasticityStore,
    learning_attempt_identity,
)
from .plasticity_types import (
    BUDGET_VECTOR_COUNTERS,
    CHANNEL_UPDATE_SCHEMA_VERSION,
    CLOSED_LEARNING_CHANNELS,
    ChannelUpdate,
    ExperienceGradient,
    GRADIENT_SCHEMA_VERSION,
    GradientOutcome,
    LearningChannel,
    NONE_SENTINEL,
    NONFACTUAL_LEARNING_CHANNELS,
    ORGAN_CANONICAL_ORDER,
    PlasticityTypeRejection,
    SKELETON_PHASE13_CHANNEL_UPDATE,
    SKELETON_PHASE13_GRADIENT,
    ScopeKind,
    VerifierVerdict,
    channel_update_from_raw,
    compute_channel_update_identity,
    compute_gradient_identity,
    gradient_from_raw,
)


# The closed grading organs: only OUTCOME_JUDGMENT or FALSIFICATION results
# may grade an evaluated pass, mirroring the Phase 11 falsification and
# Phase 12 gate-receipt disciplines (D-08).  Canonical organ order decides
# ties deterministically (falsification precedes outcome_judgment).
GRADING_ORGANS = (AgentOrgan.FALSIFICATION, AgentOrgan.OUTCOME_JUDGMENT)

# The frozen closed channel decision table documented in the module
# docstring: outcome -> priority row; first permitted member wins.
CHANNEL_DECISION_TABLE: Mapping[GradientOutcome, tuple[LearningChannel, ...]] = (
    MappingProxyType(
        {
            GradientOutcome.SUCCESS: (
                LearningChannel.FAST_WEIGHTS,
                LearningChannel.RETRIEVAL,
                LearningChannel.ROUTING,
                LearningChannel.EXPERIMENT_SELECTION,
                LearningChannel.UNCERTAINTY,
            ),
            GradientOutcome.FAILURE: (
                LearningChannel.FAST_WEIGHTS,
                LearningChannel.UNCERTAINTY,
                LearningChannel.RETRIEVAL,
                LearningChannel.ROUTING,
                LearningChannel.EXPERIMENT_SELECTION,
            ),
            GradientOutcome.UNRESOLVED: NONFACTUAL_LEARNING_CHANNELS,
        }
    )
)

# Per non-factual channel: the versioned-table reference member and the
# exact-integer adjustment member of its closed payload branch.
_NONFACTUAL_BINDING_MEMBERS: Mapping[LearningChannel, tuple[str, str]] = (
    MappingProxyType(
        {
            LearningChannel.UNCERTAINTY: (
                "calibration_table_version_id",
                "widen_permille",
            ),
            LearningChannel.RETRIEVAL: (
                "retrieval_table_version_id",
                "reweight_permille",
            ),
            LearningChannel.ROUTING: ("routing_table_version_id", "route_ordinal"),
            LearningChannel.EXPERIMENT_SELECTION: (
                "experiment_queue_version_id",
                "priority_ordinal",
            ),
        }
    )
)

_EMIT_OPERATION_DOMAIN = "SKELETON_PHASE13_GRADIENT_EMIT_OPERATION_V1"
_DERIVE_OPERATION_DOMAIN = "SKELETON_PHASE13_CHANNEL_DERIVE_OPERATION_V1"
_ATTEMPT_OPERATION_DOMAIN = "SKELETON_PHASE13_LEARNING_ATTEMPT_OPERATION_V1"


class PlasticityGradientRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise PlasticityGradientRejection(code)


def _typed(error: PlasticityTypeRejection) -> PlasticityGradientRejection:
    return PlasticityGradientRejection(error.code)


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


def _exact_int(value: object, code: str) -> int:
    if type(value) is not int:
        _reject(code)
    return int(value)


def _operation_identity(domain: str, record_identity: str) -> str:
    """Deterministic operation identity: framed digest of one record id."""

    domain_bytes = domain.encode("ascii", errors="strict")
    payload = record_identity.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def _encode_optional_text(value: str | None, code: str) -> dict[str, object]:
    if value is None:
        return {"present": False}
    if not isinstance(value, str) or not value:
        _reject(code)
    return {"present": True, "text": value}


@dataclass(frozen=True, slots=True)
class ActionRecord:
    """One ordinal-keyed action of the attempt's inventory."""

    action_ordinal: int
    description: str
    tool_evidence_id: str | None


@dataclass(frozen=True, slots=True)
class VerifierResult:
    """One independent verifier verdict bound to a receipt identity."""

    verifier_organ: AgentOrgan
    verdict: VerifierVerdict
    receipt_id: str


@dataclass(frozen=True, slots=True)
class CreditAssignment:
    """Causal credit over one listed action ordinal, in exact permille."""

    action_ordinal: int
    credit_permille: int


@dataclass(frozen=True, slots=True)
class EvaluatedEffortView:
    """The typed evaluated-effort inputs of exactly one completed attempt."""

    scope_kind: ScopeKind
    project_id: str | None
    objective: str
    pre_action_prediction: str | None
    retrieved_evidence_ids: tuple[str, ...]
    actions: tuple[ActionRecord, ...]
    verifier_results: tuple[VerifierResult, ...]
    outcome: GradientOutcome
    costs: Mapping[str, int]
    causal_credit: tuple[CreditAssignment, ...]
    repaired_or_counterfactual_trajectory: str | None
    permitted_learning_targets: tuple[LearningChannel, ...]
    producer_organ: AgentOrgan
    attempt_ordinal: int


@dataclass(frozen=True, slots=True)
class FenceBinding:
    """The store fence under which an emitter or gate appends."""

    fence_id: str
    generation: int
    writer_id: str


@dataclass(frozen=True, slots=True)
class ChannelBindings:
    """Per-channel reference material offered to one channel derivation.

    ``delta_id`` binds only the ``fast_weights`` branch; the four
    versioned-table references and their exact integer adjustments bind
    only their own non-factual branch.  Offering a delta reference to a
    non-factual derivation is the typed failure
    ``channel_update_delta_ref_forbidden``.
    """

    delta_id: str | None = None
    calibration_table_version_id: str | None = None
    widen_permille: int | None = None
    retrieval_table_version_id: str | None = None
    reweight_permille: int | None = None
    routing_table_version_id: str | None = None
    route_ordinal: int | None = None
    experiment_queue_version_id: str | None = None
    priority_ordinal: int | None = None


def authenticate_gradient_bytes(
    raw: bytes, registry: object | None = None
) -> ExperienceGradient:
    """Authenticate raw gradient bytes through this module's validation path.

    Sealed fixture cases replay through the same authority the emitter
    uses (``gradient_from_raw``), so a hostile fixture rejects with the
    exact typed code its corpus entry pins (for example
    ``gradient_self_grading_forbidden`` or
    ``gradient_credit_unlisted_action``).
    """

    try:
        return gradient_from_raw(raw, registry)
    except PlasticityTypeRejection as error:
        raise _typed(error) from error


def _scope_document(view: EvaluatedEffortView) -> dict[str, object]:
    if not isinstance(view.scope_kind, ScopeKind):
        _reject("gradient_scope_invalid")
    if view.scope_kind is ScopeKind.PROJECT:
        return {
            "scope_kind": view.scope_kind.value,
            "project_id": _sha256_field(view.project_id, "gradient_scope_invalid"),
        }
    if view.project_id is not None:
        _reject("gradient_scope_invalid")
    return {"scope_kind": view.scope_kind.value}


def _costs_document(costs: Mapping[str, int]) -> dict[str, int]:
    if not isinstance(costs, Mapping) or set(costs) != set(BUDGET_VECTOR_COUNTERS):
        _reject("gradient_costs_invalid")
    return {
        counter: _exact_int(costs[counter], "gradient_costs_invalid")
        for counter in BUDGET_VECTOR_COUNTERS
    }


def _verifier_documents(
    verifier_results: Sequence[VerifierResult], producer: AgentOrgan
) -> list[dict[str, object]]:
    entries: list[tuple[int, dict[str, object]]] = []
    for result in verifier_results:
        if not isinstance(result, VerifierResult):
            _reject("gradient_emit_input_invalid")
        if not isinstance(result.verifier_organ, AgentOrgan) or not isinstance(
            result.verdict, VerifierVerdict
        ):
            _reject("gradient_emit_input_invalid")
        if result.verifier_organ is producer:
            # The structural D-08 inequality: no producer may appear among
            # its own graders, even disguised beside independent entries.
            _reject("gradient_self_grading_forbidden")
        entries.append(
            (
                ORGAN_CANONICAL_ORDER.index(result.verifier_organ),
                {
                    "verifier_organ": result.verifier_organ.value,
                    "verdict": result.verdict.value,
                    "receipt_id": _sha256_field(
                        result.receipt_id, "gradient_verifier_entry_invalid"
                    ),
                },
            )
        )
    positions = [position for position, _entry in entries]
    if len(positions) != len(set(positions)):
        # Duplicate organ entries cannot canonicalize; the inventory is
        # one result per organ in canonical order.
        _reject("gradient_verifier_order_invalid")
    return [entry for _position, entry in sorted(entries, key=lambda item: item[0])]


def build_experience_gradient(
    view: EvaluatedEffortView, *, registry: object | None = None
) -> ExperienceGradient:
    """Deterministically build one authenticated gradient from typed inputs.

    Pure: no store, clock, or ambient state.  The result's
    ``canonical_bytes`` are the exact JCS bytes the emitter appends.
    """

    if not isinstance(view, EvaluatedEffortView):
        _reject("gradient_emit_input_invalid")
    if not isinstance(view.producer_organ, AgentOrgan):
        _reject("gradient_emit_input_invalid")
    if not isinstance(view.outcome, GradientOutcome):
        _reject("gradient_outcome_unknown")
    attempt_ordinal = _exact_int(
        view.attempt_ordinal, "gradient_attempt_ordinal_invalid"
    )
    if attempt_ordinal < 1:
        _reject("gradient_attempt_ordinal_invalid")

    verifier_documents = _verifier_documents(
        tuple(view.verifier_results), view.producer_organ
    )
    if view.outcome is not GradientOutcome.UNRESOLVED:
        if view.pre_action_prediction is None:
            _reject("gradient_prediction_missing_for_resolved_outcome")
        if not verifier_documents:
            # A resolved outcome requires at least one independent
            # verifier result (>=1 with organ != producer).
            _reject("gradient_verifier_results_missing")

    targets: list[LearningChannel] = []
    for target in view.permitted_learning_targets:
        if not isinstance(target, LearningChannel):
            _reject("gradient_target_unknown")
        if target not in targets:
            targets.append(target)
    if (
        view.outcome is GradientOutcome.UNRESOLVED
        and LearningChannel.FAST_WEIGHTS in targets
    ):
        # The unresolved branch structurally cannot credit fast weights.
        _reject("gradient_unresolved_forbids_fast_weights")
    targets.sort(key=CLOSED_LEARNING_CHANNELS.index)

    action_documents: list[tuple[int, dict[str, object]]] = []
    for action in view.actions:
        if not isinstance(action, ActionRecord):
            _reject("gradient_emit_input_invalid")
        ordinal = _exact_int(action.action_ordinal, "gradient_action_entry_invalid")
        tool_evidence: str
        if action.tool_evidence_id is None:
            tool_evidence = NONE_SENTINEL
        else:
            tool_evidence = _sha256_field(
                action.tool_evidence_id, "gradient_action_entry_invalid"
            )
        action_documents.append(
            (
                ordinal,
                {
                    "action_ordinal": ordinal,
                    "description": action.description,
                    "tool_evidence_id": tool_evidence,
                },
            )
        )
    action_documents.sort(key=lambda item: item[0])
    listed_ordinals = frozenset(ordinal for ordinal, _entry in action_documents)

    credit_documents: list[tuple[int, dict[str, object]]] = []
    for credit in view.causal_credit:
        if not isinstance(credit, CreditAssignment):
            _reject("gradient_emit_input_invalid")
        ordinal = _exact_int(credit.action_ordinal, "gradient_credit_entry_invalid")
        if ordinal not in listed_ordinals:
            # Credit may flow only to actions listed in the inventory.
            _reject("gradient_credit_unlisted_action")
        credit_documents.append(
            (
                ordinal,
                {
                    "action_ordinal": ordinal,
                    "credit_permille": _exact_int(
                        credit.credit_permille, "gradient_credit_entry_invalid"
                    ),
                },
            )
        )
    credit_documents.sort(key=lambda item: item[0])

    evidence_ids = tuple(view.retrieved_evidence_ids)
    for evidence_id in evidence_ids:
        _sha256_field(evidence_id, "gradient_evidence_order_invalid")

    value: dict[str, object] = {
        "schema_version": GRADIENT_SCHEMA_VERSION,
        "record_type": "experience_gradient",
        "schema_domain": SKELETON_PHASE13_GRADIENT,
        "scope": _scope_document(view),
        "objective": view.objective,
        "pre_action_prediction": _encode_optional_text(
            view.pre_action_prediction, "gradient_optional_text_invalid"
        ),
        "retrieved_evidence_ids": sorted(set(evidence_ids)),
        "actions": [entry for _ordinal, entry in action_documents],
        "verifier_results": verifier_documents,
        "outcome": view.outcome.value,
        "costs": _costs_document(view.costs),
        "causal_credit": [entry for _ordinal, entry in credit_documents],
        "repaired_or_counterfactual_trajectory": _encode_optional_text(
            view.repaired_or_counterfactual_trajectory,
            "gradient_optional_text_invalid",
        ),
        "permitted_learning_targets": [target.value for target in targets],
        "producer_organ": view.producer_organ.value,
        "attempt_ordinal": attempt_ordinal,
    }
    try:
        value["gradient_id"] = compute_gradient_identity(value)
        raw = canonicalize(value)
    except PlasticityGradientRejection:
        raise
    except PlasticityTypeRejection as error:
        raise _typed(error) from error
    except Exception as error:
        raise PlasticityGradientRejection("gradient_emit_input_invalid") from error
    return authenticate_gradient_bytes(raw, registry)


def select_learning_channel(
    outcome: GradientOutcome | str,
    permitted_learning_targets: Sequence[LearningChannel | str],
) -> LearningChannel:
    """Select the channel by the frozen decision table; membership only.

    Deterministic and closed: any permutation of the same permitted set
    selects the same channel, an unresolved outcome can never reach
    ``fast_weights``, and an empty intersection is
    ``gradient_channel_unroutable``.
    """

    try:
        resolved_outcome = GradientOutcome(outcome)
    except (TypeError, ValueError) as error:
        raise PlasticityGradientRejection("gradient_outcome_unknown") from error
    permitted: set[LearningChannel] = set()
    for target in permitted_learning_targets:
        try:
            permitted.add(LearningChannel(target))
        except (TypeError, ValueError) as error:
            raise PlasticityGradientRejection("gradient_target_unknown") from error
    if (
        resolved_outcome is GradientOutcome.UNRESOLVED
        and LearningChannel.FAST_WEIGHTS in permitted
    ):
        _reject("gradient_unresolved_forbids_fast_weights")
    for channel in CHANNEL_DECISION_TABLE[resolved_outcome]:
        if channel in permitted:
            return channel
    _reject("gradient_channel_unroutable")
    raise AssertionError("unreachable")


def select_grader_organ(gradient: ExperienceGradient) -> AgentOrgan:
    """Bind the grader: first canonical grading-organ result that evaluated.

    Only ``FALSIFICATION`` or ``OUTCOME_JUDGMENT`` results grade an
    evaluated pass, the grader can never equal the producer, and a
    gradient without a qualifying grading result is the typed failure
    ``gradient_grader_missing``.
    """

    if not isinstance(gradient, ExperienceGradient):
        _reject("gradient_value_required")
    producer = gradient.producer_organ
    for entry in gradient.verifier_results:
        organ = AgentOrgan(entry["verifier_organ"])
        if organ is producer:
            # Defensive re-check of the structural inequality already
            # enforced at construction (D-08).
            _reject("gradient_self_grading_forbidden")
        if organ in GRADING_ORGANS and (
            entry["verdict"] != VerifierVerdict.NOT_EVALUATED.value
        ):
            return organ
    _reject("gradient_grader_missing")
    raise AssertionError("unreachable")


def _channel_payload(
    channel: LearningChannel,
    bindings: ChannelBindings,
) -> dict[str, object]:
    if channel is LearningChannel.FAST_WEIGHTS:
        if bindings.delta_id is None:
            _reject("channel_update_delta_ref_missing")
        return {
            "payload_kind": channel.value,
            "delta_id": _sha256_field(
                bindings.delta_id, "channel_update_payload_invalid"
            ),
        }
    if bindings.delta_id is not None:
        # The four non-factual channels can never carry a delta reference:
        # their payloads assert no unobserved fact (D-09).
        _reject("channel_update_delta_ref_forbidden")
    reference_member, adjustment_member = _NONFACTUAL_BINDING_MEMBERS[channel]
    reference = getattr(bindings, reference_member)
    adjustment = getattr(bindings, adjustment_member)
    if reference is None or adjustment is None:
        _reject("channel_update_binding_missing")
    return {
        "payload_kind": channel.value,
        reference_member: _sha256_field(
            reference, "channel_update_payload_invalid"
        ),
        adjustment_member: _exact_int(
            adjustment, "channel_update_payload_invalid"
        ),
    }


def build_channel_update(
    gradient: ExperienceGradient,
    bindings: ChannelBindings,
    *,
    fence_id: str,
    generation: int,
    update_ordinal: int,
    registry: object | None = None,
) -> ChannelUpdate:
    """Deterministically derive the single channel update of one gradient.

    Pure: channel selection is the frozen decision table, the grader is
    bound from the gradient's verifier results, and the fast-weights
    branch is reachable only from a resolved outcome that permits it.
    """

    if not isinstance(gradient, ExperienceGradient):
        _reject("gradient_value_required")
    if not isinstance(bindings, ChannelBindings):
        _reject("channel_update_binding_missing")
    grader = select_grader_organ(gradient)
    channel = select_learning_channel(
        gradient.outcome, gradient.permitted_learning_targets
    )
    if channel is LearningChannel.FAST_WEIGHTS:
        # Mirror the schema cross-field: a fast_weights update references
        # a gradient whose outcome is resolved and whose permitted
        # targets contain fast_weights.  The decision table guarantees
        # both; these defensive re-checks keep the invariant local.
        if gradient.outcome is GradientOutcome.UNRESOLVED:
            _reject("gradient_unresolved_forbids_fast_weights")
        if LearningChannel.FAST_WEIGHTS not in gradient.permitted_learning_targets:
            _reject("gradient_channel_unroutable")
    value: dict[str, object] = {
        "schema_version": CHANNEL_UPDATE_SCHEMA_VERSION,
        "record_type": "channel_update",
        "schema_domain": SKELETON_PHASE13_CHANNEL_UPDATE,
        "gradient_id": gradient.gradient_id,
        "channel": channel.value,
        "payload": _channel_payload(channel, bindings),
        "producer_organ": gradient.producer_organ.value,
        "grader_organ": grader.value,
        "update_ordinal": _exact_int(
            update_ordinal, "channel_update_ordinal_invalid"
        ),
        "fence_id": _sha256_field(fence_id, "channel_update_reference_invalid"),
        "generation": _exact_int(generation, "channel_update_ordinal_invalid"),
        "attempt_ordinal": gradient.attempt_ordinal,
    }
    value["channel_update_id"] = compute_channel_update_identity(value)
    raw = canonicalize(value)
    try:
        return channel_update_from_raw(raw, registry)
    except PlasticityTypeRejection as error:
        raise _typed(error) from error


def _fence_binding(fence: FenceBinding) -> FenceBinding:
    if not isinstance(fence, FenceBinding):
        _reject("gradient_fence_binding_invalid")
    _sha256_field(fence.fence_id, "gradient_fence_binding_invalid")
    _sha256_field(fence.writer_id, "gradient_fence_binding_invalid")
    generation = _exact_int(fence.generation, "gradient_fence_binding_invalid")
    if generation < 0:
        _reject("gradient_fence_binding_invalid")
    return fence


def _recorded_at_text(value: object) -> str:
    if not isinstance(value, str) or len(value) < 20 or not value.endswith("Z"):
        _reject("gradient_recorded_at_invalid")
    return value


class GradientEmitter:
    """Validate gradients while preventing non-atomic durable emission."""

    __slots__ = ("_fence", "_recorded_at", "_registry", "_store")

    def __init__(
        self,
        store: PlasticityStore,
        *,
        fence: FenceBinding,
        recorded_at: str,
        registry: object | None = None,
    ) -> None:
        if not isinstance(store, PlasticityStore):
            _reject("gradient_store_required")
        self._store = store
        self._fence = _fence_binding(fence)
        self._recorded_at = _recorded_at_text(recorded_at)
        self._registry = registry

    def emit_gradient(
        self, view: EvaluatedEffortView
    ) -> tuple[ExperienceGradient, OperationReceipt]:
        """Validate a gradient, then require the atomic attempt API."""

        gradient = build_experience_gradient(view, registry=self._registry)
        self._store.append_gradient(
            GradientAppend(
                gradient.canonical_bytes,
                self._fence.fence_id,
                self._fence.generation,
                gradient.attempt_ordinal,
                self._recorded_at,
            ),
            writer_id=self._fence.writer_id,
            operation_id=_operation_identity(
                _EMIT_OPERATION_DOMAIN, gradient.gradient_id
            ),
        )
        raise AssertionError("unreachable")


class EvaluatedEffortGate:
    """Derive exactly one accounted channel update per evaluated gradient."""

    __slots__ = ("_channeled", "_fence", "_recorded_at", "_registry", "_store")

    def __init__(
        self,
        store: PlasticityStore,
        *,
        fence: FenceBinding,
        recorded_at: str,
        registry: object | None = None,
    ) -> None:
        if not isinstance(store, PlasticityStore):
            _reject("gradient_store_required")
        self._store = store
        self._fence = _fence_binding(fence)
        self._recorded_at = _recorded_at_text(recorded_at)
        self._registry = registry
        self._channeled: dict[str, str] = {}

    @property
    def channeled_gradient_ids(self) -> tuple[str, ...]:
        """The gradients this gate has accounted, in derivation order."""

        return tuple(self._channeled)

    def commit_attempt(
        self,
        view: EvaluatedEffortView,
        bindings: ChannelBindings,
    ) -> tuple[ExperienceGradient, ChannelUpdate, OperationReceipt]:
        """Build and atomically commit the sole gradient/update pair.

        The stable attempt identity excludes evaluation results, so a retry
        that changes an outcome, verifier, or causal-credit claim collides
        with the already-accounted attempt instead of creating a second
        learning event.
        """

        gradient = build_experience_gradient(view, registry=self._registry)
        attempt_id = learning_attempt_identity(gradient.canonical_bytes)
        update = build_channel_update(
            gradient,
            bindings,
            fence_id=self._fence.fence_id,
            generation=self._fence.generation,
            update_ordinal=0,
            registry=self._registry,
        )
        receipt = self._store.commit_learning_attempt(
            attempt_id=attempt_id,
            gradient=GradientAppend(
                gradient.canonical_bytes,
                self._fence.fence_id,
                self._fence.generation,
                gradient.attempt_ordinal,
                self._recorded_at,
            ),
            update=ChannelUpdateAppend(update.canonical_bytes, self._recorded_at),
            writer_id=self._fence.writer_id,
            operation_id=_operation_identity(_ATTEMPT_OPERATION_DOMAIN, attempt_id),
        )
        self._channeled[gradient.gradient_id] = update.channel_update_id
        return gradient, update, receipt

    def derive_channel_update(
        self, gradient: ExperienceGradient, bindings: ChannelBindings
    ) -> tuple[ChannelUpdate, OperationReceipt]:
        """Validate an update, then require :meth:`commit_attempt`."""

        if not isinstance(gradient, ExperienceGradient):
            _reject("gradient_value_required")
        if gradient.gradient_id in self._channeled:
            _reject("gradient_already_channeled")
        update = build_channel_update(
            gradient,
            bindings,
            fence_id=self._fence.fence_id,
            generation=self._fence.generation,
            update_ordinal=len(self._channeled),
            registry=self._registry,
        )
        self._store.append_channel_update(
            ChannelUpdateAppend(update.canonical_bytes, self._recorded_at),
            writer_id=self._fence.writer_id,
            operation_id=_operation_identity(
                _DERIVE_OPERATION_DOMAIN, update.channel_update_id
            ),
        )
        raise AssertionError("unreachable")

    def assert_channel_accounting(self, gradient_id: str) -> str:
        """Require exactly one accounted update; zero is a typed failure.

        Multiplicity above one is unrepresentable here: the gate ledger
        and the store's UNIQUE constraint both stop the second append.
        """

        identity = _sha256_field(gradient_id, "gradient_identity_invalid")
        accounted = self._channeled.get(identity)
        if accounted is None:
            _reject("gradient_channel_unaccounted")
        return str(accounted)


__all__ = [
    "ActionRecord",
    "CHANNEL_DECISION_TABLE",
    "ChannelBindings",
    "CreditAssignment",
    "EvaluatedEffortGate",
    "EvaluatedEffortView",
    "FenceBinding",
    "GRADING_ORGANS",
    "GradientEmitter",
    "PlasticityGradientRejection",
    "VerifierResult",
    "authenticate_gradient_bytes",
    "build_channel_update",
    "build_experience_gradient",
    "select_grader_organ",
    "select_learning_channel",
]
