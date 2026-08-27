"""Closed immutable values for authenticated Phase 13 plasticity documents.

Every trusted Phase 13 primitive value (experience gradient, parameter delta,
channel update, pending-owner-hardware placeholder) is constructed only
through the ``*_from_raw`` functions in this module: raw I-JSON bytes are
parsed, required to be exact JCS canonical bytes, optionally validated
against the published Draft 2020-12 schema, cross-field validated, and their
content-addressed identity is recomputed under a length-framed
domain-separated SHA-256 before any field is trusted.  Direct construction,
``dataclasses.replace``, and mapping-based construction all fail.

This module imports no store, network, provider, execution, or clock
surface and never represents a float or wall-clock member.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Any

from .agent_types import AgentOrgan
from .canonical import canonicalize, parse_raw_json, sha256_hex


SAFE_INTEGER_MAX = 9_007_199_254_740_991
GENESIS_SHA256 = "0" * 64
NONE_SENTINEL = "none"
MAX_GRADIENT_TEXT_CODEPOINTS = 4096
MAX_GRADIENT_ACTION_ITEMS = 256
MAX_GRADIENT_VERIFIER_ITEMS = 64
MAX_CREDIT_PERMILLE = 1000
MAX_SCALE_LOG2 = 62

GRADIENT_SCHEMA_VERSION = "skeleton.experience-gradient.v1"
DELTA_SCHEMA_VERSION = "skeleton.plasticity-delta.v1"
CHANNEL_UPDATE_SCHEMA_VERSION = "skeleton.learning-channel-update.v1"
PLACEHOLDER_SCHEMA_VERSION = "skeleton.pending-owner-hardware.v1"

GRADIENT_SCHEMA_ID = "https://schemas.skeleton.local/v1/experience-gradient.schema.json"
DELTA_SCHEMA_ID = "https://schemas.skeleton.local/v1/plasticity-delta.schema.json"
CHANNEL_UPDATE_SCHEMA_ID = (
    "https://schemas.skeleton.local/v1/learning-channel-update.schema.json"
)
PLACEHOLDER_SCHEMA_ID = (
    "https://schemas.skeleton.local/v1/pending-owner-hardware.schema.json"
)

# The exact x-skeleton-identity-domain annotations published by the ten
# Phase 13 schemas.  The schemas are authoritative: no ``_V1`` suffix.
SKELETON_PHASE13_GRADIENT = "SKELETON_PHASE13_GRADIENT"
SKELETON_PHASE13_DELTA = "SKELETON_PHASE13_DELTA"
SKELETON_PHASE13_CHANNEL_UPDATE = "SKELETON_PHASE13_CHANNEL_UPDATE"
SKELETON_PHASE13_MIXTURE = "SKELETON_PHASE13_MIXTURE"
SKELETON_PHASE13_SCOPE = "SKELETON_PHASE13_SCOPE"
SKELETON_PHASE13_ABSTRACTION = "SKELETON_PHASE13_ABSTRACTION"
SKELETON_PHASE13_PROBE = "SKELETON_PHASE13_PROBE"
SKELETON_PHASE13_HOMEOSTASIS = "SKELETON_PHASE13_HOMEOSTASIS"
SKELETON_PHASE13_CANDIDATE_VERSION = "SKELETON_PHASE13_CANDIDATE_VERSION"
SKELETON_PHASE13_PLACEHOLDER = "SKELETON_PHASE13_PLACEHOLDER"

PHASE13_IDENTITY_DOMAINS = (
    SKELETON_PHASE13_ABSTRACTION,
    SKELETON_PHASE13_CANDIDATE_VERSION,
    SKELETON_PHASE13_CHANNEL_UPDATE,
    SKELETON_PHASE13_DELTA,
    SKELETON_PHASE13_GRADIENT,
    SKELETON_PHASE13_HOMEOSTASIS,
    SKELETON_PHASE13_MIXTURE,
    SKELETON_PHASE13_PLACEHOLDER,
    SKELETON_PHASE13_PROBE,
    SKELETON_PHASE13_SCOPE,
)


class ScopeKind(StrEnum):
    """The closed D-02 scope-binding namespace used by gradients and deltas."""

    KERNEL = "kernel"
    IDENTITY = "identity"
    LOBE_CODING = "lobe_coding"
    LOBE_TRADING = "lobe_trading"
    LOBE_RESEARCH = "lobe_research"
    PROJECT = "project"


class ScopeRegistryKind(StrEnum):
    """The closed scope-registration taxonomy of the plasticity-scope rows."""

    KERNEL = "kernel"
    IDENTITY = "identity"
    LOBE = "lobe"
    PROJECT = "project"


class LobeName(StrEnum):
    """The initially installed lobes; trading is one lobe, never the root."""

    CODING = "coding"
    TRADING = "trading"
    RESEARCH = "research"


class LearningChannel(StrEnum):
    """The closed exhaustive five-channel accounting enum (D-09, PLT-03)."""

    FAST_WEIGHTS = "fast_weights"
    UNCERTAINTY = "uncertainty"
    RETRIEVAL = "retrieval"
    ROUTING = "routing"
    EXPERIMENT_SELECTION = "experiment_selection"


class GradientOutcome(StrEnum):
    """The closed outcome branches of one completed attempt (D-04)."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNRESOLVED = "unresolved"


class VerifierVerdict(StrEnum):
    """The closed per-verifier verdict vocabulary in a gradient."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_EVALUATED = "not_evaluated"


class ProbeKind(StrEnum):
    """The frozen ordered five-probe candidate battery (D-10)."""

    DOMAIN = "domain"
    GENERAL_CAPABILITY = "general_capability"
    CALIBRATION = "calibration"
    SAFETY = "safety"
    PRIOR_REGRESSION = "prior_regression"


class EvaluationBasis(StrEnum):
    """The closed probe evaluation bases; real_model is hardware-gated."""

    REFERENCE_KERNEL = "reference_kernel"
    FIXTURE_BATTERY = "fixture_battery"
    REAL_MODEL = "real_model"


class ProbeStatus(StrEnum):
    """The closed probe receipt statuses with exact pass/fail accounting."""

    PASSED = "passed"
    FAILED = "failed"


class HomeostasisBudgetKind(StrEnum):
    """The closed nine integer-exact homeostatic budget kinds (D-15)."""

    RANK = "rank"
    DRIFT = "drift"
    KL_DIVERGENCE = "kl_divergence"
    REGRESSION_LOSS = "regression_loss"
    STORAGE_BYTES = "storage_bytes"
    TRAINING_COMPUTE = "training_compute"
    DELTA_MAGNITUDE = "delta_magnitude"
    DELTA_COUNT = "delta_count"
    APPLICATION_FREQUENCY = "application_frequency"


class PressureBand(StrEnum):
    """The deterministic pressure ladder bands (D-16)."""

    NOMINAL = "nominal"
    ELEVATED = "elevated"
    HIGH = "high"
    CEILING = "ceiling"


class HomeostasisAction(StrEnum):
    """The closed five-action admission ladder outcomes (D-16)."""

    ADMIT = "admit"
    CLAMP_MAGNITUDE = "clamp_magnitude"
    DEFER_ADMISSION = "defer_admission"
    QUARANTINE_PRESSURE = "quarantine_pressure"
    HOMEOSTASIS_CLAMPED = "homeostasis_clamped"


class HomeostasisAppendClass(StrEnum):
    """The closed append classes; only delta admission feels pressure."""

    DELTA_ADMISSION = "delta_admission"
    RECEIPT_APPEND = "receipt_append"
    ROLLBACK_APPEND = "rollback_append"
    AUDIT_APPEND = "audit_append"
    PLACEHOLDER_APPEND = "placeholder_append"


class PlaceholderReason(StrEnum):
    """The closed hardware-honesty placeholder reasons (D-18)."""

    DGX_ABSENT = "dgx_absent"
    OWNER_AUTHORIZATION_PENDING = "owner_authorization_pending"
    ARM64_PARITY_UNVERIFIED = "arm64_parity_unverified"


class BoundRequirement(StrEnum):
    """The closed hardware-gated requirement facets a placeholder binds."""

    REAL_TRAINING_RUN = "real_training_run"
    REAL_MODEL_PROBE = "real_model_probe"
    REAL_MODEL_KL_DRIFT = "real_model_kl_drift"
    PROVIDER_CONFORMANCE = "provider_conformance"


class ReplayObligationKind(StrEnum):
    """The closed replay obligations a future owner hardware run discharges."""

    REPRODUCE_TRAINING_STEP_RECEIPTS = "reproduce_training_step_receipts"
    REPRODUCE_PROBE_RECEIPT = "reproduce_probe_receipt"
    REPRODUCE_KL_DRIFT_MEASUREMENT = "reproduce_kl_drift_measurement"
    REPRODUCE_FIXTURE_CONFORMANCE_RECEIPTS = "reproduce_fixture_conformance_receipts"


class ChangeKind(StrEnum):
    """The closed LRN-13 candidate-version change kinds."""

    MODEL = "model"
    PROMPT = "prompt"
    CALIBRATION = "calibration"
    TOOL = "tool"
    FEATURE = "feature"
    THRESHOLD = "threshold"
    POLICY = "policy"


CLOSED_SCOPE_KINDS = tuple(ScopeKind)
CLOSED_SCOPE_REGISTRY_KINDS = tuple(ScopeRegistryKind)
CLOSED_LOBE_NAMES = tuple(LobeName)
CLOSED_LEARNING_CHANNELS = tuple(LearningChannel)
CLOSED_GRADIENT_OUTCOMES = tuple(GradientOutcome)
CLOSED_VERIFIER_VERDICTS = tuple(VerifierVerdict)
CLOSED_PROBE_KINDS = tuple(ProbeKind)
CLOSED_EVALUATION_BASES = tuple(EvaluationBasis)
CLOSED_PROBE_STATUSES = tuple(ProbeStatus)
CLOSED_HOMEOSTASIS_BUDGET_KINDS = tuple(HomeostasisBudgetKind)
CLOSED_PRESSURE_BANDS = tuple(PressureBand)
CLOSED_HOMEOSTASIS_ACTIONS = tuple(HomeostasisAction)
CLOSED_HOMEOSTASIS_APPEND_CLASSES = tuple(HomeostasisAppendClass)
CLOSED_PLACEHOLDER_REASONS = tuple(PlaceholderReason)
CLOSED_BOUND_REQUIREMENTS = tuple(BoundRequirement)
CLOSED_REPLAY_OBLIGATION_KINDS = tuple(ReplayObligationKind)
CLOSED_CHANGE_KINDS = tuple(ChangeKind)

# The four non-factual channels an unresolved outcome may still update
# (D-09): no unobserved fact may be asserted through fast weights.
NONFACTUAL_LEARNING_CHANNELS = (
    LearningChannel.UNCERTAINTY,
    LearningChannel.RETRIEVAL,
    LearningChannel.ROUTING,
    LearningChannel.EXPERIMENT_SELECTION,
)

# The frozen five-probe battery order; the receipt schema pins each kind to
# this exact ordinal (D-10).
PROBE_BATTERY_ORDER = tuple(ProbeKind)

# Structural requirement-to-obligation binding of the placeholder schema.
BOUND_REQUIREMENT_OBLIGATIONS: Mapping[BoundRequirement, ReplayObligationKind] = (
    MappingProxyType(
        {
            BoundRequirement.REAL_TRAINING_RUN: (
                ReplayObligationKind.REPRODUCE_TRAINING_STEP_RECEIPTS
            ),
            BoundRequirement.REAL_MODEL_PROBE: (
                ReplayObligationKind.REPRODUCE_PROBE_RECEIPT
            ),
            BoundRequirement.REAL_MODEL_KL_DRIFT: (
                ReplayObligationKind.REPRODUCE_KL_DRIFT_MEASUREMENT
            ),
            BoundRequirement.PROVIDER_CONFORMANCE: (
                ReplayObligationKind.REPRODUCE_FIXTURE_CONFORMANCE_RECEIPTS
            ),
        }
    )
)

BUDGET_VECTOR_COUNTERS = (
    "input_tokens",
    "output_tokens",
    "elapsed_milliseconds",
    "memory_items",
    "memory_bytes",
    "tool_calls",
    "accelerator_milliseconds",
)

# Canonical agent-organ order for verifier-result inventories.
ORGAN_CANONICAL_ORDER = tuple(AgentOrgan)


class PlasticityTypeRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise PlasticityTypeRejection(code)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(nested) for nested in value]
    return value


def _safe_integers(value: Any) -> None:
    """Reject floats anywhere and integers outside the exact safe range."""

    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if not 0 <= value <= SAFE_INTEGER_MAX:
            _reject("plasticity_safe_integer_invalid")
        return
    if isinstance(value, float):
        _reject("plasticity_float_forbidden")
    if isinstance(value, Mapping):
        for nested in value.values():
            _safe_integers(nested)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            _safe_integers(nested)
        return


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


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def compute_phase13_identity(
    domain: str, identity_field: str, value: Mapping[str, Any]
) -> str:
    """Recompute a domain-framed identity without trusting its declared field.

    Unknown domains reject fail-closed: only the ten closed
    ``SKELETON_PHASE13_*`` frames may name a Phase 13 identity.
    """

    if domain not in PHASE13_IDENTITY_DOMAINS:
        _reject("plasticity_identity_domain_unknown")
    body = _thaw(value)
    body.pop(identity_field, None)
    return _framed_digest(domain, canonicalize(body))


def compute_gradient_identity(value: Mapping[str, Any]) -> str:
    return compute_phase13_identity(SKELETON_PHASE13_GRADIENT, "gradient_id", value)


def compute_delta_identity(value: Mapping[str, Any]) -> str:
    return compute_phase13_identity(SKELETON_PHASE13_DELTA, "delta_id", value)


def compute_channel_update_identity(value: Mapping[str, Any]) -> str:
    return compute_phase13_identity(
        SKELETON_PHASE13_CHANNEL_UPDATE, "channel_update_id", value
    )


def compute_placeholder_identity(value: Mapping[str, Any]) -> str:
    return compute_phase13_identity(
        SKELETON_PHASE13_PLACEHOLDER, "placeholder_id", value
    )


_VALUE_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class PlasticityValue:
    """Base authenticated Phase 13 value; constructible only under the token."""

    identity: str
    schema_version: str
    canonical_bytes: bytes
    canonical_sha256: str
    value: Mapping[str, Any]

    def __init__(
        self,
        *,
        identity: str,
        schema_version: str,
        value: Mapping[str, Any],
        canonical_bytes: bytes,
        canonical_sha256: str,
        token: object,
    ) -> None:
        if token is not _VALUE_TOKEN:
            raise TypeError(f"{type(self).__name__} requires authenticated construction")
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "canonical_bytes", bytes(canonical_bytes))
        object.__setattr__(self, "canonical_sha256", canonical_sha256)
        object.__setattr__(self, "value", _freeze(value))


@dataclass(frozen=True, slots=True, init=False)
class ExperienceGradient(PlasticityValue):
    """The closed PLT-02 record of exactly one completed attempt (D-04).

    ``pre_action_prediction`` and ``repaired_or_counterfactual_trajectory``
    are ``None`` exactly when the document carries the schema's
    ``{"present": false}`` absent-text branch.  ``project_id`` is ``None``
    unless the scope binding names a registered project.
    """

    gradient_id: str
    scope_kind: ScopeKind
    project_id: str | None
    scope: Mapping[str, Any]
    objective: str
    pre_action_prediction: str | None
    retrieved_evidence_ids: tuple[str, ...]
    actions: tuple[Mapping[str, Any], ...]
    verifier_results: tuple[Mapping[str, Any], ...]
    outcome: GradientOutcome
    costs: Mapping[str, int]
    causal_credit: tuple[Mapping[str, Any], ...]
    repaired_or_counterfactual_trajectory: str | None
    permitted_learning_targets: tuple[LearningChannel, ...]
    producer_organ: AgentOrgan
    attempt_ordinal: int


@dataclass(frozen=True, slots=True, init=False)
class ParameterDelta(PlasticityValue):
    """One complete-or-unrepresentable content-addressed delta (D-06).

    The inverse-proof members are first-class: a delta whose committed
    round-trip root differs from its pre-apply root is unconstructible, so
    nothing missing an inverse proof can ever reach the applied state (D-13).
    """

    delta_id: str
    parent_delta_id: str
    genesis_parent: bool
    scope_kind: ScopeKind
    project_id: str | None
    scope: Mapping[str, Any]
    base_snapshot_id: str
    evidence_gradient_ids: tuple[str, ...]
    expiry_ordinal: int
    scale_log2: int
    declared_rank: int
    tensor_payload_root: str
    inverse_payload_root: str
    pre_apply_payload_root: str
    post_apply_payload_root: str
    roundtrip_payload_root: str
    payload_bytes: int
    version_ordinal: int


@dataclass(frozen=True, slots=True, init=False)
class ChannelUpdate(PlasticityValue):
    """Exactly-one channel-update row per evaluated pass (D-09).

    ``delta_id`` is set exactly for the ``fast_weights`` branch;
    ``reference_version_id`` and ``adjustment`` are set exactly for the four
    non-factual branches.
    """

    channel_update_id: str
    gradient_id: str
    channel: LearningChannel
    payload: Mapping[str, Any]
    delta_id: str | None
    reference_version_id: str | None
    adjustment: int | None
    producer_organ: AgentOrgan
    grader_organ: AgentOrgan
    update_ordinal: int
    fence_id: str
    generation: int
    attempt_ordinal: int


@dataclass(frozen=True, slots=True, init=False)
class PendingOwnerHardware(PlasticityValue):
    """One typed enumerable hardware-honesty placeholder row (D-18)."""

    placeholder_id: str
    reason: PlaceholderReason
    bound_requirement: BoundRequirement
    bound_artifact_id: str
    obligation_kind: ReplayObligationKind
    conformance_oracle_root: str
    expected_receipt_count: int
    replay_obligation: Mapping[str, Any]
    recorded_ordinal: int


def _construct(value_type: type[PlasticityValue], **fields: Any) -> Any:
    base = {
        name: fields.pop(name)
        for name in ("identity", "schema_version", "value", "canonical_bytes", "canonical_sha256")
    }
    instance = value_type(token=_VALUE_TOKEN, **base)
    for name, item in fields.items():
        object.__setattr__(instance, name, item)
    return instance


def _schema_validate(raw: bytes, registry: object | None, schema_id: str) -> None:
    if registry is None:
        return
    validate_raw = getattr(registry, "validate_raw", None)
    if not callable(validate_raw):
        _reject("plasticity_registry_invalid")
    try:
        validate_raw(raw, schema_id)
    except PlasticityTypeRejection:
        raise
    except Exception as error:
        raise PlasticityTypeRejection("plasticity_schema_validation_failed") from error


def _authenticated_document(raw: bytes, expected_version: str) -> dict[str, Any]:
    """Raw-bytes-first parse, canonical-bytes equality, and exact arithmetic."""

    if not isinstance(raw, bytes):
        _reject("plasticity_bytes_required")
    try:
        parsed = parse_raw_json(raw)
    except Exception as error:
        raise PlasticityTypeRejection("plasticity_document_parse_invalid") from error
    if not isinstance(parsed, dict):
        _reject("plasticity_document_shape_invalid")
    if canonicalize(parsed) != raw:
        _reject("plasticity_document_noncanonical")
    _safe_integers(parsed)
    if parsed.get("schema_version") != expected_version:
        _reject("plasticity_schema_version_unknown")
    return parsed


def _require_frame(value: Mapping[str, Any], record_type: str, domain: str) -> None:
    if value.get("record_type") != record_type:
        _reject("plasticity_record_type_invalid")
    if value.get("schema_domain") != domain:
        _reject("plasticity_schema_domain_invalid")


def _bounded_text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        _reject(code)
    if len(value) > MAX_GRADIENT_TEXT_CODEPOINTS:
        _reject("gradient_text_bounds_exceeded")
    return str(value)


def _optional_text(value: object) -> str | None:
    """Decode the schema's closed ``{present, text}`` optional-text branch."""

    if not isinstance(value, Mapping):
        _reject("gradient_optional_text_invalid")
    present = value.get("present")
    if present is False:
        if set(value) != {"present"}:
            _reject("gradient_optional_text_invalid")
        return None
    if present is True:
        if set(value) != {"present", "text"}:
            _reject("gradient_optional_text_invalid")
        return _bounded_text(value["text"], "gradient_optional_text_invalid")
    _reject("gradient_optional_text_invalid")
    return None


def _sorted_unique_hashes(
    value: object, code: str, *, nonempty: bool = False, missing_code: str | None = None
) -> tuple[str, ...]:
    if not isinstance(value, list):
        _reject(code)
    if nonempty and not value:
        _reject(missing_code or code)
    for item in value:
        if not _is_sha256(item):
            _reject(code)
    items = tuple(str(item) for item in value)
    if items != tuple(sorted(set(items))):
        _reject(code)
    return items


def _scope_binding(value: object, code: str) -> tuple[ScopeKind, str | None]:
    """Decode the closed scopeBinding branch shared by gradient and delta."""

    if not isinstance(value, Mapping):
        _reject(code)
    kind_raw = value.get("scope_kind")
    try:
        kind = ScopeKind(kind_raw)
    except (TypeError, ValueError) as error:
        raise PlasticityTypeRejection(code) from error
    if kind is ScopeKind.PROJECT:
        if set(value) != {"scope_kind", "project_id"}:
            _reject(code)
        return kind, _sha256_field(value["project_id"], code)
    if set(value) != {"scope_kind"}:
        _reject(code)
    return kind, None


def _organ(value: object, code: str) -> AgentOrgan:
    try:
        return AgentOrgan(value)
    except (TypeError, ValueError) as error:
        raise PlasticityTypeRejection(code) from error


def _budget_vector(value: object) -> Mapping[str, int]:
    if not isinstance(value, Mapping) or set(value) != set(BUDGET_VECTOR_COUNTERS):
        _reject("gradient_costs_invalid")
    for counter in BUDGET_VECTOR_COUNTERS:
        _exact_int(value[counter], "gradient_costs_invalid")
    return value


_GRADIENT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "schema_domain",
        "gradient_id",
        "scope",
        "objective",
        "pre_action_prediction",
        "retrieved_evidence_ids",
        "actions",
        "verifier_results",
        "outcome",
        "costs",
        "causal_credit",
        "repaired_or_counterfactual_trajectory",
        "permitted_learning_targets",
        "producer_organ",
        "attempt_ordinal",
    }
)


def _gradient_actions(value: object) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or not value or len(value) > MAX_GRADIENT_ACTION_ITEMS:
        _reject("gradient_actions_order_invalid")
    ordinals: list[int] = []
    for entry in value:
        if not isinstance(entry, Mapping) or set(entry) != {
            "action_ordinal",
            "description",
            "tool_evidence_id",
        }:
            _reject("gradient_action_entry_invalid")
        ordinals.append(_exact_int(entry["action_ordinal"], "gradient_action_entry_invalid"))
        _bounded_text(entry["description"], "gradient_action_entry_invalid")
        tool_evidence = entry["tool_evidence_id"]
        if tool_evidence != NONE_SENTINEL and not _is_sha256(tool_evidence):
            _reject("gradient_action_entry_invalid")
    if ordinals != sorted(set(ordinals)):
        _reject("gradient_actions_order_invalid")
    return tuple(value)


def _gradient_verifiers(
    value: object, producer: AgentOrgan
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or len(value) > MAX_GRADIENT_VERIFIER_ITEMS:
        _reject("gradient_verifier_order_invalid")
    positions: list[int] = []
    for entry in value:
        if not isinstance(entry, Mapping) or set(entry) != {
            "verifier_organ",
            "verdict",
            "receipt_id",
        }:
            _reject("gradient_verifier_entry_invalid")
        organ = _organ(entry["verifier_organ"], "gradient_verifier_entry_invalid")
        if organ is producer:
            _reject("gradient_self_grading_forbidden")
        try:
            VerifierVerdict(entry["verdict"])
        except (TypeError, ValueError) as error:
            raise PlasticityTypeRejection("gradient_verifier_verdict_unknown") from error
        _sha256_field(entry["receipt_id"], "gradient_verifier_entry_invalid")
        positions.append(ORGAN_CANONICAL_ORDER.index(organ))
    if positions != sorted(set(positions)):
        _reject("gradient_verifier_order_invalid")
    return tuple(value)


def _gradient_credit(
    value: object, action_ordinals: frozenset[int]
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or len(value) > MAX_GRADIENT_ACTION_ITEMS:
        _reject("gradient_credit_order_invalid")
    ordinals: list[int] = []
    for entry in value:
        if not isinstance(entry, Mapping) or set(entry) != {
            "action_ordinal",
            "credit_permille",
        }:
            _reject("gradient_credit_entry_invalid")
        ordinal = _exact_int(entry["action_ordinal"], "gradient_credit_entry_invalid")
        permille = _exact_int(entry["credit_permille"], "gradient_credit_entry_invalid")
        if not 0 <= permille <= MAX_CREDIT_PERMILLE:
            _reject("gradient_credit_entry_invalid")
        if ordinal not in action_ordinals:
            _reject("gradient_credit_unlisted_action")
        ordinals.append(ordinal)
    if ordinals != sorted(set(ordinals)):
        _reject("gradient_credit_order_invalid")
    return tuple(value)


def _gradient_targets(
    value: object, outcome: GradientOutcome
) -> tuple[LearningChannel, ...]:
    if not isinstance(value, list) or len(value) > len(CLOSED_LEARNING_CHANNELS):
        _reject("gradient_targets_order_invalid")
    channels: list[LearningChannel] = []
    for entry in value:
        try:
            channels.append(LearningChannel(entry))
        except (TypeError, ValueError) as error:
            raise PlasticityTypeRejection("gradient_target_unknown") from error
    positions = [CLOSED_LEARNING_CHANNELS.index(channel) for channel in channels]
    if positions != sorted(set(positions)):
        _reject("gradient_targets_order_invalid")
    if outcome is GradientOutcome.UNRESOLVED and LearningChannel.FAST_WEIGHTS in channels:
        _reject("gradient_unresolved_forbids_fast_weights")
    return tuple(channels)


def gradient_from_raw(raw: bytes, registry: object | None = None) -> ExperienceGradient:
    """Authenticate raw gradient bytes into one frozen ``ExperienceGradient``."""

    value = _authenticated_document(raw, GRADIENT_SCHEMA_VERSION)
    _schema_validate(raw, registry, GRADIENT_SCHEMA_ID)
    if set(value) != _GRADIENT_FIELDS:
        _reject("plasticity_document_shape_invalid")
    _require_frame(value, "experience_gradient", SKELETON_PHASE13_GRADIENT)

    scope_kind, project_id = _scope_binding(value["scope"], "gradient_scope_invalid")
    objective = _bounded_text(value["objective"], "gradient_text_invalid")
    prediction = _optional_text(value["pre_action_prediction"])
    trajectory = _optional_text(value["repaired_or_counterfactual_trajectory"])
    try:
        outcome = GradientOutcome(value["outcome"])
    except (TypeError, ValueError) as error:
        raise PlasticityTypeRejection("gradient_outcome_unknown") from error
    producer = _organ(value["producer_organ"], "gradient_organ_unknown")
    evidence = _sorted_unique_hashes(
        value["retrieved_evidence_ids"], "gradient_evidence_order_invalid"
    )
    actions = _gradient_actions(value["actions"])
    verifier_results = _gradient_verifiers(value["verifier_results"], producer)
    action_ordinals = frozenset(
        int(entry["action_ordinal"]) for entry in actions
    )
    causal_credit = _gradient_credit(value["causal_credit"], action_ordinals)
    targets = _gradient_targets(value["permitted_learning_targets"], outcome)
    costs = _budget_vector(value["costs"])
    attempt_ordinal = _exact_int(value["attempt_ordinal"], "gradient_attempt_ordinal_invalid")
    if attempt_ordinal < 1:
        _reject("gradient_attempt_ordinal_invalid")

    if outcome is not GradientOutcome.UNRESOLVED:
        # A resolved outcome requires a committed pre-action prediction and
        # at least one independent verifier result (D-04, D-08).
        if prediction is None:
            _reject("gradient_prediction_missing_for_resolved_outcome")
        if not verifier_results:
            _reject("gradient_verifier_results_missing")

    declared = _sha256_field(value["gradient_id"], "plasticity_identity_invalid")
    expected = compute_gradient_identity(value)
    if declared != expected:
        _reject("plasticity_identity_mismatch")

    return _construct(
        ExperienceGradient,
        identity=expected,
        schema_version=GRADIENT_SCHEMA_VERSION,
        value=value,
        canonical_bytes=raw,
        canonical_sha256=sha256_hex(raw),
        gradient_id=expected,
        scope_kind=scope_kind,
        project_id=project_id,
        scope=_freeze(value["scope"]),
        objective=objective,
        pre_action_prediction=prediction,
        retrieved_evidence_ids=evidence,
        actions=_freeze(actions),
        verifier_results=_freeze(verifier_results),
        outcome=outcome,
        costs=_freeze(costs),
        causal_credit=_freeze(causal_credit),
        repaired_or_counterfactual_trajectory=trajectory,
        permitted_learning_targets=targets,
        producer_organ=producer,
        attempt_ordinal=attempt_ordinal,
    )


_DELTA_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "schema_domain",
        "delta_id",
        "parent_delta_id",
        "scope",
        "base_snapshot_id",
        "evidence_gradient_ids",
        "expiry_ordinal",
        "declared_scale",
        "declared_rank",
        "tensor_payload_root",
        "inverse_payload_root",
        "inverse_proof",
        "payload_bytes",
        "version_ordinal",
    }
)
_INVERSE_PROOF_FIELDS = frozenset(
    {
        "proof_kind",
        "pre_apply_payload_root",
        "post_apply_payload_root",
        "roundtrip_payload_root",
    }
)


def delta_from_raw(raw: bytes, registry: object | None = None) -> ParameterDelta:
    """Authenticate raw delta bytes into one frozen ``ParameterDelta``."""

    value = _authenticated_document(raw, DELTA_SCHEMA_VERSION)
    _schema_validate(raw, registry, DELTA_SCHEMA_ID)
    if set(value) != _DELTA_FIELDS:
        _reject("plasticity_document_shape_invalid")
    _require_frame(value, "plasticity_delta", SKELETON_PHASE13_DELTA)

    parent_delta_id = _sha256_field(value["parent_delta_id"], "delta_parent_invalid")
    scope_kind, project_id = _scope_binding(value["scope"], "delta_scope_invalid")
    base_snapshot_id = _sha256_field(
        value["base_snapshot_id"], "delta_base_snapshot_unpinned"
    )
    if base_snapshot_id == GENESIS_SHA256:
        # The genesis sentinel is a parent marker, never a pinned base
        # snapshot; a delta without an exact base identity is unpinned (D-01).
        _reject("delta_base_snapshot_unpinned")
    evidence = _sorted_unique_hashes(
        value["evidence_gradient_ids"],
        "delta_evidence_order_invalid",
        nonempty=True,
        missing_code="delta_evidence_missing",
    )
    expiry_ordinal = _exact_int(value["expiry_ordinal"], "delta_expiry_ordinal_invalid")
    declared_scale = value["declared_scale"]
    if not isinstance(declared_scale, Mapping) or set(declared_scale) != {
        "representation",
        "scale_log2",
    }:
        _reject("delta_scale_invalid")
    if declared_scale["representation"] != "fixed_point_int64":
        _reject("delta_scale_invalid")
    scale_log2 = _exact_int(declared_scale["scale_log2"], "delta_scale_invalid")
    if not 0 <= scale_log2 <= MAX_SCALE_LOG2:
        _reject("delta_scale_invalid")
    declared_rank = _exact_int(value["declared_rank"], "delta_rank_invalid")
    tensor_payload_root = _sha256_field(
        value["tensor_payload_root"], "delta_payload_root_invalid"
    )
    inverse_payload_root = _sha256_field(
        value["inverse_payload_root"], "delta_payload_root_invalid"
    )
    proof = value["inverse_proof"]
    if not isinstance(proof, Mapping) or set(proof) != _INVERSE_PROOF_FIELDS:
        _reject("delta_inverse_proof_invalid")
    if proof["proof_kind"] != "inverse_apply_byte_identity":
        _reject("delta_inverse_proof_invalid")
    pre_apply = _sha256_field(proof["pre_apply_payload_root"], "delta_inverse_proof_invalid")
    post_apply = _sha256_field(
        proof["post_apply_payload_root"], "delta_inverse_proof_invalid"
    )
    roundtrip = _sha256_field(
        proof["roundtrip_payload_root"], "delta_inverse_proof_invalid"
    )
    if roundtrip != pre_apply:
        # D-13: the committed inverse proof must reproduce the pre-apply
        # payload bytes exactly; anything else is unconstructible.
        _reject("delta_inverse_roundtrip_mismatch")
    payload_bytes = _exact_int(value["payload_bytes"], "delta_payload_bytes_invalid")
    version_ordinal = _exact_int(value["version_ordinal"], "delta_version_ordinal_invalid")

    declared = _sha256_field(value["delta_id"], "plasticity_identity_invalid")
    expected = compute_delta_identity(value)
    if declared != expected:
        _reject("plasticity_identity_mismatch")

    return _construct(
        ParameterDelta,
        identity=expected,
        schema_version=DELTA_SCHEMA_VERSION,
        value=value,
        canonical_bytes=raw,
        canonical_sha256=sha256_hex(raw),
        delta_id=expected,
        parent_delta_id=parent_delta_id,
        genesis_parent=parent_delta_id == GENESIS_SHA256,
        scope_kind=scope_kind,
        project_id=project_id,
        scope=_freeze(value["scope"]),
        base_snapshot_id=base_snapshot_id,
        evidence_gradient_ids=evidence,
        expiry_ordinal=expiry_ordinal,
        scale_log2=scale_log2,
        declared_rank=declared_rank,
        tensor_payload_root=tensor_payload_root,
        inverse_payload_root=inverse_payload_root,
        pre_apply_payload_root=pre_apply,
        post_apply_payload_root=post_apply,
        roundtrip_payload_root=roundtrip,
        payload_bytes=payload_bytes,
        version_ordinal=version_ordinal,
    )


_CHANNEL_UPDATE_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "schema_domain",
        "channel_update_id",
        "gradient_id",
        "channel",
        "payload",
        "producer_organ",
        "grader_organ",
        "update_ordinal",
        "fence_id",
        "generation",
        "attempt_ordinal",
    }
)
# Per-channel payload shape: (reference member, adjustment member); the
# fast_weights branch carries a delta reference and no adjustment.
_CHANNEL_PAYLOAD_MEMBERS: Mapping[LearningChannel, tuple[str, str | None]] = (
    MappingProxyType(
        {
            LearningChannel.FAST_WEIGHTS: ("delta_id", None),
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
_PERMILLE_ADJUSTMENTS = frozenset({"widen_permille", "reweight_permille"})


def channel_update_from_raw(raw: bytes, registry: object | None = None) -> ChannelUpdate:
    """Authenticate raw channel-update bytes into one frozen ``ChannelUpdate``."""

    value = _authenticated_document(raw, CHANNEL_UPDATE_SCHEMA_VERSION)
    _schema_validate(raw, registry, CHANNEL_UPDATE_SCHEMA_ID)
    if set(value) != _CHANNEL_UPDATE_FIELDS:
        _reject("plasticity_document_shape_invalid")
    _require_frame(value, "channel_update", SKELETON_PHASE13_CHANNEL_UPDATE)

    try:
        channel = LearningChannel(value["channel"])
    except (TypeError, ValueError) as error:
        raise PlasticityTypeRejection("channel_update_channel_unknown") from error
    payload = value["payload"]
    reference_member, adjustment_member = _CHANNEL_PAYLOAD_MEMBERS[channel]
    expected_members = {"payload_kind", reference_member}
    if adjustment_member is not None:
        expected_members.add(adjustment_member)
    if not isinstance(payload, Mapping) or set(payload) != expected_members:
        _reject("channel_update_payload_invalid")
    if payload["payload_kind"] != str(channel):
        # Branch pinning: the payload kind must equal the declared channel.
        _reject("channel_update_payload_mismatch")
    reference = _sha256_field(payload[reference_member], "channel_update_payload_invalid")
    adjustment: int | None = None
    if adjustment_member is not None:
        adjustment = _exact_int(payload[adjustment_member], "channel_update_payload_invalid")
        if adjustment_member in _PERMILLE_ADJUSTMENTS and not (
            0 <= adjustment <= MAX_CREDIT_PERMILLE
        ):
            _reject("channel_update_payload_invalid")
    producer = _organ(value["producer_organ"], "channel_update_organ_unknown")
    grader = _organ(value["grader_organ"], "channel_update_organ_unknown")
    if producer is grader:
        _reject("channel_update_self_grading_forbidden")
    gradient_id = _sha256_field(value["gradient_id"], "channel_update_reference_invalid")
    fence_id = _sha256_field(value["fence_id"], "channel_update_reference_invalid")
    update_ordinal = _exact_int(value["update_ordinal"], "channel_update_ordinal_invalid")
    generation = _exact_int(value["generation"], "channel_update_ordinal_invalid")
    attempt_ordinal = _exact_int(value["attempt_ordinal"], "channel_update_ordinal_invalid")
    if attempt_ordinal < 1:
        _reject("channel_update_ordinal_invalid")

    declared = _sha256_field(value["channel_update_id"], "plasticity_identity_invalid")
    expected = compute_channel_update_identity(value)
    if declared != expected:
        _reject("plasticity_identity_mismatch")

    return _construct(
        ChannelUpdate,
        identity=expected,
        schema_version=CHANNEL_UPDATE_SCHEMA_VERSION,
        value=value,
        canonical_bytes=raw,
        canonical_sha256=sha256_hex(raw),
        channel_update_id=expected,
        gradient_id=gradient_id,
        channel=channel,
        payload=_freeze(payload),
        delta_id=reference if channel is LearningChannel.FAST_WEIGHTS else None,
        reference_version_id=(
            None if channel is LearningChannel.FAST_WEIGHTS else reference
        ),
        adjustment=adjustment,
        producer_organ=producer,
        grader_organ=grader,
        update_ordinal=update_ordinal,
        fence_id=fence_id,
        generation=generation,
        attempt_ordinal=attempt_ordinal,
    )


_PLACEHOLDER_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "schema_domain",
        "placeholder_id",
        "reason",
        "bound_requirement",
        "bound_artifact_id",
        "replay_obligation",
        "recorded_ordinal",
    }
)
_REPLAY_OBLIGATION_FIELDS = frozenset(
    {"obligation_kind", "conformance_oracle_root", "expected_receipt_count"}
)


def placeholder_from_raw(
    raw: bytes, registry: object | None = None
) -> PendingOwnerHardware:
    """Authenticate raw placeholder bytes into one frozen honesty row."""

    value = _authenticated_document(raw, PLACEHOLDER_SCHEMA_VERSION)
    _schema_validate(raw, registry, PLACEHOLDER_SCHEMA_ID)
    if set(value) != _PLACEHOLDER_FIELDS:
        _reject("plasticity_document_shape_invalid")
    _require_frame(value, "pending_owner_hardware", SKELETON_PHASE13_PLACEHOLDER)

    try:
        reason = PlaceholderReason(value["reason"])
    except (TypeError, ValueError) as error:
        raise PlasticityTypeRejection("placeholder_reason_unknown") from error
    try:
        requirement = BoundRequirement(value["bound_requirement"])
    except (TypeError, ValueError) as error:
        raise PlasticityTypeRejection("placeholder_requirement_unknown") from error
    bound_artifact_id = _sha256_field(
        value["bound_artifact_id"], "placeholder_artifact_invalid"
    )
    obligation = value["replay_obligation"]
    if not isinstance(obligation, Mapping) or set(obligation) != _REPLAY_OBLIGATION_FIELDS:
        _reject("placeholder_obligation_invalid")
    try:
        obligation_kind = ReplayObligationKind(obligation["obligation_kind"])
    except (TypeError, ValueError) as error:
        raise PlasticityTypeRejection("placeholder_obligation_invalid") from error
    if obligation_kind is not BOUND_REQUIREMENT_OBLIGATIONS[requirement]:
        _reject("placeholder_obligation_mismatch")
    conformance_oracle_root = _sha256_field(
        obligation["conformance_oracle_root"], "placeholder_obligation_invalid"
    )
    expected_receipt_count = _exact_int(
        obligation["expected_receipt_count"], "placeholder_receipt_count_invalid"
    )
    if expected_receipt_count < 1:
        _reject("placeholder_receipt_count_invalid")
    recorded_ordinal = _exact_int(value["recorded_ordinal"], "placeholder_ordinal_invalid")

    declared = _sha256_field(value["placeholder_id"], "plasticity_identity_invalid")
    expected = compute_placeholder_identity(value)
    if declared != expected:
        _reject("plasticity_identity_mismatch")

    return _construct(
        PendingOwnerHardware,
        identity=expected,
        schema_version=PLACEHOLDER_SCHEMA_VERSION,
        value=value,
        canonical_bytes=raw,
        canonical_sha256=sha256_hex(raw),
        placeholder_id=expected,
        reason=reason,
        bound_requirement=requirement,
        bound_artifact_id=bound_artifact_id,
        obligation_kind=obligation_kind,
        conformance_oracle_root=conformance_oracle_root,
        expected_receipt_count=expected_receipt_count,
        replay_obligation=_freeze(obligation),
        recorded_ordinal=recorded_ordinal,
    )


__all__ = [name for name in globals() if not name.startswith("_")]
