"""The closed ordered Phase 13 five-probe candidate battery (Plan 13-09, D-10).

``ProbeBatteryRunner`` is the sole authority that evaluates one authenticated
candidate ``ParameterDelta`` against the frozen five-probe battery pinned by
the published ``plasticity-probe-receipt`` schema — ``domain`` (0),
``general_capability`` (1), ``calibration`` (2), ``safety`` (3),
``prior_regression`` (4) — with the Plan 13-09 CPU semantic binding:

``domain`` (ordinal 0) — the structural probe
    Kernel-level checks over the authenticated delta: exact fixed-point scale
    bounds, rank/shape/payload consistency in exact integer arithmetic, and
    inverse-proof recomputation through the deterministic reference kernel
    (``plasticity_kernel``).  When the kernel dependency is unavailable the
    runner rejects typed at construction — it never silently skips the proof.

``general_capability`` (ordinal 1) — the reference-behavior probe
    Deterministic fixed-point evaluation of the delta against a sealed
    synthetic reference input battery.  Every input tensor is derived from
    the delta's content identity by framed SHA-256 expansion — digest-seeded,
    never random — and the evaluated invariants are exact-integer norm bounds
    and zero-effect-outside-scope.  Evaluation inputs are drawn by the
    deterministic lowest-framed-digest sample of
    ``(ledger_state_root, delta_id, case_id)``.

``calibration`` (ordinal 2) — the regression-replay probe
    Replay of a closed caller-supplied set of prior sealed out-of-scope
    behaviors (``RegressionCase``), proving the delta does not alter any
    out-of-scope output byte-exactly: the recomputed output root of every
    sealed behavior must equal its sealed expectation exactly.

``safety`` (ordinal 3) and ``prior_regression`` (ordinal 4) — HARDWARE-GATED
    The real-model capability probe and the real-model KL/drift probe.  On
    CPU these MUST NOT fake results (D-18): each emits exactly one typed
    ``pending_owner_hardware`` placeholder row (reason ``dgx_absent``, bound
    requirement ``real_model_probe`` / ``real_model_kl_drift``) and one
    receipt in the schema's only honest pending form — ``evaluation_basis``
    ``real_model`` bound to that placeholder identity, whose counts declare
    the recorded replay obligation, never a measurement.  The schema makes a
    real-model receipt without a placeholder unrepresentable by shape.

Receipts are content-addressed, schema-valid, and exact-integer accounted;
the battery is complete iff all five probes ran (a placeholder emission
counts as ran-with-placeholder), and partial with a typed cause on any
short-circuit.  ``commit_probe_outcome`` is the two-phase store commit:
phase one appends every placeholder row (pressure-exempt) and then every
receipt row in frozen order through the sole writer under fence discipline;
phase two seals the deterministic battery disposition referencing the exact
triggering receipt for a failing delta.  A partially probed delta reports
``battery_incomplete`` and holds no downstream-eligible status.

Deterministic and typed throughout: no wall clock, no randomness, no float,
no unsorted iteration; every rejection carries a closed snake_case code.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from importlib import import_module
from types import MappingProxyType
from typing import Any, Protocol

from .canonical import canonicalize, parse_raw_json
from .plasticity_kernel import payload_from_bytes, tensor_payload_root
from .plasticity_store import (
    OperationReceipt,
    PlaceholderAppend,
    ProbeBatteryAppend,
    ProbeReceiptAppend,
    plasticity_record_identity,
)
from .plasticity_types import (
    BOUND_REQUIREMENT_OBLIGATIONS,
    BoundRequirement,
    EvaluationBasis,
    MAX_SCALE_LOG2,
    NONE_SENTINEL,
    PLACEHOLDER_SCHEMA_VERSION,
    PROBE_BATTERY_ORDER,
    ParameterDelta,
    PlaceholderReason,
    ProbeKind,
    ProbeStatus,
    SAFE_INTEGER_MAX,
    SKELETON_PHASE13_PLACEHOLDER,
    SKELETON_PHASE13_PROBE,
    compute_delta_identity,
    compute_placeholder_identity,
    compute_phase13_identity,
)


# ---------------------------------------------------------------------------
# Frozen battery constants
# ---------------------------------------------------------------------------

PROBE_RECEIPT_SCHEMA_VERSION = "skeleton.plasticity-probe-receipt.v1"

# Deterministic evaluation-input sampling, mirroring the Phase 12
# gate-sample discipline: the PROBE_SAMPLE_SIZE lowest length-framed SHA-256
# digests of (ledger_state_root, delta_id, case_id) under the frozen domain.
SKELETON_PHASE13_PROBE_SAMPLE_V1 = "SKELETON_PHASE13_PROBE_SAMPLE_V1"
PROBE_SAMPLE_SIZE = 3
PROBE_SAMPLE_DERIVATION = "lowest_framed_digest"
PROBE_SAMPLE_DERIVATION_INPUTS = ("ledger_state_root", "delta_id", "case_id")

# Digest-seeded synthetic tensor derivation (never random): framed SHA-256
# expansion domains for the sealed reference battery, the regression replay,
# and the placeholder conformance oracle roots.
SKELETON_PHASE13_PROBE_REFERENCE_V1 = "SKELETON_PHASE13_PROBE_REFERENCE_V1"
SKELETON_PHASE13_PROBE_REGRESSION_V1 = "SKELETON_PHASE13_PROBE_REGRESSION_V1"
SKELETON_PHASE13_PROBE_ORACLE_V1 = "SKELETON_PHASE13_PROBE_ORACLE_V1"
SKELETON_PHASE13_PROBE_BATTERY_V1 = "SKELETON_PHASE13_PROBE_BATTERY_V1"

# The sealed synthetic reference battery: case count, elements per tensor,
# and the exact signed 32-bit element range of the framed expansion.
REFERENCE_CASE_COUNT = 5
REFERENCE_TENSOR_ELEMENTS = 8
_ELEMENT_MODULUS = 1 << 32
_ELEMENT_OFFSET = 1 << 31

# The frozen ordinal pin of the published receipt schema.
PROBE_ORDINALS: Mapping[ProbeKind, int] = MappingProxyType(
    {kind: ordinal for ordinal, kind in enumerate(PROBE_BATTERY_ORDER)}
)

# The Plan 13-09 CPU semantic binding of the five pinned probe kinds.
PROBE_SEMANTIC_BINDINGS: Mapping[ProbeKind, str] = MappingProxyType(
    {
        ProbeKind.DOMAIN: "structural",
        ProbeKind.GENERAL_CAPABILITY: "reference_behavior",
        ProbeKind.CALIBRATION: "regression_replay",
        ProbeKind.SAFETY: "real_model_capability",
        ProbeKind.PRIOR_REGRESSION: "real_model_kl_drift",
    }
)

# The two HARDWARE-GATED probe kinds and their bound placeholder
# requirements (D-18): honest measurement requires the real local model.
HARDWARE_GATED_REQUIREMENTS: Mapping[ProbeKind, BoundRequirement] = MappingProxyType(
    {
        ProbeKind.SAFETY: BoundRequirement.REAL_MODEL_PROBE,
        ProbeKind.PRIOR_REGRESSION: BoundRequirement.REAL_MODEL_KL_DRIFT,
    }
)
HARDWARE_GATED_PROBE_KINDS = tuple(
    kind for kind in PROBE_BATTERY_ORDER if kind in HARDWARE_GATED_REQUIREMENTS
)

# The CPU evaluation basis of each non-gated probe kind.
CPU_PROBE_BASES: Mapping[ProbeKind, EvaluationBasis] = MappingProxyType(
    {
        ProbeKind.DOMAIN: EvaluationBasis.REFERENCE_KERNEL,
        ProbeKind.GENERAL_CAPABILITY: EvaluationBasis.REFERENCE_KERNEL,
        ProbeKind.CALIBRATION: EvaluationBasis.FIXTURE_BATTERY,
    }
)

# The closed structural checklist of the domain probe, in evaluation order.
STRUCTURAL_CHECKS = ("scale_bounds", "rank_shape", "inverse_proof_recomputation")

COMPLETENESS_COMPLETE = "complete"
COMPLETENESS_PARTIAL = "partial"

# The closed battery statuses: no member of this enum means
# real-model-verified pre-DGX, and only the passed-with-placeholders state
# is downstream-eligible for the 13-10 apply path.
BATTERY_STATUS_PASSED = "cpu_battery_passed_with_placeholders"
BATTERY_STATUS_QUARANTINE = "quarantine_intent"
BATTERY_STATUS_INCOMPLETE = "battery_incomplete"
CLOSED_BATTERY_STATUSES = (
    BATTERY_STATUS_INCOMPLETE,
    BATTERY_STATUS_PASSED,
    BATTERY_STATUS_QUARANTINE,
)

CLOSED_PROBE_REJECTION_CODES = (
    "probe_commit_operation_ids_invalid",
    "probe_delta_invalid",
    "probe_input_invalid",
    "probe_kernel_dependency_unavailable",
    "probe_outcome_invalid",
    "probe_payload_resolver_unavailable",
    "probe_receipt_count_mismatch",
    "probe_receipt_field_invalid",
    "probe_receipt_placeholder_binding_invalid",
    "probe_receipt_verdict_inconsistent",
    "probe_sample_input_invalid",
)

CLOSED_PROBE_OUTCOME_CODES = (
    "battery_all_ran_with_placeholders",
    "battery_pending_owner_hardware",
    "probe_failed_calibration",
    "probe_failed_domain",
    "probe_failed_general_capability",
    "probe_kernel_evaluation_failed",
    "probe_regression_inventory_invalid",
)


class PlasticityProbeRejection(ValueError):
    """Stable fail-closed rejection carrying a closed snake_case code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise PlasticityProbeRejection(code)


class _ProbeShortCircuit(Exception):
    """Internal: a probe could not evaluate to a verdict; typed cause only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


# ---------------------------------------------------------------------------
# Shared exact helpers
# ---------------------------------------------------------------------------


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def _exact_int(value: object, minimum: int, code: str) -> int:
    if type(value) is not int or not minimum <= value <= SAFE_INTEGER_MAX:
        _reject(code)
    return int(value)


def _expand_signed_elements(
    domain: str, material: Sequence[object], count: int
) -> tuple[int, ...]:
    """Digest-seeded expansion into exact signed 32-bit integers.

    Framed SHA-256 blocks of ``canonicalize([*material, block_index])`` are
    consumed eight bytes at a time; each word reduces into the exact range
    ``[-2**31, 2**31)``.  Never random, never a float, order-independent of
    any environment state.
    """

    values: list[int] = []
    block_index = 0
    while len(values) < count:
        digest = _framed_digest(
            domain, canonicalize([*list(material), block_index])
        )
        block = bytes.fromhex(digest)
        for offset in range(0, len(block), 8):
            if len(values) >= count:
                break
            word = int.from_bytes(block[offset : offset + 8], "big")
            values.append((word % _ELEMENT_MODULUS) - _ELEMENT_OFFSET)
        block_index += 1
    return tuple(values)


# ---------------------------------------------------------------------------
# Deterministic lowest-framed-digest evaluation-input sampling
# ---------------------------------------------------------------------------


def probe_sample_digest(ledger_state_root: str, delta_id: str, case_id: str) -> str:
    """The framed ordering digest of one ``(ledger_state_root, delta_id, case_id)``."""

    if not (
        _is_sha256(ledger_state_root) and _is_sha256(delta_id) and _is_sha256(case_id)
    ):
        _reject("probe_sample_input_invalid")
    return _framed_digest(
        SKELETON_PHASE13_PROBE_SAMPLE_V1,
        canonicalize([ledger_state_root, delta_id, case_id]),
    )


def draw_probe_sample(
    ledger_state_root: str, delta_id: str, case_ids: Sequence[str]
) -> tuple[str, ...]:
    """Select the ``PROBE_SAMPLE_SIZE`` lowest framed digests, seedlessly.

    Ties are impossible by digest uniqueness over distinct case identities;
    insertion order never matters.  The returned inventory is sorted by case
    identity — the declared receipt-side ordering.
    """

    if not _is_sha256(ledger_state_root) or not _is_sha256(delta_id):
        _reject("probe_sample_input_invalid")
    if not isinstance(case_ids, (list, tuple)) or not case_ids:
        _reject("probe_sample_input_invalid")
    unique: set[str] = set()
    for case_id in case_ids:
        if not _is_sha256(case_id) or case_id in unique:
            _reject("probe_sample_input_invalid")
        unique.add(case_id)
    ranked = sorted(
        (probe_sample_digest(ledger_state_root, delta_id, case_id), case_id)
        for case_id in unique
    )
    selected = tuple(case_id for _digest, case_id in ranked[:PROBE_SAMPLE_SIZE])
    return tuple(sorted(selected))


# ---------------------------------------------------------------------------
# Reference kernel dependency (typed rejection when unavailable)
# ---------------------------------------------------------------------------


class ReferenceKernel(Protocol):
    """The deterministic reference-kernel surface the structural probe uses."""

    def recompute_inverse_proof(self, delta: ParameterDelta) -> Mapping[str, str]: ...


class _ProductionReferenceKernel:
    """Bind the production kernel proof API to a content resolver."""

    __slots__ = ("_module", "_payload_resolver")

    def __init__(self, module: object, payload_resolver: Callable[[str], bytes | None]):
        self._module = module
        self._payload_resolver = payload_resolver

    def recompute_inverse_proof(self, delta: ParameterDelta) -> Mapping[str, str]:
        return self._module.recompute_inverse_proof(delta, self._payload_resolver)


def resolve_reference_kernel(
    payload_resolver: Callable[[str], bytes | None] | None,
) -> ReferenceKernel:
    """Resolve ``skeleton_kernel.plasticity_kernel`` or reject typed.

    The structural probe's inverse-proof recomputation is a hard dependency:
    when the deterministic reference kernel is unavailable the battery is
    unconstructible — it never degrades to skipping the proof.
    """

    try:
        module = import_module("skeleton_kernel.plasticity_kernel")
    except ImportError as error:
        raise PlasticityProbeRejection(
            "probe_kernel_dependency_unavailable"
        ) from error
    if (
        not callable(getattr(module, "recompute_inverse_proof", None))
        or not callable(payload_resolver)
    ):
        _reject("probe_kernel_dependency_unavailable")
    return _ProductionReferenceKernel(module, payload_resolver)


# ---------------------------------------------------------------------------
# Typed values
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RegressionCase:
    """One frozen model behavior sealed before a candidate is evaluated.

    The case owns the exact model snapshot, input and expected output bytes,
    plus an explicit scope mask.  A candidate is presented to inference only
    when its scope is named by that mask; an empty mask is genuinely
    out-of-scope rather than a comment attached to an in-scope calculation.
    """

    case_id: str
    model_snapshot_id: str
    input_bytes: bytes
    input_root: str
    expected_output_bytes: bytes
    expected_output_root: str
    scope_mask: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PlaceholderEmission:
    """One typed hardware-honesty placeholder emitted by a gated probe."""

    probe_kind: ProbeKind
    placeholder_id: str
    reason: PlaceholderReason
    bound_requirement: BoundRequirement
    bound_artifact_id: str
    conformance_oracle_root: str
    recorded_ordinal: int
    placeholder_value: Mapping[str, Any]
    placeholder_bytes: bytes


@dataclass(frozen=True, slots=True)
class ProbeEvaluation:
    """One probe's sealed receipt with exact integer accounting."""

    probe_kind: ProbeKind
    probe_ordinal: int
    semantic: str
    evaluation_basis: EvaluationBasis
    passed_count: int
    failed_count: int
    total_count: int
    status: ProbeStatus
    placeholder_id: str
    sample_declaration: Mapping[str, Any] | None
    receipt_value: Mapping[str, Any]
    receipt_bytes: bytes
    receipt_id: str
    receipt_row_id: str


@dataclass(frozen=True, slots=True)
class ProbeBatteryOutcome:
    """The complete deterministic result of one battery run over one delta."""

    delta_id: str
    ledger_state_root: str
    status: str
    code: str
    completeness: str
    short_circuit_kind: ProbeKind | None
    failing_receipt_row_id: str
    evaluations: tuple[ProbeEvaluation, ...]
    placeholders: tuple[PlaceholderEmission, ...]
    fence_id: str
    generation: int
    attempt_ordinal: int
    battery_root: str


@dataclass(frozen=True, slots=True)
class ProbeDisposition:
    """Phase-two seal: the atomic battery disposition after the appends."""

    delta_id: str
    status: str
    code: str
    completeness: str
    failing_receipt_row_id: str
    receipt_row_ids: tuple[str, ...]
    placeholder_ids: tuple[str, ...]
    battery_id: str
    battery_root: str


@dataclass(frozen=True, slots=True)
class ProbeCommit:
    """The two-phase commit product: appended rows plus the disposition."""

    placeholder_receipts: tuple[OperationReceipt, ...]
    receipt_receipts: tuple[OperationReceipt, ...]
    disposition: ProbeDisposition


class ProbeStore(Protocol):
    """The narrow append-only store handle the probe commit path uses."""

    def commit_probe_battery(
        self,
        *,
        placeholders: tuple[PlaceholderAppend, ...],
        receipts: tuple[ProbeReceiptAppend, ...],
        disposition: ProbeBatteryAppend,
        writer_id: str,
        operation_id: str,
        failure_after_row: int = 0,
    ) -> OperationReceipt: ...


# ---------------------------------------------------------------------------
# Receipt sealing (the only writers of receipt documents)
# ---------------------------------------------------------------------------


def seal_probe_receipt(
    *,
    delta_id: str,
    probe_kind: ProbeKind | str,
    evaluation_basis: EvaluationBasis | str,
    passed_count: int,
    failed_count: int,
    total_count: int,
    status: ProbeStatus | str,
    placeholder_id: str,
    fence_id: str,
    generation: int,
    attempt_ordinal: int,
) -> tuple[Mapping[str, Any], bytes, str, str]:
    """Seal one schema-valid content-addressed probe receipt document.

    Enforces the published schema's three structural constraints before any
    bytes exist: the frozen ordinal pin, verdict consistency with exact
    integer accounting, and the hardware-honesty placeholder binding — a
    ``real_model`` basis without a placeholder identity (or a placeholder on
    a CPU basis) rejects typed, so fabricated real-model measurements are
    unrepresentable through this module.
    """

    try:
        kind = ProbeKind(probe_kind)
        basis = EvaluationBasis(evaluation_basis)
        verdict = ProbeStatus(status)
    except (TypeError, ValueError) as error:
        raise PlasticityProbeRejection("probe_receipt_field_invalid") from error
    if not _is_sha256(delta_id) or not _is_sha256(fence_id):
        _reject("probe_receipt_field_invalid")
    passed = _exact_int(passed_count, 0, "probe_receipt_field_invalid")
    failed = _exact_int(failed_count, 0, "probe_receipt_field_invalid")
    total = _exact_int(total_count, 1, "probe_receipt_field_invalid")
    if passed + failed != total:
        _reject("probe_receipt_count_mismatch")
    if (verdict is ProbeStatus.PASSED) != (failed == 0):
        _reject("probe_receipt_verdict_inconsistent")
    if basis is EvaluationBasis.REAL_MODEL:
        if not _is_sha256(placeholder_id):
            _reject("probe_receipt_placeholder_binding_invalid")
    elif placeholder_id != NONE_SENTINEL:
        _reject("probe_receipt_placeholder_binding_invalid")
    generation = _exact_int(generation, 0, "probe_receipt_field_invalid")
    attempt = _exact_int(attempt_ordinal, 1, "probe_receipt_field_invalid")
    value: dict[str, Any] = {
        "schema_version": PROBE_RECEIPT_SCHEMA_VERSION,
        "record_type": "probe_receipt",
        "schema_domain": SKELETON_PHASE13_PROBE,
        "delta_id": delta_id,
        "probe_kind": kind.value,
        "probe_ordinal": PROBE_ORDINALS[kind],
        "evaluation_basis": basis.value,
        "passed_count": passed,
        "failed_count": failed,
        "total_count": total,
        "status": verdict.value,
        "placeholder_id": placeholder_id,
        "fence_id": fence_id,
        "generation": generation,
        "attempt_ordinal": attempt,
    }
    receipt_id = compute_phase13_identity(SKELETON_PHASE13_PROBE, "receipt_id", value)
    value["receipt_id"] = receipt_id
    raw = canonicalize(value)
    row_id = receipt_id
    return _freeze(value), raw, receipt_id, row_id


# ---------------------------------------------------------------------------
# Fail-closed delta authentication
# ---------------------------------------------------------------------------


def _authenticate_delta(delta: ParameterDelta) -> None:
    """Recompute the delta's content identity before trusting any field."""

    if not isinstance(delta, ParameterDelta):
        _reject("probe_delta_invalid")
    body = _thaw(delta.value)
    if not isinstance(body, dict):
        _reject("probe_delta_invalid")
    if canonicalize(body) != delta.canonical_bytes:
        _reject("probe_delta_invalid")
    if compute_delta_identity(body) != delta.delta_id:
        _reject("probe_delta_invalid")


# ---------------------------------------------------------------------------
# CPU probe evaluators
# ---------------------------------------------------------------------------


def derive_reference_case_ids(delta_id: str) -> tuple[str, ...]:
    """The sealed synthetic reference battery bound to one delta identity."""

    if not _is_sha256(delta_id):
        _reject("probe_input_invalid")
    return tuple(
        _framed_digest(
            SKELETON_PHASE13_PROBE_REFERENCE_V1,
            canonicalize(["case", delta_id, index]),
        )
        for index in range(REFERENCE_CASE_COUNT)
    )


def derive_reference_input(case_id: str) -> tuple[int, ...]:
    """The digest-seeded synthetic input tensor of one reference case."""

    if not _is_sha256(case_id):
        _reject("probe_input_invalid")
    return _expand_signed_elements(
        SKELETON_PHASE13_PROBE_REFERENCE_V1,
        ["input", case_id],
        REFERENCE_TENSOR_ELEMENTS,
    )


def derive_delta_coefficients(
    delta: ParameterDelta, payload_resolver: Callable[[str], bytes | None]
) -> tuple[int, ...]:
    """Resolve the authenticated candidate tensor's actual coefficients."""

    try:
        payload = payload_resolver(delta.tensor_payload_root)
    except Exception as error:
        raise _ProbeShortCircuit("probe_payload_resolver_unavailable") from error
    if (
        not isinstance(payload, bytes)
        or tensor_payload_root(payload) != delta.tensor_payload_root
    ):
        raise _ProbeShortCircuit("probe_payload_resolver_unavailable")
    try:
        tensor = payload_from_bytes(payload)
    except Exception as error:
        raise _ProbeShortCircuit("probe_payload_resolver_unavailable") from error
    if tensor.scale_log2 != delta.scale_log2 or not tensor.elements:
        raise _ProbeShortCircuit("probe_payload_resolver_unavailable")
    return tuple(tensor.elements[:REFERENCE_TENSOR_ELEMENTS])


def reference_effect(
    delta: ParameterDelta,
    input_tensor: Sequence[int],
    payload_resolver: Callable[[str], bytes | None],
) -> tuple[int, ...]:
    """The delta's exact fixed-point effect vector on one input tensor.

    In-scope elements (the first ``declared_rank`` positions, capped by the
    tensor width) receive ``(coefficient * element) >> scale_log2`` in exact
    integer arithmetic; every out-of-scope element receives exactly zero.
    """

    coefficients = derive_delta_coefficients(delta, payload_resolver)
    effect: list[int] = []
    for index, element in enumerate(input_tensor):
        if index < len(coefficients):
            effect.append((coefficients[index] * int(element)) >> delta.scale_log2)
        else:
            effect.append(0)
    return tuple(effect)


def _structural_failures(
    delta: ParameterDelta, kernel: ReferenceKernel
) -> tuple[str, ...]:
    """Probe 0 (domain/structural): the closed kernel-level checklist."""

    failing: list[str] = []
    if not 0 <= delta.scale_log2 <= MAX_SCALE_LOG2:
        failing.append("scale_bounds")
    element_bytes = 8 * delta.declared_rank
    if (
        delta.declared_rank < 1
        or delta.payload_bytes < element_bytes
        or delta.payload_bytes % element_bytes != 0
    ):
        failing.append("rank_shape")
    try:
        proof = kernel.recompute_inverse_proof(delta)
    except PlasticityProbeRejection:
        raise
    except Exception as error:
        raise _ProbeShortCircuit("probe_kernel_evaluation_failed") from error
    if not isinstance(proof, Mapping):
        raise _ProbeShortCircuit("probe_kernel_evaluation_failed")
    recomputed = (
        proof.get("pre_apply_payload_root"),
        proof.get("post_apply_payload_root"),
        proof.get("roundtrip_payload_root"),
    )
    if not all(_is_sha256(root) for root in recomputed):
        raise _ProbeShortCircuit("probe_kernel_evaluation_failed")
    declared = (
        delta.pre_apply_payload_root,
        delta.post_apply_payload_root,
        delta.roundtrip_payload_root,
    )
    if recomputed != declared or recomputed[2] != recomputed[0]:
        failing.append("inverse_proof_recomputation")
    return tuple(failing)


def _reference_behavior_failures(
    delta: ParameterDelta,
    sampled_case_ids: tuple[str, ...],
    payload_resolver: Callable[[str], bytes | None],
) -> tuple[str, ...]:
    """Probe 1 (general_capability/reference-behavior): exact invariants."""

    coefficients = derive_delta_coefficients(delta, payload_resolver)
    norm_bound = len(coefficients) * (1 << max(0, 62 - delta.scale_log2))
    failing: list[str] = []
    for case_id in sampled_case_ids:
        tensor = derive_reference_input(case_id)
        effect = reference_effect(delta, tensor, payload_resolver)
        in_bounds = sum(abs(value) for value in effect) <= norm_bound
        zero_outside_scope = all(
            value == 0 for value in effect[len(coefficients) :]
        )
        if not (in_bounds and zero_outside_scope):
            failing.append(case_id)
    return tuple(sorted(failing))


def _behavior_root(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        _reject("probe_input_invalid")
    return _framed_digest(SKELETON_PHASE13_PROBE_REGRESSION_V1, raw)


def _scope_key(delta: ParameterDelta) -> str:
    if delta.scope_kind.value == "project":
        assert delta.project_id is not None
        return f"project:{delta.project_id}"
    return delta.scope_kind.value


def seal_regression_case(
    *,
    behavior_seed: str,
    model_snapshot_id: str | None = None,
    input_bytes: bytes | None = None,
    expected_output_bytes: bytes | None = None,
    scope_mask: Sequence[str] = (),
) -> RegressionCase:
    """Seal exact held-out bytes and scope before candidate creation."""

    if not _is_sha256(behavior_seed):
        _reject("probe_input_invalid")
    snapshot = (
        _framed_digest(
            SKELETON_PHASE13_PROBE_REGRESSION_V1,
            canonicalize(["snapshot", behavior_seed]),
        )
        if model_snapshot_id is None
        else model_snapshot_id
    )
    if not _is_sha256(snapshot):
        _reject("probe_input_invalid")
    if input_bytes is None:
        input_bytes = canonicalize(
            list(
                _expand_signed_elements(
                    SKELETON_PHASE13_PROBE_REGRESSION_V1,
                    ["tensor", behavior_seed],
                    REFERENCE_TENSOR_ELEMENTS,
                )
            )
        )
    if expected_output_bytes is None:
        expected_output_bytes = input_bytes
    if not isinstance(input_bytes, bytes) or not isinstance(
        expected_output_bytes, bytes
    ):
        _reject("probe_input_invalid")
    mask = tuple(scope_mask)
    if (
        not all(isinstance(item, str) and item for item in mask)
        or mask != tuple(sorted(set(mask)))
    ):
        _reject("probe_input_invalid")
    input_root = _behavior_root(input_bytes)
    expected_root = regression_expected_output_root(expected_output_bytes)
    case_id = _framed_digest(
        SKELETON_PHASE13_PROBE_REGRESSION_V1,
        canonicalize(
            {
                "behavior_seed": behavior_seed,
                "expected_output_root": expected_root,
                "input_root": input_root,
                "model_snapshot_id": snapshot,
                "scope_mask": list(mask),
            }
        ),
    )
    return RegressionCase(
        case_id=case_id,
        model_snapshot_id=snapshot,
        input_bytes=bytes(input_bytes),
        input_root=input_root,
        expected_output_bytes=bytes(expected_output_bytes),
        expected_output_root=expected_root,
        scope_mask=mask,
    )


def regression_expected_output_root(expected_output_bytes: bytes) -> str:
    """Seal expected held-out output bytes independently of a candidate."""

    return _behavior_root(expected_output_bytes)


def regression_output_root(
    delta: ParameterDelta,
    case: RegressionCase,
    payload_resolver: Callable[[str], bytes | None],
    inference: "RegressionInference",
) -> str:
    """Execute one frozen case through the provider inference boundary.

    The behavior's tensor is out-of-scope for the candidate delta, so the
    replayed output must be the input plus the delta's out-of-scope effect —
    which the reference semantics require to be exactly zero everywhere.
    """

    candidate = delta if _scope_key(delta) in case.scope_mask else None
    try:
        output = inference.infer(
            case.model_snapshot_id, case.input_bytes, candidate, payload_resolver
        )
    except _ProbeShortCircuit:
        raise
    except Exception as error:
        raise _ProbeShortCircuit("probe_regression_evaluation_failed") from error
    if not isinstance(output, bytes):
        raise _ProbeShortCircuit("probe_regression_evaluation_failed")
    return _behavior_root(output)


class RegressionInference(Protocol):
    """Frozen provider inference boundary used by regression replay."""

    def infer(
        self,
        model_snapshot_id: str,
        input_bytes: bytes,
        candidate: ParameterDelta | None,
        payload_resolver: Callable[[str], bytes | None],
    ) -> bytes: ...


class _ReferenceRegressionInference:
    """Deterministic CPU provider for exact fixed-point conformance tests."""

    def infer(
        self,
        model_snapshot_id: str,
        input_bytes: bytes,
        candidate: ParameterDelta | None,
        payload_resolver: Callable[[str], bytes | None],
    ) -> bytes:
        if not _is_sha256(model_snapshot_id):
            raise _ProbeShortCircuit("probe_regression_inventory_invalid")
        try:
            parsed = parse_raw_json(input_bytes)
        except Exception as error:
            raise _ProbeShortCircuit("probe_regression_inventory_invalid") from error
        if (
            not isinstance(parsed, list)
            or len(parsed) != REFERENCE_TENSOR_ELEMENTS
            or any(type(item) is not int for item in parsed)
        ):
            raise _ProbeShortCircuit("probe_regression_inventory_invalid")
        output = tuple(int(item) for item in parsed)
        if candidate is not None:
            effect = reference_effect(candidate, output, payload_resolver)
            output = tuple(value + effect[index] for index, value in enumerate(output))
        return canonicalize(list(output))
    # The sealed behavior is out-of-scope for the candidate delta: its
    # in-scope coefficient window does not cover this tensor, so the only
    # contribution the replay may add is the delta's out-of-scope effect —
    # which the reference semantics require to be exactly zero everywhere.
def _regression_failures(
    delta: ParameterDelta,
    cases: Sequence[RegressionCase],
    payload_resolver: Callable[[str], bytes | None],
    inference: RegressionInference,
) -> tuple[tuple[str, ...], int]:
    """Probe 2 (calibration/regression-replay): byte-exact replay of the
    closed caller-supplied prior sealed behaviors."""

    if not isinstance(cases, (list, tuple)) or not cases:
        raise _ProbeShortCircuit("probe_regression_inventory_invalid")
    seen: set[str] = set()
    ordered: list[RegressionCase] = []
    for case in cases:
        if (
            not isinstance(case, RegressionCase)
            or not _is_sha256(case.case_id)
            or not _is_sha256(case.model_snapshot_id)
            or not _is_sha256(case.input_root)
            or not _is_sha256(case.expected_output_root)
            or _behavior_root(case.input_bytes) != case.input_root
            or regression_expected_output_root(case.expected_output_bytes)
            != case.expected_output_root
            or case.scope_mask != tuple(sorted(set(case.scope_mask)))
            or case.case_id in seen
        ):
            raise _ProbeShortCircuit("probe_regression_inventory_invalid")
        seen.add(case.case_id)
        ordered.append(case)
    ordered.sort(key=lambda case: case.case_id)
    failing: list[str] = []
    for case in ordered:
        recomputed = regression_output_root(delta, case, payload_resolver, inference)
        if recomputed != case.expected_output_root:
            failing.append(case.case_id)
    return tuple(sorted(failing)), len(ordered)


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


class ProbeBatteryRunner:
    """Deterministic frozen-order five-probe evaluator for candidate deltas."""

    __slots__ = (
        "_attempt_ordinal",
        "_fence_id",
        "_generation",
        "_kernel",
        "_ledger_state_root",
        "_placeholder_base_ordinal",
        "_payload_resolver",
        "_regression_inference",
    )

    def __init__(
        self,
        *,
        ledger_state_root: str,
        fence_id: str,
        generation: int,
        attempt_ordinal: int,
        placeholder_base_ordinal: int,
        kernel: ReferenceKernel | None = None,
        payload_resolver: Callable[[str], bytes | None] | None = None,
        regression_inference: RegressionInference | None = None,
    ) -> None:
        if not _is_sha256(ledger_state_root) or not _is_sha256(fence_id):
            _reject("probe_input_invalid")
        self._ledger_state_root = str(ledger_state_root)
        self._fence_id = str(fence_id)
        self._generation = _exact_int(generation, 0, "probe_input_invalid")
        self._attempt_ordinal = _exact_int(attempt_ordinal, 1, "probe_input_invalid")
        self._placeholder_base_ordinal = _exact_int(
            placeholder_base_ordinal, 0, "probe_input_invalid"
        )
        if kernel is None:
            kernel = resolve_reference_kernel(payload_resolver)
        elif not callable(getattr(kernel, "recompute_inverse_proof", None)):
            _reject("probe_kernel_dependency_unavailable")
        self._kernel = kernel
        if not callable(payload_resolver):
            _reject("probe_payload_resolver_unavailable")
        self._payload_resolver = payload_resolver
        if regression_inference is None:
            regression_inference = _ReferenceRegressionInference()
        if not callable(getattr(regression_inference, "infer", None)):
            _reject("probe_regression_inference_unavailable")
        self._regression_inference = regression_inference

    @property
    def ledger_state_root(self) -> str:
        return self._ledger_state_root

    def run_battery(
        self,
        delta: ParameterDelta,
        *,
        regression_cases: Sequence[RegressionCase],
    ) -> ProbeBatteryOutcome:
        """Run the five probes in the frozen order over one candidate delta.

        A CPU probe failure seals its typed failed receipt and short-circuits
        the battery (partial, ``quarantine_intent``); a probe that cannot
        evaluate short-circuits typed without a receipt (partial,
        ``battery_incomplete``).  Only a battery in which all five probes ran
        — the two hardware-gated kinds as placeholder emissions — reports
        the complete ``cpu_battery_passed_with_placeholders`` state.
        """

        _authenticate_delta(delta)
        evaluations: list[ProbeEvaluation] = []
        placeholders: list[PlaceholderEmission] = []
        failing_kind: ProbeKind | None = None
        short_circuit_kind: ProbeKind | None = None
        short_circuit_code: str | None = None
        for kind in PROBE_BATTERY_ORDER:
            try:
                if kind in HARDWARE_GATED_REQUIREMENTS:
                    emission = self._pending_real_model_probe(
                        delta, kind, len(placeholders)
                    )
                    placeholders.append(emission)
                    continue
                if kind is ProbeKind.DOMAIN:
                    failing = _structural_failures(delta, self._kernel)
                    total = len(STRUCTURAL_CHECKS)
                    sample_declaration: Mapping[str, Any] | None = None
                elif kind is ProbeKind.GENERAL_CAPABILITY:
                    case_ids = derive_reference_case_ids(delta.delta_id)
                    sample = draw_probe_sample(
                        self._ledger_state_root, delta.delta_id, case_ids
                    )
                    failing = _reference_behavior_failures(
                        delta, sample, self._payload_resolver
                    )
                    total = len(sample)
                    sample_declaration = _freeze(
                        {
                            "derivation": PROBE_SAMPLE_DERIVATION,
                            "derivation_domain": SKELETON_PHASE13_PROBE_SAMPLE_V1,
                            "derivation_inputs": list(
                                PROBE_SAMPLE_DERIVATION_INPUTS
                            ),
                            "sample_size": len(sample),
                            "sampled_case_ids": list(sample),
                        }
                    )
                else:
                    failing, total = _regression_failures(
                        delta,
                        regression_cases,
                        self._payload_resolver,
                        self._regression_inference,
                    )
                    sample_declaration = None
            except _ProbeShortCircuit as cause:
                short_circuit_kind = kind
                short_circuit_code = cause.code
                break
            evaluation = self._seal_cpu_evaluation(
                delta, kind, len(failing), total, sample_declaration
            )
            evaluations.append(evaluation)
            if failing:
                failing_kind = kind
                break
        return self._seal_outcome(
            delta,
            tuple(evaluations),
            tuple(placeholders),
            failing_kind,
            short_circuit_kind,
            short_circuit_code,
        )

    def _seal_cpu_evaluation(
        self,
        delta: ParameterDelta,
        kind: ProbeKind,
        failed_count: int,
        total_count: int,
        sample_declaration: Mapping[str, Any] | None,
    ) -> ProbeEvaluation:
        basis = CPU_PROBE_BASES[kind]
        status = ProbeStatus.FAILED if failed_count else ProbeStatus.PASSED
        value, raw, receipt_id, row_id = seal_probe_receipt(
            delta_id=delta.delta_id,
            probe_kind=kind,
            evaluation_basis=basis,
            passed_count=total_count - failed_count,
            failed_count=failed_count,
            total_count=total_count,
            status=status,
            placeholder_id=NONE_SENTINEL,
            fence_id=self._fence_id,
            generation=self._generation,
            attempt_ordinal=self._attempt_ordinal,
        )
        return ProbeEvaluation(
            probe_kind=kind,
            probe_ordinal=PROBE_ORDINALS[kind],
            semantic=PROBE_SEMANTIC_BINDINGS[kind],
            evaluation_basis=basis,
            passed_count=total_count - failed_count,
            failed_count=failed_count,
            total_count=total_count,
            status=status,
            placeholder_id=NONE_SENTINEL,
            sample_declaration=sample_declaration,
            receipt_value=value,
            receipt_bytes=raw,
            receipt_id=receipt_id,
            receipt_row_id=row_id,
        )

    def _pending_real_model_probe(
        self, delta: ParameterDelta, kind: ProbeKind, emission_index: int
    ) -> PlaceholderEmission:
        """HARDWARE-GATED: emit the honest pending obligation, never a result.

        The real local model is absent on CPU, so this path fabricates
        nothing: it seals exactly one typed ``pending_owner_hardware``
        placeholder (reason ``dgx_absent``, the kind's bound requirement and
        pinned replay obligation) and one receipt in the schema's only
        representable pending form — ``evaluation_basis`` ``real_model``
        bound to that placeholder identity, whose single-count accounting
        records the one replay obligation an owner DGX run must discharge,
        never a measurement.
        """

        requirement = HARDWARE_GATED_REQUIREMENTS[kind]
        oracle_root = _framed_digest(
            SKELETON_PHASE13_PROBE_ORACLE_V1,
            canonicalize([self._ledger_state_root, delta.delta_id, kind.value]),
        )
        placeholder_value: dict[str, Any] = {
            "schema_version": PLACEHOLDER_SCHEMA_VERSION,
            "record_type": "pending_owner_hardware",
            "schema_domain": SKELETON_PHASE13_PLACEHOLDER,
            "reason": PlaceholderReason.DGX_ABSENT.value,
            "bound_requirement": requirement.value,
            "bound_artifact_id": delta.delta_id,
            "replay_obligation": {
                "obligation_kind": BOUND_REQUIREMENT_OBLIGATIONS[requirement].value,
                "conformance_oracle_root": oracle_root,
                "expected_receipt_count": 1,
            },
            "recorded_ordinal": self._placeholder_base_ordinal + emission_index,
        }
        placeholder_id = compute_placeholder_identity(placeholder_value)
        placeholder_value["placeholder_id"] = placeholder_id
        placeholder_bytes = canonicalize(placeholder_value)
        emission = PlaceholderEmission(
            probe_kind=kind,
            placeholder_id=placeholder_id,
            reason=PlaceholderReason.DGX_ABSENT,
            bound_requirement=requirement,
            bound_artifact_id=delta.delta_id,
            conformance_oracle_root=oracle_root,
            recorded_ordinal=self._placeholder_base_ordinal + emission_index,
            placeholder_value=_freeze(placeholder_value),
            placeholder_bytes=placeholder_bytes,
        )
        return emission

    def _seal_outcome(
        self,
        delta: ParameterDelta,
        evaluations: tuple[ProbeEvaluation, ...],
        placeholders: tuple[PlaceholderEmission, ...],
        failing_kind: ProbeKind | None,
        short_circuit_kind: ProbeKind | None,
        short_circuit_code: str | None,
    ) -> ProbeBatteryOutcome:
        completeness = (
            COMPLETENESS_COMPLETE
            if len(evaluations) == len(PROBE_BATTERY_ORDER)
            else COMPLETENESS_PARTIAL
        )
        if failing_kind is not None:
            status = BATTERY_STATUS_QUARANTINE
            code = f"probe_failed_{failing_kind.value}"
            failing_receipt_row_id = evaluations[-1].receipt_row_id
        elif short_circuit_kind is not None:
            status = BATTERY_STATUS_INCOMPLETE
            code = str(short_circuit_code)
            failing_receipt_row_id = NONE_SENTINEL
        elif placeholders:
            status = BATTERY_STATUS_INCOMPLETE
            code = "battery_pending_owner_hardware"
            failing_receipt_row_id = NONE_SENTINEL
        else:
            status = BATTERY_STATUS_PASSED
            code = "battery_all_ran_with_placeholders"
            failing_receipt_row_id = NONE_SENTINEL
        battery_root = _framed_digest(
            SKELETON_PHASE13_PROBE_BATTERY_V1,
            canonicalize(
                {
                    "delta_id": delta.delta_id,
                    "ledger_state_root": self._ledger_state_root,
                    "status": status,
                    "code": code,
                    "completeness": completeness,
                    "failing_receipt_row_id": failing_receipt_row_id,
                    "receipt_row_ids": [
                        evaluation.receipt_row_id for evaluation in evaluations
                    ],
                    "placeholder_ids": [
                        emission.placeholder_id for emission in placeholders
                    ],
                }
            ),
        )
        return ProbeBatteryOutcome(
            delta_id=delta.delta_id,
            ledger_state_root=self._ledger_state_root,
            status=status,
            code=code,
            completeness=completeness,
            short_circuit_kind=short_circuit_kind,
            failing_receipt_row_id=failing_receipt_row_id,
            evaluations=evaluations,
            placeholders=placeholders,
            fence_id=self._fence_id,
            generation=self._generation,
            attempt_ordinal=self._attempt_ordinal,
            battery_root=battery_root,
        )


# ---------------------------------------------------------------------------
# Two-phase store commit under fence discipline
# ---------------------------------------------------------------------------


def probe_receipt_append(
    evaluation: ProbeEvaluation, *, recorded_at: str
) -> ProbeReceiptAppend:
    """Build the append-only store row for one sealed probe receipt."""

    if not isinstance(evaluation, ProbeEvaluation):
        _reject("probe_outcome_invalid")
    value = evaluation.receipt_value
    return ProbeReceiptAppend(
        receipt_id=evaluation.receipt_row_id,
        delta_id=str(value["delta_id"]),
        probe_kind=str(value["probe_kind"]),
        probe_ordinal=int(value["probe_ordinal"]),
        evaluation_basis=str(value["evaluation_basis"]),
        passed_count=int(value["passed_count"]),
        failed_count=int(value["failed_count"]),
        total_count=int(value["total_count"]),
        status=str(value["status"]),
        placeholder_id=str(value["placeholder_id"]),
        fence_id=str(value["fence_id"]),
        generation=int(value["generation"]),
        attempt_ordinal=int(value["attempt_ordinal"]),
        recorded_at=recorded_at,
        canonical_bytes=evaluation.receipt_bytes,
    )


def placeholder_append(
    emission: PlaceholderEmission,
    *,
    fence_id: str,
    generation: int,
    attempt_ordinal: int,
    recorded_at: str,
) -> PlaceholderAppend:
    """Build the pressure-exempt store row for one placeholder emission."""

    if not isinstance(emission, PlaceholderEmission):
        _reject("probe_outcome_invalid")
    return PlaceholderAppend(
        placeholder_bytes=emission.placeholder_bytes,
        fence_id=fence_id,
        generation=generation,
        attempt_ordinal=attempt_ordinal,
        recorded_at=recorded_at,
    )


def commit_probe_outcome(
    store: ProbeStore,
    outcome: ProbeBatteryOutcome,
    *,
    writer_id: str,
    placeholder_operation_ids: Sequence[str],
    receipt_operation_ids: Sequence[str],
    recorded_at: str,
    failure_after_row: int = 0,
) -> ProbeCommit:
    """Commit one battery outcome through the sole writer, two-phase.

    Phase one appends every hardware-honesty placeholder row first (each
    pressure-exempt through the store) and then every sealed receipt row in
    the frozen probe order — all under the outcome's fence: a stale fence
    rejects every append typed and nothing half-commits silently, because
    each operation is idempotent under its operation identity and replays
    byte-exactly.  Phase two seals the deterministic disposition: the
    passing ``cpu_battery_passed_with_placeholders`` state, the atomic
    ``quarantine_intent`` referencing the exact triggering receipt row, or
    the non-eligible ``battery_incomplete`` report.
    """

    if not isinstance(outcome, ProbeBatteryOutcome):
        _reject("probe_outcome_invalid")
    if outcome.status not in CLOSED_BATTERY_STATUSES:
        _reject("probe_outcome_invalid")
    if not isinstance(placeholder_operation_ids, (list, tuple)) or len(
        placeholder_operation_ids
    ) != len(outcome.placeholders):
        _reject("probe_commit_operation_ids_invalid")
    if not isinstance(receipt_operation_ids, (list, tuple)) or len(
        receipt_operation_ids
    ) != len(outcome.evaluations):
        _reject("probe_commit_operation_ids_invalid")
    for operation_id in (*placeholder_operation_ids, *receipt_operation_ids):
        if not _is_sha256(operation_id):
            _reject("probe_commit_operation_ids_invalid")

    placeholder_rows = tuple(
        placeholder_append(
            emission,
            fence_id=outcome.fence_id,
            generation=outcome.generation,
            attempt_ordinal=outcome.attempt_ordinal,
            recorded_at=recorded_at,
        )
        for emission in outcome.placeholders
    )
    receipt_rows = tuple(
        probe_receipt_append(evaluation, recorded_at=recorded_at)
        for evaluation in outcome.evaluations
    )
    disposition_value = {
        "schema_version": "skeleton.probe-battery-disposition.v1",
        "record_type": "probe_battery_disposition",
        "battery_root": outcome.battery_root,
        "delta_id": outcome.delta_id,
        "ledger_state_root": outcome.ledger_state_root,
        "status": outcome.status,
        "code": outcome.code,
        "completeness": outcome.completeness,
        "failing_receipt_row_id": outcome.failing_receipt_row_id,
        "receipt_row_ids": [
            evaluation.receipt_row_id for evaluation in outcome.evaluations
        ],
        "placeholder_ids": [
            emission.placeholder_id for emission in outcome.placeholders
        ],
        "fence_id": outcome.fence_id,
        "generation": outcome.generation,
        "attempt_ordinal": outcome.attempt_ordinal,
    }
    disposition_raw = canonicalize(disposition_value)
    battery_id = plasticity_record_identity("probe_battery", disposition_raw)
    operation_receipt = store.commit_probe_battery(
        placeholders=placeholder_rows,
        receipts=receipt_rows,
        disposition=ProbeBatteryAppend(
            battery_id=battery_id,
            delta_id=outcome.delta_id,
            ledger_state_root=outcome.ledger_state_root,
            status=outcome.status,
            code=outcome.code,
            completeness=outcome.completeness,
            failing_receipt_row_id=outcome.failing_receipt_row_id,
            receipt_count=len(receipt_rows),
            placeholder_count=len(placeholder_rows),
            fence_id=outcome.fence_id,
            generation=outcome.generation,
            attempt_ordinal=outcome.attempt_ordinal,
            recorded_at=recorded_at,
            canonical_bytes=disposition_raw,
        ),
        writer_id=writer_id,
        operation_id=outcome.battery_root,
        failure_after_row=failure_after_row,
    )
    disposition = ProbeDisposition(
        delta_id=outcome.delta_id,
        status=outcome.status,
        code=outcome.code,
        completeness=outcome.completeness,
        failing_receipt_row_id=outcome.failing_receipt_row_id,
        receipt_row_ids=tuple(
            evaluation.receipt_row_id for evaluation in outcome.evaluations
        ),
        placeholder_ids=tuple(
            emission.placeholder_id for emission in outcome.placeholders
        ),
        battery_id=battery_id,
        battery_root=outcome.battery_root,
    )
    return ProbeCommit(
        placeholder_receipts=tuple(
            operation_receipt for _item in outcome.placeholders
        ),
        receipt_receipts=tuple(
            operation_receipt for _item in outcome.evaluations
        ),
        disposition=disposition,
    )


__all__ = [
    "BATTERY_STATUS_INCOMPLETE",
    "BATTERY_STATUS_PASSED",
    "BATTERY_STATUS_QUARANTINE",
    "CLOSED_BATTERY_STATUSES",
    "CLOSED_PROBE_OUTCOME_CODES",
    "CLOSED_PROBE_REJECTION_CODES",
    "COMPLETENESS_COMPLETE",
    "COMPLETENESS_PARTIAL",
    "CPU_PROBE_BASES",
    "HARDWARE_GATED_PROBE_KINDS",
    "HARDWARE_GATED_REQUIREMENTS",
    "PROBE_BATTERY_ORDER",
    "PROBE_ORDINALS",
    "PROBE_RECEIPT_SCHEMA_VERSION",
    "PROBE_SAMPLE_DERIVATION",
    "PROBE_SAMPLE_DERIVATION_INPUTS",
    "PROBE_SAMPLE_SIZE",
    "PROBE_SEMANTIC_BINDINGS",
    "PlaceholderEmission",
    "PlasticityProbeRejection",
    "ProbeBatteryOutcome",
    "ProbeBatteryRunner",
    "ProbeCommit",
    "ProbeDisposition",
    "ProbeEvaluation",
    "ProbeStore",
    "REFERENCE_CASE_COUNT",
    "REFERENCE_TENSOR_ELEMENTS",
    "ReferenceKernel",
    "RegressionCase",
    "SKELETON_PHASE13_PROBE_BATTERY_V1",
    "SKELETON_PHASE13_PROBE_ORACLE_V1",
    "SKELETON_PHASE13_PROBE_REFERENCE_V1",
    "SKELETON_PHASE13_PROBE_REGRESSION_V1",
    "SKELETON_PHASE13_PROBE_SAMPLE_V1",
    "STRUCTURAL_CHECKS",
    "commit_probe_outcome",
    "derive_delta_coefficients",
    "derive_reference_case_ids",
    "derive_reference_input",
    "draw_probe_sample",
    "placeholder_append",
    "probe_receipt_append",
    "probe_sample_digest",
    "reference_effect",
    "regression_output_root",
    "regression_expected_output_root",
    "resolve_reference_kernel",
    "seal_probe_receipt",
    "seal_regression_case",
]
