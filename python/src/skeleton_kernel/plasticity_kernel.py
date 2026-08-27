"""Pure stdlib fixed-point reference tensor kernel for Phase 13 plasticity.

Every value is an immutable ``FixedPointTensor`` over exact signed-64-bit
integer elements with a declared row-major shape and a declared
``scale_log2`` (value = integer / 2**scale_log2).  All arithmetic is exact
Python-integer arithmetic with typed fail-closed rejection at the signed
64-bit boundaries — never a silent wraparound, never a clamp, and never a
binary floating representation anywhere in the module.

Canonical payload geometry (frozen; content-addressed evidence):

* ``canonical_payload_bytes`` is a deterministic length-framed big-endian
  encoding — ``u64be(scale_log2) || u64be(len(shape)) || u64be(dim)... ||
  u64be(element_count) || s64be(element)...`` — with two's-complement
  signed 8-byte elements, no dict iteration, and no platform-dependent
  width.  JSON cannot carry the payload because RFC 8785 I-JSON integers
  stop at the binary64 safe range while kernel elements span all of int64.
* ``content_root`` is the domain-separated SHA-256 over those canonical
  bytes under ``KERNEL_PAYLOAD_DOMAIN``, using the exact 8-byte
  length-framing shape of ``plasticity_types``' identity digests, so the
  root slots directly into the ``tensor_payload_root`` /
  ``inverse_payload_root`` / ``inverse_proof`` members of a
  ``plasticity-delta`` document.
* ``payload_bytes`` is ``8 * element_count`` — the raw int64 element width
  the sealed kernel-conformance fixtures account (a rank-``r`` factor pair
  over 4x4 geometry carries ``8r`` elements = ``64r`` bytes).

Scale renormalization rule (frozen): low-rank materialization multiplies
two scale-``s`` factors, producing scale-``2s`` products, and renormalizes
by an exact right shift of ``s`` bits.  A non-zero remainder rejects typed
(``kernel_scale_remainder``); there is no silent rounding or truncation —
the Phase 13 research mandate is bit-exactness, so an inexpressible
materialization is unrepresentable rather than approximated.

The module imports nothing beyond the standard library and the repository's
own canonical/hash helpers.  No torch, PEFT, numpy, wall clock, or
randomness surface exists here, and no binary floating value ever touches
payload math.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
from typing import Any, Callable, Mapping

from .canonical import sha256_hex


INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
SAFE_INTEGER_MAX = 9_007_199_254_740_991
MAX_SCALE_LOG2 = 62
SCALE_BITS = 32
ELEMENT_BYTE_WIDTH = 8
DIVERGENCE_CONTEXT_BYTES = 16

KERNEL_PAYLOAD_DOMAIN = "SKELETON_PHASE13_TENSOR_PAYLOAD"
INVERSE_PROOF_KIND = "inverse_apply_byte_identity"

# The closed kernel rejection vocabulary; every failure path names exactly
# one of these snake_case codes and nothing else.
KERNEL_REJECTION_CODES = (
    "kernel_distribution_invalid",
    "kernel_element_invalid",
    "kernel_int64_overflow",
    "kernel_inverse_payload_mismatch",
    "kernel_kl_support_invalid",
    "kernel_payload_root_mismatch",
    "kernel_payload_unavailable",
    "kernel_rank_invalid",
    "kernel_roundtrip_mismatch",
    "kernel_safe_integer_overflow",
    "kernel_scale_invalid",
    "kernel_scale_mismatch",
    "kernel_scale_remainder",
    "kernel_shape_invalid",
    "kernel_shape_mismatch",
)


class PlasticityKernelRejection(ValueError):
    """Stable fail-closed kernel rejection carrying a closed code only."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise PlasticityKernelRejection(code)


def _framed_digest(domain: str, payload: bytes) -> str:
    """Length-framed domain-separated SHA-256, identical in shape to the
    ``plasticity_types`` identity framing."""

    domain_bytes = domain.encode("ascii", errors="strict")
    frame = (
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    )
    return sha256(frame).hexdigest()


def tensor_payload_root(payload: bytes) -> str:
    """Return the one canonical identity for serialized tensor payload bytes."""

    if not isinstance(payload, bytes):
        _reject("kernel_element_invalid")
    return _framed_digest(KERNEL_PAYLOAD_DOMAIN, payload)


def payload_from_bytes(payload: bytes) -> "FixedPointTensor":
    """Decode and validate the frozen tensor payload encoding fail-closed."""

    if not isinstance(payload, bytes) or len(payload) < 32:
        _reject("kernel_element_invalid")
    scale = int.from_bytes(payload[0:8], "big")
    dimension_count = int.from_bytes(payload[8:16], "big")
    if dimension_count < 1 or dimension_count > (len(payload) - 24) // 8:
        _reject("kernel_shape_invalid")
    offset = 16
    shape = tuple(
        int.from_bytes(payload[offset + 8 * index : offset + 8 * index + 8], "big")
        for index in range(dimension_count)
    )
    offset += 8 * dimension_count
    element_count = int.from_bytes(payload[offset : offset + 8], "big")
    offset += 8
    if element_count != _element_count(shape) or len(payload) != offset + 8 * element_count:
        _reject("kernel_shape_mismatch")
    elements = tuple(
        int.from_bytes(
            payload[offset + 8 * index : offset + 8 * index + 8],
            "big",
            signed=True,
        )
        for index in range(element_count)
    )
    return FixedPointTensor.from_elements(shape, elements, scale)


def payload_to_bytes(tensor: "FixedPointTensor") -> bytes:
    """Encode a validated tensor through its frozen canonical representation."""

    if not isinstance(tensor, FixedPointTensor):
        _reject("kernel_element_invalid")
    return tensor.canonical_payload_bytes()


def _element_count(shape: tuple[int, ...]) -> int:
    count = 1
    for dimension in shape:
        if dimension < 1:
            _reject("kernel_shape_invalid")
        count *= dimension
    return count


def _exact_int(value: object, code: str) -> int:
    if type(value) is not int:
        _reject(code)
    return int(value)


def _int64_element(value: object) -> int:
    element = _exact_int(value, "kernel_element_invalid")
    if not INT64_MIN <= element <= INT64_MAX:
        _reject("kernel_int64_overflow")
    return element


_TENSOR_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class FixedPointTensor:
    """Immutable exact fixed-point tensor: int64 elements, declared shape
    (row-major), declared ``scale_log2``.  Constructible only through the
    validating classmethods."""

    scale_log2: int
    shape: tuple[int, ...]
    elements: tuple[int, ...]

    def __init__(
        self,
        *,
        scale_log2: int,
        shape: tuple[int, ...],
        elements: tuple[int, ...],
        token: object,
    ) -> None:
        if token is not _TENSOR_TOKEN:
            raise TypeError(
                "FixedPointTensor requires validated construction via "
                "from_elements or zeros"
            )
        object.__setattr__(self, "scale_log2", scale_log2)
        object.__setattr__(self, "shape", shape)
        object.__setattr__(self, "elements", elements)

    @classmethod
    def from_elements(
        cls, shape: object, elements: object, scale_log2: object
    ) -> "FixedPointTensor":
        scale = _exact_int(scale_log2, "kernel_scale_invalid")
        if not 0 <= scale <= MAX_SCALE_LOG2:
            _reject("kernel_scale_invalid")
        if not isinstance(shape, (tuple, list)) or not shape:
            _reject("kernel_shape_invalid")
        dimensions: list[int] = []
        for dimension in shape:
            size = _exact_int(dimension, "kernel_shape_invalid")
            if size < 1:
                _reject("kernel_shape_invalid")
            dimensions.append(size)
        expected_count = 1
        for size in dimensions:
            expected_count *= size
        if not isinstance(elements, (tuple, list)):
            _reject("kernel_element_invalid")
        checked = tuple(_int64_element(element) for element in elements)
        if len(checked) != expected_count:
            _reject("kernel_shape_mismatch")
        return cls(
            scale_log2=scale,
            shape=tuple(dimensions),
            elements=checked,
            token=_TENSOR_TOKEN,
        )

    @classmethod
    def zeros(cls, shape: object, scale_log2: object) -> "FixedPointTensor":
        scale = _exact_int(scale_log2, "kernel_scale_invalid")
        if not 0 <= scale <= MAX_SCALE_LOG2:
            _reject("kernel_scale_invalid")
        if not isinstance(shape, (tuple, list)) or not shape:
            _reject("kernel_shape_invalid")
        count = 1
        for dimension in shape:
            size = _exact_int(dimension, "kernel_shape_invalid")
            if size < 1:
                _reject("kernel_shape_invalid")
            count *= size
        return cls.from_elements(shape, (0,) * count, scale)

    @property
    def element_count(self) -> int:
        return len(self.elements)

    @property
    def payload_bytes(self) -> int:
        return ELEMENT_BYTE_WIDTH * len(self.elements)

    def canonical_payload_bytes(self) -> bytes:
        """The frozen deterministic length-framed big-endian encoding."""

        parts = [self.scale_log2.to_bytes(8, "big")]
        parts.append(len(self.shape).to_bytes(8, "big"))
        for dimension in self.shape:
            parts.append(dimension.to_bytes(8, "big"))
        parts.append(len(self.elements).to_bytes(8, "big"))
        for element in self.elements:
            parts.append(element.to_bytes(ELEMENT_BYTE_WIDTH, "big", signed=True))
        return b"".join(parts)

    def content_root(self) -> str:
        return tensor_payload_root(self.canonical_payload_bytes())


def _require_compatible(left: FixedPointTensor, right: FixedPointTensor) -> None:
    if left.shape != right.shape:
        _reject("kernel_shape_mismatch")
    if left.scale_log2 != right.scale_log2:
        _reject("kernel_scale_mismatch")


def _checked_sum(left: FixedPointTensor, right: FixedPointTensor) -> FixedPointTensor:
    _require_compatible(left, right)
    summed: list[int] = []
    for first, second in zip(left.elements, right.elements):
        total = first + second
        if not INT64_MIN <= total <= INT64_MAX:
            # Exact addition left the signed-64 range: reject before any
            # partial payload exists; never wrap, never clamp.
            _reject("kernel_int64_overflow")
        summed.append(total)
    return FixedPointTensor.from_elements(left.shape, summed, left.scale_log2)


def apply(base: FixedPointTensor, delta: FixedPointTensor) -> FixedPointTensor:
    """Elementwise exact addition of ``delta`` onto ``base``."""

    return _checked_sum(base, delta)


def inverse(delta: FixedPointTensor) -> FixedPointTensor:
    """Exact elementwise negation; the INT64_MIN edge has no int64 negation
    and rejects typed instead of wrapping."""

    negated: list[int] = []
    for element in delta.elements:
        if element == INT64_MIN:
            _reject("kernel_int64_overflow")
        negated.append(-element)
    return FixedPointTensor.from_elements(delta.shape, negated, delta.scale_log2)


def compose(first: FixedPointTensor, second: FixedPointTensor) -> FixedPointTensor:
    """One delta exactly equal to applying ``first`` then ``second``."""

    return _checked_sum(first, second)


def materialize(
    u_factor: FixedPointTensor, v_factor: FixedPointTensor
) -> FixedPointTensor:
    """Materialize a rank-``r`` factor pair to the dense delta tensor.

    ``u_factor`` is ``n x r`` and ``v_factor`` is ``r x m``, both at one
    shared ``scale_log2``.  The exact integer matmul produces scale-``2s``
    products; renormalization right-shifts by ``s`` bits and REJECTS on any
    non-zero remainder (``kernel_scale_remainder``): no silent rounding, no
    truncation — an inexact materialization is unrepresentable.
    """

    if len(u_factor.shape) != 2 or len(v_factor.shape) != 2:
        _reject("kernel_rank_invalid")
    if u_factor.shape[1] != v_factor.shape[0]:
        _reject("kernel_rank_invalid")
    if u_factor.scale_log2 != v_factor.scale_log2:
        _reject("kernel_scale_mismatch")
    rows, rank = u_factor.shape
    _, columns = v_factor.shape
    scale = u_factor.scale_log2
    divisor = 1 << scale
    dense: list[int] = []
    for row in range(rows):
        for column in range(columns):
            accumulator = 0
            for inner in range(rank):
                accumulator += (
                    u_factor.elements[row * rank + inner]
                    * v_factor.elements[inner * columns + column]
                )
            quotient, remainder = divmod(accumulator, divisor)
            if remainder != 0:
                _reject("kernel_scale_remainder")
            if not INT64_MIN <= quotient <= INT64_MAX:
                _reject("kernel_int64_overflow")
            dense.append(quotient)
    return FixedPointTensor.from_elements((rows, columns), dense, scale)


@dataclass(frozen=True, slots=True)
class LowRankAdapter:
    """A declared-rank factor pair with exact PLT-07 rank/byte accounting."""

    u_factor: FixedPointTensor
    v_factor: FixedPointTensor

    def __post_init__(self) -> None:
        if len(self.u_factor.shape) != 2 or len(self.v_factor.shape) != 2:
            _reject("kernel_rank_invalid")
        if self.u_factor.shape[1] != self.v_factor.shape[0]:
            _reject("kernel_rank_invalid")
        if self.u_factor.scale_log2 != self.v_factor.scale_log2:
            _reject("kernel_scale_mismatch")

    @property
    def declared_rank(self) -> int:
        return self.u_factor.shape[1]

    @property
    def scale_log2(self) -> int:
        return self.u_factor.scale_log2

    @property
    def payload_bytes(self) -> int:
        return self.u_factor.payload_bytes + self.v_factor.payload_bytes

    def materialize(self) -> FixedPointTensor:
        return materialize(self.u_factor, self.v_factor)


@dataclass(frozen=True, slots=True)
class InverseProof:
    """The schema's committed ``inverse_proof`` triple over payload roots."""

    pre_apply_payload_root: str
    post_apply_payload_root: str
    roundtrip_payload_root: str

    @property
    def proof_kind(self) -> str:
        return INVERSE_PROOF_KIND

    def jsonable(self) -> dict[str, Any]:
        return {
            "proof_kind": INVERSE_PROOF_KIND,
            "pre_apply_payload_root": self.pre_apply_payload_root,
            "post_apply_payload_root": self.post_apply_payload_root,
            "roundtrip_payload_root": self.roundtrip_payload_root,
        }


def apply_proof(base: FixedPointTensor, delta: FixedPointTensor) -> InverseProof:
    """Compute and enforce the byte-exact inverse proof for one apply.

    ``roundtrip = apply(apply(base, delta), inverse(delta))`` must reproduce
    the pre-apply payload bytes exactly (D-13); any divergence rejects typed
    before a proof value exists.
    """

    post = apply(base, delta)
    roundtrip = apply(post, inverse(delta))
    if roundtrip.canonical_payload_bytes() != base.canonical_payload_bytes():
        _reject("kernel_roundtrip_mismatch")
    pre_root = base.content_root()
    proof = InverseProof(
        pre_apply_payload_root=pre_root,
        post_apply_payload_root=post.content_root(),
        roundtrip_payload_root=roundtrip.content_root(),
    )
    if proof.roundtrip_payload_root != proof.pre_apply_payload_root:
        _reject("kernel_roundtrip_mismatch")
    return proof


def recompute_inverse_proof(
    delta: object, payload_resolver: Callable[[str], bytes | None]
) -> Mapping[str, str]:
    """Recompute a delta proof from authenticated base/delta/inverse payloads.

    The contract document contains only content roots.  Production callers
    must therefore provide a fail-closed resolver; every returned payload is
    re-hashed under the canonical tensor domain before any arithmetic runs.
    """

    if not callable(payload_resolver):
        _reject("kernel_payload_unavailable")

    def resolve(root: object) -> bytes:
        if not isinstance(root, str) or len(root) != 64:
            _reject("kernel_payload_unavailable")
        try:
            payload = payload_resolver(root)
        except Exception as error:
            raise PlasticityKernelRejection("kernel_payload_unavailable") from error
        if not isinstance(payload, bytes):
            _reject("kernel_payload_unavailable")
        if tensor_payload_root(payload) != root:
            _reject("kernel_payload_root_mismatch")
        return payload

    try:
        pre_root = getattr(delta, "pre_apply_payload_root")
        tensor_root = getattr(delta, "tensor_payload_root")
        inverse_root = getattr(delta, "inverse_payload_root")
    except AttributeError as error:
        raise PlasticityKernelRejection("kernel_payload_unavailable") from error
    base = payload_from_bytes(resolve(pre_root))
    tensor = payload_from_bytes(resolve(tensor_root))
    inverse_payload = resolve(inverse_root)
    expected_inverse = inverse(tensor).canonical_payload_bytes()
    if inverse_payload != expected_inverse:
        _reject("kernel_inverse_payload_mismatch")
    proof = apply_proof(base, tensor)
    return proof.jsonable()


def parameter_drift(
    baseline: FixedPointTensor, candidate: FixedPointTensor
) -> int:
    """Exact L1 distance over fixed-point integers, safe-integer bounded."""

    _require_compatible(baseline, candidate)
    total = 0
    for first, second in zip(baseline.elements, candidate.elements):
        total += abs(first - second)
        if total > SAFE_INTEGER_MAX:
            _reject("kernel_safe_integer_overflow")
    return total


def reference_kl_divergence(
    p_distribution: FixedPointTensor, q_distribution: FixedPointTensor
) -> Fraction:
    """The frozen exact rational divergence surrogate for reference
    distributions.

    Both tensors are nonnegative fixed-point mass vectors with positive
    totals.  The surrogate is the exact chi-square-style per-element ratio
    bound ``sum_i P_i * (P_i / Q_i - 1)`` over the normalized masses ``P``
    and ``Q`` — a pure ``Fraction`` computation that is nonnegative, zero
    exactly when the normalized distributions coincide, and deterministic
    with no logarithm approximation (real-model KL stays hardware-gated).
    Any support point where ``q`` carries zero mass while ``p`` does not
    rejects typed.
    """

    _require_compatible(p_distribution, q_distribution)
    for mass in p_distribution.elements:
        if mass < 0:
            _reject("kernel_distribution_invalid")
    for mass in q_distribution.elements:
        if mass < 0:
            _reject("kernel_distribution_invalid")
    p_total = sum(p_distribution.elements)
    q_total = sum(q_distribution.elements)
    if p_total == 0 or q_total == 0:
        _reject("kernel_distribution_invalid")
    accumulator = Fraction(0)
    for p_mass, q_mass in zip(p_distribution.elements, q_distribution.elements):
        if p_mass == 0:
            continue
        if q_mass == 0:
            _reject("kernel_kl_support_invalid")
        p_probability = Fraction(p_mass, p_total)
        q_probability = Fraction(q_mass, q_total)
        accumulator += p_probability * (p_probability / q_probability - 1)
    return accumulator


@dataclass(frozen=True, slots=True)
class PayloadDivergence:
    """The exact first byte divergence between two payload encodings, in the
    ``DerivedArtifactDivergence`` style: exact offset, bounded context, and
    the content roots of both sides."""

    byte_offset: int
    expected_length: int
    observed_length: int
    context_start: int
    expected_context_hex: str
    observed_context_hex: str
    expected_root: str
    observed_root: str

    def jsonable(self) -> dict[str, Any]:
        return {
            "byte_offset": self.byte_offset,
            "expected_length": self.expected_length,
            "observed_length": self.observed_length,
            "context_start": self.context_start,
            "expected_context_hex": self.expected_context_hex,
            "observed_context_hex": self.observed_context_hex,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
        }


def first_byte_divergence(
    expected: bytes, actual: bytes
) -> PayloadDivergence | None:
    """Locate the exact first differing byte offset, or ``None`` if the two
    payload encodings are byte-identical."""

    if not isinstance(expected, bytes) or not isinstance(actual, bytes):
        _reject("kernel_element_invalid")
    if expected == actual:
        return None
    limit = min(len(expected), len(actual))
    offset = limit
    for index in range(limit):
        if expected[index] != actual[index]:
            offset = index
            break
    context_start = max(0, offset - DIVERGENCE_CONTEXT_BYTES)
    context_end = offset + DIVERGENCE_CONTEXT_BYTES
    return PayloadDivergence(
        byte_offset=offset,
        expected_length=len(expected),
        observed_length=len(actual),
        context_start=context_start,
        expected_context_hex=expected[context_start:context_end].hex(),
        observed_context_hex=actual[context_start:context_end].hex(),
        expected_root=sha256_hex(expected),
        observed_root=sha256_hex(actual),
    )


# Plan 13-07 artifact aliases: the frozen plan names the payload value
# ``TensorPayload`` and the algebra ``apply_delta``/``inverse_delta``/
# ``compose_deltas``; they are the same pure objects.
TensorPayload = FixedPointTensor
apply_delta = apply
inverse_delta = inverse
compose_deltas = compose


__all__ = [
    "DIVERGENCE_CONTEXT_BYTES",
    "ELEMENT_BYTE_WIDTH",
    "FixedPointTensor",
    "INT64_MAX",
    "INT64_MIN",
    "INVERSE_PROOF_KIND",
    "InverseProof",
    "KERNEL_PAYLOAD_DOMAIN",
    "KERNEL_REJECTION_CODES",
    "LowRankAdapter",
    "MAX_SCALE_LOG2",
    "PayloadDivergence",
    "PlasticityKernelRejection",
    "SAFE_INTEGER_MAX",
    "SCALE_BITS",
    "TensorPayload",
    "apply",
    "apply_delta",
    "apply_proof",
    "compose",
    "compose_deltas",
    "first_byte_divergence",
    "inverse",
    "inverse_delta",
    "materialize",
    "parameter_drift",
    "payload_from_bytes",
    "payload_to_bytes",
    "recompute_inverse_proof",
    "reference_kl_divergence",
    "tensor_payload_root",
]
