"""Deterministic Phase 9 discrete clock, total ordering, and counter stream."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Mapping

from .canonical import canonicalize


EVENT_CLASS_RANK_V1: Mapping[str, int] = MappingProxyType(
    {
        "market_observation": 0,
        "order_intent": 1,
        "arrival": 2,
        "venue_state": 3,
        "failure": 4,
        "fill": 5,
        "settlement": 6,
        "resolution": 7,
        "correction": 8,
    }
)
_UINT64_MAX = 18_446_744_073_709_551_615


@dataclass(slots=True)
class SimulationClockRejection(ValueError):
    code: str
    redacted: bool = True

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise SimulationClockRejection(code)


def _hash(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _timestamp_microseconds(value: object) -> int:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject("simulation_time_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SimulationClockRejection("simulation_time_invalid") from error
    if parsed.tzinfo != UTC:
        _reject("simulation_time_invalid")
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = parsed - epoch
    return (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )


def typed_digest(domain: str, payload: bytes) -> str:
    if not isinstance(domain, str) or not domain.startswith("SKELETON_SIMULATION_"):
        _reject("digest_domain_invalid")
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    domain_bytes = domain.encode("ascii", errors="strict")
    return sha256(
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def total_event_key(event: Any) -> tuple[int, int, int, int, str]:
    """Return the frozen five-component event order."""

    available = _timestamp_microseconds(getattr(event, "available_at", None))
    effective = _timestamp_microseconds(getattr(event, "effective_at", None))
    sequence = getattr(event, "explicit_sequence", None)
    if type(sequence) is not int or sequence < 0:
        _reject("event_sequence_invalid")
    event_class = getattr(event, "event_class", None)
    if event_class not in EVENT_CLASS_RANK_V1:
        _reject("event_class_unknown")
    content_sha256 = _hash(
        getattr(event, "artifact_id", None), "event_content_identity_invalid"
    )
    return (
        available,
        effective,
        sequence,
        EVENT_CLASS_RANK_V1[str(event_class)],
        content_sha256,
    )


@dataclass(frozen=True, slots=True)
class CounterDraw:
    draw_id: str
    namespace: str
    index: int
    upper_bound: int
    value: int
    canonical_bytes: bytes


class CounterStream:
    """Explicit, manifest-bound SHA-256 counter stream with single-use indices."""

    __slots__ = (
        "_algorithm",
        "_manifest_id",
        "_seed",
        "_namespaces",
        "_used",
    )

    def __init__(
        self,
        *,
        algorithm: str,
        manifest_id: str,
        seed: str,
        namespaces: tuple[str, ...],
    ) -> None:
        if algorithm != "sha256_counter_v1":
            _reject("counter_algorithm_unknown")
        _hash(manifest_id, "counter_manifest_invalid")
        if not isinstance(seed, str) or not seed.isdigit():
            _reject("counter_seed_invalid")
        seed_value = int(seed)
        if seed != str(seed_value) or not 0 <= seed_value <= _UINT64_MAX:
            _reject("counter_seed_invalid")
        if (
            not isinstance(namespaces, tuple)
            or not namespaces
            or tuple(sorted(set(namespaces))) != namespaces
            or any(not isinstance(item, str) or not item for item in namespaces)
        ):
            _reject("counter_namespace_inventory_invalid")
        self._algorithm = algorithm
        self._manifest_id = manifest_id
        self._seed = seed
        self._namespaces = frozenset(namespaces)
        self._used: set[tuple[str, int]] = set()

    def draw(self, namespace: str, index: int, *, upper_bound: int) -> CounterDraw:
        if namespace not in self._namespaces:
            _reject("counter_namespace_unknown")
        if type(index) is not int or index < 0:
            _reject("counter_index_invalid")
        if type(upper_bound) is not int or not 1 <= upper_bound <= _UINT64_MAX:
            _reject("counter_range_invalid")
        key = (namespace, index)
        if key in self._used:
            _reject("counter_index_reused")
        preimage = canonicalize(
            {
                "algorithm": self._algorithm,
                "index": index,
                "manifest_id": self._manifest_id,
                "namespace": namespace,
                "seed": self._seed,
                "upper_bound": str(upper_bound),
            }
        )
        raw = typed_digest("SKELETON_SIMULATION_COUNTER_PREIMAGE_V1", preimage)
        value = int(raw, 16) % upper_bound
        canonical = canonicalize(
            {
                "index": index,
                "manifest_id": self._manifest_id,
                "namespace": namespace,
                "upper_bound": str(upper_bound),
                "value": str(value),
            }
        )
        self._used.add(key)
        return CounterDraw(
            draw_id=typed_digest("SKELETON_SIMULATION_COUNTER_DRAW_V1", canonical),
            namespace=namespace,
            index=index,
            upper_bound=upper_bound,
            value=value,
            canonical_bytes=canonical,
        )


def probability_hit(draw: CounterDraw, *, numerator: int, denominator: int) -> bool:
    if not isinstance(draw, CounterDraw):
        raise TypeError("CounterDraw required")
    if (
        type(numerator) is not int
        or type(denominator) is not int
        or denominator <= 0
        or numerator < 0
        or numerator > denominator
    ):
        _reject("probability_range_invalid")
    return draw.value * denominator < numerator * draw.upper_bound


__all__ = [
    "CounterDraw",
    "CounterStream",
    "EVENT_CLASS_RANK_V1",
    "SimulationClockRejection",
    "probability_hit",
    "total_event_key",
    "typed_digest",
]
