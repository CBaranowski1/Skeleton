"""Deterministic compatibility-first retrieval for Phase 10 memory.

The module deliberately keeps candidate enumeration, compatibility, ranking, and
budgeting as separate steps.  Snapshot construction authenticates the complete
candidate inventory before a predicate runs; retrieval never accepts a database
handle or an SQL-filtered iterable as its considered universe.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .memory_contracts import MemoryContractPublication, compute_document_identity
from .memory_safety import scan_memory_document
from .memory_types import MemoryEnvelope, MemoryOperationClass


_ENVELOPE_SCHEMA_ID = "https://schemas.skeleton.local/v1/memory-envelope.schema.json"
_RANK_PROFILE_ID = "skeleton.memory-rank.v1"
_ZERO = "0" * 64
_TIMESTAMP = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d*[1-9]))?Z$"
)
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_CLOSED_ENCODER = json.JSONEncoder(
    ensure_ascii=False,
    allow_nan=False,
    sort_keys=True,
    separators=(",", ":"),
)

_QUALITY_RANK = MappingProxyType(
    {
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
)
_PROVENANCE_RANK = MappingProxyType(
    {
        "verified_real": 0,
        "derived_real": 1,
        "owner_asserted": 2,
        "seeded_test": 3,
        "fixture": 4,
        "simulated": 5,
        "synthetic": 6,
        "unknown": 7,
    }
)
_OPERATING_MODES = frozenset(
    {"evaluation", "fixture", "historical", "offline", "paper", "research", "simulation"}
)
_MODEL_STAGES = frozenset({"none", "candidate", "challenger", "shadow", "paper"})
_MEMORY_KINDS = frozenset({"working", "episodic", "semantic", "procedural", "model", "audit"})
_PURPOSE_KIND_RANK = MappingProxyType(
    {
        "implementation_support": MappingProxyType(
            {"semantic": 0, "procedural": 1, "episodic": 2, "model": 3, "working": 4, "audit": 5}
        ),
        "research": MappingProxyType(
            {"semantic": 0, "episodic": 1, "procedural": 2, "model": 3, "working": 4, "audit": 5}
        ),
        "evaluation": MappingProxyType(
            {"semantic": 0, "episodic": 1, "model": 2, "procedural": 3, "working": 4, "audit": 5}
        ),
        "audit": MappingProxyType(
            {"audit": 0, "semantic": 1, "episodic": 2, "procedural": 3, "model": 4, "working": 5}
        ),
        "replay": MappingProxyType(
            {"audit": 0, "working": 1, "episodic": 2, "semantic": 3, "procedural": 4, "model": 5}
        ),
        "integrity": MappingProxyType(
            {"audit": 0, "semantic": 1, "episodic": 2, "procedural": 3, "model": 4, "working": 5}
        ),
        "rebuild": MappingProxyType(
            {"audit": 0, "semantic": 1, "episodic": 2, "procedural": 3, "model": 4, "working": 5}
        ),
    }
)
_RIGHTS_STATES = frozenset({"active", "unresolved", "revoked", "denied"})
_INTEGRITY_STATES = frozenset(
    {"healthy", "exact_duplicate", "contradiction_member", "quarantined", "unverifiable_bytes", "contradiction_integrity_invalid"}
)
_REASON_ORDER = (
    "unverifiable_bytes",
    "quarantined",
    "namespace_mismatch",
    "project_mismatch",
    "lobe_mismatch",
    "future_available",
    "not_yet_effective",
    "expired",
    "stale",
    "purpose_kind_incompatible",
    "scope_mismatch",
    "operating_mode_mismatch",
    "model_stage_mismatch",
    "rights_unresolved",
    "rights_revoked",
    "rights_denied",
    "provenance_rejected",
    "quality_below_minimum",
    "paper_seeded_test",
    "paper_simulated",
    "paper_synthetic",
    "paper_contaminated",
    "contradiction_integrity_invalid",
)
_REASON_INDEX = MappingProxyType({reason: index for index, reason in enumerate(_REASON_ORDER)})
_DURABLE_PURPOSES = frozenset({"audit", "replay", "integrity", "rebuild"})


@dataclass(slots=True)
class RetrievalRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise RetrievalRejection(code)


def _hash(value: object, code: str = "retrieval_identity_invalid") -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        _reject(code)
    return value


def _framed_digest(domain: str, payload: bytes) -> str:
    name = domain.encode("ascii", errors="strict")
    return sha256(
        len(name).to_bytes(8, "big")
        + name
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _closed_retrieval_canonicalize(value: object) -> bytes:
    """Encode the closed retrieval graph in its proven RFC 8785 subset.

    Retrieval output contains only nonnegative safe integers, booleans, arrays,
    objects with fixed ASCII keys, lowercase identifiers/reasons, and SHA-256
    strings.  For that subset the stdlib encoder configuration is byte-identical
    to the repository JCS canonicalizer, while avoiding an O(total string bytes)
    Unicode validation pass for each of the duplicated 10,000-item result and
    ledger graphs.  ``verify_retrieval_result`` independently re-parses and
    compares these bytes with ``canonicalize``; the authenticated benchmark runs
    that proof on every measured output set before sealing its record.
    """

    try:
        return _CLOSED_ENCODER.encode(value).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as error:
        raise RetrievalRejection("retrieval_seal_invalid") from error


def utc_epoch_microseconds(value: str) -> int:
    """Convert canonical UTC to exact integer microseconds without a float."""

    if not isinstance(value, str):
        _reject("retrieval_timestamp_invalid")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        _reject("retrieval_timestamp_invalid")
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    fractional = match.group(7) or ""
    if len(fractional) > 6:
        _reject("retrieval_timestamp_precision_unsupported")
    microsecond = int(fractional.ljust(6, "0")) if fractional else 0
    try:
        instant = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=UTC)
    except ValueError as error:
        raise RetrievalRejection("retrieval_timestamp_invalid") from error
    delta = instant - _EPOCH
    result = ((delta.days * 86_400 + delta.seconds) * 1_000_000) + delta.microseconds
    if result < 0:
        _reject("retrieval_timestamp_invalid")
    return result


@dataclass(frozen=True, slots=True)
class FrozenCandidate:
    memory_id: str
    memory_kind: str
    namespace: str
    lobe_id: str
    project_id: str
    scope_kind: str
    scope_id: str | None
    evidence_root_ids: tuple[str, ...]
    lineage_root_ids: tuple[str, ...]
    rights_decision_id: str
    quality_class: str
    provenance_class: str
    quarantine_state: str
    effective_from_us: int
    effective_to_us: int | None
    available_at_us: int
    recorded_at_us: int
    operating_mode: str
    model_stage: str
    correction_of: str
    contradiction_set_id: str
    canonical_sha256: str
    canonical_bytes: bytes
    canonical_byte_count: int


@dataclass(frozen=True, slots=True)
class CandidateSnapshot:
    snapshot_id: str
    candidate_ids: tuple[str, ...]
    candidates: tuple[FrozenCandidate, ...]
    correction_edges: Mapping[str, str]
    canonical_sha256: str
    canonical_bytes: bytes
    authenticated: bool


@dataclass(frozen=True, slots=True)
class IntegritySnapshot:
    snapshot_id: str
    candidate_ids: tuple[str, ...]
    statuses: Mapping[str, str]
    resolved_evidence_ids: tuple[str, ...]
    resolved_lineage_ids: tuple[str, ...]
    complete: bool
    canonical_sha256: str
    canonical_bytes: bytes
    authenticated: bool


@dataclass(frozen=True, slots=True)
class RightsSnapshot:
    snapshot_id: str
    decisions: Mapping[str, str]
    canonical_sha256: str
    canonical_bytes: bytes
    authenticated: bool


@dataclass(frozen=True, slots=True)
class RetrievalQuery:
    query_id: str
    candidate_snapshot_id: str
    decision_at: str
    known_at: str
    world_at: str
    namespace: str
    lobe_id: str
    project_id: str
    purpose: str
    scope_kind: str
    scope_id: str | None
    operating_mode: str
    rights_boundary: str
    minimum_quality: str
    accepted_provenance_classes: tuple[str, ...]
    model_stage: str
    paper_eligible: bool
    item_budget: int
    byte_budget: int
    rank_profile_id: str
    integrity_snapshot_id: str
    known_at_us: int
    world_at_us: int
    canonical_sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class RankFactors:
    purpose_rank: int
    quality_rank: int
    provenance_rank: int
    effective_epoch_us: int
    available_epoch_us: int
    contradiction_group_id: str
    rank_tie_breaker: str

    @property
    def sort_key(self) -> tuple[int, int, int, int, int, str, str]:
        return (
            self.purpose_rank,
            self.quality_rank,
            self.provenance_rank,
            -self.effective_epoch_us,
            -self.available_epoch_us,
            self.contradiction_group_id if self.contradiction_group_id != "none" else self.rank_tie_breaker,
            self.rank_tie_breaker,
        )

    def as_value(self) -> dict[str, object]:
        return {
            "purpose_rank": self.purpose_rank,
            "quality_rank": self.quality_rank,
            "provenance_rank": self.provenance_rank,
            "effective_epoch_us": self.effective_epoch_us,
            "available_epoch_us": self.available_epoch_us,
            "contradiction_group_id": self.contradiction_group_id,
            "rank_tie_breaker": self.rank_tie_breaker,
        }


@dataclass(frozen=True, slots=True)
class CompatibilityEvaluation:
    memory_id: str
    all_failures: tuple[str, ...]
    terminal_reason: str | None
    rank_factors: RankFactors | None


@dataclass(frozen=True, slots=True)
class LedgerItem:
    memory_id: str
    disposition: str
    exclusion_reason: str | None
    rank_factors: RankFactors | None
    canonical_byte_count: int | None


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    result_id: str
    query_id: str
    snapshot_id: str
    integrity_snapshot_id: str
    included_ids: tuple[str, ...]
    ranked_included_ids: tuple[str, ...]
    ledger_items: tuple[LedgerItem, ...]
    evaluations: tuple[CompatibilityEvaluation, ...]
    candidate_count: int
    included_count: int
    excluded_count: int
    used_items: int
    used_bytes: int
    ledger_sha256: str
    ledger_bytes: bytes
    canonical_sha256: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class BenchmarkProfile:
    cache_state: str
    iteration_count: int
    samples_us: tuple[int, ...]
    p50_us: int
    p95_us: int
    maximum_us: int
    candidate_count: int
    included_count: int
    excluded_count: int
    used_items: int
    used_bytes: int
    result_canonical_bytes: int
    ledger_canonical_bytes: int
    query_id: str
    result_id: str
    ledger_sha256: str


@dataclass(frozen=True, slots=True)
class RetrievalBenchmarkRecord:
    benchmark_id: str
    runtime_root_sha256: str
    sqlite_root_sha256: str
    schema_root_sha256: str
    index_root_sha256: str
    measurement_clock_id: str
    query_id: str
    result_id: str
    ledger_sha256: str
    candidate_count: int
    included_count: int
    excluded_count: int
    used_items: int
    used_bytes: int
    result_canonical_bytes: int
    ledger_canonical_bytes: int
    compatibility_evaluation_count: int
    ledger_item_count: int
    deterministic_operation_count: int
    deterministic_operation_bound: int
    performance_target_us: int
    cold_target_met: bool
    warm_target_met: bool
    performance_disposition: str
    cold: BenchmarkProfile
    warm: BenchmarkProfile
    canonical_sha256: str
    canonical_bytes: bytes


def _percentile(sorted_samples: tuple[int, ...], numerator: int) -> int:
    if not sorted_samples or numerator <= 0 or numerator > 100:
        _reject("retrieval_benchmark_invalid")
    # Exact nearest-rank percentile: ceil(n * p / 100) - 1.
    index = ((len(sorted_samples) * numerator) + 99) // 100 - 1
    return sorted_samples[index]


def _benchmark_profile(
    cache_state: str,
    samples: Sequence[int],
    *,
    query_id: str,
    result_id: str,
    ledger_sha256: str,
    candidate_count: int,
    included_count: int,
    excluded_count: int,
    used_items: int,
    used_bytes: int,
    result_canonical_bytes: int,
    ledger_canonical_bytes: int,
) -> BenchmarkProfile:
    ordered = tuple(sorted(samples))
    if (
        cache_state not in {"cold", "warm"}
        or not ordered
        or any(type(sample) is not int or sample < 0 for sample in ordered)
    ):
        _reject("retrieval_benchmark_invalid")
    return BenchmarkProfile(
        cache_state=cache_state,
        iteration_count=len(ordered),
        samples_us=ordered,
        p50_us=_percentile(ordered, 50),
        p95_us=_percentile(ordered, 95),
        maximum_us=ordered[-1],
        candidate_count=candidate_count,
        included_count=included_count,
        excluded_count=excluded_count,
        used_items=used_items,
        used_bytes=used_bytes,
        result_canonical_bytes=result_canonical_bytes,
        ledger_canonical_bytes=ledger_canonical_bytes,
        query_id=query_id,
        result_id=result_id,
        ledger_sha256=ledger_sha256,
    )


def _benchmark_profile_value(profile: BenchmarkProfile) -> dict[str, object]:
    return {
        "cache_state": profile.cache_state,
        "iteration_count": profile.iteration_count,
        "samples_us": list(profile.samples_us),
        "p50_us": profile.p50_us,
        "p95_us": profile.p95_us,
        "maximum_us": profile.maximum_us,
        "candidate_count": profile.candidate_count,
        "included_count": profile.included_count,
        "excluded_count": profile.excluded_count,
        "used_items": profile.used_items,
        "used_bytes": profile.used_bytes,
        "result_canonical_bytes": profile.result_canonical_bytes,
        "ledger_canonical_bytes": profile.ledger_canonical_bytes,
        "query_id": profile.query_id,
        "result_id": profile.result_id,
        "ledger_sha256": profile.ledger_sha256,
    }


def seal_retrieval_benchmark(
    *,
    environment_roots: Mapping[str, str],
    query_id: str,
    result_id: str,
    ledger_sha256: str,
    candidate_count: int,
    included_count: int,
    excluded_count: int,
    used_items: int,
    used_bytes: int,
    result_canonical_bytes: int,
    ledger_canonical_bytes: int,
    compatibility_evaluation_count: int,
    ledger_item_count: int,
    cold_samples_us: Sequence[int],
    warm_samples_us: Sequence[int],
    measurement_clock_id: str,
) -> RetrievalBenchmarkRecord:
    required_roots = {
        "runtime_root_sha256", "sqlite_root_sha256", "schema_root_sha256", "index_root_sha256"
    }
    if set(environment_roots) != required_roots:
        _reject("retrieval_benchmark_invalid")
    roots = {name: _hash(environment_roots[name], "retrieval_benchmark_invalid") for name in required_roots}
    query = _hash(query_id, "retrieval_benchmark_invalid")
    result = _hash(result_id, "retrieval_benchmark_invalid")
    ledger = _hash(ledger_sha256, "retrieval_benchmark_invalid")
    counters = (
        candidate_count, included_count, excluded_count, used_items, used_bytes,
        result_canonical_bytes, ledger_canonical_bytes,
        compatibility_evaluation_count, ledger_item_count,
    )
    deterministic_operation_count = (
        candidate_count + compatibility_evaluation_count + ledger_item_count
    )
    deterministic_operation_bound = 30_000
    performance_target_us = 100_000
    if (
        any(type(value) is not int or value < 0 for value in counters)
        or candidate_count != 10_000
        or included_count + excluded_count != candidate_count
        or used_items != included_count
        or compatibility_evaluation_count != candidate_count
        or ledger_item_count != candidate_count
        or deterministic_operation_count != deterministic_operation_bound
        or not isinstance(measurement_clock_id, str)
        or measurement_clock_id != "time.perf_counter_ns.monotonic.v1"
    ):
        _reject("retrieval_benchmark_invalid")
    shared = dict(
        query_id=query,
        result_id=result,
        ledger_sha256=ledger,
        candidate_count=candidate_count,
        included_count=included_count,
        excluded_count=excluded_count,
        used_items=used_items,
        used_bytes=used_bytes,
        result_canonical_bytes=result_canonical_bytes,
        ledger_canonical_bytes=ledger_canonical_bytes,
    )
    cold = _benchmark_profile("cold", cold_samples_us, **shared)
    warm = _benchmark_profile("warm", warm_samples_us, **shared)
    cold_target_met = cold.p95_us <= performance_target_us
    warm_target_met = warm.p95_us <= performance_target_us
    performance_disposition = (
        "target_met"
        if cold_target_met and warm_target_met
        else "observation_requires_capacity_review"
    )
    value: dict[str, object] = {
        "schema_version": "skeleton.memory-retrieval-benchmark.v2",
        **roots,
        "measurement_clock_id": measurement_clock_id,
        **shared,
        "compatibility_evaluation_count": compatibility_evaluation_count,
        "ledger_item_count": ledger_item_count,
        "deterministic_operation_count": deterministic_operation_count,
        "deterministic_operation_bound": deterministic_operation_bound,
        "performance_target_us": performance_target_us,
        "cold_target_met": cold_target_met,
        "warm_target_met": warm_target_met,
        "performance_disposition": performance_disposition,
        "cold": _benchmark_profile_value(cold),
        "warm": _benchmark_profile_value(warm),
    }
    benchmark_id = _framed_digest(
        "SKELETON_PHASE10_MEMORY_RETRIEVAL_BENCHMARK_V2", canonicalize(value)
    )
    value["benchmark_id"] = benchmark_id
    raw = canonicalize(value)
    record = RetrievalBenchmarkRecord(
        benchmark_id=benchmark_id,
        runtime_root_sha256=roots["runtime_root_sha256"],
        sqlite_root_sha256=roots["sqlite_root_sha256"],
        schema_root_sha256=roots["schema_root_sha256"],
        index_root_sha256=roots["index_root_sha256"],
        measurement_clock_id=measurement_clock_id,
        query_id=query,
        result_id=result,
        ledger_sha256=ledger,
        candidate_count=candidate_count,
        included_count=included_count,
        excluded_count=excluded_count,
        used_items=used_items,
        used_bytes=used_bytes,
        result_canonical_bytes=result_canonical_bytes,
        ledger_canonical_bytes=ledger_canonical_bytes,
        compatibility_evaluation_count=compatibility_evaluation_count,
        ledger_item_count=ledger_item_count,
        deterministic_operation_count=deterministic_operation_count,
        deterministic_operation_bound=deterministic_operation_bound,
        performance_target_us=performance_target_us,
        cold_target_met=cold_target_met,
        warm_target_met=warm_target_met,
        performance_disposition=performance_disposition,
        cold=cold,
        warm=warm,
        canonical_sha256=sha256_hex(raw),
        canonical_bytes=raw,
    )
    verify_retrieval_benchmark(record)
    return record


def verify_retrieval_benchmark(record: RetrievalBenchmarkRecord) -> bool:
    if not isinstance(record, RetrievalBenchmarkRecord):
        _reject("retrieval_benchmark_invalid")
    try:
        value = parse_raw_json(record.canonical_bytes)
        if not isinstance(value, Mapping) or canonicalize(value) != record.canonical_bytes:
            _reject("retrieval_benchmark_invalid")
        body = dict(value)
        declared_id = body.pop("benchmark_id", None)
        expected_id = _framed_digest(
            "SKELETON_PHASE10_MEMORY_RETRIEVAL_BENCHMARK_V2", canonicalize(body)
        )
        scalar_fields = (
            "runtime_root_sha256", "sqlite_root_sha256", "schema_root_sha256",
            "index_root_sha256", "measurement_clock_id", "query_id", "result_id",
            "ledger_sha256", "candidate_count", "included_count", "excluded_count",
            "used_items", "used_bytes", "result_canonical_bytes", "ledger_canonical_bytes",
            "compatibility_evaluation_count", "ledger_item_count",
            "deterministic_operation_count", "deterministic_operation_bound",
            "performance_target_us", "cold_target_met", "warm_target_met",
            "performance_disposition",
        )
        if (
            declared_id != record.benchmark_id
            or expected_id != record.benchmark_id
            or sha256_hex(record.canonical_bytes) != record.canonical_sha256
            or any(value.get(field) != getattr(record, field) for field in scalar_fields)
            or record.candidate_count != 10_000
            or record.included_count + record.excluded_count != record.candidate_count
            or record.used_items != record.included_count
            or record.compatibility_evaluation_count != record.candidate_count
            or record.ledger_item_count != record.candidate_count
            or record.deterministic_operation_count != (
                record.candidate_count
                + record.compatibility_evaluation_count
                + record.ledger_item_count
            )
            or record.deterministic_operation_count != record.deterministic_operation_bound
            or record.deterministic_operation_bound != 30_000
            or record.performance_target_us != 100_000
            or record.cold_target_met != (record.cold.p95_us <= record.performance_target_us)
            or record.warm_target_met != (record.warm.p95_us <= record.performance_target_us)
            or record.performance_disposition != (
                "target_met"
                if record.cold_target_met and record.warm_target_met
                else "observation_requires_capacity_review"
            )
        ):
            _reject("retrieval_benchmark_invalid")
        for name, profile in (("cold", record.cold), ("warm", record.warm)):
            if value.get(name) != _benchmark_profile_value(profile):
                _reject("retrieval_benchmark_invalid")
            recomputed = _benchmark_profile(
                name,
                profile.samples_us,
                query_id=record.query_id,
                result_id=record.result_id,
                ledger_sha256=record.ledger_sha256,
                candidate_count=record.candidate_count,
                included_count=record.included_count,
                excluded_count=record.excluded_count,
                used_items=record.used_items,
                used_bytes=record.used_bytes,
                result_canonical_bytes=record.result_canonical_bytes,
                ledger_canonical_bytes=record.ledger_canonical_bytes,
            )
            if recomputed != profile:
                _reject("retrieval_benchmark_invalid")
        if record.cold.ledger_sha256 != record.warm.ledger_sha256:
            _reject("retrieval_benchmark_invalid")
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        if isinstance(error, RetrievalRejection):
            raise
        raise RetrievalRejection("retrieval_benchmark_invalid") from error
    return True


def verify_retrieval_result(result: RetrievalResult) -> bool:
    """Recompute every public counter, identity, budget, and ledger seal."""

    if not isinstance(result, RetrievalResult):
        _reject("retrieval_result_invalid")
    try:
        result_value = parse_raw_json(result.canonical_bytes)
        ledger_value = parse_raw_json(result.ledger_bytes)
        if (
            not isinstance(result_value, Mapping)
            or not isinstance(ledger_value, Mapping)
            or canonicalize(result_value) != result.canonical_bytes
            or canonicalize(ledger_value) != result.ledger_bytes
            or sha256_hex(result.canonical_bytes) != result.canonical_sha256
            or sha256_hex(result.ledger_bytes) != result.ledger_sha256
            or result_value.get("ledger_sha256") != result.ledger_sha256
            or result_value.get("result_id") != result.result_id
            or result_value.get("query_id") != result.query_id
            or result_value.get("candidate_snapshot_id") != result.snapshot_id
            or result_value.get("integrity_snapshot_id") != result.integrity_snapshot_id
        ):
            _reject("retrieval_result_invalid")
        identity_body = dict(result_value)
        identity_body.pop("result_id", None)
        if _framed_digest(
            "SKELETON_PHASE10_MEMORY_RETRIEVAL_RESULT_V1",
            canonicalize(identity_body),
        ) != result.result_id:
            _reject("retrieval_result_invalid")
        result_sha = identity_body.pop("result_sha256", None)
        if not isinstance(result_sha, str) or sha256_hex(canonicalize(identity_body)) != result_sha:
            _reject("retrieval_result_invalid")
        considered = ledger_value.get("considered_items")
        included_ids = ledger_value.get("included_ids")
        ranked_ids = ledger_value.get("ranked_included_ids")
        if (
            not isinstance(considered, list)
            or not isinstance(included_ids, list)
            or not isinstance(ranked_ids, list)
            or any(not isinstance(item, Mapping) for item in considered)
        ):
            _reject("retrieval_result_invalid")
        memory_ids = [str(item.get("memory_id", "")) for item in considered]
        included_from_items = sorted(
            str(item["memory_id"])
            for item in considered
            if item.get("disposition") == "included"
        )
        included_bytes = sum(
            int(item["canonical_byte_count"])
            for item in considered
            if item.get("disposition") == "included"
        )
        if (
            memory_ids != sorted(memory_ids)
            or len(set(memory_ids)) != len(memory_ids)
            or included_ids != sorted(included_ids)
            or included_ids != included_from_items
            or tuple(included_ids) != result.included_ids
            or tuple(ranked_ids) != result.ranked_included_ids
            or set(ranked_ids) != set(included_ids)
            or int(ledger_value.get("candidate_count", -1)) != len(considered)
            or int(ledger_value.get("included_count", -1)) != len(included_ids)
            or int(ledger_value.get("excluded_count", -1)) != len(considered) - len(included_ids)
            or int(ledger_value.get("used_items", -1)) != len(included_ids)
            or int(ledger_value.get("used_bytes", -1)) != included_bytes
            or result.candidate_count != len(considered)
            or result.included_count != len(included_ids)
            or result.excluded_count != len(considered) - len(included_ids)
            or result.used_items != len(included_ids)
            or result.used_bytes != included_bytes
            or result_value.get("considered_items") != considered
            or result_value.get("included_ids") != included_ids
            or int(result_value.get("candidate_count", -1)) != result.candidate_count
            or int(result_value.get("included_count", -1)) != result.included_count
            or int(result_value.get("excluded_count", -1)) != result.excluded_count
            or int(result_value.get("used_items", -1)) != result.used_items
            or int(result_value.get("used_bytes", -1)) != result.used_bytes
            or result.used_items > int(result_value.get("item_budget", -1))
            or result.used_bytes > int(result_value.get("byte_budget", -1))
        ):
            _reject("retrieval_result_invalid")
        ledger_by_id = {item.memory_id: item for item in result.ledger_items}
        if tuple(ledger_by_id) != tuple(memory_ids) or len(ledger_by_id) != len(memory_ids):
            _reject("retrieval_result_invalid")
        for value in considered:
            item = ledger_by_id[str(value["memory_id"])]
            if _ledger_item_value(item) != dict(value):
                _reject("retrieval_result_invalid")
        ranked_values = [
            ledger_by_id[identity].rank_factors for identity in result.ranked_included_ids
        ]
        if any(value is None for value in ranked_values) or tuple(
            sorted(
                result.ranked_included_ids,
                key=lambda identity: ledger_by_id[identity].rank_factors.sort_key,  # type: ignore[union-attr]
            )
        ) != result.ranked_included_ids:
            _reject("retrieval_result_invalid")
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        if isinstance(error, RetrievalRejection):
            raise
        raise RetrievalRejection("retrieval_result_invalid") from error
    return True


def _candidate_from_raw(raw: bytes) -> FrozenCandidate:
    if not isinstance(raw, bytes):
        _reject("candidate_bytes_required")
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise RetrievalRejection("candidate_bytes_invalid") from error
    if not isinstance(value, Mapping) or canonicalize(value) != raw:
        _reject("candidate_bytes_invalid")
    try:
        memory_id = _hash(value["memory_id"], "candidate_identity_invalid")
        if compute_document_identity(_ENVELOPE_SCHEMA_ID, value) != memory_id:
            _reject("candidate_identity_invalid")
        kind = str(value["memory_kind"])
        if kind not in _MEMORY_KINDS:
            _reject("candidate_shape_invalid")
        scope = value["scope"]
        if not isinstance(scope, Mapping) or scope.get("scope_kind") not in {"none", "domain", "market"}:
            _reject("candidate_shape_invalid")
        scope_kind = str(scope["scope_kind"])
        scope_id = None if scope_kind == "none" else str(scope["scope_id"])
        quality = str(value["quality_class"])
        provenance = str(value["provenance_class"])
        if quality not in _QUALITY_RANK or provenance not in _PROVENANCE_RANK:
            _reject("candidate_shape_invalid")
        effective_to_value = value["effective_to"]
        effective_to = None if effective_to_value == "none" else utc_epoch_microseconds(str(effective_to_value))
        payload = value["payload"]
        contradiction = "none"
        if kind == "semantic":
            if not isinstance(payload, Mapping):
                _reject("candidate_shape_invalid")
            contradiction = str(payload.get("contradiction_set_id", "none"))
            if contradiction == "0" * 64:
                contradiction = "none"
            if contradiction != "none":
                _hash(contradiction, "candidate_shape_invalid")
        canonical_sha = sha256_hex(raw)
        evidence_roots = tuple(value["evidence_root_ids"])
        lineage_roots = tuple(value["lineage_root_ids"])
        if (
            not evidence_roots
            or evidence_roots != tuple(sorted(set(evidence_roots)))
            or not lineage_roots
            or lineage_roots != tuple(sorted(set(lineage_roots)))
        ):
            _reject("candidate_shape_invalid")
        for identity in (*evidence_roots, *lineage_roots):
            _hash(identity, "candidate_shape_invalid")
        return FrozenCandidate(
            memory_id=memory_id,
            memory_kind=kind,
            namespace=str(value["namespace"]),
            lobe_id=str(value["lobe_id"]),
            project_id=str(value["project_id"]),
            scope_kind=scope_kind,
            scope_id=scope_id,
            evidence_root_ids=evidence_roots,
            lineage_root_ids=lineage_roots,
            rights_decision_id=_hash(value["ingest_rights_decision_id"], "candidate_shape_invalid"),
            quality_class=quality,
            provenance_class=provenance,
            quarantine_state=str(value["initial_quarantine_state"]),
            effective_from_us=utc_epoch_microseconds(str(value["effective_from"])),
            effective_to_us=effective_to,
            available_at_us=utc_epoch_microseconds(str(value["available_at"])),
            recorded_at_us=utc_epoch_microseconds(str(value["recorded_at"])),
            operating_mode=str(value["operating_mode"]),
            model_stage=str(value["model_stage"]),
            correction_of=str(value["correction_of"]),
            contradiction_set_id=contradiction,
            canonical_sha256=canonical_sha,
            canonical_bytes=bytes(raw),
            canonical_byte_count=len(raw),
        )
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, RetrievalRejection):
            raise
        raise RetrievalRejection("candidate_shape_invalid") from error


def _freeze_candidates(
    candidates: Iterable[bytes | FrozenCandidate],
    *,
    authenticated: bool,
    correction_edges: Mapping[str, str] | None = None,
) -> CandidateSnapshot:
    frozen = tuple(
        candidate if isinstance(candidate, FrozenCandidate) else _candidate_from_raw(candidate)
        for candidate in candidates
    )
    if not frozen:
        _reject("candidate_snapshot_empty")
    ordered = tuple(sorted(frozen, key=lambda candidate: candidate.memory_id))
    identifiers = tuple(candidate.memory_id for candidate in ordered)
    if len(set(identifiers)) != len(identifiers):
        _reject("candidate_snapshot_duplicate")
    edges = (
        {
            candidate.memory_id: candidate.correction_of
            for candidate in ordered
            if candidate.correction_of != "none"
        }
        if correction_edges is None
        else {str(child): str(parent) for child, parent in correction_edges.items()}
    )
    if any(child not in identifiers or parent not in identifiers for child, parent in edges.items()):
        _reject("candidate_correction_edge_invalid")
    value = {
        "schema_version": "skeleton.memory-candidate-snapshot.v1",
        "candidates": [
            {
                "memory_id": candidate.memory_id,
                "canonical_sha256": candidate.canonical_sha256,
                "canonical_byte_count": candidate.canonical_byte_count,
            }
            for candidate in ordered
        ],
    }
    raw = canonicalize(value)
    return CandidateSnapshot(
        snapshot_id=_framed_digest("SKELETON_PHASE10_CANDIDATE_SNAPSHOT_V1", raw),
        candidate_ids=identifiers,
        candidates=ordered,
        correction_edges=MappingProxyType(edges),
        canonical_sha256=sha256_hex(raw),
        canonical_bytes=raw,
        authenticated=authenticated,
    )


def _freeze_candidate_snapshot_for_test(
    candidates: Iterable[bytes | FrozenCandidate],
) -> CandidateSnapshot:
    """Raw constructor reserved for deterministic algorithm tests."""

    return _freeze_candidates(candidates, authenticated=False)


def freeze_candidate_snapshot(
    candidates: Iterable[MemoryEnvelope],
) -> CandidateSnapshot:
    """Freeze only schema-valid, safety-cleared admitted contract values."""

    publication = MemoryContractPublication.from_registry(
        Path(__file__).resolve().parents[3] / "contracts" / "v1"
    )
    raws: list[bytes] = []
    for candidate in candidates:
        if not isinstance(candidate, MemoryEnvelope):
            _reject("candidate_admission_required")
        contract = publication.validate_contract(
            candidate.canonical_bytes, _ENVELOPE_SCHEMA_ID
        )
        if contract.typed_value != candidate:
            _reject("candidate_admission_required")
        scan_memory_document(candidate.canonical_bytes)
        raws.append(candidate.canonical_bytes)
    return _freeze_candidates(raws, authenticated=True, correction_edges={})


def freeze_store_candidate_snapshot(store: object) -> CandidateSnapshot:
    """Freeze the complete typed store enumeration before compatibility."""

    from .memory_store import MemoryStore

    if not isinstance(store, MemoryStore):
        _reject("retrieval_store_invalid")
    rows = store.snapshot_candidates()
    if not rows:
        _reject("candidate_snapshot_empty")
    return _freeze_candidates(
        tuple(row.canonical_bytes for row in rows),
        authenticated=True,
        correction_edges=dict(store.snapshot_corrections()),
    )


def _freeze_integrity_snapshot(
    candidate_ids: Iterable[str],
    statuses: Mapping[str, str],
    *,
    complete: bool = True,
    resolved_evidence_ids: Iterable[str] = (),
    resolved_lineage_ids: Iterable[str] = (),
    authenticated: bool = False,
) -> IntegritySnapshot:
    identifiers = tuple(sorted(_hash(identity, "integrity_snapshot_invalid") for identity in candidate_ids))
    if len(set(identifiers)) != len(identifiers):
        _reject("integrity_snapshot_invalid")
    copied = {str(identity): str(status) for identity, status in statuses.items()}
    if any(status not in _INTEGRITY_STATES for status in copied.values()):
        _reject("integrity_snapshot_invalid")
    if set(copied) != set(identifiers):
        _reject("integrity_snapshot_invalid")
    evidence = tuple(sorted(_hash(identity, "integrity_snapshot_invalid") for identity in resolved_evidence_ids))
    lineage = tuple(sorted(_hash(identity, "integrity_snapshot_invalid") for identity in resolved_lineage_ids))
    if len(set(evidence)) != len(evidence) or len(set(lineage)) != len(lineage):
        _reject("integrity_snapshot_invalid")
    value = {
        "schema_version": "skeleton.memory-integrity-snapshot.v1",
        "complete": bool(complete),
        "resolved_evidence_ids": list(evidence),
        "resolved_lineage_ids": list(lineage),
        "findings": [
            {"memory_id": identity, "status": copied[identity]} for identity in identifiers
        ],
    }
    raw = canonicalize(value)
    return IntegritySnapshot(
        snapshot_id=_framed_digest("SKELETON_PHASE10_INTEGRITY_SNAPSHOT_V1", raw),
        candidate_ids=identifiers,
        statuses=MappingProxyType(copied),
        resolved_evidence_ids=evidence,
        resolved_lineage_ids=lineage,
        complete=bool(complete),
        canonical_sha256=sha256_hex(raw),
        canonical_bytes=raw,
        authenticated=authenticated,
    )


def freeze_integrity_snapshot(
    candidate_ids: Iterable[str],
    statuses: Mapping[str, str],
    *,
    complete: bool = True,
    resolved_evidence_ids: Iterable[str] = (),
    resolved_lineage_ids: Iterable[str] = (),
) -> IntegritySnapshot:
    """Construct an untrusted snapshot that public retrieval will reject."""

    return _freeze_integrity_snapshot(
        candidate_ids,
        statuses,
        complete=complete,
        resolved_evidence_ids=resolved_evidence_ids,
        resolved_lineage_ids=resolved_lineage_ids,
        authenticated=False,
    )


_freeze_integrity_snapshot_for_test = freeze_integrity_snapshot


def _freeze_rights_snapshot(
    decisions: Mapping[str, str], *, authenticated: bool = False
) -> RightsSnapshot:
    copied = {str(identity): str(status) for identity, status in decisions.items()}
    for identity, status in copied.items():
        _hash(identity, "rights_snapshot_invalid")
        if status not in _RIGHTS_STATES:
            _reject("rights_snapshot_invalid")
    value = {
        "schema_version": "skeleton.memory-rights-snapshot.v1",
        "decisions": [
            {"decision_id": identity, "status": copied[identity]}
            for identity in sorted(copied)
        ],
    }
    raw = canonicalize(value)
    return RightsSnapshot(
        snapshot_id=_framed_digest("SKELETON_PHASE10_RIGHTS_SNAPSHOT_V1", raw),
        decisions=MappingProxyType(copied),
        canonical_sha256=sha256_hex(raw),
        canonical_bytes=raw,
        authenticated=authenticated,
    )


def freeze_rights_snapshot(decisions: Mapping[str, str]) -> RightsSnapshot:
    """Construct an untrusted snapshot that public retrieval will reject."""

    return _freeze_rights_snapshot(decisions, authenticated=False)


_freeze_rights_snapshot_for_test = freeze_rights_snapshot


def freeze_store_rights_snapshot(
    store: object, snapshot: CandidateSnapshot
) -> RightsSnapshot:
    """Derive exact rights state from persisted Phase 7 authority rows."""

    from .memory_store import MemoryStore

    if not isinstance(store, MemoryStore) or not snapshot.authenticated:
        _reject("rights_store_snapshot_invalid")
    decision_ids = tuple(
        sorted({candidate.rights_decision_id for candidate in snapshot.candidates})
    )
    return _freeze_rights_snapshot(
        dict(store.snapshot_rights(decision_ids)), authenticated=True
    )


def build_retrieval_query(**fields: object) -> RetrievalQuery:
    required = {
        "candidate_snapshot_id", "decision_at", "known_at", "world_at",
        "namespace", "lobe_id", "project_id", "purpose", "scope",
        "operating_mode", "rights_boundary", "minimum_quality",
        "accepted_provenance_classes", "model_stage", "paper_eligible",
        "item_budget", "byte_budget", "rank_profile_id", "integrity_snapshot_id",
    }
    if set(fields) != required:
        _reject("retrieval_query_invalid")
    try:
        scope = fields["scope"]
        provenance = tuple(fields["accepted_provenance_classes"])  # type: ignore[arg-type]
        if (
            not isinstance(scope, Mapping)
            or scope.get("scope_kind") not in {"none", "domain", "market"}
            or set(scope) != ({"scope_kind"} if scope.get("scope_kind") == "none" else {"scope_kind", "scope_id"})
            or fields["purpose"] not in _PURPOSE_KIND_RANK
            or fields["operating_mode"] not in _OPERATING_MODES
            or fields["rights_boundary"] != "retrieval"
            or fields["minimum_quality"] not in _QUALITY_RANK
            or not provenance
            or provenance != tuple(sorted(set(provenance)))
            or any(item not in _PROVENANCE_RANK for item in provenance)
            or fields["model_stage"] not in _MODEL_STAGES
            or type(fields["paper_eligible"]) is not bool
            or type(fields["item_budget"]) is not int
            or int(fields["item_budget"]) <= 0
            or type(fields["byte_budget"]) is not int
            or int(fields["byte_budget"]) <= 0
            or fields["rank_profile_id"] != _RANK_PROFILE_ID
            or (
                bool(fields["paper_eligible"])
                and (
                    fields["operating_mode"] != "paper"
                    or fields["model_stage"] != "paper"
                )
            )
            or (
                fields["operating_mode"] == "paper"
                and fields["paper_eligible"] is not True
            )
            or any(not isinstance(fields[name], str) or not fields[name] for name in ("namespace", "lobe_id", "project_id"))
        ):
            _reject("retrieval_query_invalid")
        candidate_snapshot_id = _hash(fields["candidate_snapshot_id"], "retrieval_query_invalid")
        integrity_snapshot_id = _hash(fields["integrity_snapshot_id"], "retrieval_query_invalid")
        decision_at = str(fields["decision_at"])
        known_at = str(fields["known_at"])
        world_at = str(fields["world_at"])
        utc_epoch_microseconds(decision_at)
        known_us = utc_epoch_microseconds(known_at)
        world_us = utc_epoch_microseconds(world_at)
        scope_kind = str(scope["scope_kind"])
        scope_id = None if scope_kind == "none" else str(scope["scope_id"])
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, RetrievalRejection):
            raise RetrievalRejection("retrieval_query_invalid") from error
        raise RetrievalRejection("retrieval_query_invalid") from error
    value: dict[str, object] = {
        "schema_version": "skeleton.memory-retrieval.v1",
        "record_type": "query",
        "candidate_snapshot_id": candidate_snapshot_id,
        "decision_at": decision_at,
        "known_at": known_at,
        "world_at": world_at,
        "namespace": fields["namespace"],
        "lobe_id": fields["lobe_id"],
        "project_id": fields["project_id"],
        "purpose": fields["purpose"],
        "scope": dict(scope),
        "operating_mode": fields["operating_mode"],
        "rights_boundary": "retrieval",
        "minimum_quality": fields["minimum_quality"],
        "accepted_provenance_classes": list(provenance),
        "model_stage": fields["model_stage"],
        "paper_eligible": fields["paper_eligible"],
        "item_budget": fields["item_budget"],
        "byte_budget": fields["byte_budget"],
        "rank_profile_id": _RANK_PROFILE_ID,
        "integrity_snapshot_id": integrity_snapshot_id,
    }
    query_id = _framed_digest(
        "SKELETON_PHASE10_MEMORY_RETRIEVAL_QUERY_V1", canonicalize(value)
    )
    value["query_id"] = query_id
    raw = canonicalize(value)
    if compute_document_identity(
        "https://schemas.skeleton.local/v1/memory-retrieval.schema.json", value
    ) != query_id:
        _reject("retrieval_query_identity_mismatch")
    return RetrievalQuery(
        query_id=query_id,
        candidate_snapshot_id=candidate_snapshot_id,
        decision_at=decision_at,
        known_at=known_at,
        world_at=world_at,
        namespace=str(fields["namespace"]),
        lobe_id=str(fields["lobe_id"]),
        project_id=str(fields["project_id"]),
        purpose=str(fields["purpose"]),
        scope_kind=scope_kind,
        scope_id=scope_id,
        operating_mode=str(fields["operating_mode"]),
        rights_boundary="retrieval",
        minimum_quality=str(fields["minimum_quality"]),
        accepted_provenance_classes=provenance,
        model_stage=str(fields["model_stage"]),
        paper_eligible=bool(fields["paper_eligible"]),
        item_budget=int(fields["item_budget"]),
        byte_budget=int(fields["byte_budget"]),
        rank_profile_id=_RANK_PROFILE_ID,
        integrity_snapshot_id=integrity_snapshot_id,
        known_at_us=known_us,
        world_at_us=world_us,
        canonical_sha256=sha256_hex(raw),
        canonical_bytes=raw,
    )


def _rank_factors(query: RetrievalQuery, candidate: FrozenCandidate) -> RankFactors:
    contradiction = candidate.contradiction_set_id
    return RankFactors(
        purpose_rank=_PURPOSE_KIND_RANK[query.purpose][candidate.memory_kind],
        quality_rank=_QUALITY_RANK[candidate.quality_class],
        provenance_rank=_PROVENANCE_RANK[candidate.provenance_class],
        effective_epoch_us=candidate.effective_from_us,
        available_epoch_us=candidate.available_at_us,
        contradiction_group_id=contradiction,
        rank_tie_breaker=candidate.memory_id,
    )


def _evaluate(
    query: RetrievalQuery,
    candidate: FrozenCandidate,
    integrity_status: str,
    rights_status: str,
    corrected_predecessors: frozenset[str],
    contradiction_integrity_invalid: bool,
    paper_foundation_resolved: bool,
) -> CompatibilityEvaluation:
    failures: list[str] = []
    paper_profile = query.paper_eligible
    paper_provenance_reason = {
        "seeded_test": "paper_seeded_test",
        "simulated": "paper_simulated",
        "synthetic": "paper_synthetic",
    }.get(candidate.provenance_class) if paper_profile else None
    # Candidate bytes and their digest were recomputed while freezing the
    # immutable snapshot.  Rehashing every full envelope per query would repeat
    # authenticated snapshot work without changing the trust boundary.
    if integrity_status == "unverifiable_bytes" or candidate.quarantine_state == "unverifiable":
        failures.append("unverifiable_bytes")
    paper_contaminated = paper_profile and candidate.quarantine_state == "contaminated"
    if (
        integrity_status == "quarantined"
        or (
            candidate.quarantine_state
            not in {"clean", "stale", "revoked_rights", "unverifiable"}
            and not paper_contaminated
        )
        or (
            paper_profile
            and integrity_status not in {"healthy", "contradiction_member"}
            and integrity_status not in {
                "quarantined",
                "unverifiable_bytes",
                "contradiction_integrity_invalid",
            }
        )
    ):
        failures.append("quarantined")
    if paper_profile and not paper_foundation_resolved and "quarantined" not in failures:
        failures.append("quarantined")
    if candidate.namespace != query.namespace:
        failures.append("namespace_mismatch")
    if candidate.project_id != query.project_id:
        failures.append("project_mismatch")
    if candidate.lobe_id != query.lobe_id:
        failures.append("lobe_mismatch")
    if candidate.available_at_us > query.known_at_us or candidate.recorded_at_us > query.known_at_us:
        failures.append("future_available")
    if candidate.effective_from_us > query.world_at_us:
        failures.append("not_yet_effective")
    if candidate.effective_to_us is not None and candidate.effective_to_us <= query.world_at_us:
        failures.append("expired")
    if candidate.quarantine_state == "stale" or candidate.memory_id in corrected_predecessors:
        failures.append("stale")
    if candidate.memory_kind not in _PURPOSE_KIND_RANK[query.purpose]:
        failures.append("purpose_kind_incompatible")
    if candidate.scope_kind != query.scope_kind or candidate.scope_id != query.scope_id:
        failures.append("scope_mismatch")
    if candidate.operating_mode != query.operating_mode:
        failures.append("operating_mode_mismatch")
    if candidate.model_stage != query.model_stage:
        failures.append("model_stage_mismatch")
    rights_reason = {
        "unresolved": "rights_unresolved",
        "revoked": "rights_revoked",
        "denied": "rights_denied",
    }.get(rights_status)
    if rights_reason is not None:
        failures.append(rights_reason)
    if candidate.quarantine_state == "revoked_rights" and "rights_revoked" not in failures:
        failures.append("rights_revoked")
    if (
        candidate.provenance_class not in query.accepted_provenance_classes
        and paper_provenance_reason is None
    ):
        failures.append("provenance_rejected")
    if _QUALITY_RANK[candidate.quality_class] > _QUALITY_RANK[query.minimum_quality]:
        failures.append("quality_below_minimum")
    if paper_profile:
        if paper_provenance_reason is not None:
            failures.append(paper_provenance_reason)
        elif candidate.provenance_class != "verified_real" and "provenance_rejected" not in failures:
            failures.append("provenance_rejected")
        if paper_contaminated:
            failures.append("paper_contaminated")
    if integrity_status == "contradiction_integrity_invalid" or contradiction_integrity_invalid:
        failures.append("contradiction_integrity_invalid")
    failures.sort(key=_REASON_INDEX.__getitem__)
    terminal = failures[0] if failures else None
    factors = None if terminal is not None else _rank_factors(query, candidate)
    return CompatibilityEvaluation(candidate.memory_id, tuple(failures), terminal, factors)


def _invalid_contradiction_members(
    snapshot: CandidateSnapshot, integrity: IntegritySnapshot
) -> frozenset[str]:
    """Return every candidate whose contradiction membership is not total.

    The integrity snapshot is authoritative for membership classification, but
    retrieval still verifies that its classification and the canonical semantic
    payload agree and that every declared set has at least two sourced members.
    This happens before rank so malformed cohorts cannot manufacture a winner.
    """

    groups: dict[str, list[str]] = {}
    invalid: set[str] = set()
    for candidate in snapshot.candidates:
        status = integrity.statuses[candidate.memory_id]
        if candidate.contradiction_set_id == "none":
            if status == "contradiction_member":
                invalid.add(candidate.memory_id)
            continue
        groups.setdefault(candidate.contradiction_set_id, []).append(candidate.memory_id)
        if status != "contradiction_member":
            invalid.add(candidate.memory_id)
    for members in groups.values():
        if len(members) < 2 or any(identity in invalid for identity in members):
            invalid.update(members)
    return frozenset(invalid)


def _share_contradiction_rank_prefixes(
    evaluations: tuple[CompatibilityEvaluation, ...],
    by_id: Mapping[str, FrozenCandidate],
) -> tuple[CompatibilityEvaluation, ...]:
    """Give compatible members one cohort prefix while retaining peer IDs."""

    groups: dict[str, list[CompatibilityEvaluation]] = {}
    for evaluation in evaluations:
        if evaluation.terminal_reason is not None:
            continue
        group_id = by_id[evaluation.memory_id].contradiction_set_id
        if group_id != "none":
            groups.setdefault(group_id, []).append(evaluation)
    if not groups:
        return evaluations

    replacements: dict[str, CompatibilityEvaluation] = {}
    for group_id, members in groups.items():
        leader = min(
            members,
            key=lambda member: member.rank_factors.sort_key,  # type: ignore[union-attr]
        )
        assert leader.rank_factors is not None
        prefix = leader.rank_factors
        for member in members:
            shared = RankFactors(
                purpose_rank=prefix.purpose_rank,
                quality_rank=prefix.quality_rank,
                provenance_rank=prefix.provenance_rank,
                effective_epoch_us=prefix.effective_epoch_us,
                available_epoch_us=prefix.available_epoch_us,
                contradiction_group_id=group_id,
                rank_tie_breaker=member.memory_id,
            )
            replacements[member.memory_id] = CompatibilityEvaluation(
                member.memory_id,
                member.all_failures,
                None,
                shared,
            )
    return tuple(replacements.get(item.memory_id, item) for item in evaluations)


def _ledger_item_value(item: LedgerItem) -> dict[str, object]:
    if item.disposition == "included":
        assert item.rank_factors is not None and item.canonical_byte_count is not None
        return {
            "memory_id": item.memory_id,
            "disposition": "included",
            "rank_factors": item.rank_factors.as_value(),
            "canonical_byte_count": item.canonical_byte_count,
        }
    assert item.exclusion_reason is not None
    return {
        "memory_id": item.memory_id,
        "disposition": "excluded",
        "exclusion_reason": item.exclusion_reason,
    }


class MemoryRetriever:
    """Pure retriever with an optional typed MemoryStore persistence sink."""

    __slots__ = ("_cache", "_operation_capability_issuer", "_store")

    def __init__(
        self,
        store: object | None = None,
        *,
        operation_capability_issuer: Callable[[object, str, str, bytes], bytes]
        | None = None,
    ) -> None:
        if store is not None:
            from .memory_store import MemoryStore

            if not isinstance(store, MemoryStore):
                _reject("retrieval_store_invalid")
        self._store = store
        self._operation_capability_issuer = operation_capability_issuer
        self._cache: dict[tuple[str, str, str, str], RetrievalResult] = {}

    def retrieve(
        self,
        query: RetrievalQuery,
        snapshot: CandidateSnapshot,
        integrity: IntegritySnapshot,
        rights: RightsSnapshot,
        *,
        operation_id: str | None = None,
    ) -> RetrievalResult:
        return self._retrieve(
            query,
            snapshot,
            integrity,
            rights,
            operation_id=operation_id,
            allow_untrusted=False,
        )

    def _retrieve_for_test(
        self,
        query: RetrievalQuery,
        snapshot: CandidateSnapshot,
        integrity: IntegritySnapshot,
        rights: RightsSnapshot,
        *,
        operation_id: str | None = None,
    ) -> RetrievalResult:
        """Exercise deterministic projection with synthetic test snapshots."""

        return self._retrieve(
            query,
            snapshot,
            integrity,
            rights,
            operation_id=operation_id,
            allow_untrusted=True,
        )

    def _retrieve(
        self,
        query: RetrievalQuery,
        snapshot: CandidateSnapshot,
        integrity: IntegritySnapshot,
        rights: RightsSnapshot,
        *,
        operation_id: str | None = None,
        allow_untrusted: bool,
    ) -> RetrievalResult:
        if not isinstance(query, RetrievalQuery) or not isinstance(snapshot, CandidateSnapshot):
            _reject("retrieval_input_invalid")
        if not allow_untrusted and not (
            snapshot.authenticated and integrity.authenticated and rights.authenticated
        ):
            _reject("retrieval_authority_required")
        if query.candidate_snapshot_id != snapshot.snapshot_id:
            _reject("candidate_snapshot_mismatch")
        if query.integrity_snapshot_id != integrity.snapshot_id:
            _reject("integrity_snapshot_mismatch")
        if (
            not integrity.complete
            or integrity.candidate_ids != snapshot.candidate_ids
            or set(integrity.statuses) != set(snapshot.candidate_ids)
        ):
            _reject("integrity_snapshot_incomplete")
        cache_key = (
            query.canonical_sha256,
            snapshot.canonical_sha256,
            integrity.canonical_sha256,
            rights.canonical_sha256,
        )
        durable = query.purpose in _DURABLE_PURPOSES or query.operating_mode == "paper"
        if not durable and cache_key in self._cache:
            return self._cache[cache_key]

        invalid_contradictions = _invalid_contradiction_members(snapshot, integrity)
        resolved_evidence = frozenset(integrity.resolved_evidence_ids)
        resolved_lineage = frozenset(integrity.resolved_lineage_ids)
        def evaluate(candidate: FrozenCandidate, superseded: frozenset[str]) -> CompatibilityEvaluation:
            return _evaluate(
                query,
                candidate,
                integrity.statuses[candidate.memory_id],
                rights.decisions.get(candidate.rights_decision_id, "unresolved"),
                superseded,
                candidate.memory_id in invalid_contradictions,
                (
                    not query.paper_eligible
                    or (
                        set(candidate.evidence_root_ids).issubset(resolved_evidence)
                        and set(candidate.lineage_root_ids).issubset(resolved_lineage)
                    )
                ),
            )
        preliminary = tuple(
            evaluate(candidate, frozenset()) for candidate in snapshot.candidates
        )
        eligible_children = {
            evaluation.memory_id
            for evaluation in preliminary
            if evaluation.terminal_reason is None
        }
        corrected_predecessors = frozenset(
            parent
            for child, parent in snapshot.correction_edges.items()
            if child in eligible_children
        )
        evaluations = tuple(
            (
                evaluate(candidate, corrected_predecessors)
                if candidate.memory_id in corrected_predecessors
                else preliminary[ordinal]
            )
            for ordinal, candidate in enumerate(snapshot.candidates)
        )
        by_id = {candidate.memory_id: candidate for candidate in snapshot.candidates}
        evaluations = _share_contradiction_rank_prefixes(evaluations, by_id)
        compatible = sorted(
            (evaluation for evaluation in evaluations if evaluation.terminal_reason is None),
            key=lambda evaluation: evaluation.rank_factors.sort_key,  # type: ignore[union-attr]
        )
        disposition_by_id: dict[str, LedgerItem] = {
            evaluation.memory_id: LedgerItem(
                evaluation.memory_id,
                "excluded",
                evaluation.terminal_reason,
                None,
                None,
            )
            for evaluation in evaluations
            if evaluation.terminal_reason is not None
        }
        ranked_included: list[str] = []
        used_items = 0
        used_bytes = 0
        item_exhausted = False
        byte_exhausted = False
        cohorts: list[tuple[CompatibilityEvaluation, ...]] = []
        seen_groups: set[str] = set()
        for evaluation in compatible:
            group_id = by_id[evaluation.memory_id].contradiction_set_id
            if group_id == "none":
                cohorts.append((evaluation,))
            elif group_id not in seen_groups:
                members = tuple(
                    item
                    for item in compatible
                    if by_id[item.memory_id].contradiction_set_id == group_id
                )
                cohorts.append(members)
                seen_groups.add(group_id)

        for cohort in cohorts:
            candidates = tuple(by_id[item.memory_id] for item in cohort)
            is_contradiction = candidates[0].contradiction_set_id != "none"
            cohort_items = len(candidates)
            cohort_bytes = sum(candidate.canonical_byte_count for candidate in candidates)
            if item_exhausted or used_items + cohort_items > query.item_budget:
                item_exhausted = True
                reason = "budget_contradiction_group" if is_contradiction else "budget_item"
                for candidate in candidates:
                    disposition_by_id[candidate.memory_id] = LedgerItem(
                        candidate.memory_id, "excluded", reason, None, None
                    )
            elif byte_exhausted or used_bytes + cohort_bytes > query.byte_budget:
                byte_exhausted = True
                reason = "budget_contradiction_group" if is_contradiction else "budget_bytes"
                for candidate in candidates:
                    disposition_by_id[candidate.memory_id] = LedgerItem(
                        candidate.memory_id, "excluded", reason, None, None
                    )
            else:
                used_items += cohort_items
                used_bytes += cohort_bytes
                for evaluation, candidate in zip(cohort, candidates, strict=True):
                    assert evaluation.rank_factors is not None
                    ranked_included.append(candidate.memory_id)
                    disposition_by_id[candidate.memory_id] = LedgerItem(
                        candidate.memory_id,
                        "included",
                        None,
                        evaluation.rank_factors,
                        candidate.canonical_byte_count,
                    )
        ledger_items = tuple(disposition_by_id[identity] for identity in snapshot.candidate_ids)
        if len(ledger_items) != len(snapshot.candidate_ids) or {item.memory_id for item in ledger_items} != set(snapshot.candidate_ids):
            _reject("retrieval_ledger_incomplete")
        included_ids = tuple(sorted(ranked_included))
        considered_values = [_ledger_item_value(item) for item in ledger_items]
        ledger_value = {
            "schema_version": "skeleton.memory-considered-ledger.v1",
            "query_id": query.query_id,
            "query_sha256": query.canonical_sha256,
            "candidate_snapshot_id": snapshot.snapshot_id,
            "candidate_snapshot_sha256": snapshot.canonical_sha256,
            "integrity_snapshot_id": integrity.snapshot_id,
            "integrity_snapshot_sha256": integrity.canonical_sha256,
            "rights_snapshot_id": rights.snapshot_id,
            "rights_snapshot_sha256": rights.canonical_sha256,
            "rank_profile_id": _RANK_PROFILE_ID,
            "rank_profile_sha256": _framed_digest(
                "SKELETON_PHASE10_MEMORY_RANK_PROFILE_V1", _RANK_PROFILE_ID.encode("ascii")
            ),
            "candidate_count": len(ledger_items),
            "included_count": len(included_ids),
            "excluded_count": len(ledger_items) - len(included_ids),
            "used_items": used_items,
            "used_bytes": used_bytes,
            "included_ids": list(included_ids),
            "ranked_included_ids": list(ranked_included),
            "considered_items": considered_values,
        }
        ledger_raw = _closed_retrieval_canonicalize(ledger_value)
        ledger_sha = sha256_hex(ledger_raw)
        result_value: dict[str, object] = {
            "schema_version": "skeleton.memory-retrieval.v1",
            "record_type": "result",
            "query_id": query.query_id,
            "query_sha256": query.canonical_sha256,
            "candidate_snapshot_id": snapshot.snapshot_id,
            "candidate_snapshot_sha256": snapshot.canonical_sha256,
            "integrity_snapshot_id": integrity.snapshot_id,
            "integrity_snapshot_sha256": integrity.canonical_sha256,
            "rank_profile_id": _RANK_PROFILE_ID,
            "rank_profile_sha256": ledger_value["rank_profile_sha256"],
            "ledger_sha256": ledger_sha,
            "included_ids": list(included_ids),
            "considered_items": considered_values,
            "candidate_count": len(ledger_items),
            "included_count": len(included_ids),
            "excluded_count": len(ledger_items) - len(included_ids),
            "item_budget": query.item_budget,
            "byte_budget": query.byte_budget,
            "used_items": used_items,
            "used_bytes": used_bytes,
        }
        result_body_raw = _closed_retrieval_canonicalize(result_value)
        result_sha256 = sha256_hex(result_body_raw)
        result_identity_raw = result_body_raw.replace(
            b'"schema_version":',
            b'"result_sha256":"' + result_sha256.encode("ascii") + b'","schema_version":',
            1,
        )
        result_id = _framed_digest(
            "SKELETON_PHASE10_MEMORY_RETRIEVAL_RESULT_V1",
            result_identity_raw,
        )
        result_raw = result_identity_raw.replace(
            b'"result_sha256":',
            b'"result_id":"' + result_id.encode("ascii") + b'","result_sha256":',
            1,
        )
        result = RetrievalResult(
            result_id=result_id,
            query_id=query.query_id,
            snapshot_id=snapshot.snapshot_id,
            integrity_snapshot_id=integrity.snapshot_id,
            included_ids=included_ids,
            ranked_included_ids=tuple(ranked_included),
            ledger_items=ledger_items,
            evaluations=evaluations,
            candidate_count=len(ledger_items),
            included_count=len(included_ids),
            excluded_count=len(ledger_items) - len(included_ids),
            used_items=used_items,
            used_bytes=used_bytes,
            ledger_sha256=ledger_sha,
            ledger_bytes=ledger_raw,
            canonical_sha256=sha256_hex(result_raw),
            canonical_bytes=result_raw,
        )
        if sha256_hex(result.ledger_bytes) != result.ledger_sha256 or sha256_hex(result.canonical_bytes) != result.canonical_sha256:
            _reject("retrieval_seal_mismatch")
        if durable:
            if self._store is None or operation_id is None:
                _reject("retrieval_persistence_required")
            self._persist(result, query, snapshot, operation_id)
        else:
            self._cache[cache_key] = result
        return result

    def _persist(
        self,
        result: RetrievalResult,
        query: RetrievalQuery,
        snapshot: CandidateSnapshot,
        operation_id: str,
    ) -> None:
        from .memory_store import RetrievalAppend, RetrievalItemAppend

        _hash(operation_id, "retrieval_operation_identity_invalid")
        if self._operation_capability_issuer is None:
            _reject("retrieval_operation_capability_required")
        items = tuple(
            RetrievalItemAppend(
                memory_id=item.memory_id,
                disposition=item.disposition,
                reason_code=item.exclusion_reason or "included",
                rank_factors=canonicalize(item.rank_factors.as_value()) if item.rank_factors else b"{}",
            )
            for item in result.ledger_items
        )
        self._store.persist_retrieval(  # type: ignore[union-attr]
            RetrievalAppend(
                result_id=result.result_id,
                snapshot_id=snapshot.snapshot_id,
                candidate_ids=snapshot.candidate_ids,
                query_root=query.canonical_sha256,
                integrity_snapshot_id=result.integrity_snapshot_id,
                rank_profile_id=_RANK_PROFILE_ID,
                used_items=result.used_items,
                used_bytes=result.used_bytes,
                ledger_root=result.ledger_sha256,
                canonical_bytes=result.canonical_bytes,
                items=items,
            ),
            operation_id=operation_id,
            capability_raw=self._operation_capability_issuer(
                MemoryOperationClass.RETRIEVAL,
                operation_id,
                result.result_id,
                result.canonical_bytes,
            ),
        )


__all__ = [
    "BenchmarkProfile", "CandidateSnapshot", "CompatibilityEvaluation", "FrozenCandidate",
    "IntegritySnapshot", "LedgerItem", "MemoryRetriever", "RankFactors",
    "RetrievalBenchmarkRecord", "RetrievalQuery", "RetrievalRejection",
    "RetrievalResult", "RightsSnapshot",
    "build_retrieval_query", "freeze_candidate_snapshot",
    "freeze_integrity_snapshot", "freeze_rights_snapshot",
    "freeze_store_candidate_snapshot", "freeze_store_rights_snapshot",
    "seal_retrieval_benchmark",
    "utc_epoch_microseconds", "verify_retrieval_benchmark", "verify_retrieval_result",
]
