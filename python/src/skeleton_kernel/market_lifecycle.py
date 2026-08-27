"""Code-owned, non-interchangeable market-family lifecycle graphs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from .canonical import canonicalize, sha256_hex
from .schema_registry import SchemaRegistry


TRACE_SCHEMA_ID = "https://schemas.skeleton.local/v1/market-conformance-trace.schema.json"
VALID_PATH = "fixtures/phase08-family-fixtures.jsonl"
POISON_PATH = "fixtures/phase08-family-poison-fixtures.jsonl"

_FAMILY_TRANSITIONS = MappingProxyType(
    {
        "listed_option": MappingProxyType(
            {("listed", "normal"): "open", ("listed", "amend"): "listed", ("listed", "cancel"): "cancelled",
             ("listed", "halt"): "halted", ("listed", "outage"): "unavailable", ("listed", "expiry"): "expired",
             ("listed", "correction"): "corrected", ("listed", "exercise"): "exercised",
             ("listed", "assignment"): "assigned", ("listed", "settlement"): "settled"}
        ),
        "future": MappingProxyType(
            {("listed", "normal"): "open", ("listed", "amend"): "listed", ("listed", "cancel"): "cancelled",
             ("listed", "halt"): "halted", ("listed", "outage"): "unavailable", ("listed", "expiry"): "expired",
             ("listed", "correction"): "corrected", ("listed", "roll"): "rolled",
             ("listed", "delivery"): "delivered", ("listed", "settlement"): "settled"}
        ),
        "contingent_contract": MappingProxyType(
            {("listed", "normal"): "open", ("listed", "amend"): "listed", ("listed", "cancel"): "cancelled",
             ("listed", "halt"): "halted", ("listed", "outage"): "unavailable", ("listed", "expiry"): "expired",
             ("listed", "void"): "voided", ("listed", "correction"): "corrected",
             ("listed", "dispute"): "disputed", ("listed", "settlement"): "settled"}
        ),
        "sports_event_contract": MappingProxyType(
            {("listed", "normal"): "open", ("listed", "amend"): "listed", ("listed", "cancel"): "cancelled",
             ("listed", "halt"): "halted", ("listed", "outage"): "unavailable", ("listed", "expiry"): "expired",
             ("listed", "void"): "voided", ("listed", "correction"): "corrected",
             ("listed", "dispute"): "disputed", ("listed", "settlement"): "settled",
             ("listed", "postponement"): "postponed"}
        ),
    }
)
_KNOWN_EVENTS = frozenset(event for table in _FAMILY_TRANSITIONS.values() for _state, event in table)
_STATES = frozenset({state for table in _FAMILY_TRANSITIONS.values() for edge in table for state in (edge[0], table[edge])})


@dataclass(slots=True)
class MarketLifecycleRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class FamilyLifecycleGraph:
    family: str
    version: str = "v1"

    def transition(self, state: str, event: str) -> str:
        if self.family not in _FAMILY_TRANSITIONS:
            raise MarketLifecycleRejection("family_unknown")
        if state not in _STATES:
            raise MarketLifecycleRejection("unknown_state")
        if event not in _KNOWN_EVENTS:
            raise MarketLifecycleRejection("unknown_event")
        transitions = _FAMILY_TRANSITIONS[self.family]
        if event not in {candidate for _source, candidate in transitions}:
            raise MarketLifecycleRejection("event_not_applicable")
        if (state, event) not in transitions:
            raise MarketLifecycleRejection("illegal_transition")
        return transitions[(state, event)]


@dataclass(frozen=True, slots=True)
class ConformanceTraceResult:
    trace_id: str
    family: str
    disposition: str
    final_state: str
    evidence_ids: tuple[str, ...]
    canonical_bytes: bytes
    content_sha256: str


@dataclass(frozen=True, slots=True, init=False)
class ConformanceTraceRunner:
    coverage: Mapping[str, frozenset[str]]
    durable_write_count: int
    _registry: SchemaRegistry

    def __init__(self, registry: SchemaRegistry, coverage: Mapping[str, frozenset[str]]) -> None:
        object.__setattr__(self, "_registry", registry)
        object.__setattr__(self, "coverage", MappingProxyType(dict(coverage)))
        object.__setattr__(self, "durable_write_count", 0)

    @classmethod
    def from_registry(cls, registry: SchemaRegistry) -> "ConformanceTraceRunner":
        if TRACE_SCHEMA_ID not in registry.schema_ids:
            raise MarketLifecycleRejection("trace_schema_missing")
        if not {VALID_PATH, POISON_PATH}.issubset(registry.fixture_paths):
            raise MarketLifecycleRejection("trace_fixture_missing")
        coverage: dict[str, set[str]] = {family: set() for family in _FAMILY_TRANSITIONS}
        for record in registry.fixture_records(VALID_PATH):
            trace = record.get("trace")
            if not isinstance(trace, dict):
                raise MarketLifecycleRejection("trace_shape_invalid")
            registry.validate_raw(canonicalize(trace), TRACE_SCHEMA_ID)
            family = str(trace["family"])
            for event in trace["events"]:
                coverage[family].add(str(event["event"]))
        return cls(registry, {key: frozenset(value) for key, value in coverage.items()})

    @staticmethod
    def payload_bytes(payload: object) -> bytes:
        return canonicalize(payload)  # type: ignore[arg-type]

    def run(self, trace: object) -> ConformanceTraceResult:
        if not isinstance(trace, Mapping):
            raise MarketLifecycleRejection("trace_shape_invalid")
        self._registry.validate_raw(canonicalize(dict(trace)), TRACE_SCHEMA_ID)
        family = str(trace["family"])
        graph = FamilyLifecycleGraph(family)
        state = str(trace["initial_state"])
        evidence_ids: list[str] = []
        for event in trace["events"]:  # type: ignore[index]
            if not isinstance(event, Mapping):
                raise MarketLifecycleRejection("trace_shape_invalid")
            state = graph.transition(state, str(event["event"]))
            _validate_semantics(family, str(event["event"]), event.get("semantics"))
            evidence_ids.append(str(event["evidence_id"]))
        expected = trace.get("expected_final_state")
        if expected is not None and expected != state:
            raise MarketLifecycleRejection("final_state_mismatch")
        body = {
            "disposition": "accept",
            "evidence_ids": evidence_ids,
            "family": family,
            "final_state": state,
            "trace_id": trace["trace_id"],
        }
        raw = canonicalize(body)
        return ConformanceTraceResult(
            trace_id=str(trace["trace_id"]),
            family=family,
            disposition="accept",
            final_state=state,
            evidence_ids=tuple(evidence_ids),
            canonical_bytes=raw,
            content_sha256=sha256_hex(raw),
        )

    def run_seeded(self, *, family: str, state: str, event: str) -> ConformanceTraceResult:
        trace = {
            "schema_version": "skeleton.market-conformance-trace.v1",
            "trace_id": sha256_hex(canonicalize({"event": event, "family": family, "state": state})),
            "family": family,
            "initial_state": state,
            "events": [{"event": event, "evidence_id": "0" * 64}],
            "expected_verdict": "accept",
            "expected_final_state": None,
            "rejection_code": None,
        }
        return self.run(trace)


def _validate_semantics(family: str, event: str, semantics: object) -> None:
    required_fields: frozenset[str] = frozenset()
    if family == "listed_option" and event == "normal":
        required_fields = frozenset(
            {
                "expected_multiplier",
                "observed_multiplier",
                "requests_margin_authority",
                "requires_fee_basis",
                "fee_basis_id",
                "resolution_candidate_ids",
                "requires_settlement_basis",
                "settlement_basis_id",
            }
        )
    elif family == "future" and event == "normal":
        required_fields = frozenset({"expected_tick", "observed_tick"})
    elif family == "future" and event == "roll":
        required_fields = frozenset({"roll_available_at", "decision_time"})
    if semantics is None:
        if required_fields:
            raise MarketLifecycleRejection("semantic_evidence_missing")
        return
    if not isinstance(semantics, Mapping):
        raise MarketLifecycleRejection("semantic_shape_invalid")
    if required_fields.difference(semantics):
        raise MarketLifecycleRejection("semantic_evidence_missing")
    expected_multiplier = semantics.get("expected_multiplier")
    observed_multiplier = semantics.get("observed_multiplier")
    if expected_multiplier is not None or observed_multiplier is not None:
        if family != "listed_option":
            raise MarketLifecycleRejection("semantic_family_mismatch")
        if expected_multiplier != observed_multiplier:
            raise MarketLifecycleRejection("multiplier_mismatch")
    expected_tick = semantics.get("expected_tick")
    observed_tick = semantics.get("observed_tick")
    if expected_tick is not None or observed_tick is not None:
        if family != "future":
            raise MarketLifecycleRejection("semantic_family_mismatch")
        if expected_tick != observed_tick:
            raise MarketLifecycleRejection("tick_mismatch")
    if "roll_available_at" in semantics or "decision_time" in semantics:
        if family != "future" or event != "roll":
            raise MarketLifecycleRejection("semantic_family_mismatch")
        available = _semantic_time(semantics.get("roll_available_at"))
        decision = _semantic_time(semantics.get("decision_time"))
        if available > decision:
            raise MarketLifecycleRejection("stale_roll")
    if semantics.get("requests_margin_authority") is True:
        raise MarketLifecycleRejection("margin_authority_forbidden")
    if family == "listed_option" and event == "normal" and (
        semantics.get("requires_fee_basis") is not True
        or semantics.get("fee_basis_id") is None
    ):
        raise MarketLifecycleRejection("fee_basis_missing")
    if "resolution_candidate_ids" in semantics:
        candidates = semantics["resolution_candidate_ids"]
        if not isinstance(candidates, list) or len(set(candidates)) != 1:
            raise MarketLifecycleRejection("resolution_ambiguous")
    if family == "listed_option" and event == "normal" and (
        semantics.get("requires_settlement_basis") is not True
        or semantics.get("settlement_basis_id") is None
    ):
        raise MarketLifecycleRejection("settlement_basis_missing")


def _semantic_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise MarketLifecycleRejection("semantic_clock_invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as error:
        raise MarketLifecycleRejection("semantic_clock_invalid") from error
