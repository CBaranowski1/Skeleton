"""Deterministic Phase 9 orchestration around authenticated opaque results.

Family economics intentionally do not live here.  The engine owns only lawful
event ordering, availability rechecks, counter identity, and transition hashing.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Mapping

from .canonical import canonicalize
from .simulation_clock import CounterStream, total_event_key, typed_digest
from .simulation_contracts import AllInputsRightsExcluded, SimulationContractValue
from .simulation_inputs import (
    ResolvedSimulationEvent,
    ResolvedSimulationInputs,
    SimulationInputRejection,
)
from .simulation_models import (
    FamilyModelRegistry,
    FamilySimulationRequest,
    FamilySimulationResult,
)


_OPAQUE_TOKEN = object()
_RESULT_SET_TOKEN = object()
_ZERO = "0" * 64


@dataclass(slots=True)
class SimulationEngineRejection(ValueError):
    code: str
    redacted: bool = True

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise SimulationEngineRejection(code)


def _time_key(value: str) -> int:
    probe = type(
        "_ClockProbe",
        (),
        {
            "available_at": value,
            "effective_at": value,
            "explicit_sequence": 0,
            "event_class": "market_observation",
            "artifact_id": _ZERO,
        },
    )()
    return total_event_key(probe)[0]


@dataclass(frozen=True, slots=True, init=False)
class OpaqueModelResult:
    contract_identity: str
    canonical_sha256: str
    canonical_bytes: bytes

    def __init__(
        self,
        contract_identity: str,
        canonical_sha256: str,
        canonical_bytes: bytes | None = None,
        *,
        _token: object | None = None,
    ) -> None:
        if _token is not _OPAQUE_TOKEN:
            raise TypeError("authenticated SimulationContractValue required")
        object.__setattr__(self, "contract_identity", contract_identity)
        object.__setattr__(self, "canonical_sha256", canonical_sha256)
        object.__setattr__(self, "canonical_bytes", bytes(canonical_bytes or b""))

    @classmethod
    def from_contract(cls, contract: SimulationContractValue) -> "OpaqueModelResult":
        if not isinstance(contract, SimulationContractValue):
            raise TypeError("authenticated SimulationContractValue required")
        if contract.schema_id != "https://schemas.skeleton.local/v1/simulation-artifact.schema.json":
            _reject("opaque_result_schema_invalid")
        if contract.value.get("artifact_type") not in {
            "simulation_state",
            "simulation_cost",
            "simulation_label",
        }:
            _reject("opaque_result_type_invalid")
        return cls(
            contract.identity,
            contract.canonical_sha256,
            contract.canonical_bytes,
            _token=_OPAQUE_TOKEN,
        )


@dataclass(frozen=True, slots=True, init=False)
class OpaqueResultSet:
    results: Mapping[str, OpaqueModelResult]

    def __init__(self, results: Mapping[str, OpaqueModelResult], token: object) -> None:
        if token is not _RESULT_SET_TOKEN:
            raise TypeError("OpaqueResultSet requires authenticated results")
        if any(
            not isinstance(key, str) or not isinstance(value, OpaqueModelResult)
            for key, value in results.items()
        ):
            raise TypeError("OpaqueResultSet requires authenticated results")
        object.__setattr__(self, "results", MappingProxyType(dict(sorted(results.items()))))

    @classmethod
    def from_results(cls, results: Mapping[str, OpaqueModelResult]) -> "OpaqueResultSet":
        return cls(results, _RESULT_SET_TOKEN)

    @classmethod
    def empty(cls) -> "OpaqueResultSet":
        return cls({}, _RESULT_SET_TOKEN)


@dataclass(frozen=True, slots=True)
class SimulationTransition:
    transition_id: str
    ordinal: int
    event_id: str
    prior_transition_id: str | None
    simulated_at: str
    pre_state_hash: str
    decision_hash: str
    fill_hashes: tuple[str, ...]
    cost_hashes: tuple[str, ...]
    label_hash: str
    post_state_hash: str
    draw_ids: tuple[str, ...]
    model_profile_id: str
    engine_version: str
    ordering_policy_version: str
    canonical_bytes: bytes


@dataclass(frozen=True, slots=True)
class SimulationTrace:
    manifest_id: str
    transition_count: int
    transitions: tuple[SimulationTransition, ...]
    trace_root: str
    candidate_inputs: tuple[str, ...]
    admitted_inputs: tuple[str, ...]
    rights_excluded_inputs: tuple[str, ...]
    upstream_pre_sha256: str
    upstream_post_sha256: str
    canonical_bytes: bytes
    family_results: tuple[FamilySimulationResult, ...] = ()


class SimulationEngine:
    """Availability-first deterministic trace orchestration."""

    __slots__ = ()

    @staticmethod
    def _verify_resolution(resolved: ResolvedSimulationInputs) -> None:
        if not isinstance(resolved, ResolvedSimulationInputs):
            raise TypeError("ResolvedSimulationInputs required")
        try:
            resolved.verify_capability()
        except SimulationInputRejection as error:
            raise SimulationEngineRejection("resolution_capability_invalid") from error

    def run(
        self,
        resolved: ResolvedSimulationInputs,
        opaque_results: OpaqueResultSet,
    ) -> SimulationTrace | AllInputsRightsExcluded:
        """Contained legacy tracer seam retained for the Phase 09-04 harness."""

        self._verify_resolution(resolved)
        return self._run_trace(resolved, opaque_results, None)

    def run_family_models(
        self,
        resolved: ResolvedSimulationInputs,
        requests: Mapping[str, FamilySimulationRequest],
        registry: FamilyModelRegistry,
    ) -> SimulationTrace | AllInputsRightsExcluded:
        """Production path: rights-safe events dispatch through the closed registry."""

        self._verify_resolution(resolved)
        if not isinstance(requests, Mapping):
            raise TypeError("family request mapping required")
        if not isinstance(registry, FamilyModelRegistry):
            raise TypeError("FamilyModelRegistry required")
        excluded = set(resolved.rights_excluded_inputs)
        if set(requests) & excluded:
            _reject("excluded_dispatch_forbidden")
        if resolved.resolution_status == "all_excluded":
            if requests:
                _reject("all_excluded_dispatch_forbidden")
            return self._run_trace(resolved, OpaqueResultSet.empty(), None)
        event_by_id = {event.event_id: event for event in resolved.events}
        if set(requests) != set(event_by_id):
            _reject("family_request_inventory_mismatch")
        opaques: dict[str, OpaqueModelResult] = {}
        results: dict[str, FamilySimulationResult] = {}
        for event_id in sorted(event_by_id):
            request = requests[event_id]
            event = event_by_id[event_id]
            if (
                request.event != event
                or request.event.canonical_bytes != event.canonical_bytes
                or request.resolution_capability_sha256
                != resolved.resolution_capability_sha256
            ):
                _reject("family_request_event_mismatch")
            result = registry.evaluate(request)
            results[event_id] = result
            opaques[event_id] = OpaqueModelResult(
                result.canonical_sha256,
                result.canonical_sha256,
                result.canonical_bytes,
                _token=_OPAQUE_TOKEN,
            )
        return self._run_trace(resolved, OpaqueResultSet.from_results(opaques), results)

    def _run_trace(
        self,
        resolved: ResolvedSimulationInputs,
        opaque_results: OpaqueResultSet,
        family_results: Mapping[str, FamilySimulationResult] | None,
    ) -> SimulationTrace | AllInputsRightsExcluded:
        if not isinstance(resolved, ResolvedSimulationInputs):
            raise TypeError("ResolvedSimulationInputs required")
        self._verify_resolution(resolved)
        if not isinstance(opaque_results, OpaqueResultSet):
            raise TypeError("OpaqueResultSet required")
        if resolved.upstream_pre_sha256 != resolved.upstream_post_sha256:
            _reject("upstream_mutation_detected")
        if resolved.resolution_status == "all_excluded":
            if resolved.all_excluded is None or resolved.events or resolved.admitted_inputs:
                _reject("all_excluded_claim_invalid")
            if opaque_results.results:
                _reject("all_excluded_opaque_result_forbidden")
            return resolved.all_excluded
        if resolved.all_excluded is not None or not resolved.events:
            _reject("resolved_event_inventory_invalid")
        event_ids = {event.event_id for event in resolved.events}
        if set(opaque_results.results) != event_ids:
            _reject("opaque_result_inventory_mismatch")
        evaluation_key = _time_key(resolved.evaluation_at)
        ordered = tuple(sorted(resolved.events, key=total_event_key))
        counter = CounterStream(
            algorithm=resolved.counter_algorithm,
            manifest_id=resolved.manifest_id,
            seed=resolved.seed,
            namespaces=("transition",),
        )
        transitions: list[SimulationTransition] = []
        prior_transition_id: str | None = None
        pre_state_hash = typed_digest(
            "SKELETON_SIMULATION_PRE_STATE_V1",
            canonicalize(
                {
                    "manifest_id": resolved.manifest_id,
                    "state": "initial",
                }
            ),
        )
        for ordinal, event in enumerate(ordered):
            # The same availability gate is deliberately repeated at each
            # consumption seam so later economic integrations cannot bypass it.
            for _seam in ("decision", "arrival", "result", "settlement", "label"):
                if total_event_key(event)[0] > evaluation_key:
                    _reject("observation_future_available")
            opaque = opaque_results.results[event.event_id]
            family_result = None if family_results is None else family_results[event.event_id]
            draw = counter.draw("transition", ordinal, upper_bound=2**63 - 1)
            decision_hash = typed_digest(
                "SKELETON_SIMULATION_DECISION_V1",
                canonicalize(
                    {
                        "event_artifact_id": event.artifact_id,
                        "opaque_contract_identity": opaque.contract_identity,
                        "opaque_sha256": opaque.canonical_sha256,
                        "family": event.family,
                    }
                ),
            )
            fill_hashes = ()
            cost_hashes = ()
            if family_result is not None:
                fill_hashes = (
                    typed_digest(
                        "SKELETON_SIMULATION_FILL_V1",
                        canonicalize(
                            {
                                "event_id": event.event_id,
                                "fill_state": family_result.fill_state,
                                "filled_quantity": family_result.filled_quantity,
                                "native_unit": family_result.native_unit,
                                "price": family_result.price.lexical,
                            }
                        ),
                    ),
                )
                cost_hashes = tuple(item.canonical_sha256 for item in family_result.costs)
            label_hash = typed_digest(
                "SKELETON_SIMULATION_LABEL_V1",
                canonicalize(
                    {
                        "event_id": event.event_id,
                        "state": (
                            "opaque_unresolved"
                            if family_result is None
                            else family_result.settlement_state
                        ),
                        "successful": (
                            None if family_result is None else family_result.successful
                        ),
                    }
                ),
            )
            post_state_hash = typed_digest(
                "SKELETON_SIMULATION_POST_STATE_V1",
                canonicalize(
                    {
                        "decision_hash": decision_hash,
                        "draw_id": draw.draw_id,
                        "event_id": event.event_id,
                        "fill_hashes": list(fill_hashes),
                        "cost_hashes": list(cost_hashes),
                        "pre_state_hash": pre_state_hash,
                    }
                ),
            )
            body = {
                "ordinal": ordinal,
                "event_id": event.event_id,
                "prior_transition_id": prior_transition_id,
                "simulated_at": event.available_at,
                "pre_state_hash": pre_state_hash,
                "decision_hash": decision_hash,
                "fill_hashes": list(fill_hashes),
                "cost_hashes": list(cost_hashes),
                "label_hash": label_hash,
                "post_state_hash": post_state_hash,
                "draw_ids": [draw.draw_id],
                "model_profile_id": (
                    resolved.model_profile_ids[0]
                    if family_result is None
                    else family_result.model_profile_id
                ),
                "engine_version": resolved.engine_version,
                "ordering_policy_version": resolved.ordering_policy_version,
            }
            raw = canonicalize(body)
            transition_id = typed_digest("SKELETON_SIMULATION_TRANSITION_V1", raw)
            transitions.append(
                SimulationTransition(
                    transition_id=transition_id,
                    ordinal=ordinal,
                    event_id=event.event_id,
                    prior_transition_id=prior_transition_id,
                    simulated_at=event.available_at,
                    pre_state_hash=pre_state_hash,
                    decision_hash=decision_hash,
                    fill_hashes=fill_hashes,
                    cost_hashes=cost_hashes,
                    label_hash=label_hash,
                    post_state_hash=post_state_hash,
                    draw_ids=(draw.draw_id,),
                    model_profile_id=(
                        resolved.model_profile_ids[0]
                        if family_result is None
                        else family_result.model_profile_id
                    ),
                    engine_version=resolved.engine_version,
                    ordering_policy_version=resolved.ordering_policy_version,
                    canonical_bytes=raw,
                )
            )
            prior_transition_id = transition_id
            pre_state_hash = post_state_hash
        trace_value = {
            "candidate_inputs": list(resolved.candidate_inputs),
            "manifest_id": resolved.manifest_id,
            "rights_excluded_inputs": list(resolved.rights_excluded_inputs),
            "transition_ids": [item.transition_id for item in transitions],
            "upstream_post_sha256": resolved.upstream_post_sha256,
            "upstream_pre_sha256": resolved.upstream_pre_sha256,
        }
        raw = canonicalize(trace_value)
        root = typed_digest("SKELETON_SIMULATION_TRACE_V1", raw)
        return SimulationTrace(
            manifest_id=resolved.manifest_id,
            transition_count=len(transitions),
            transitions=tuple(transitions),
            trace_root=root,
            candidate_inputs=resolved.candidate_inputs,
            admitted_inputs=resolved.admitted_inputs,
            rights_excluded_inputs=resolved.rights_excluded_inputs,
            upstream_pre_sha256=resolved.upstream_pre_sha256,
            upstream_post_sha256=resolved.upstream_post_sha256,
            canonical_bytes=raw,
            family_results=(
                ()
                if family_results is None
                else tuple(family_results[event.event_id] for event in ordered)
            ),
        )


def deterministic_case_roots(
    *, manifest_id: str, seed: str, count: int
) -> tuple[str, ...]:
    """Generate the frozen differential/property corpus without ambient state."""

    if type(count) is not int or count != 512:
        _reject("generated_case_count_invalid")
    stream = CounterStream(
        algorithm="sha256_counter_v1",
        manifest_id=manifest_id,
        seed=seed,
        namespaces=("generated_case",),
    )
    roots = []
    for index in range(count):
        draw = stream.draw("generated_case", index, upper_bound=2**63 - 1)
        roots.append(
            typed_digest(
                "SKELETON_SIMULATION_GENERATED_CASE_V1",
                canonicalize(
                    {
                        "draw_id": draw.draw_id,
                        "index": index,
                        "manifest_id": manifest_id,
                        "seed": seed,
                    }
                ),
            )
        )
    return tuple(roots)


__all__ = [
    "OpaqueModelResult",
    "OpaqueResultSet",
    "SimulationEngine",
    "SimulationEngineRejection",
    "SimulationTrace",
    "SimulationTransition",
    "deterministic_case_roots",
]
