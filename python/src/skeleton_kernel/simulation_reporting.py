"""Canonical complete-disclosure reports for deterministic simulation.

Reports are projections of authenticated input resolution and an executed trace.
They accept no caller counts, labels, conclusions, economic values, or exclusions.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping

from .canonical import canonicalize, parse_raw_json
from .simulation_contracts import (
    ARTIFACT_SCHEMA_ID,
    MANIFEST_SCHEMA_ID,
    REPORT_SCHEMA_ID,
    AllInputsRightsExcluded,
    SimulationContractPublication,
    SimulationContractValue,
    compute_document_identity,
)
from .simulation_engine import SimulationTrace
from .simulation_inputs import ResolvedSimulationInputs
from .simulation_models import FamilySimulationResult
from .simulation_store import PersistedRunAncestry, SimulationStore


@dataclass(slots=True)
class SimulationReportingRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise SimulationReportingRejection(code)


def _sorted_strings(*inventories: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    values = tuple(item for inventory in inventories for item in inventory)
    if any(not isinstance(item, str) or not item for item in values):
        _reject("report_inventory_invalid")
    return tuple(sorted(set(values)))


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class SimulationReport:
    contract: SimulationContractValue
    family_results: tuple[FamilySimulationResult, ...]
    resolved: ResolvedSimulationInputs
    trace: SimulationTrace | None

    @property
    def report_id(self) -> str:
        return self.contract.identity

    @property
    def canonical_bytes(self) -> bytes:
        return self.contract.canonical_bytes

    @property
    def status(self) -> str:
        return str(self.contract.value["status"])

    @property
    def persistence_payload(self) -> dict[str, object]:
        value = _json_value(self.contract.value)
        if not isinstance(value, dict):
            _reject("report_payload_invalid")
        return value


class SimulationReporter:
    """Build one immutable report from complete authenticated runtime evidence."""

    __slots__ = ("_publication",)

    def __init__(self, publication: SimulationContractPublication) -> None:
        if not isinstance(publication, SimulationContractPublication):
            raise TypeError("SimulationContractPublication required")
        self._publication = publication

    def build_from_submitted(self, *, candidate_inputs: object) -> None:
        if candidate_inputs is None:
            _reject("simulation_events_null")
        if isinstance(candidate_inputs, (tuple, list)) and not candidate_inputs:
            _reject("simulation_event_stream_empty")
        _reject("simulation_manifest_required")

    def build(
        self,
        *,
        manifest: SimulationContractValue,
        resolved: ResolvedSimulationInputs,
        outcome: SimulationTrace | AllInputsRightsExcluded,
        calibration: SimulationContractValue | None = None,
        ancestry: PersistedRunAncestry | None = None,
    ) -> SimulationReport:
        if (
            not isinstance(manifest, SimulationContractValue)
            or manifest.schema_id != MANIFEST_SCHEMA_ID
        ):
            _reject("simulation_manifest_required")
        if not isinstance(resolved, ResolvedSimulationInputs):
            raise TypeError("ResolvedSimulationInputs required")
        self._validate_resolution(manifest, resolved)
        if resolved.upstream_pre_sha256 != resolved.upstream_post_sha256:
            _reject("upstream_mutation_detected")
        if not resolved.candidate_inputs:
            _reject("simulation_event_stream_empty")
        if set(resolved.admitted_inputs) & set(resolved.rights_excluded_inputs):
            _reject("resolution_inventory_overlap")
        if set(resolved.candidate_inputs) != (
            set(resolved.admitted_inputs) | set(resolved.rights_excluded_inputs)
        ):
            _reject("resolution_inventory_invalid")
        if resolved.candidate_inputs != tuple(sorted(resolved.candidate_inputs)):
            _reject("report_inventory_order_invalid")

        if isinstance(outcome, AllInputsRightsExcluded):
            return self._build_all_excluded(resolved, outcome, calibration, ancestry)
        if not isinstance(outcome, SimulationTrace):
            raise TypeError("SimulationTrace or AllInputsRightsExcluded required")
        return self._build_trace_report(resolved, outcome, calibration, ancestry)

    @staticmethod
    def _validate_resolution(
        manifest: SimulationContractValue,
        resolved: ResolvedSimulationInputs,
    ) -> None:
        candidates = tuple(
            sorted(str(item["candidate_id"]) for item in manifest.value["candidate_inputs"])
        )
        try:
            value = parse_raw_json(resolved.canonical_bytes)
        except Exception as error:
            raise SimulationReportingRejection("resolution_evidence_invalid") from error
        expected = {
            "schema_version": "skeleton.simulation-artifact.v1",
            "artifact_type": "simulation_input_resolution",
            "artifact_id": resolved.artifact_id,
            "manifest_id": resolved.manifest_id,
            "candidate_inputs": list(resolved.candidate_inputs),
            "admitted_inputs": list(resolved.admitted_inputs),
            "rights_excluded_inputs": list(resolved.rights_excluded_inputs),
            "resolution_status": resolved.resolution_status,
        }
        if (
            manifest.identity != resolved.manifest_id
            or candidates != resolved.candidate_inputs
            or value != expected
            or canonicalize(value) != resolved.canonical_bytes
            or compute_document_identity(ARTIFACT_SCHEMA_ID, value) != resolved.artifact_id
        ):
            _reject("resolution_evidence_invalid")
        for exclusion in resolved.exclusions:
            try:
                exclusion_value = parse_raw_json(exclusion.canonical_bytes)
            except Exception as error:
                raise SimulationReportingRejection("rights_exclusion_evidence_invalid") from error
            expected_exclusion = {
                "schema_version": "skeleton.simulation-artifact.v1",
                "artifact_type": "simulation_rights_exclusion",
                "artifact_id": exclusion.artifact_id,
                "manifest_id": resolved.manifest_id,
                "candidate_id": exclusion.candidate_id,
                "request_id": exclusion.request_id,
                "rights_record_id": exclusion.rights_record_id,
                "legal_terms_id": exclusion.legal_terms_id,
                "reason_code": exclusion.reason_code,
            }
            if (
                exclusion_value != expected_exclusion
                or canonicalize(exclusion_value) != exclusion.canonical_bytes
                or compute_document_identity(ARTIFACT_SCHEMA_ID, exclusion_value)
                != exclusion.artifact_id
            ):
                _reject("rights_exclusion_evidence_invalid")

    def _build_all_excluded(
        self,
        resolved: ResolvedSimulationInputs,
        outcome: AllInputsRightsExcluded,
        calibration: SimulationContractValue | None,
        ancestry: PersistedRunAncestry | None,
    ) -> SimulationReport:
        if calibration is not None or ancestry is not None:
            _reject("all_excluded_reference_forbidden")
        if (
            resolved.resolution_status != "all_excluded"
            or resolved.events
            or resolved.admitted_inputs
            or resolved.all_excluded is not outcome
            or outcome.candidate_inputs != resolved.candidate_inputs
            or outcome.rights_excluded_inputs != resolved.rights_excluded_inputs
            or len(resolved.exclusions) != len(resolved.rights_excluded_inputs)
        ):
            _reject("all_excluded_claim_invalid")
        value = self._base_value(resolved)
        value.update(
            {
                "status": "simulation_all_inputs_rights_excluded",
                "successful": False,
                "calibration_eligible": False,
                "calibration_id": None,
                "trace_root": None,
                "events": [],
                "fills": [],
                "costs": [],
                "settlements": [],
                "success_labels": [],
                "missing_evidence": sorted(item.artifact_id for item in resolved.exclusions),
                "unresolved_outcomes": [],
                "assumptions": [],
                "sensitivities": [],
                "clocks": [],
                "currencies": [],
                "collateral_bases": [],
                "payoff_units": [],
                "abstain_reasons": sorted(
                    {"all_inputs_rights_excluded"}
                    | {item.reason_code for item in resolved.exclusions}
                ),
                "no_fill_reasons": [],
                "rollback_reasons": [],
                "corrections": [],
            }
        )
        return self._seal(value, (), resolved, None)

    def _build_trace_report(
        self,
        resolved: ResolvedSimulationInputs,
        trace: SimulationTrace,
        calibration: SimulationContractValue | None,
        ancestry: PersistedRunAncestry | None,
    ) -> SimulationReport:
        if resolved.resolution_status == "all_excluded" or resolved.all_excluded is not None:
            _reject("all_excluded_trace_forbidden")
        if (
            trace.manifest_id != resolved.manifest_id
            or trace.candidate_inputs != resolved.candidate_inputs
            or trace.admitted_inputs != resolved.admitted_inputs
            or trace.rights_excluded_inputs != resolved.rights_excluded_inputs
            or trace.upstream_pre_sha256 != resolved.upstream_pre_sha256
            or trace.upstream_post_sha256 != resolved.upstream_post_sha256
            or trace.transition_count != len(trace.transitions)
            or not trace.transitions
        ):
            _reject("report_trace_mismatch")
        self._validate_trace_bytes(trace)
        results = trace.family_results
        if len(results) != len(trace.transitions) or len(results) != len(resolved.events):
            _reject("report_family_result_inventory_invalid")
        event_by_id = {item.event_id: item for item in resolved.events}
        result_by_id = {item.event_id: item for item in results}
        transition_by_id = {item.event_id: item for item in trace.transitions}
        if (
            len(event_by_id) != len(resolved.events)
            or len(result_by_id) != len(results)
            or set(event_by_id) != set(result_by_id)
            or set(event_by_id) != set(transition_by_id)
        ):
            _reject("report_family_result_inventory_invalid")
        for result in results:
            self._validate_family_result(result)
            event = event_by_id[result.event_id]
            if event.family != result.family:
                _reject("report_family_result_mismatch")

        statuses = {item.lifecycle_state for item in results}
        if "rolled_back" in statuses:
            status = "rolled_back"
        elif "abstained" in statuses:
            status = "abstained"
        elif any(
            item.successful is None
            or item.settlement_state in {"unresolved", "corrected"}
            or item.lifecycle_state == "incompatible"
            for item in results
        ):
            status = "unresolved"
        else:
            status = "completed"
        successful = all(item.successful is True for item in results)
        calibration_eligible = status == "completed"
        calibration_id = self._calibration_id(
            calibration, resolved.manifest_id, calibration_eligible
        )
        correction_ids: list[str] = [
            item.canonical_sha256 for item in results if item.disruption == "correction"
        ]
        if ancestry is not None:
            if not isinstance(ancestry, PersistedRunAncestry):
                raise TypeError("PersistedRunAncestry required")
            self._validate_ancestry(ancestry)
            correction_ids.append(ancestry.canonical_sha256)

        costs = [cost for result in results for cost in result.costs]
        value = self._base_value(resolved)
        value.update(
            {
                "status": status,
                "successful": successful,
                "calibration_eligible": calibration_eligible,
                "calibration_id": calibration_id,
                "trace_root": trace.trace_root,
                "events": sorted(item.artifact_id for item in resolved.events),
                "fills": sorted(
                    transition_by_id[item.event_id].fill_hashes[0]
                    for item in results
                    if item.filled_quantity > 0
                ),
                "costs": sorted({item.canonical_sha256 for item in costs}),
                "settlements": sorted(
                    {
                    evidence_id
                    for item in results
                    for evidence_id in item.settlement_evidence_ids
                    }
                ),
                "success_labels": sorted(
                    transition_by_id[item.event_id].label_hash
                    for item in results
                    if item.successful is True
                ),
                "missing_evidence": sorted(
                    [item.artifact_id for item in resolved.exclusions]
                    + [
                        item.canonical_sha256
                        for item in costs
                        if item.disposition == "unresolved"
                    ]
                ),
                "unresolved_outcomes": sorted(
                    item.canonical_sha256 for item in results if item.successful is None
                ),
                "assumptions": sorted(
                    {
                        "arithmetic:canonical_fixed_decimal",
                        f"engine:{resolved.engine_version}",
                        f"ordering:{resolved.ordering_policy_version}",
                    }
                    | {
                        f"native:{item.family}:{item.native_clock}:{item.native_unit}:"
                        f"{item.currency}:{item.collateral}:{item.payoff_unit}"
                        for item in results
                    }
                ),
                "sensitivities": sorted(
                    {f"{item.family}:{item.scenario}" for item in results}
                ),
                "clocks": sorted(
                    {f"{item.family}:{item.native_clock}" for item in results}
                ),
                "currencies": sorted({item.currency for item in results}),
                "collateral_bases": sorted(
                    {f"{item.family}:{item.collateral}" for item in results}
                ),
                "payoff_units": sorted(
                    {f"{item.family}:{item.payoff_unit}" for item in results}
                ),
                "abstain_reasons": sorted(
                    {item.reason_code for item in resolved.exclusions}
                    | {
                        item.reason_code
                        for item in results
                        if item.lifecycle_state in {"abstained", "incompatible"}
                        and item.reason_code is not None
                    }
                ),
                "no_fill_reasons": sorted(
                    {
                        item.reason_code or "no_fill"
                        for item in results
                        if item.fill_state == "no_fill"
                    }
                ),
                "rollback_reasons": sorted(
                    {
                        item.reason_code or "rollback"
                        for item in results
                        if item.lifecycle_state == "rolled_back"
                    }
                ),
                "corrections": sorted(set(correction_ids)),
            }
        )
        return self._seal(
            value,
            tuple(sorted(results, key=lambda item: item.event_id)),
            resolved,
            trace,
        )

    @staticmethod
    def _validate_trace_bytes(trace: SimulationTrace) -> None:
        try:
            value = parse_raw_json(trace.canonical_bytes)
        except Exception as error:
            raise SimulationReportingRejection("report_trace_evidence_invalid") from error
        expected = {
            "candidate_inputs": list(trace.candidate_inputs),
            "manifest_id": trace.manifest_id,
            "rights_excluded_inputs": list(trace.rights_excluded_inputs),
            "transition_ids": [item.transition_id for item in trace.transitions],
            "upstream_post_sha256": trace.upstream_post_sha256,
            "upstream_pre_sha256": trace.upstream_pre_sha256,
        }
        if (
            value != expected
            or canonicalize(value) != trace.canonical_bytes
            or SimulationStore.trace_identity(trace.canonical_bytes) != trace.trace_root
        ):
            _reject("report_trace_evidence_invalid")
        prior = None
        for ordinal, item in enumerate(trace.transitions):
            try:
                transition_value = parse_raw_json(item.canonical_bytes)
            except Exception as error:
                raise SimulationReportingRejection("report_transition_evidence_invalid") from error
            expected_transition = {
                "ordinal": item.ordinal,
                "event_id": item.event_id,
                "prior_transition_id": item.prior_transition_id,
                "simulated_at": item.simulated_at,
                "pre_state_hash": item.pre_state_hash,
                "decision_hash": item.decision_hash,
                "fill_hashes": list(item.fill_hashes),
                "cost_hashes": list(item.cost_hashes),
                "label_hash": item.label_hash,
                "post_state_hash": item.post_state_hash,
                "draw_ids": list(item.draw_ids),
                "model_profile_id": item.model_profile_id,
                "engine_version": item.engine_version,
                "ordering_policy_version": item.ordering_policy_version,
            }
            if (
                item.ordinal != ordinal
                or item.prior_transition_id != prior
                or transition_value != expected_transition
                or canonicalize(transition_value) != item.canonical_bytes
                or SimulationStore.transition_identity(item.canonical_bytes)
                != item.transition_id
            ):
                _reject("report_transition_evidence_invalid")
            prior = item.transition_id

    @staticmethod
    def _validate_family_result(result: FamilySimulationResult) -> None:
        costs = []
        for item in result.costs:
            cost_value = {
                "currency": item.currency,
                "dimension": item.dimension,
                "disposition": item.disposition,
                "equation_version": item.equation_version,
                "evidence_ids": list(item.evidence_ids),
                "evidence_value": (
                    None if item.evidence_value is None else item.evidence_value.lexical
                ),
                "model_identity": item.model_identity,
                "observed_price": (
                    None if item.observed_price is None else item.observed_price.lexical
                ),
                "parameter_scale": (
                    None if item.parameter_scale is None else item.parameter_scale.lexical
                ),
                "reason_code": item.reason_code,
                "unit": item.unit,
                "value": None if item.value is None else item.value.lexical,
            }
            if sha256(canonicalize(cost_value)).hexdigest() != item.canonical_sha256:
                _reject("report_cost_evidence_invalid")
            costs.append(
                {
                    "canonical_sha256": item.canonical_sha256,
                    "dimension": item.dimension,
                    "disposition": item.disposition,
                    "evidence_ids": list(item.evidence_ids),
                    "reason_code": item.reason_code,
                    "value": None if item.value is None else item.value.lexical,
                }
            )
        expected = {
            "adapter_identity": result.adapter_identity,
            "collateral": result.collateral,
            "costs": costs,
            "currency": result.currency,
            "event_id": result.event_id,
            "family": result.family,
            "fill_state": result.fill_state,
            "filled_quantity": result.filled_quantity,
            "model_profile_id": result.model_profile_id,
            "native_clock": result.native_clock,
            "native_unit": result.native_unit,
            "owner_class": result.owner_class,
            "payoff_unit": result.payoff_unit,
            "price": result.price.lexical,
            "reason_code": result.reason_code,
            "requested_quantity": result.requested_quantity,
            "scenario": result.scenario,
            "disruption": result.disruption,
            "lifecycle_state": result.lifecycle_state,
            "settlement_state": result.settlement_state,
            "settlement_evidence_ids": list(result.settlement_evidence_ids),
            "successful": result.successful,
        }
        if (
            canonicalize(expected) != result.canonical_bytes
            or sha256(result.canonical_bytes).hexdigest() != result.canonical_sha256
        ):
            _reject("report_family_result_hash_mismatch")

    @staticmethod
    def _base_value(resolved: ResolvedSimulationInputs) -> dict[str, object]:
        return {
            "schema_version": "skeleton.simulation-report.v1",
            "report_id": "0" * 64,
            "manifest_id": resolved.manifest_id,
            "candidate_inputs": list(resolved.candidate_inputs),
            "admitted_inputs": sorted(resolved.admitted_inputs),
            "rights_excluded_inputs": sorted(resolved.rights_excluded_inputs),
        }

    @staticmethod
    def _calibration_id(
        calibration: SimulationContractValue | None,
        manifest_id: str,
        eligible: bool,
    ) -> str | None:
        if calibration is None:
            return None
        if (
            not isinstance(calibration, SimulationContractValue)
            or calibration.value.get("artifact_type") != "simulation_calibration"
            or calibration.value.get("manifest_id") != manifest_id
        ):
            _reject("calibration_reference_invalid")
        if not eligible:
            _reject("calibration_reference_ineligible")
        return calibration.identity

    @staticmethod
    def _validate_ancestry(ancestry: PersistedRunAncestry) -> None:
        try:
            value = parse_raw_json(ancestry.canonical_bytes)
        except Exception as error:
            raise SimulationReportingRejection("correction_ancestry_invalid") from error
        if not isinstance(value, dict):
            _reject("correction_ancestry_invalid")
        expected = {
            "child_run_id": ancestry.child_run_id,
            "changed_input_ids": list(ancestry.changed_input_ids),
            "parent_run_id": ancestry.parent_run_id,
            "superseded_report_id": ancestry.superseded_report_id,
        }
        if (
            value != expected
            or canonicalize(value) != ancestry.canonical_bytes
            or ancestry.child_run_id == ancestry.parent_run_id
            or not ancestry.changed_input_ids
            or ancestry.changed_input_ids != tuple(sorted(ancestry.changed_input_ids))
            or len(set(ancestry.changed_input_ids)) != len(ancestry.changed_input_ids)
            or SimulationStore.ancestry_identity(ancestry.canonical_bytes)
            != ancestry.canonical_sha256
        ):
            _reject("correction_ancestry_invalid")

    def _seal(
        self,
        value: dict[str, object],
        results: tuple[FamilySimulationResult, ...],
        resolved: ResolvedSimulationInputs,
        trace: SimulationTrace | None,
    ) -> SimulationReport:
        value["report_id"] = compute_document_identity(REPORT_SCHEMA_ID, value)
        contract = self._publication.validate_contract(canonicalize(value), REPORT_SCHEMA_ID)
        return SimulationReport(
            contract=contract,
            family_results=results,
            resolved=resolved,
            trace=trace,
        )


__all__ = [
    "SimulationReport",
    "SimulationReporter",
    "SimulationReportingRejection",
]
