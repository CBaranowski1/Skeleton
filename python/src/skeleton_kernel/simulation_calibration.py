"""Rights-bound immutable calibration descendants for Phase 9 fixtures."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import re
from typing import Mapping, Sequence

from .canonical import canonicalize, parse_raw_json
from .market_values import CanonicalDecimal, MarketValueRejection
from .simulation_capabilities import (
    SimulationCapabilityRejection,
    verify_authority_envelope,
)
from .simulation_contracts import (
    ARTIFACT_SCHEMA_ID,
    MANIFEST_SCHEMA_ID,
    SimulationContractPublication,
    SimulationContractValue,
    compute_document_identity,
)
from .simulation_inputs import (
    SealedEvidenceView,
    SimulationInputResolver,
)
from .simulation_store import SimulationStore, SimulationStoreRejection


_OBSERVATION_TOKEN = object()
_OBSERVATION_DOMAIN = "SKELETON_PHASE09_CALIBRATION_OBSERVATION_V1"
_DELTA_DOMAIN = "SKELETON_PHASE09_CALIBRATION_PARAMETER_DELTA_V1"
_DIAGNOSTICS_DOMAIN = "SKELETON_PHASE09_CALIBRATION_DIAGNOSTICS_V1"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_FIXTURE_FAMILIES = {
    "calibration-contingent-contract-admitted": "contingent_contract",
    "calibration-future-admitted": "future",
    "calibration-listed-cash-equity-admitted": "listed_cash_equity",
    "calibration-listed-option-admitted": "listed_option",
    "calibration-sports-event-contract-admitted": "sports_event_contract",
}


@dataclass(slots=True)
class SimulationCalibrationRejection(ValueError):
    code: str

    def __str__(self) -> str:
        return self.code


def _reject(code: str) -> None:
    raise SimulationCalibrationRejection(code)


def _framed_digest(domain: str, payload: bytes) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    return sha256(
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _hash(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _time(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SimulationCalibrationRejection(code) from error
    if parsed.tzinfo != UTC:
        _reject(code)
    return parsed


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True, init=False)
class CalibrationObservation:
    observation_id: str
    candidate_id: str
    source_evidence_sha256: str
    family: str
    available_at: str
    parameter_name: str
    model_value: CanonicalDecimal
    observed_value: CanonicalDecimal
    unit: str
    canonical_bytes: bytes
    source_run_id: str
    source_report_id: str
    source_semantic_path: str
    authority_envelope: bytes

    def __init__(self, value: Mapping[str, object], raw: bytes, token: object) -> None:
        if token is not _OBSERVATION_TOKEN:
            raise TypeError("CalibrationObservation requires canonical bytes")
        required = {
            "observation_id",
            "candidate_id",
            "source_evidence_sha256",
            "family",
            "available_at",
            "parameter_name",
            "model_value",
            "observed_value",
            "unit",
            "source_run_id",
            "source_report_id",
            "source_semantic_path",
        }
        if set(value) != required:
            _reject("calibration_observation_shape_invalid")
        observed_id = _hash(
            value.get("observation_id"), "calibration_observation_identity_invalid"
        )
        if observed_id != self.compute_identity(value):
            _reject("calibration_observation_identity_invalid")
        candidate_id = _hash(
            value.get("candidate_id"), "calibration_observation_candidate_invalid"
        )
        source_id = _hash(
            value.get("source_evidence_sha256"),
            "calibration_observation_source_invalid",
        )
        source_run_id = _hash(
            value.get("source_run_id"), "calibration_source_run_invalid"
        )
        source_report_id = _hash(
            value.get("source_report_id"), "calibration_source_report_invalid"
        )
        source_semantic_path = value.get("source_semantic_path")
        family = value.get("family")
        parameter = value.get("parameter_name")
        unit = value.get("unit")
        if (
            family not in set(_FIXTURE_FAMILIES.values())
            or not isinstance(parameter, str)
            or _IDENTIFIER.fullmatch(parameter) is None
            or not isinstance(unit, str)
            or _IDENTIFIER.fullmatch(unit) is None
            or not isinstance(source_semantic_path, str)
            or re.fullmatch(r"/[a-z][a-z0-9_/-]{0,255}", source_semantic_path)
            is None
        ):
            _reject("calibration_observation_dimension_invalid")
        _time(value.get("available_at"), "calibration_observation_time_invalid")
        try:
            model = CanonicalDecimal(str(value.get("model_value")))
            observed = CanonicalDecimal(str(value.get("observed_value")))
        except MarketValueRejection as error:
            raise SimulationCalibrationRejection(
                "calibration_observation_decimal_invalid"
            ) from error
        object.__setattr__(self, "observation_id", observed_id)
        object.__setattr__(self, "candidate_id", candidate_id)
        object.__setattr__(self, "source_evidence_sha256", source_id)
        object.__setattr__(self, "family", str(family))
        object.__setattr__(self, "available_at", str(value["available_at"]))
        object.__setattr__(self, "parameter_name", parameter)
        object.__setattr__(self, "model_value", model)
        object.__setattr__(self, "observed_value", observed)
        object.__setattr__(self, "unit", unit)
        object.__setattr__(self, "canonical_bytes", bytes(raw))
        object.__setattr__(self, "source_run_id", source_run_id)
        object.__setattr__(self, "source_report_id", source_report_id)
        object.__setattr__(self, "source_semantic_path", source_semantic_path)
        object.__setattr__(self, "authority_envelope", b"")

    @staticmethod
    def compute_identity(value: Mapping[str, object]) -> str:
        body = dict(value)
        body.pop("observation_id", None)
        return _framed_digest(_OBSERVATION_DOMAIN, canonicalize(body))

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> "CalibrationObservation":
        del raw
        _reject("calibration_observation_authority_required")

    @classmethod
    def from_authority_envelope(cls, raw: bytes) -> "CalibrationObservation":
        try:
            value = verify_authority_envelope(
                raw, object_class="simulation_calibration_observation"
            )
        except SimulationCapabilityRejection as error:
            raise SimulationCalibrationRejection(
                "calibration_observation_authority_invalid"
            ) from error
        canonical_body = canonicalize(value)
        observed = cls(value, canonical_body, _OBSERVATION_TOKEN)
        object.__setattr__(observed, "authority_envelope", bytes(raw))
        return observed


@dataclass(frozen=True, slots=True)
class CalibrationResult:
    output_profile: SimulationContractValue
    calibration: SimulationContractValue
    observation_ids: tuple[str, ...]
    rights_exclusion_ids: tuple[str, ...]
    parameter_deltas: tuple[tuple[str, str, str], ...]
    upstream_pre_sha256: str
    upstream_post_sha256: str


class SimulationCalibrationService:
    """Create one immutable model descendant from lawful admitted observations."""

    __slots__ = ("_publication", "_store")

    def __init__(
        self,
        publication: SimulationContractPublication,
        store: SimulationStore,
    ) -> None:
        if not isinstance(publication, SimulationContractPublication):
            raise TypeError("authenticated SimulationContractPublication required")
        if not isinstance(store, SimulationStore):
            raise TypeError("SimulationStore required")
        self._publication = publication
        self._store = store

    def calibrate(
        self,
        *,
        fixture_id: str,
        manifest: SimulationContractValue,
        view: SealedEvidenceView,
        prior_profile: SimulationContractValue,
        observations: Sequence[CalibrationObservation] | None,
        algorithm_id: str,
        code_sha256: str,
    ) -> CalibrationResult:
        if observations is None:
            _reject("calibration_observations_null")
        if not isinstance(observations, tuple) or not observations:
            _reject("calibration_observations_empty")
        if any(not isinstance(item, CalibrationObservation) for item in observations):
            _reject("calibration_observation_required")
        if (
            not isinstance(manifest, SimulationContractValue)
            or manifest.schema_id != MANIFEST_SCHEMA_ID
        ):
            _reject("calibration_manifest_required")
        if not isinstance(view, SealedEvidenceView) or view.publication is not self._publication:
            _reject("calibration_fixture_manifest_unauthenticated")
        if (
            not isinstance(prior_profile, SimulationContractValue)
            or prior_profile.schema_id != ARTIFACT_SCHEMA_ID
            or prior_profile.value.get("artifact_type") != "simulation_model_profile"
        ):
            _reject("calibration_prior_profile_required")
        family = _FIXTURE_FAMILIES.get(fixture_id)
        if family is None or prior_profile.value.get("family") != family:
            _reject("calibration_fixture_identity_mismatch")
        if not isinstance(algorithm_id, str) or _IDENTIFIER.fullmatch(algorithm_id) is None:
            _reject("calibration_algorithm_invalid")
        code_id = _hash(code_sha256, "calibration_code_identity_invalid")

        resolved = SimulationInputResolver(view).resolve(manifest)
        if resolved.resolution_status == "all_excluded":
            _reject("simulation_all_inputs_rights_excluded")
        admitted = {event.candidate_id: event for event in resolved.events}
        evaluation_at = _time(
            resolved.evaluation_at, "calibration_evaluation_time_invalid"
        )
        ordered = tuple(sorted(observations, key=lambda item: item.observation_id))
        if len({item.observation_id for item in ordered}) != len(ordered):
            _reject("calibration_observation_duplicate")
        deltas: list[tuple[str, str, str]] = []
        bound_sources: dict[tuple[str, str], Mapping[str, object]] = {}
        for observation in ordered:
            event = admitted.get(observation.candidate_id)
            if event is None:
                _reject("calibration_observation_not_admitted")
            if observation.family != family or event.family != family:
                _reject("calibration_observation_family_mismatch")
            if observation.source_evidence_sha256 != event.payload_sha256:
                _reject("calibration_observation_source_mismatch")
            if _time(
                observation.available_at,
                "calibration_observation_time_invalid",
            ) > evaluation_at:
                _reject("calibration_observation_future")
            source_key = (observation.source_run_id, observation.source_report_id)
            report_value = bound_sources.get(source_key)
            if report_value is None:
                try:
                    persisted_run = self._store.fetch_complete_run(
                        observation.source_run_id
                    )
                except SimulationStoreRejection as error:
                    raise SimulationCalibrationRejection(
                        "calibration_source_artifact_missing"
                    ) from error
                if (
                    persisted_run.report.report_id != observation.source_report_id
                    or persisted_run.manifest_id != manifest.identity
                    or persisted_run.report.run_id != persisted_run.run_id
                    or persisted_run.report.trace_root != persisted_run.trace_root
                ):
                    _reject("calibration_source_artifact_mismatch")
                try:
                    parsed_report = parse_raw_json(
                        persisted_run.report.canonical_bytes
                    )
                except Exception as error:
                    raise SimulationCalibrationRejection(
                        "calibration_source_artifact_invalid"
                    ) from error
                if (
                    not isinstance(parsed_report, dict)
                    or canonicalize(parsed_report)
                    != persisted_run.report.canonical_bytes
                    or parsed_report.get("report_id")
                    != persisted_run.report.report_id
                    or parsed_report.get("manifest_id") != manifest.identity
                    or parsed_report.get("trace_root") != persisted_run.trace_root
                ):
                    _reject("calibration_source_artifact_invalid")
                report_value = parsed_report
                bound_sources[source_key] = report_value
            if observation.candidate_id not in tuple(
                report_value.get("admitted_inputs", ())
            ):
                _reject("calibration_source_candidate_missing")
            if observation.source_semantic_path != "/successful":
                _reject("calibration_source_semantic_path_invalid")
            successful = report_value.get("successful")
            if not isinstance(successful, bool):
                _reject("calibration_source_value_invalid")
            expected_observed = "1" if successful else "0"
            if (
                observation.observed_value.lexical != expected_observed
                or observation.unit != "boolean"
            ):
                _reject("calibration_source_value_mismatch")
            delta = CanonicalDecimal.from_decimal(
                observation.observed_value.decimal - observation.model_value.decimal
            )
            deltas.append(
                (observation.parameter_name, delta.lexical, observation.unit)
            )
        deltas.sort()
        if len({item[0] for item in deltas}) != len(deltas):
            _reject("calibration_parameter_duplicate")
        observation_ids = tuple(item.observation_id for item in ordered)
        exclusion_ids = tuple(sorted(item.artifact_id for item in resolved.exclusions))
        delta_value = [
            {"parameter_name": name, "delta": delta, "unit": unit}
            for name, delta, unit in deltas
        ]
        delta_raw = canonicalize(delta_value)
        parameter_delta_sha256 = _framed_digest(_DELTA_DOMAIN, delta_raw)
        diagnostics_value = {
            "admitted_observation_count": len(observation_ids),
            "excluded_input_count": len(exclusion_ids),
            "family": family,
            "fixture_id": fixture_id,
            "upstream_snapshot_sha256": resolved.upstream_pre_sha256,
        }
        diagnostics_sha256 = _framed_digest(
            _DIAGNOSTICS_DOMAIN, canonicalize(diagnostics_value)
        )
        output_value = _plain(prior_profile.value)
        if not isinstance(output_value, dict):
            _reject("calibration_prior_profile_required")
        output_value["artifact_id"] = "0" * 64
        output_value["model_version"] = (
            "calibrated-" + parameter_delta_sha256[:16]
        )
        output_value["artifact_id"] = compute_document_identity(
            ARTIFACT_SCHEMA_ID, output_value
        )
        output_profile = self._publication.validate_contract(
            canonicalize(output_value), ARTIFACT_SCHEMA_ID
        )
        calibration_value = {
            "schema_version": "skeleton.simulation-artifact.v1",
            "artifact_type": "simulation_calibration",
            "artifact_id": "0" * 64,
            "manifest_id": manifest.identity,
            "prior_model_profile_id": prior_profile.identity,
            "output_model_profile_id": output_profile.identity,
            "observation_ids": list(observation_ids),
            "rights_exclusion_ids": list(exclusion_ids),
            "evaluation_request_id": str(
                manifest.value["evaluation_request"]["request_id"]
            ),
            "algorithm_id": algorithm_id,
            "code_sha256": code_id,
            "parameter_delta_sha256": parameter_delta_sha256,
            "diagnostics_sha256": diagnostics_sha256,
            "training_eligible": False,
            "readiness_eligible": False,
            "promotion_eligible": False,
        }
        calibration_value["artifact_id"] = compute_document_identity(
            ARTIFACT_SCHEMA_ID, calibration_value
        )
        calibration = self._publication.validate_contract(
            canonicalize(calibration_value), ARTIFACT_SCHEMA_ID
        )
        upstream_before = self._store.upstream_table_snapshot()
        self._store.persist_calibration_descendant(
            prior_profile=prior_profile,
            output_profile=output_profile,
            calibration=calibration,
        )
        upstream_after = self._store.upstream_table_snapshot()
        if upstream_before != upstream_after:
            _reject("upstream_mutation_detected")
        return CalibrationResult(
            output_profile=output_profile,
            calibration=calibration,
            observation_ids=observation_ids,
            rights_exclusion_ids=exclusion_ids,
            parameter_deltas=tuple(deltas),
            upstream_pre_sha256=upstream_before,
            upstream_post_sha256=upstream_after,
        )


__all__ = [
    "CalibrationObservation",
    "CalibrationResult",
    "SimulationCalibrationRejection",
    "SimulationCalibrationService",
]
