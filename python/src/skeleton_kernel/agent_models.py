"""Authenticated offline provider port for deterministic Phase 11 fixtures."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
import sys
from typing import Protocol, runtime_checkable

from .agent_contracts import (
    AgentContractPublication,
    compute_agent_document_identity,
)
from .agent_types import (
    AgentOrgan,
    AgentResult,
    ModelExchange,
    SAFE_INTEGER_MAX,
    SpecialistRole,
)
from .canonical import canonicalize, parse_raw_json
from .agent_safety import AgentSafetyRejection, AgentSafetyScanner, AgentSink
from .schema_registry import SchemaRegistry


MODEL_EXCHANGE_SCHEMA_ID = (
    "https://schemas.skeleton.local/v1/agent-model-exchange.schema.json"
)
AGENT_RESULT_SCHEMA_ID = "https://schemas.skeleton.local/v1/agent-result.schema.json"
PROVIDER_FIXTURE_PATH = "fixtures/phase11-provider-fixtures.jsonl"
_EXPLICIT_PARAMETERS = {
    "temperature_ppm": 0,
    "top_p_ppm": 1_000_000,
    "max_input_tokens": 8_192,
    "max_output_tokens": 1_024,
    "random_seed": 0,
}
_FORBIDDEN_RAW_KEYS = (
    b'"credential"',
    b'"hidden_reasoning"',
    b'"private_key"',
    b'"raw_prompt"',
    b'"scratchpad"',
    b'"secret"',
    b'"session_id"',
    b'"transcript"',
)
_ADAPTER_TOKEN = object()


class AgentModelRejection(ValueError):
    """Stable provider-boundary rejection without submitted payload detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject(code: str) -> None:
    raise AgentModelRejection(code)


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _digest(domain: str, value: object) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    payload = canonicalize(_plain(value))
    return sha256(
        len(domain_bytes).to_bytes(8, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _sha256(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _reject(code)
    return value


def _safe_nonnegative(value: object, code: str) -> int:
    if type(value) is not int or not 0 <= value <= SAFE_INTEGER_MAX:
        _reject(code)
    return value


@dataclass(frozen=True, slots=True)
class ExplicitModelParameters:
    temperature_ppm: int
    top_p_ppm: int
    max_input_tokens: int
    max_output_tokens: int
    random_seed: int

    def __post_init__(self) -> None:
        for name in (
            "temperature_ppm",
            "top_p_ppm",
            "max_input_tokens",
            "max_output_tokens",
            "random_seed",
        ):
            value = _safe_nonnegative(getattr(self, name), "model_parameter_invalid")
            if name in {"temperature_ppm", "top_p_ppm"} and value > 1_000_000:
                _reject("model_parameter_invalid")

    def as_mapping(self) -> dict[str, int]:
        return {
            "temperature_ppm": self.temperature_ppm,
            "top_p_ppm": self.top_p_ppm,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "random_seed": self.random_seed,
        }


@dataclass(frozen=True, slots=True, init=False)
class ProviderDescriptor:
    provider_descriptor_id: str
    provider_id: str
    adapter_artifact_root: str
    pinning_disposition: str
    snapshot_id: str
    capability_profile_id: str
    context_construction_version: str
    parameter_profile_root: str
    usage_semantics_root: str
    regression_evidence_root: str
    fixture_case_id: str
    fixture_record_root: str
    contract: ModelExchange


@dataclass(frozen=True, slots=True)
class ModelRequest:
    case_id: str
    model_request_id: str
    invocation_id: str
    attempt: int
    organ: AgentOrgan
    specialist_role: SpecialistRole | None
    provider_descriptor_id: str
    provider_id: str
    pinning_disposition: str
    snapshot_id: str
    capability_profile_id: str
    sealed_context_id: str
    sealed_context_root: str
    context_construction_version: str
    output_schema_id: str
    output_schema_root: str
    explicit_parameters: ExplicitModelParameters
    budget_allocation_id: str
    max_response_bytes: int
    contract: ModelExchange

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not self.case_id.startswith("phase11-"):
            _reject("model_case_identity_invalid")
        for value in (
            self.model_request_id,
            self.invocation_id,
            self.provider_descriptor_id,
            self.provider_id,
            self.capability_profile_id,
            self.sealed_context_id,
            self.sealed_context_root,
            self.output_schema_root,
            self.budget_allocation_id,
        ):
            _sha256(value, "model_request_identity_invalid")
        if type(self.attempt) is not int or self.attempt < 1:
            _reject("model_request_attempt_invalid")
        if not isinstance(self.organ, AgentOrgan) or (
            self.specialist_role is not None
            and not isinstance(self.specialist_role, SpecialistRole)
        ):
            _reject("model_request_role_invalid")
        if self.context_construction_version != "skeleton.agent-context.v1":
            _reject("model_context_version_invalid")
        if self.output_schema_id != AGENT_RESULT_SCHEMA_ID:
            _reject("model_output_schema_invalid")
        if self.pinning_disposition == "exact_snapshot":
            _sha256(self.snapshot_id, "model_snapshot_identity_invalid")
        elif (
            self.pinning_disposition != "unsupported_snapshot_pinning"
            or self.snapshot_id != "none"
        ):
            _reject("model_snapshot_binding_invalid")
        _safe_nonnegative(self.max_response_bytes, "model_response_limit_invalid")
        if self.max_response_bytes == 0 or not isinstance(self.contract, ModelExchange):
            _reject("model_request_contract_invalid")


@dataclass(frozen=True, slots=True)
class ModelReceipt:
    model_receipt_id: str
    fixture_case_id: str
    model_request_id: str
    provider_descriptor_id: str
    provider_id: str
    pinning_disposition: str
    snapshot_id: str
    capability_profile_id: str
    attempt: int
    raw_response_sha256: str
    raw_response_byte_count: int
    input_tokens: int
    output_tokens: int
    elapsed_milliseconds: int
    accelerator_milliseconds: int
    usage_semantics_root: str
    regression_verdict: str
    finish_disposition: str


@dataclass(frozen=True, slots=True)
class ModelResponse:
    raw_response_bytes: bytes
    receipt: ModelReceipt
    result: AgentResult | None = None


@runtime_checkable
class ProviderAdapter(Protocol):
    @property
    def descriptor(self) -> ProviderDescriptor: ...

    @property
    def provider_id(self) -> str: ...

    @property
    def snapshot_id(self) -> str: ...

    @property
    def capability_profile_id(self) -> str: ...

    async def complete(self, request: ModelRequest) -> ModelResponse: ...


class ProviderResponseValidator:
    """Coordinator-owned authentication for untrusted provider responses."""

    __slots__ = ("_descriptor", "_publication", "_scanner")

    def __init__(
        self,
        descriptor: ProviderDescriptor,
        publication: AgentContractPublication,
    ) -> None:
        if not isinstance(descriptor, ProviderDescriptor) or not isinstance(
            publication, AgentContractPublication
        ):
            raise TypeError("ProviderResponseValidator requires authenticated contracts")
        self._descriptor = descriptor
        self._publication = publication
        self._scanner = AgentSafetyScanner()

    @classmethod
    def from_registry(
        cls, contracts_root: Path | str, descriptor: ProviderDescriptor
    ) -> "ProviderResponseValidator":
        return cls(descriptor, AgentContractPublication.from_registry(contracts_root))

    @property
    def provider_descriptor_id(self) -> str:
        return self._descriptor.provider_descriptor_id

    def request_for_attempt(self, request: ModelRequest, attempt: int) -> ModelRequest:
        if not isinstance(request, ModelRequest) or type(attempt) is not int or attempt < 1:
            _reject("model_request_attempt_invalid")
        plain = _plain(request.contract.value)
        if not isinstance(plain, dict):
            _reject("model_request_contract_invalid")
        value = plain
        value["attempt"] = attempt
        value["model_request_id"] = "0" * 64
        value["model_request_id"] = compute_agent_document_identity(value)
        try:
            typed = self._publication.validate_contract(
                canonicalize(value), MODEL_EXCHANGE_SCHEMA_ID
            ).typed_value
        except Exception:
            raise AgentModelRejection("model_request_contract_invalid") from None
        if not isinstance(typed, ModelExchange):
            _reject("model_request_contract_invalid")
        return replace(
            request,
            model_request_id=str(value["model_request_id"]),
            attempt=attempt,
            contract=typed,
        )

    def validate_response(
        self, request: ModelRequest, response: ModelResponse
    ) -> ModelResponse:
        if not isinstance(request, ModelRequest) or not isinstance(response, ModelResponse):
            _reject("model_response_type_invalid")
        expected_request = self.request_for_attempt(request, request.attempt)
        if expected_request != request:
            _reject("model_request_authentication_mismatch")
        receipt = response.receipt
        if not isinstance(receipt, ModelReceipt):
            _reject("model_receipt_invalid")
        if (
            receipt.fixture_case_id != request.case_id
            or receipt.model_request_id != request.model_request_id
            or receipt.provider_descriptor_id != self._descriptor.provider_descriptor_id
            or receipt.provider_descriptor_id != request.provider_descriptor_id
            or receipt.provider_id != self._descriptor.provider_id
            or receipt.provider_id != request.provider_id
            or receipt.pinning_disposition != request.pinning_disposition
            or receipt.snapshot_id != request.snapshot_id
            or receipt.capability_profile_id != request.capability_profile_id
            or receipt.attempt != request.attempt
            or receipt.usage_semantics_root != self._descriptor.usage_semantics_root
            or receipt.regression_verdict != "passed"
            or receipt.finish_disposition != "complete"
        ):
            _reject("model_receipt_invalid")
        for value, limit in (
            (receipt.input_tokens, request.explicit_parameters.max_input_tokens),
            (receipt.output_tokens, request.explicit_parameters.max_output_tokens),
        ):
            if type(value) is not int or not 0 <= value <= limit:
                _reject("model_usage_invalid")
        for value in (receipt.elapsed_milliseconds, receipt.accelerator_milliseconds):
            _safe_nonnegative(value, "model_usage_invalid")
        raw = response.raw_response_bytes
        if not isinstance(raw, bytes):
            _reject("model_response_bytes_required")
        if (
            len(raw) != receipt.raw_response_byte_count
            or len(raw) > request.max_response_bytes
            or sha256(raw).hexdigest() != receipt.raw_response_sha256
        ):
            _reject("model_response_size_or_identity_invalid")
        if any(marker in raw for marker in _FORBIDDEN_RAW_KEYS):
            _reject("model_response_safety_rejected")
        try:
            parsed = parse_raw_json(raw)
        except Exception:
            raise AgentModelRejection("model_response_parse_invalid") from None
        if canonicalize(parsed) != raw:
            _reject("model_response_noncanonical")
        try:
            safe_raw = self._scanner.scan_sink(
                raw,
                sink=AgentSink.PROVIDER_RESPONSE,
                source_id=request.model_request_id,
            )
        except AgentSafetyRejection:
            raise AgentModelRejection("model_response_safety_rejected") from None
        if safe_raw != raw:
            _reject("model_response_safety_rejected")
        try:
            wrapped = self._publication.validate_contract(raw, request.output_schema_id)
        except Exception:
            raise AgentModelRejection("model_response_contract_invalid") from None
        if not isinstance(wrapped.typed_value, AgentResult):
            _reject("model_response_semantic_invalid")
        return ModelResponse(bytes(raw), receipt, wrapped.typed_value)


def _unique_fixture_record(
    records: Sequence[Mapping[str, object]], case_id: str
) -> Mapping[str, object]:
    matches = [record for record in records if record.get("case_id") == case_id]
    if not matches:
        _reject("provider_fixture_lookup_missing")
    if len(matches) != 1:
        _reject("provider_fixture_lookup_duplicate")
    return matches[0]


def _descriptor_from_record(
    record: Mapping[str, object], publication: AgentContractPublication
) -> ProviderDescriptor:
    adapter = record.get("adapter")
    profile = record.get("profile")
    expected = record.get("expected")
    if not isinstance(adapter, Mapping) or not isinstance(profile, Mapping) or not isinstance(expected, Mapping):
        _reject("provider_fixture_shape_invalid")
    case_id = str(record.get("case_id"))
    if (
        adapter.get("kind") != "authenticated_fixture_reference"
        or not isinstance(adapter.get("request_ref"), str)
        or not isinstance(adapter.get("response_ref"), str)
        or profile.get("alias_used") is not False
        or profile.get("fallback_used") is not False
        or profile.get("authority_semantics_unchanged") is not True
        or profile.get("contract_status_semantics_unchanged") is not True
    ):
        _reject("provider_fixture_semantics_invalid")
    snapshot_capability = profile.get("snapshot_capability")
    snapshot_identity = profile.get("snapshot_identity")
    if snapshot_capability == "exact":
        pinning_disposition = "exact_snapshot"
        snapshot_binding = {
            "pinning_disposition": pinning_disposition,
            "snapshot_id": _sha256(snapshot_identity, "provider_snapshot_identity_invalid"),
            "pinning_reason": "provider_supports_exact_snapshot",
        }
    elif snapshot_capability == "unsupported_pinning" and snapshot_identity == "none":
        pinning_disposition = "unsupported_snapshot_pinning"
        snapshot_binding = {
            "pinning_disposition": pinning_disposition,
            "snapshot_id": "none",
            "pinning_reason": "provider_does_not_support_exact_snapshot",
        }
    else:
        _reject("provider_snapshot_binding_invalid")
    fixture_root = _digest("SKELETON_PHASE11_PROVIDER_FIXTURE_V1", record)
    provider_id = _digest(
        "SKELETON_PHASE11_PROVIDER_ID_V1",
        {
            "case_id": case_id,
            "request_ref": adapter["request_ref"],
            "response_ref": adapter["response_ref"],
        },
    )
    parameter_root = _digest(
        "SKELETON_PHASE11_PROVIDER_PARAMETERS_V1", _EXPLICIT_PARAMETERS
    )
    usage_root = _digest(
        "SKELETON_PHASE11_PROVIDER_USAGE_V1",
        {"accelerator": "integer_milliseconds", "tokens": "safe_nonnegative_integer"},
    )
    descriptor_value = {
        "schema_version": "skeleton.agent-model-exchange.v1",
        "record_type": "provider_descriptor",
        "provider_descriptor_id": "0" * 64,
        "provider_id": provider_id,
        "adapter_artifact_root": fixture_root,
        "snapshot_binding": snapshot_binding,
        "capability_profile_id": _sha256(
            profile.get("provider_capability_profile"),
            "provider_capability_profile_invalid",
        ),
        "context_construction_version": "skeleton.agent-context.v1",
        "parameter_profile_root": parameter_root,
        "usage_semantics_root": usage_root,
        "regression_verdict": "passed",
        "regression_evidence_root": _digest(
            "SKELETON_PHASE11_PROVIDER_REGRESSION_V1",
            {
                "authority_semantics_unchanged": True,
                "contract_status_semantics_unchanged": True,
                "expected_status": expected.get("status"),
                "terminal_reason": expected.get("terminal_reason"),
            },
        ),
        "egress_class": "none",
    }
    descriptor_value["provider_descriptor_id"] = compute_agent_document_identity(
        descriptor_value
    )
    typed = publication.validate_contract(
        canonicalize(descriptor_value), MODEL_EXCHANGE_SCHEMA_ID
    ).typed_value
    if not isinstance(typed, ModelExchange):
        _reject("provider_descriptor_contract_invalid")
    instance = object.__new__(ProviderDescriptor)
    for name, value in (
        ("provider_descriptor_id", descriptor_value["provider_descriptor_id"]),
        ("provider_id", provider_id),
        ("adapter_artifact_root", fixture_root),
        ("pinning_disposition", pinning_disposition),
        ("snapshot_id", snapshot_binding["snapshot_id"]),
        ("capability_profile_id", descriptor_value["capability_profile_id"]),
        ("context_construction_version", "skeleton.agent-context.v1"),
        ("parameter_profile_root", parameter_root),
        ("usage_semantics_root", usage_root),
        ("regression_evidence_root", descriptor_value["regression_evidence_root"]),
        ("fixture_case_id", case_id),
        ("fixture_record_root", fixture_root),
        ("contract", typed),
    ):
        object.__setattr__(instance, name, value)
    return instance


def _request_from_record(
    record: Mapping[str, object],
    descriptor: ProviderDescriptor,
    publication: AgentContractPublication,
) -> ModelRequest:
    case_id = str(record["case_id"])
    input_root = _sha256(record.get("canonical_input_root"), "model_input_root_invalid")
    sealed_context_id = _digest(
        "SKELETON_PHASE11_PROVIDER_SEALED_CONTEXT_V1",
        {"case_id": case_id, "input_root": input_root},
    )
    parameters = ExplicitModelParameters(**_EXPLICIT_PARAMETERS)
    request_value = {
        "schema_version": "skeleton.agent-model-exchange.v1",
        "record_type": "model_request",
        "model_request_id": "0" * 64,
        "invocation_id": input_root,
        "attempt": 1,
        "organ": "planning",
        "specialist_role": "none",
        "provider_descriptor_id": descriptor.provider_descriptor_id,
        "provider_id": descriptor.provider_id,
        "snapshot_binding": {
            "pinning_disposition": descriptor.pinning_disposition,
            "snapshot_id": descriptor.snapshot_id,
            "pinning_reason": (
                "provider_supports_exact_snapshot"
                if descriptor.pinning_disposition == "exact_snapshot"
                else "provider_does_not_support_exact_snapshot"
            ),
        },
        "capability_profile_id": descriptor.capability_profile_id,
        "sealed_context_id": sealed_context_id,
        "sealed_context_root": sealed_context_id,
        "context_construction_version": descriptor.context_construction_version,
        "output_schema_root": _digest(
            "SKELETON_PHASE11_PROVIDER_OUTPUT_SCHEMA_V1", AGENT_RESULT_SCHEMA_ID
        ),
        "explicit_parameters": parameters.as_mapping(),
        "regression_verdict": "passed",
        "budget_allocation_id": _digest(
            "SKELETON_PHASE11_PROVIDER_BUDGET_V1", {"case_id": case_id}
        ),
    }
    request_value["model_request_id"] = compute_agent_document_identity(request_value)
    typed = publication.validate_contract(
        canonicalize(request_value), MODEL_EXCHANGE_SCHEMA_ID
    ).typed_value
    if not isinstance(typed, ModelExchange):
        _reject("model_request_contract_invalid")
    return ModelRequest(
        case_id=case_id,
        model_request_id=str(request_value["model_request_id"]),
        invocation_id=input_root,
        attempt=1,
        organ=AgentOrgan.PLANNING,
        specialist_role=None,
        provider_descriptor_id=descriptor.provider_descriptor_id,
        provider_id=descriptor.provider_id,
        pinning_disposition=descriptor.pinning_disposition,
        snapshot_id=descriptor.snapshot_id,
        capability_profile_id=descriptor.capability_profile_id,
        sealed_context_id=sealed_context_id,
        sealed_context_root=sealed_context_id,
        context_construction_version=descriptor.context_construction_version,
        output_schema_id=AGENT_RESULT_SCHEMA_ID,
        output_schema_root=str(request_value["output_schema_root"]),
        explicit_parameters=parameters,
        budget_allocation_id=str(request_value["budget_allocation_id"]),
        max_response_bytes=16_384,
        contract=typed,
    )


def _raw_result(
    record: Mapping[str, object], request: ModelRequest, descriptor: ProviderDescriptor
) -> bytes:
    expected = record["expected"]
    if not isinstance(expected, Mapping):
        _reject("provider_fixture_shape_invalid")
    successful = expected.get("status") == "shadow_eligible"
    result = {
        "schema_version": "skeleton.agent-result.v1",
        "record_type": "terminal_result",
        "result_id": "0" * 64,
        "result_root": _digest("SKELETON_PHASE11_PROVIDER_RESULT_ROOT_V1", expected),
        "invocation_id": request.invocation_id,
        "attempt": request.attempt,
        "coordinator_generation": 0,
        "fence_id": _digest("SKELETON_PHASE11_PROVIDER_FENCE_V1", record["case_id"]),
        "organ": request.organ.value,
        "specialist_role": "none",
        "status": "shadow_eligible" if successful else "invalid",
        "completeness": "complete" if successful else "empty",
        "canonical_input_root": _sha256(
            record.get("canonical_input_root"), "model_input_root_invalid"
        ),
        "canonical_output_root": _digest(
            "SKELETON_PHASE11_PROVIDER_CANONICAL_OUTPUT_V1", expected
        ),
        "evidence_root": _sha256(expected.get("receipt_root"), "model_evidence_root_invalid"),
        "memory_root": _sha256(record.get("predecessor_root"), "model_memory_root_invalid"),
        "tool_receipt_root": "0" * 64,
        "model_snapshot_root": (
            descriptor.snapshot_id
            if descriptor.snapshot_id != "none"
            else descriptor.provider_descriptor_id
        ),
        "budget_allocation_id": request.budget_allocation_id,
        "budget_consumption_root": descriptor.usage_semantics_root,
        "objection_set_id": "none",
        "objection_root": _sha256(expected.get("objection_root"), "model_objection_root_invalid"),
        "objection_count": _safe_nonnegative(
            expected.get("objection_count"), "model_objection_count_invalid"
        ),
        "unresolved_material_objection_count": 0,
        "independent_disposition_count": 1 if successful else 0,
        "independent_verification_root": descriptor.regression_evidence_root if successful else "none",
        "conclusion": "authenticated_fixture_contract_parity",
        "rationale": "bounded_fixture_evidence_only",
        "uncertainty_ppm": 0 if successful else 1_000_000,
        "terminal_reason": "completed" if successful else "receipt_invalid",
        "eligibility": "shadow_evaluation_only" if successful else "none",
        "advisory_candidate_id": "none",
        "external_effect_count": 0,
        "recorded_at": f"2026-08-07T00:01:0{record['source_ordinal']}Z",
    }
    result["result_id"] = compute_agent_document_identity(result)
    return canonicalize(result)


class DeterministicFixtureAdapter:
    """One authenticated JSONL fixture adapter with no ambient I/O surface."""

    __slots__ = ("_descriptor", "_lookup", "_publication", "_validator")

    def __init__(
        self,
        descriptor: ProviderDescriptor,
        record: Mapping[str, object],
        publication: AgentContractPublication,
        *,
        token: object,
    ) -> None:
        if (
            token is not _ADAPTER_TOKEN
            or not isinstance(descriptor, ProviderDescriptor)
            or not isinstance(publication, AgentContractPublication)
        ):
            raise TypeError("DeterministicFixtureAdapter requires authenticated fixtures")
        if (
            record.get("case_id") != descriptor.fixture_case_id
            or _digest("SKELETON_PHASE11_PROVIDER_FIXTURE_V1", record)
            != descriptor.fixture_record_root
        ):
            _reject("provider_fixture_authentication_mismatch")
        request = _request_from_record(record, descriptor, publication)
        key = request.case_id
        self._descriptor = descriptor
        self._lookup = {key: record}
        self._publication = publication
        self._validator = ProviderResponseValidator(descriptor, publication)

    @classmethod
    def from_registry(
        cls, contracts_root: Path | str, case_id: str
    ) -> "DeterministicFixtureAdapter":
        publication = AgentContractPublication.from_registry(contracts_root)
        registry = SchemaRegistry(contracts_root)
        record = _unique_fixture_record(
            registry.fixture_records(PROVIDER_FIXTURE_PATH), case_id
        )
        descriptor = _descriptor_from_record(record, publication)
        return cls(descriptor, record, publication, token=_ADAPTER_TOKEN)

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def provider_id(self) -> str:
        return self._descriptor.provider_id

    @property
    def snapshot_id(self) -> str:
        return self._descriptor.snapshot_id

    @property
    def capability_profile_id(self) -> str:
        return self._descriptor.capability_profile_id

    def request(self) -> ModelRequest:
        record = next(iter(self._lookup.values()))
        return _request_from_record(record, self._descriptor, self._publication)

    def validate_response(
        self, request: ModelRequest, response: ModelResponse
    ) -> ModelResponse:
        return self._validator.validate_response(request, response)

    async def complete(self, request: ModelRequest) -> ModelResponse:
        if self._validator.request_for_attempt(request, request.attempt) != request:
            _reject("model_request_authentication_mismatch")
        if request.provider_descriptor_id != self._descriptor.provider_descriptor_id:
            _reject("provider_descriptor_substitution")
        if request.pinning_disposition != "exact_snapshot":
            _reject("provider_snapshot_pinning_unsupported")
        expected_parameters = ExplicitModelParameters(**_EXPLICIT_PARAMETERS)
        if request.explicit_parameters != expected_parameters:
            _reject("provider_parameter_profile_mismatch")
        try:
            record = self._lookup[request.case_id]
        except KeyError:
            raise AgentModelRejection("provider_fixture_lookup_missing") from None
        raw = _raw_result(record, request, self._descriptor)
        receipt_values = {
            "fixture_case_id": request.case_id,
            "model_request_id": request.model_request_id,
            "provider_descriptor_id": self._descriptor.provider_descriptor_id,
            "provider_id": self.provider_id,
            "pinning_disposition": self._descriptor.pinning_disposition,
            "snapshot_id": self.snapshot_id,
            "capability_profile_id": self.capability_profile_id,
            "attempt": request.attempt,
            "raw_response_sha256": sha256(raw).hexdigest(),
            "raw_response_byte_count": len(raw),
            "input_tokens": 128,
            "output_tokens": 64,
            "elapsed_milliseconds": 0,
            "accelerator_milliseconds": 0,
            "usage_semantics_root": self._descriptor.usage_semantics_root,
            "regression_verdict": "passed",
            "finish_disposition": "complete",
        }
        receipt = ModelReceipt(
            model_receipt_id=_digest(
                "SKELETON_PHASE11_PROVIDER_RECEIPT_V1", receipt_values
            ),
            **receipt_values,
        )
        sys.audit(
            "skeleton.agent.fixture_model.invoke",
            _digest(
                "SKELETON_PHASE11_PROVIDER_AUDIT_V1",
                {
                    "case_id": request.case_id,
                    "descriptor_id": request.provider_descriptor_id,
                    "request_id": request.model_request_id,
                },
            ),
        )
        return self.validate_response(
            request, ModelResponse(raw_response_bytes=raw, receipt=receipt)
        )


def authenticated_fixture_adapters(
    contracts_root: Path | str,
) -> tuple[DeterministicFixtureAdapter, DeterministicFixtureAdapter]:
    publication = AgentContractPublication.from_registry(contracts_root)
    registry = SchemaRegistry(contracts_root)
    records = registry.fixture_records(PROVIDER_FIXTURE_PATH)
    case_ids = tuple(str(record.get("case_id")) for record in records)
    if len(case_ids) != 2 or len(set(case_ids)) != 2:
        _reject("provider_fixture_inventory_invalid")
    adapters = tuple(
        DeterministicFixtureAdapter(
            _descriptor_from_record(_unique_fixture_record(records, case_id), publication),
            _unique_fixture_record(records, case_id),
            publication,
            token=_ADAPTER_TOKEN,
        )
        for case_id in case_ids
    )
    if len(adapters) != 2:
        _reject("provider_fixture_inventory_invalid")
    return adapters  # type: ignore[return-value]


__all__ = [name for name in globals() if not name.startswith("_")]
