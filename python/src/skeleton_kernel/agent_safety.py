"""Bounded privacy, taint, canary, and secret gate for agent boundaries."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
import re
from typing import Any

from .canonical import canonicalize, parse_raw_json
from .memory_safety import MemorySafetyRejection, scan_memory_document


DETECTOR_VERSION = "skeleton.agent-safety.v1"
MAX_SCAN_NODES = 4096
MAX_SCAN_DEPTH = 32
MAX_SCALAR_UTF8_BYTES = 4096


class AgentSafetyCategory(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    MEMORY_POISONING = "memory_poisoning"
    TOOL_MANIPULATION = "tool_manipulation"
    EXFILTRATION = "exfiltration"
    MALICIOUS_DOCUMENT = "malicious_document"
    INDIRECT_INSTRUCTION = "indirect_instruction"
    CREDENTIAL = "credential"
    PRIVATE_DATA = "private_data"
    CANARY = "canary"
    SECRET = "secret"


class AgentBoundary(StrEnum):
    INPUT = "input"
    CONTEXT = "context"
    TOOL_ARGUMENT = "tool_argument"
    TOOL_RESULT = "tool_result"
    MODEL_OUTPUT = "model_output"
    ORGAN_RESULT = "organ_result"
    MEMORY_WRITE = "memory_write"
    LOG = "log"
    DIAGNOSTIC = "diagnostic"
    EXPORT = "export"
    CRASH_RECORD = "crash_record"


class AgentSink(StrEnum):
    """Closed pre-sink coverage inventory; aliases are intentionally absent."""

    RAW_INPUT = "raw_input"
    MINIMIZED_CONTEXT = "minimized_context"
    TOOL_ARGUMENT = "tool_argument"
    TOOL_RESULT = "tool_result"
    PROVIDER_RESPONSE = "provider_response"
    PROVIDER_RECEIPT = "provider_receipt"
    ORGAN_RESULT = "organ_result"
    MEMORY_CANDIDATE = "memory_candidate"
    STORE_CANONICAL_BLOB = "store_canonical_blob"
    SQLITE_DATABASE = "sqlite_database"
    SQLITE_WAL_SHM = "sqlite_wal_shm"
    LOG = "log"
    DIAGNOSTIC = "diagnostic"
    EXPORT = "export"
    VERIFIER_ARTIFACT = "verifier_artifact"
    CRASH_MARKER = "crash_marker"


AGENT_SINK_INVENTORY = tuple(AgentSink)


@dataclass(frozen=True, slots=True)
class AgentIncident:
    category: AgentSafetyCategory
    detector_version: str
    rule_id: str
    boundary: AgentBoundary
    disposition: str
    lineage_root: str
    nonce: str
    retention_disposition: str


class AgentSafetyRejection(ValueError):
    """Metadata-only boundary rejection."""

    def __init__(self, code: str, incident: AgentIncident) -> None:
        self.code = code
        self.incident = incident
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SafetyScanResult:
    canonical_bytes: bytes
    taints: tuple[str, ...]
    minimized_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HostileDisposition:
    """Closed non-actionable result that cannot carry submitted content."""

    category: AgentSafetyCategory
    status: str
    terminal_reason: str
    incident: AgentIncident
    authority_effect_count: int = 0
    external_effect_count: int = 0
    should_dispatch: bool = False


_SEGMENT_PURPOSES = {
    "user_input": frozenset({"owner_request", "security_conformance"}),
    "evidence": frozenset({"decision_support", "research", "security_conformance"}),
    "memory": frozenset({"organ_recall", "security_conformance"}),
    "candidate": frozenset({"independent_falsification", "security_conformance"}),
    "tool_result": frozenset({"local_tool_result", "security_conformance"}),
}
_SEGMENT_CLASSIFICATIONS = {
    "user_input": frozenset({"internal", "confidential", "restricted"}),
    "evidence": frozenset({"public", "internal", "confidential", "restricted"}),
    "memory": frozenset({"internal", "confidential"}),
    "candidate": frozenset({"internal", "confidential"}),
    "tool_result": frozenset({"internal", "confidential", "restricted"}),
}
_RETENTIONS = frozenset(
    {
        "ephemeral_discard",
        "retain_audit_metadata",
        "retain_until_work_complete",
        "retain_under_source_policy",
        "quarantine_pending_review",
    }
)
_BASE_TAINT = {
    "user_input": "untrusted_user_input",
    "evidence": "untrusted_external_evidence",
    "memory": "untrusted_memory",
    "candidate": "untrusted_candidate",
    "tool_result": "untrusted_tool_result",
}

_PRIVACY_FIELDS = {
    "precise_geolocation": "precise_geolocation",
    "gps_coordinates": "precise_geolocation",
    "latitude": "precise_geolocation",
    "longitude": "precise_geolocation",
    "street_address": "precise_geolocation",
    "personal_identity": "personal_identity",
    "legal_name": "personal_identity",
    "email_address": "personal_identity",
    "phone_number": "personal_identity",
    "biometric_identifier": "personal_identity",
    "unrelated_project_data": "unrelated_project_data",
    "other_project_payload": "unrelated_project_data",
}
_ACCOUNT_FIELDS = frozenset(
    {
        "account_id", "account_number", "broker_account_id", "bank_account_id",
        "customer_account_id", "routing_number",
    }
)
_SECRET_FIELDS = frozenset(
    {
        "credential", "credentials", "api_key", "access_token", "refresh_token",
        "password", "passphrase", "client_secret", "private_key", "recovery_secret",
        "authorization", "authentication_material", "credential_store",
    }
)
_DERIVATIVE_FIELDS = frozenset(
    {"secret_sha256", "credential_hash", "credential_digest", "canary_digest", "reusable_secret_digest"}
)
_HIDDEN_FIELDS = frozenset(
    {"raw_prompt", "system_prompt", "transcript", "scratchpad", "hidden_reasoning", "chain_of_thought", "reasoning_trace"}
)
_AUTHORITY_FIELDS = frozenset(
    {
        "execution_tool", "execution_handle", "broker_connection", "order_submitter",
        "shell_handle", "database_connection", "signer", "private_signer",
        "permission_override", "tool_allowlist_override", "coordinator_policy_override",
    }
)
_CANARY = re.compile(r"phase11\.synthetic\.(?:category-)?canary\.v1", re.IGNORECASE)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE)
_KNOWN_SECRET = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[0-9A-Za-z]{20,255}|sk-(?:proj-)?[0-9A-Za-z_-]{10,255})\b"
)
_ASSIGNMENT = re.compile(
    r"\b(?:password|api[ _-]?key|access[ _-]?token|client[ _-]?secret)\b\s*(?:is|=|:)\s*[^\s,;]{4,256}",
    re.IGNORECASE,
)
_INJECTION = re.compile(
    r"(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|"
    r"(?:change|replace|extend)\s+(?:the\s+)?(?:tool\s+allowlist|permissions|system\s+contract|coordinator\s+policy)|"
    r"(?:call|use)\s+(?:an?\s+)?(?:undeclared|execution|broker)\s+tool",
    re.IGNORECASE,
)
_MEMORY_POISONING = re.compile(
    r"(?:mark|treat|declare)\s+(?:this\s+)?memory\s+(?:as\s+)?(?:clean|trusted|eligible)|"
    r"(?:clear|remove|manufacture)\s+(?:the\s+)?taint|"
    r"persist\s+(?:this\s+)?(?:claim|memory)\s+(?:without|despite)",
    re.IGNORECASE,
)
_TOOL_EXFILTRATION = re.compile(
    r"(?:add|declare|invoke|call|use)\s+(?:a\s+|an\s+|the\s+)?(?:new|undeclared|external|execution|broker)?\s*tool|"
    r"(?:send|post|upload|exfiltrate)\s+.*(?:external|network|endpoint|destination|https?://)|"
    r"(?:access|discover|read)\s+(?:the\s+)?credentials|"
    r"(?:sign|execute|submit)\s+(?:the\s+)?(?:command|order|request)",
    re.IGNORECASE,
)
_MALICIOUS_DOCUMENT = re.compile(
    r"<\s*/?\s*(?:system|assistant|tool)\b|"
    r"(?:begin|end)\s+(?:system|privileged)\s+(?:message|instructions?)|"
    r"document\s+(?:payload|metadata)\s+(?:replaces|overrides)",
    re.IGNORECASE,
)
_INDIRECT_INSTRUCTION = re.compile(
    r"(?:the|this|that)\s+(?:document|message|memory|tool result|web page)\s+"
    r"(?:says|asks|instructs|requires)\s+(?:you|the agent|the system)\s+to",
    re.IGNORECASE,
)

_HOSTILE_OUTCOMES = {
    AgentSafetyCategory.PROMPT_INJECTION: (
        "abstain", "prompt_injection_quarantined", "rejected_before_context",
        "untrusted_instruction_data_only",
    ),
    AgentSafetyCategory.MEMORY_POISONING: (
        "invalid", "memory_poisoning_quarantined", "rejected_before_persistence",
        "tainted_memory_requires_admission",
    ),
    AgentSafetyCategory.TOOL_MANIPULATION: (
        "abstain", "egress_default_denied", "rejected_before_context",
        "tool_and_egress_allowlist_default_deny",
    ),
    AgentSafetyCategory.EXFILTRATION: (
        "abstain", "egress_default_denied", "rejected_before_context",
        "tool_and_egress_allowlist_default_deny",
    ),
    AgentSafetyCategory.MALICIOUS_DOCUMENT: (
        "invalid", "malicious_document_quarantined", "source_quarantined",
        "document_instruction_and_capability_substitution",
    ),
    AgentSafetyCategory.INDIRECT_INSTRUCTION: (
        "abstain", "prompt_injection_quarantined", "rejected_before_context",
        "untrusted_instruction_data_only",
    ),
}

_SINK_BOUNDARIES = {
    AgentSink.RAW_INPUT: AgentBoundary.INPUT,
    AgentSink.MINIMIZED_CONTEXT: AgentBoundary.CONTEXT,
    AgentSink.TOOL_ARGUMENT: AgentBoundary.TOOL_ARGUMENT,
    AgentSink.TOOL_RESULT: AgentBoundary.TOOL_RESULT,
    AgentSink.PROVIDER_RESPONSE: AgentBoundary.MODEL_OUTPUT,
    AgentSink.PROVIDER_RECEIPT: AgentBoundary.MODEL_OUTPUT,
    AgentSink.ORGAN_RESULT: AgentBoundary.ORGAN_RESULT,
    AgentSink.MEMORY_CANDIDATE: AgentBoundary.MEMORY_WRITE,
    AgentSink.STORE_CANONICAL_BLOB: AgentBoundary.MEMORY_WRITE,
    AgentSink.SQLITE_DATABASE: AgentBoundary.MEMORY_WRITE,
    AgentSink.SQLITE_WAL_SHM: AgentBoundary.MEMORY_WRITE,
    AgentSink.LOG: AgentBoundary.LOG,
    AgentSink.DIAGNOSTIC: AgentBoundary.DIAGNOSTIC,
    AgentSink.EXPORT: AgentBoundary.EXPORT,
    AgentSink.VERIFIER_ARTIFACT: AgentBoundary.EXPORT,
    AgentSink.CRASH_MARKER: AgentBoundary.CRASH_RECORD,
}


def _hash(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(code)
    return value


def _incident(
    category: AgentSafetyCategory,
    rule_id: str,
    boundary: AgentBoundary,
    source_id: str,
    *,
    disposition: str = "rejected_before_persistence",
) -> AgentIncident:
    nonce_body = canonicalize(
        {
            "boundary": boundary.value,
            "category": category.value,
            "detector_version": DETECTOR_VERSION,
            "lineage_root": source_id,
            "rule_id": rule_id,
        }
    )
    return AgentIncident(
        category=category,
        detector_version=DETECTOR_VERSION,
        rule_id=rule_id,
        boundary=boundary,
        disposition=disposition,
        lineage_root=source_id,
        nonce=sha256(b"SKELETON_PHASE11_AGENT_INCIDENT_NONCE_V1" + nonce_body).hexdigest(),
        retention_disposition="retain_audit_metadata",
    )


def _reject(
    category: AgentSafetyCategory,
    rule_id: str,
    boundary: AgentBoundary,
    source_id: str,
) -> None:
    raise AgentSafetyRejection(
        "agent_safety_rejected", _incident(category, rule_id, boundary, source_id)
    )


class AgentSafetyScanner:
    """Code-owned minimizer and bounded scanner with no sink or egress handle."""

    __slots__ = ()

    def assess_hostile(
        self,
        raw: bytes,
        *,
        source_id: str,
        boundary: AgentBoundary,
    ) -> HostileDisposition | None:
        """Classify hostile instructions before provider, tool, writer, or export dispatch."""

        _hash(source_id, "agent_safety_source_invalid")
        value = self._parse(raw, source_id, boundary)
        fragments: list[str] = []

        def collect(current: Any, depth: int) -> None:
            if depth > MAX_SCAN_DEPTH or len(fragments) > MAX_SCAN_NODES:
                _reject(
                    AgentSafetyCategory.MALICIOUS_DOCUMENT,
                    "scan_bound_v1",
                    boundary,
                    source_id,
                )
            if isinstance(current, Mapping):
                for key, nested in current.items():
                    fragments.append(str(key))
                    collect(nested, depth + 1)
            elif isinstance(current, (list, tuple)):
                for item in current:
                    collect(item, depth + 1)
            elif isinstance(current, str):
                fragments.append(current)

        collect(value, 0)
        text = "\n".join(fragments)
        category: AgentSafetyCategory | None = None
        if _MALICIOUS_DOCUMENT.search(text):
            category = AgentSafetyCategory.MALICIOUS_DOCUMENT
        elif _MEMORY_POISONING.search(text):
            category = AgentSafetyCategory.MEMORY_POISONING
        elif _TOOL_EXFILTRATION.search(text):
            category = (
                AgentSafetyCategory.EXFILTRATION
                if re.search(r"send|post|upload|exfiltrate|endpoint|destination|https?://", text, re.IGNORECASE)
                else AgentSafetyCategory.TOOL_MANIPULATION
            )
        elif _INDIRECT_INSTRUCTION.search(text):
            category = AgentSafetyCategory.INDIRECT_INSTRUCTION
        elif _INJECTION.search(text):
            category = AgentSafetyCategory.PROMPT_INJECTION
        if category is None:
            return None
        status, reason, disposition, rule_id = _HOSTILE_OUTCOMES[category]
        return HostileDisposition(
            category=category,
            status=status,
            terminal_reason=reason,
            incident=_incident(
                category,
                rule_id,
                boundary,
                source_id,
                disposition=disposition,
            ),
        )

    def require_safe_for_dispatch(
        self,
        raw: bytes,
        *,
        source_id: str,
        boundary: AgentBoundary,
    ) -> None:
        """Reject hostile content without exposing its bytes or reusable digest."""

        disposition = self.assess_hostile(raw, source_id=source_id, boundary=boundary)
        if disposition is not None:
            raise AgentSafetyRejection("agent_hostile_input_rejected", disposition.incident)

    def scan_sink(
        self,
        raw: bytes,
        *,
        sink: AgentSink | str,
        source_id: str,
    ) -> bytes:
        """Apply the bounded protected-data gate immediately before one named sink."""

        try:
            sink_value = AgentSink(sink)
        except ValueError as error:
            raise ValueError("agent_sink_unknown") from error
        _hash(source_id, "agent_safety_source_invalid")
        boundary = _SINK_BOUNDARIES[sink_value]
        value = self._parse(raw, source_id, boundary)
        minimized, private_fields, _injection = self._walk(
            value,
            source_id=source_id,
            boundary=boundary,
            minimize_privacy=False,
            allow_instructions=False,
        )
        if private_fields:
            _reject(
                AgentSafetyCategory.PRIVATE_DATA,
                "purpose_bound_minimization_v1",
                boundary,
                source_id,
            )
        return canonicalize(minimized)

    def scan_system_contract(self, raw: bytes, *, source_id: str) -> bytes:
        _hash(source_id, "agent_safety_source_invalid")
        value = self._parse(raw, source_id, AgentBoundary.CONTEXT)
        minimized, fields, _injection = self._walk(
            value,
            source_id=source_id,
            boundary=AgentBoundary.CONTEXT,
            minimize_privacy=False,
            allow_instructions=True,
        )
        if fields:
            _reject(
                AgentSafetyCategory.PRIVATE_DATA,
                "system_contract_private_data_v1",
                AgentBoundary.CONTEXT,
                source_id,
            )
        result = canonicalize(minimized)
        if result != raw:
            raise ValueError("agent_system_contract_not_canonical")
        return result

    def scan(
        self,
        raw: bytes,
        *,
        segment_type: str,
        source_id: str,
        purpose: str,
        classification: str,
        retention: str,
        boundary: AgentBoundary = AgentBoundary.CONTEXT,
    ) -> SafetyScanResult:
        _hash(source_id, "agent_safety_source_invalid")
        if (
            segment_type not in _SEGMENT_PURPOSES
            or purpose not in _SEGMENT_PURPOSES[segment_type]
            or classification not in _SEGMENT_CLASSIFICATIONS[segment_type]
            or retention not in _RETENTIONS
        ):
            raise ValueError("agent_privacy_purpose_invalid")
        value = self._parse(raw, source_id, boundary)
        minimized, fields, injection = self._walk(
            value,
            source_id=source_id,
            boundary=boundary,
            minimize_privacy=True,
            allow_instructions=False,
        )
        canonical = canonicalize(minimized)
        if not canonical:
            raise ValueError("agent_minimized_payload_empty")
        try:
            if isinstance(minimized, Mapping):
                scan_memory_document(
                    minimized,
                    schema_id="https://schemas.skeleton.local/v1/agent-context.schema.json",
                    source_event_id=source_id,
                )
        except MemorySafetyRejection as error:
            category = (
                AgentSafetyCategory.CREDENTIAL
                if error.metadata.category.value in {
                    "credential", "authentication_material", "private_key",
                    "recovery_secret", "token",
                }
                else AgentSafetyCategory.SECRET
            )
            _reject(category, error.metadata.rule_id, boundary, source_id)
        taints = {_BASE_TAINT[segment_type]}
        if injection:
            taints.add("prompt_injection_suspected")
        if fields:
            taints.add("privacy_minimized")
        return SafetyScanResult(
            canonical_bytes=canonical,
            taints=tuple(sorted(taints)),
            minimized_fields=tuple(sorted(fields)),
        )

    @staticmethod
    def _parse(raw: bytes, source_id: str, boundary: AgentBoundary) -> Any:
        if not isinstance(raw, bytes) or not raw:
            _reject(AgentSafetyCategory.MALICIOUS_DOCUMENT, "bytes_required_v1", boundary, source_id)
        try:
            value = parse_raw_json(raw)
        except Exception:
            _reject(AgentSafetyCategory.MALICIOUS_DOCUMENT, "canonical_json_required_v1", boundary, source_id)
        if canonicalize(value) != raw:
            _reject(AgentSafetyCategory.MALICIOUS_DOCUMENT, "canonical_json_required_v1", boundary, source_id)
        return value

    def _walk(
        self,
        value: Any,
        *,
        source_id: str,
        boundary: AgentBoundary,
        minimize_privacy: bool,
        allow_instructions: bool,
    ) -> tuple[Any, set[str], bool]:
        visited = 0
        minimized_fields: set[str] = set()
        injection = False

        def visit(current: Any, depth: int) -> Any:
            nonlocal visited, injection
            visited += 1
            if visited > MAX_SCAN_NODES or depth > MAX_SCAN_DEPTH:
                _reject(AgentSafetyCategory.MALICIOUS_DOCUMENT, "scan_bound_v1", boundary, source_id)
            if isinstance(current, Mapping):
                result: dict[str, Any] = {}
                for key, nested in current.items():
                    if not isinstance(key, str):
                        _reject(AgentSafetyCategory.MALICIOUS_DOCUMENT, "field_name_invalid_v1", boundary, source_id)
                    normalized = key.casefold().replace("-", "_")
                    if normalized in _PRIVACY_FIELDS:
                        if minimize_privacy:
                            minimized_fields.add(_PRIVACY_FIELDS[normalized])
                            continue
                        minimized_fields.add(_PRIVACY_FIELDS[normalized])
                    if normalized in _ACCOUNT_FIELDS:
                        _reject(AgentSafetyCategory.PRIVATE_DATA, "account_identifier_v1", boundary, source_id)
                    if normalized in _SECRET_FIELDS:
                        _reject(AgentSafetyCategory.CREDENTIAL, "credential_field_v1", boundary, source_id)
                    if normalized in _DERIVATIVE_FIELDS:
                        _reject(AgentSafetyCategory.SECRET, "reusable_secret_derivative_v1", boundary, source_id)
                    if normalized in _HIDDEN_FIELDS:
                        _reject(AgentSafetyCategory.SECRET, "hidden_state_field_v1", boundary, source_id)
                    if normalized in _AUTHORITY_FIELDS:
                        _reject(AgentSafetyCategory.TOOL_MANIPULATION, "authority_handle_v1", boundary, source_id)
                    result[key] = visit(nested, depth + 1)
                return result
            if isinstance(current, (list, tuple)):
                return [visit(item, depth + 1) for item in current]
            if current is None or type(current) in {bool, int}:
                return current
            if not isinstance(current, str):
                _reject(AgentSafetyCategory.MALICIOUS_DOCUMENT, "scalar_type_invalid_v1", boundary, source_id)
            if len(current.encode("utf-8", errors="strict")) > MAX_SCALAR_UTF8_BYTES:
                _reject(AgentSafetyCategory.MALICIOUS_DOCUMENT, "scalar_bound_v1", boundary, source_id)
            if _CANARY.search(current):
                _reject(AgentSafetyCategory.CANARY, "synthetic_category_canary_v1", boundary, source_id)
            if _PRIVATE_KEY.search(current) or _KNOWN_SECRET.search(current) or _ASSIGNMENT.search(current):
                _reject(AgentSafetyCategory.SECRET, "secret_material_v1", boundary, source_id)
            if not allow_instructions and _INJECTION.search(current):
                injection = True
            return current

        return visit(value, 0), minimized_fields, injection


def exact_sink_coverage(observed: Iterable[AgentSink | str]) -> tuple[str, ...]:
    """Return the code-owned sink ledger only when every sink occurs exactly once."""

    try:
        values = tuple(AgentSink(item) for item in observed)
    except ValueError as error:
        raise ValueError("agent_sink_unknown") from error
    if len(values) != len(AGENT_SINK_INVENTORY) or set(values) != set(AGENT_SINK_INVENTORY):
        raise ValueError("agent_sink_inventory_incomplete")
    if len(set(values)) != len(values):
        raise ValueError("agent_sink_inventory_duplicate")
    return tuple(item.value for item in AGENT_SINK_INVENTORY)


__all__ = [
    "AgentBoundary",
    "AgentIncident",
    "AgentSink",
    "AgentSafetyCategory",
    "AgentSafetyRejection",
    "AgentSafetyScanner",
    "AGENT_SINK_INVENTORY",
    "DETECTOR_VERSION",
    "MAX_SCAN_DEPTH",
    "MAX_SCAN_NODES",
    "MAX_SCALAR_UTF8_BYTES",
    "HostileDisposition",
    "SafetyScanResult",
    "exact_sink_coverage",
]
