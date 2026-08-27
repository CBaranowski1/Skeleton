"""Authenticated immutable contracts for the universal market kernel."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from jsonschema import ValidationError

from .canonical import CanonicalizationError, canonicalize, parse_raw_json, sha256_hex
from .evidence_contracts import FrozenObject, FrozenValue, _freeze
from .schema_registry import SchemaRegistry, ValidatedDocument


ENVELOPE_SCHEMA_ID = "https://schemas.skeleton.local/v1/market-event-envelope.schema.json"
PAYLOAD_SCHEMA_ID = "https://schemas.skeleton.local/v1/market-cash-equity-payload.schema.json"
ADAPTER_SCHEMA_ID = "https://schemas.skeleton.local/v1/adapter-descriptor.schema.json"
MARKET_SCHEMA_IDS = frozenset(
    {
        ENVELOPE_SCHEMA_ID,
        PAYLOAD_SCHEMA_ID,
        ADAPTER_SCHEMA_ID,
        "https://schemas.skeleton.local/v1/market-primitives.schema.json",
    }
)
TRACER_FIXTURE_PATH = "fixtures/phase08-tracer-fixtures.jsonl"
POISON_FIXTURE_PATH = "fixtures/phase08-poison-fixtures.jsonl"
CAPABILITY_KEYS = (
    "discovery",
    "normalization",
    "calendar_session",
    "lifecycle",
    "correction",
    "cost",
    "fill",
    "failure",
    "settlement",
    "capability",
)
PHASE08_BUNDLE_PROJECTION_SHA256 = "8c75667ed90f166e6f984eceb88c6ea7a4cec87a1c506ff1ef05da2a4dcacf3b"
PHASE08_FIXTURE_INDEX_PROJECTION_SHA256 = "4258eb8047c254fc70bec3f8c64d67208c16e240f80a0c31ebdcf77e0978ab55"
PHASE08_BASE_SCHEMA_PATHS = frozenset(
    {
        "schemas/adapter-descriptor.schema.json",
        "schemas/advisory-proposal.schema.json",
        "schemas/authority-command.schema.json",
        "schemas/authority-result.schema.json",
        "schemas/canonical-event.schema.json",
        "schemas/constitution.schema.json",
        "schemas/deletion-execution.schema.json",
        "schemas/deletion-preview.schema.json",
        "schemas/evidence-health.schema.json",
        "schemas/evidence-manifest.schema.json",
        "schemas/experience-envelope.schema.json",
        "schemas/identity-fact.schema.json",
        "schemas/kernel-status.schema.json",
        "schemas/kernel-status-v2.schema.json",
        "schemas/kernel-status-v3.schema.json",
        "schemas/legal-terms-record.schema.json",
        "schemas/lifecycle-event.schema.json",
        "schemas/lineage-record.schema.json",
        "schemas/lobe-package.schema.json",
        "schemas/market-activation-dossier.schema.json",
        "schemas/market-cash-equity-payload.schema.json",
        "schemas/market-conformance-trace.schema.json",
        "schemas/market-contingent-payload.schema.json",
        "schemas/market-conversion.schema.json",
        "schemas/market-event-envelope.schema.json",
        "schemas/market-exposure.schema.json",
        "schemas/market-future-payload.schema.json",
        "schemas/market-join-decision.schema.json",
        "schemas/market-listed-option-payload.schema.json",
        "schemas/market-primitives.schema.json",
        "schemas/market-sports-event-payload.schema.json",
        "schemas/material-authorization.schema.json",
        "schemas/primitives.schema.json",
        "schemas/project-manifest.schema.json",
        "schemas/reference-fact.schema.json",
        "schemas/rejection.schema.json",
        "schemas/rights-record.schema.json",
        "schemas/rights-use-decision.schema.json",
        "schemas/rights-use-request.schema.json",
        "schemas/stable-identity.schema.json",
        "schemas/universe-event.schema.json",
        "schemas/work-object.schema.json",
    }
)
PHASE08_BASE_FIXTURE_PATHS = frozenset(
    {
        "fixtures/core-fixtures.jsonl",
        "fixtures/envelope-fixtures.jsonl",
        "fixtures/jcs-rfc8785-vectors.jsonl",
        "fixtures/phase07-fixtures.jsonl",
        "fixtures/phase07-poison-fixtures.jsonl",
        "fixtures/phase08-activation-fixtures.jsonl",
        "fixtures/phase08-activation-poison-fixtures.jsonl",
        "fixtures/phase08-family-fixtures.jsonl",
        "fixtures/phase08-family-poison-fixtures.jsonl",
        "fixtures/phase08-poison-fixtures.jsonl",
        "fixtures/phase08-tracer-fixtures.jsonl",
        "fixtures/phase08-value-fixtures.jsonl",
        "fixtures/phase08-value-poison-fixtures.jsonl",
        "fixtures/protocol-fixtures.jsonl",
    }
)
PHASE08_BASE_INDEX_SOURCE_PATHS = PHASE08_BASE_FIXTURE_PATHS | {
    "fixtures/adversarial/duplicate-member.json"
}
PHASE09_SCHEMA_PATHS = frozenset(
    {
        "schemas/simulation-artifact.schema.json",
        "schemas/simulation-manifest.schema.json",
        "schemas/simulation-primitives.schema.json",
        "schemas/simulation-report.schema.json",
    }
)
PHASE09_FIXTURE_PATHS = frozenset(
    {
        "fixtures/phase09-calibration-fixtures.jsonl",
        "fixtures/phase09-failure-fixtures.jsonl",
        "fixtures/phase09-golden-fixtures.jsonl",
        "fixtures/phase09-poison-fixtures.jsonl",
    }
)
PHASE10_SCHEMA_PATHS = frozenset(
    {
        "schemas/audit-memory-payload.schema.json",
        "schemas/episodic-memory-payload.schema.json",
        "schemas/memory-envelope.schema.json",
        "schemas/memory-integrity.schema.json",
        "schemas/memory-primitives.schema.json",
        "schemas/memory-quarantine.schema.json",
        "schemas/memory-rebuild.schema.json",
        "schemas/memory-rejection.schema.json",
        "schemas/memory-retrieval.schema.json",
        "schemas/model-memory-payload.schema.json",
        "schemas/procedural-memory-payload.schema.json",
        "schemas/semantic-memory-payload.schema.json",
        "schemas/working-memory-payload.schema.json",
    }
)
PHASE10_FIXTURE_PATHS = frozenset(
    {
        "fixtures/phase10-admission-fixtures.jsonl",
        "fixtures/phase10-integrity-fixtures.jsonl",
        "fixtures/phase10-retrieval-fixtures.jsonl",
        "fixtures/phase10-safety-fixtures.jsonl",
    }
)
PHASE11_SCHEMA_PATHS = frozenset(
    {
        "schemas/agent-activation-trigger.schema.json",
        "schemas/agent-budget.schema.json",
        "schemas/agent-context.schema.json",
        "schemas/agent-identity.schema.json",
        "schemas/agent-incident.schema.json",
        "schemas/agent-invocation.schema.json",
        "schemas/agent-lifecycle.schema.json",
        "schemas/agent-model-exchange.schema.json",
        "schemas/agent-objection.schema.json",
        "schemas/agent-organ-contract.schema.json",
        "schemas/agent-primitives.schema.json",
        "schemas/agent-result.schema.json",
        "schemas/agent-tool-receipt.schema.json",
    }
)
PHASE11_FIXTURE_PATHS = frozenset(
    {
        "fixtures/phase11-budget-trigger-fixtures.jsonl",
        "fixtures/phase11-canary-privacy-fixtures.jsonl",
        "fixtures/phase11-falsifier-fixtures.jsonl",
        "fixtures/phase11-hostile-fixtures.jsonl",
        "fixtures/phase11-memory-fixtures.jsonl",
        "fixtures/phase11-organ-fixtures.jsonl",
        "fixtures/phase11-provider-fixtures.jsonl",
        "fixtures/phase11-recovery-fixtures.jsonl",
    }
)
PHASE12_SCHEMA_PATHS = frozenset(
    {
        "schemas/compression-lineage.schema.json",
        "schemas/memory-capsule.schema.json",
        "schemas/memory-derived-artifact.schema.json",
        "schemas/memory-disposition.schema.json",
        "schemas/memory-gate-receipt.schema.json",
        "schemas/memory-quota.schema.json",
        "schemas/memory-residue.schema.json",
        "schemas/metabolism-stage-receipt.schema.json",
        "schemas/recall-packet.schema.json",
        "schemas/recall-regret.schema.json",
    }
)
PHASE12_FIXTURE_PATHS = frozenset(
    {
        "fixtures/phase12-capsule-fixtures.jsonl",
        "fixtures/phase12-conductor-regret-fixtures.jsonl",
        "fixtures/phase12-disposition-fixtures.jsonl",
        "fixtures/phase12-gate-fixtures.jsonl",
        "fixtures/phase12-hostile-fixtures.jsonl",
        "fixtures/phase12-pipeline-fixtures.jsonl",
        "fixtures/phase12-residue-quota-fixtures.jsonl",
    }
)
PHASE13_SCHEMA_PATHS = frozenset(
    {
        "schemas/abstraction-candidate.schema.json",
        "schemas/candidate-version.schema.json",
        "schemas/experience-gradient.schema.json",
        "schemas/learning-channel-update.schema.json",
        "schemas/mixture-record.schema.json",
        "schemas/pending-owner-hardware.schema.json",
        "schemas/plasticity-delta.schema.json",
        "schemas/plasticity-homeostasis.schema.json",
        "schemas/plasticity-probe-receipt.schema.json",
        "schemas/plasticity-scope.schema.json",
    }
)
PHASE13_FIXTURE_PATHS = frozenset(
    {
        "fixtures/phase13-delta-mixture-fixtures.jsonl",
        "fixtures/phase13-gradient-fixtures.jsonl",
        "fixtures/phase13-homeostasis-fixtures.jsonl",
        "fixtures/phase13-hostile-fixtures.jsonl",
        "fixtures/phase13-kernel-conformance-fixtures.jsonl",
        "fixtures/phase13-probe-fixtures.jsonl",
        "fixtures/phase13-provider-training-fixtures.jsonl",
    }
)


class MarketFixtureVerdict(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"


class MarketRejectionCode(StrEnum):
    DUPLICATE_MEMBER = "duplicate_member"
    PAYLOAD_HASH_MISMATCH = "payload_hash_mismatch"
    FAMILY_PAYLOAD_MISMATCH = "family_payload_mismatch"
    UNKNOWN_CURRENCY = "unknown_currency"
    UNKNOWN_UNIT = "unknown_unit"
    UNKNOWN_TIMEZONE = "unknown_timezone"
    UNKNOWN_CALENDAR = "unknown_calendar"
    NONCANONICAL_DECIMAL = "noncanonical_decimal"
    EMPTY_CAPABILITIES = "empty_capabilities"
    PARTIAL_CAPABILITIES = "partial_capabilities"
    DUPLICATE_ADAPTER_IDENTITY = "duplicate_adapter_identity"
    FORBIDDEN_EXECUTION_SURFACE = "forbidden_execution_surface"


class MarketContractRejection(ValueError):
    """Stable redacted market rejection; candidate content is never echoed."""

    def __init__(self, code: str, *, subject_id: str | None = None) -> None:
        self.code = code
        self.subject_id = subject_id
        super().__init__(code)


@dataclass(frozen=True, slots=True, order=True)
class AdapterIdentity:
    family: str
    venue: str
    jurisdiction: str
    environment: str
    version: str

    @property
    def canonical_id(self) -> str:
        return "|".join(
            (self.family, self.venue, self.jurisdiction, self.environment, self.version)
        )


@dataclass(frozen=True, slots=True)
class CapabilityDisposition:
    state: str
    implementation_id: str | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class AdapterDescriptor:
    identity: AdapterIdentity
    capabilities: Mapping[str, CapabilityDisposition]
    canonical_sha256: str


_CONTRACT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class MarketContract:
    schema_id: str
    value: FrozenObject
    source_sha256: str
    canonical_sha256: str
    payload_sha256: str

    def __init__(self, validated: ValidatedDocument, token: object) -> None:
        if token is not _CONTRACT_TOKEN or validated.schema_id != ENVELOPE_SCHEMA_ID:
            raise TypeError("MarketContract requires authenticated envelope validation")
        if validated.source_sha256 != validated.canonical_sha256:
            raise MarketContractRejection("source_not_canonical")
        if not isinstance(validated.value, dict) or not isinstance(
            validated.value.get("payload"), dict
        ):
            raise MarketContractRejection("family_payload_mismatch")
        payload_sha256 = sha256_hex(canonicalize(validated.value["payload"]))
        if payload_sha256 != validated.value.get("payload_sha256"):
            raise MarketContractRejection("payload_hash_mismatch")
        frozen = _freeze(validated.value)
        if not isinstance(frozen, FrozenObject):
            raise MarketContractRejection("family_payload_mismatch")
        object.__setattr__(self, "schema_id", validated.schema_id)
        object.__setattr__(self, "value", frozen)
        object.__setattr__(self, "source_sha256", validated.source_sha256)
        object.__setattr__(self, "canonical_sha256", validated.canonical_sha256)
        object.__setattr__(self, "payload_sha256", payload_sha256)


def _descriptor(validated: ValidatedDocument) -> AdapterDescriptor:
    value = validated.value
    if not isinstance(value, dict):
        raise MarketContractRejection("adapter_descriptor_invalid")
    identity_value = value.get("identity")
    capabilities_value = value.get("capabilities")
    if not isinstance(identity_value, dict) or not isinstance(capabilities_value, dict):
        raise MarketContractRejection("adapter_descriptor_invalid")
    if tuple(capabilities_value) != CAPABILITY_KEYS and set(capabilities_value) != set(
        CAPABILITY_KEYS
    ):
        raise MarketContractRejection("partial_capabilities")
    identity = AdapterIdentity(
        family=str(identity_value["family"]),
        venue=str(identity_value["venue"]),
        jurisdiction=str(identity_value["jurisdiction"]),
        environment=str(identity_value["environment"]),
        version=str(identity_value["version"]),
    )
    capabilities: dict[str, CapabilityDisposition] = {}
    for name in CAPABILITY_KEYS:
        disposition = capabilities_value[name]
        if not isinstance(disposition, dict):
            raise MarketContractRejection("partial_capabilities")
        capabilities[name] = CapabilityDisposition(
            state=str(disposition["state"]),
            implementation_id=(
                str(disposition["implementation_id"])
                if "implementation_id" in disposition
                else None
            ),
            reason=str(disposition["reason"]) if "reason" in disposition else None,
        )
    return AdapterDescriptor(
        identity=identity,
        capabilities=MappingProxyType(capabilities),
        canonical_sha256=validated.canonical_sha256,
    )


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _projection_path(path: object) -> str:
    if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
        raise MarketContractRejection("market_trust_root_mismatch")
    if any(part in {"", ".", ".."} for part in path.split("/")):
        raise MarketContractRejection("market_trust_root_mismatch")
    return path


def _projection_owner(
    path: object,
    *,
    base_paths: frozenset[str],
    phase09_paths: frozenset[str],
    phase10_paths: frozenset[str],
    phase11_paths: frozenset[str],
    phase12_paths: frozenset[str] = frozenset(),
    phase13_paths: frozenset[str] = frozenset(),
) -> str:
    normalized = _projection_path(path)
    owners = tuple(
        owner
        for owner, paths in (
            ("base", base_paths),
            ("phase09", phase09_paths),
            ("phase10", phase10_paths),
            ("phase11", phase11_paths),
            ("phase12", phase12_paths),
            ("phase13", phase13_paths),
        )
        if normalized in paths
    )
    if len(owners) != 1:
        raise MarketContractRejection("market_trust_root_mismatch")
    return owners[0]


def _require_projection_inventory(
    observed: Mapping[str, set[str]],
    *,
    base_paths: frozenset[str],
    phase09_paths: frozenset[str],
    phase10_paths: frozenset[str],
    phase11_paths: frozenset[str],
    phase12_paths: frozenset[str],
    phase13_paths: frozenset[str] = frozenset(),
) -> None:
    if observed["base"] != base_paths:
        raise MarketContractRejection("market_trust_root_mismatch")
    if observed["phase09"] not in (set(), set(phase09_paths)):
        raise MarketContractRejection("market_trust_root_mismatch")
    if observed["phase10"] not in (set(), set(phase10_paths)):
        raise MarketContractRejection("market_trust_root_mismatch")
    if observed["phase11"] not in (set(), set(phase11_paths)):
        raise MarketContractRejection("market_trust_root_mismatch")
    if observed["phase12"] not in (set(), set(phase12_paths)):
        raise MarketContractRejection("market_trust_root_mismatch")
    if observed["phase13"] not in (set(), set(phase13_paths)):
        raise MarketContractRejection("market_trust_root_mismatch")


def _project_manifest_entries(
    entries: object,
    *,
    entry_kind: str,
    base_paths: frozenset[str],
    phase09_paths: frozenset[str],
    phase10_paths: frozenset[str],
    phase11_paths: frozenset[str],
    phase12_paths: frozenset[str],
    phase13_paths: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    if not isinstance(entries, list):
        raise MarketContractRejection("market_trust_root_mismatch")
    expected_fields = (
        {"path", "schema_id", "sha256"}
        if entry_kind == "schema"
        else {"path", "record_count", "sha256"}
    )
    observed = {"base": set(), "phase09": set(), "phase10": set(), "phase11": set(), "phase12": set(), "phase13": set()}
    projection: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    ordered_paths: list[str] = []
    seen_schema_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected_fields:
            raise MarketContractRejection("market_trust_root_mismatch")
        path = _projection_path(entry.get("path"))
        if path in seen_paths or not _is_sha256(entry.get("sha256")):
            raise MarketContractRejection("market_trust_root_mismatch")
        seen_paths.add(path)
        ordered_paths.append(path)
        if entry_kind == "schema":
            schema_id = entry.get("schema_id")
            if (
                not path.startswith("schemas/")
                or schema_id
                != "https://schemas.skeleton.local/v1/"
                + path.removeprefix("schemas/")
                or schema_id in seen_schema_ids
            ):
                raise MarketContractRejection("market_trust_root_mismatch")
            seen_schema_ids.add(schema_id)
        else:
            record_count = entry.get("record_count")
            if (
                not path.startswith("fixtures/")
                or isinstance(record_count, bool)
                or not isinstance(record_count, int)
                or record_count < 0
            ):
                raise MarketContractRejection("market_trust_root_mismatch")
        owner = _projection_owner(
            path,
            base_paths=base_paths,
            phase09_paths=phase09_paths,
            phase10_paths=phase10_paths,
            phase11_paths=phase11_paths,
            phase12_paths=phase12_paths,
            phase13_paths=phase13_paths,
        )
        observed[owner].add(path)
        if owner == "base":
            projection.append(entry)
    _require_projection_inventory(
        observed,
        base_paths=base_paths,
        phase09_paths=phase09_paths,
        phase10_paths=phase10_paths,
        phase11_paths=phase11_paths,
        phase12_paths=phase12_paths,
        phase13_paths=phase13_paths,
    )
    if ordered_paths != sorted(ordered_paths):
        raise MarketContractRejection("market_trust_root_mismatch")
    return projection


def _project_fixture_sources(entries: object) -> list[dict[str, Any]]:
    if not isinstance(entries, list):
        raise MarketContractRejection("market_trust_root_mismatch")
    expected_fields = {"cases", "format", "path", "record_count", "sha256"}
    observed = {"base": set(), "phase09": set(), "phase10": set(), "phase11": set(), "phase12": set(), "phase13": set()}
    projection: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    ordered_paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected_fields:
            raise MarketContractRejection("market_trust_root_mismatch")
        path = _projection_path(entry.get("path"))
        record_count = entry.get("record_count")
        if (
            path in seen_paths
            or not path.startswith("fixtures/")
            or not _is_sha256(entry.get("sha256"))
            or not isinstance(entry.get("cases"), list)
            or not isinstance(entry.get("format"), str)
            or isinstance(record_count, bool)
            or not isinstance(record_count, int)
            or record_count < 0
        ):
            raise MarketContractRejection("market_trust_root_mismatch")
        seen_paths.add(path)
        ordered_paths.append(path)
        owner = _projection_owner(
            path,
            base_paths=PHASE08_BASE_INDEX_SOURCE_PATHS,
            phase09_paths=PHASE09_FIXTURE_PATHS,
            phase10_paths=PHASE10_FIXTURE_PATHS,
            phase11_paths=PHASE11_FIXTURE_PATHS,
            phase12_paths=PHASE12_FIXTURE_PATHS,
            phase13_paths=PHASE13_FIXTURE_PATHS,
        )
        observed[owner].add(path)
        if owner == "base":
            projection.append(entry)
    _require_projection_inventory(
        observed,
        base_paths=PHASE08_BASE_INDEX_SOURCE_PATHS,
        phase09_paths=PHASE09_FIXTURE_PATHS,
        phase10_paths=PHASE10_FIXTURE_PATHS,
        phase11_paths=PHASE11_FIXTURE_PATHS,
        phase12_paths=PHASE12_FIXTURE_PATHS,
        phase13_paths=PHASE13_FIXTURE_PATHS,
    )
    if ordered_paths != sorted(ordered_paths):
        raise MarketContractRejection("market_trust_root_mismatch")
    return projection


def _require_phase10_fixture_cross_match(
    manifest_entries: object,
    source_entries: object,
) -> None:
    if not isinstance(manifest_entries, list) or not isinstance(source_entries, list):
        raise MarketContractRejection("market_trust_root_mismatch")
    manifest = {
        entry.get("path"): entry
        for entry in manifest_entries
        if isinstance(entry, dict) and entry.get("path") in PHASE10_FIXTURE_PATHS
    }
    sources = {
        entry.get("path"): entry
        for entry in source_entries
        if isinstance(entry, dict) and entry.get("path") in PHASE10_FIXTURE_PATHS
    }
    if set(manifest) != set(sources):
        raise MarketContractRejection("market_trust_root_mismatch")
    for path in manifest:
        if (
            manifest[path].get("record_count") != sources[path].get("record_count")
            or manifest[path].get("sha256") != sources[path].get("sha256")
        ):
            raise MarketContractRejection("market_trust_root_mismatch")


def _require_phase11_fixture_cross_match(
    manifest_entries: object,
    source_entries: object,
) -> None:
    if not isinstance(manifest_entries, list) or not isinstance(source_entries, list):
        raise MarketContractRejection("market_trust_root_mismatch")
    manifest = {
        entry.get("path"): entry
        for entry in manifest_entries
        if isinstance(entry, dict) and entry.get("path") in PHASE11_FIXTURE_PATHS
    }
    sources = {
        entry.get("path"): entry
        for entry in source_entries
        if isinstance(entry, dict) and entry.get("path") in PHASE11_FIXTURE_PATHS
    }
    if set(manifest) != set(sources):
        raise MarketContractRejection("market_trust_root_mismatch")
    for path in manifest:
        if (
            manifest[path].get("record_count") != sources[path].get("record_count")
            or manifest[path].get("sha256") != sources[path].get("sha256")
        ):
            raise MarketContractRejection("market_trust_root_mismatch")


def _require_phase12_fixture_cross_match(
    manifest_entries: object,
    source_entries: object,
) -> None:
    if not isinstance(manifest_entries, list) or not isinstance(source_entries, list):
        raise MarketContractRejection("market_trust_root_mismatch")
    manifest = {
        entry.get("path"): entry
        for entry in manifest_entries
        if isinstance(entry, dict) and entry.get("path") in PHASE12_FIXTURE_PATHS
    }
    sources = {
        entry.get("path"): entry
        for entry in source_entries
        if isinstance(entry, dict) and entry.get("path") in PHASE12_FIXTURE_PATHS
    }
    if set(manifest) != set(sources):
        raise MarketContractRejection("market_trust_root_mismatch")
    for path in manifest:
        if (
            manifest[path].get("record_count") != sources[path].get("record_count")
            or manifest[path].get("sha256") != sources[path].get("sha256")
        ):
            raise MarketContractRejection("market_trust_root_mismatch")


def _require_phase13_fixture_cross_match(
    manifest_entries: object,
    source_entries: object,
) -> None:
    if not isinstance(manifest_entries, list) or not isinstance(source_entries, list):
        raise MarketContractRejection("market_trust_root_mismatch")
    manifest = {
        entry.get("path"): entry
        for entry in manifest_entries
        if isinstance(entry, dict) and entry.get("path") in PHASE13_FIXTURE_PATHS
    }
    sources = {
        entry.get("path"): entry
        for entry in source_entries
        if isinstance(entry, dict) and entry.get("path") in PHASE13_FIXTURE_PATHS
    }
    if set(manifest) != set(sources):
        raise MarketContractRejection("market_trust_root_mismatch")
    for path in manifest:
        if (
            manifest[path].get("record_count") != sources[path].get("record_count")
            or manifest[path].get("sha256") != sources[path].get("sha256")
        ):
            raise MarketContractRejection("market_trust_root_mismatch")


def _phase08_projection_identities(registry: SchemaRegistry) -> tuple[str, str]:
    try:
        manifest = parse_raw_json(
            (registry.contracts_root / "bundle-manifest.json").read_bytes()
        )
        fixture_index = parse_raw_json(
            (registry.contracts_root / "fixture-index.json").read_bytes()
        )
    except Exception as error:
        raise MarketContractRejection("market_trust_root_unavailable") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "bundle_version",
        "fixtures",
        "schema_version",
        "schemas",
    }:
        raise MarketContractRejection("market_trust_root_mismatch")
    projection = {
        **manifest,
        "schemas": _project_manifest_entries(
            manifest["schemas"],
            entry_kind="schema",
            base_paths=PHASE08_BASE_SCHEMA_PATHS,
            phase09_paths=PHASE09_SCHEMA_PATHS,
            phase10_paths=PHASE10_SCHEMA_PATHS,
            phase11_paths=PHASE11_SCHEMA_PATHS,
            phase12_paths=PHASE12_SCHEMA_PATHS,
            phase13_paths=PHASE13_SCHEMA_PATHS,
        ),
        "fixtures": _project_manifest_entries(
            manifest["fixtures"],
            entry_kind="fixture",
            base_paths=PHASE08_BASE_FIXTURE_PATHS,
            phase09_paths=PHASE09_FIXTURE_PATHS,
            phase10_paths=PHASE10_FIXTURE_PATHS,
            phase11_paths=PHASE11_FIXTURE_PATHS,
            phase12_paths=PHASE12_FIXTURE_PATHS,
            phase13_paths=PHASE13_FIXTURE_PATHS,
        ),
    }
    bundle_projection_sha256 = sha256_hex(canonicalize(projection))
    if bundle_projection_sha256 != PHASE08_BUNDLE_PROJECTION_SHA256:
        raise MarketContractRejection("market_trust_root_mismatch")
    if not isinstance(fixture_index, dict) or set(fixture_index) != {
        "schema_version",
        "sources",
    }:
        raise MarketContractRejection("market_trust_root_mismatch")
    projected_sources = _project_fixture_sources(fixture_index["sources"])
    _require_phase10_fixture_cross_match(manifest["fixtures"], fixture_index["sources"])
    _require_phase11_fixture_cross_match(manifest["fixtures"], fixture_index["sources"])
    _require_phase12_fixture_cross_match(manifest["fixtures"], fixture_index["sources"])
    _require_phase13_fixture_cross_match(manifest["fixtures"], fixture_index["sources"])
    index_projection = {
        **fixture_index,
        "sources": projected_sources,
    }
    fixture_projection_sha256 = sha256_hex(canonicalize(index_projection))
    if fixture_projection_sha256 != PHASE08_FIXTURE_INDEX_PROJECTION_SHA256:
        raise MarketContractRejection("market_trust_root_mismatch")
    return bundle_projection_sha256, fixture_projection_sha256


@dataclass(frozen=True, slots=True, init=False)
class MarketContractPublication:
    schema_ids: frozenset[str]
    adapter_descriptors: tuple[AdapterDescriptor, ...]
    adapter_identity_inventory: tuple[str, ...]
    bundle_projection_sha256: str
    fixture_index_projection_sha256: str
    _fixtures: Mapping[str, MarketContract]
    _registry: SchemaRegistry
    _base_record: Mapping[str, Any]

    def __init__(
        self,
        *,
        registry: SchemaRegistry,
        fixtures: Mapping[str, MarketContract],
        adapters: tuple[AdapterDescriptor, ...],
        base_record: Mapping[str, Any],
        bundle_projection_sha256: str,
        fixture_index_projection_sha256: str,
        token: object,
    ) -> None:
        if token is not _CONTRACT_TOKEN:
            raise TypeError("MarketContractPublication requires authenticated construction")
        identities = tuple(adapter.identity.canonical_id for adapter in adapters)
        if len(identities) != len(set(identities)):
            raise MarketContractRejection("duplicate_adapter_identity")
        ordered = tuple(sorted(adapters, key=lambda item: item.identity.canonical_id))
        object.__setattr__(self, "schema_ids", MARKET_SCHEMA_IDS)
        object.__setattr__(self, "adapter_descriptors", ordered)
        object.__setattr__(
            self,
            "adapter_identity_inventory",
            tuple(item.identity.canonical_id for item in ordered),
        )
        object.__setattr__(
            self, "bundle_projection_sha256", bundle_projection_sha256
        )
        object.__setattr__(
            self,
            "fixture_index_projection_sha256",
            fixture_index_projection_sha256,
        )
        object.__setattr__(self, "_fixtures", MappingProxyType(dict(fixtures)))
        object.__setattr__(self, "_registry", registry)
        object.__setattr__(self, "_base_record", MappingProxyType(dict(base_record)))

    @classmethod
    def from_registry(cls, registry: SchemaRegistry) -> MarketContractPublication:
        if not isinstance(registry, SchemaRegistry):
            raise TypeError("registry must be SchemaRegistry")
        bundle_projection_sha256, fixture_index_projection_sha256 = (
            _phase08_projection_identities(registry)
        )
        if not MARKET_SCHEMA_IDS.issubset(registry.schema_ids):
            raise MarketContractRejection("market_schema_publication_incomplete")
        if not {TRACER_FIXTURE_PATH, POISON_FIXTURE_PATH}.issubset(
            registry.fixture_paths
        ):
            raise MarketContractRejection("market_fixture_publication_incomplete")
        records = registry.fixture_records(TRACER_FIXTURE_PATH)
        if len(records) != 1:
            raise MarketContractRejection("market_fixture_inventory")
        record = records[0]
        payload = record.get("payload")
        source_sha256 = record.get("source_sha256")
        if not isinstance(payload, dict) or sha256_hex(canonicalize(payload)) != source_sha256:
            raise MarketContractRejection("fixture_source_identity_mismatch")
        validated = registry.validate_raw(canonicalize(payload), ENVELOPE_SCHEMA_ID)
        contract = MarketContract(validated, _CONTRACT_TOKEN)
        descriptors = record.get("adapter_descriptors")
        if not isinstance(descriptors, list) or not descriptors:
            raise MarketContractRejection("empty_capabilities")
        adapters = tuple(
            _descriptor(registry.validate_raw(canonicalize(value), ADAPTER_SCHEMA_ID))
            for value in descriptors
            if isinstance(value, dict)
        )
        if len(adapters) != len(descriptors):
            raise MarketContractRejection("adapter_descriptor_invalid")
        return cls(
            registry=registry,
            fixtures={str(record["id"]): contract},
            adapters=adapters,
            base_record=record,
            bundle_projection_sha256=bundle_projection_sha256,
            fixture_index_projection_sha256=fixture_index_projection_sha256,
            token=_CONTRACT_TOKEN,
        )

    def fixture(self, fixture_id: str) -> MarketContract:
        try:
            return self._fixtures[fixture_id]
        except KeyError as error:
            raise KeyError(f"unknown market fixture: {fixture_id}") from error

    def authenticate_envelope(self, value: Mapping[str, Any]) -> MarketContract:
        """Construct an immutable contract only through the authenticated registry."""

        if not isinstance(value, Mapping):
            raise MarketContractRejection("family_payload_mismatch")
        validated = self._registry.validate_raw(
            canonicalize(dict(value)),
            ENVELOPE_SCHEMA_ID,
        )
        return MarketContract(validated, _CONTRACT_TOKEN)

    def verdict(self, fixture_id: str) -> MarketFixtureVerdict:
        self.fixture(fixture_id)
        return MarketFixtureVerdict.ACCEPT

    def evaluate_poison(self, record: Mapping[str, object]) -> None:
        """Execute one closed hostile mutation and always fail with its stable code."""

        mutation = str(record.get("mutation"))
        expected = MarketRejectionCode(str(record.get("rejection_code")))
        if mutation != expected.value and not (
            mutation == "forbidden_execution_surface"
            and expected is MarketRejectionCode.FORBIDDEN_EXECUTION_SURFACE
        ):
            raise MarketContractRejection("poison_identity_mismatch")
        envelope = deepcopy(self._base_record["payload"])
        descriptors = deepcopy(self._base_record["adapter_descriptors"])
        rejected = False
        try:
            if mutation == "duplicate_member":
                parse_raw_json(b'{"family":"listed_cash_equity","family":"future"}')
            elif mutation == "payload_hash_mismatch":
                envelope["payload_sha256"] = "0" * 64
                validated = self._registry.validate_raw(canonicalize(envelope), ENVELOPE_SCHEMA_ID)
                MarketContract(validated, _CONTRACT_TOKEN)
            elif mutation == "family_payload_mismatch":
                envelope["family"] = "future"
                self._registry.validate_raw(canonicalize(envelope), ENVELOPE_SCHEMA_ID)
            elif mutation == "unknown_currency":
                envelope["payload"]["currency"] = "ZZZ"
                self._registry.validate_raw(canonicalize(envelope), ENVELOPE_SCHEMA_ID)
            elif mutation == "unknown_unit":
                envelope["payload"]["unit"] = "contract"
                self._registry.validate_raw(canonicalize(envelope), ENVELOPE_SCHEMA_ID)
            elif mutation == "unknown_timezone":
                envelope["payload"]["session"]["tzdb_zone"] = "Mars/Olympus"
                self._registry.validate_raw(canonicalize(envelope), ENVELOPE_SCHEMA_ID)
            elif mutation == "unknown_calendar":
                envelope["payload"]["session"]["calendar"] = "UNKNOWN"
                self._registry.validate_raw(canonicalize(envelope), ENVELOPE_SCHEMA_ID)
            elif mutation == "noncanonical_decimal":
                envelope["payload"]["bid"] = "101.250"
                self._registry.validate_raw(canonicalize(envelope), ENVELOPE_SCHEMA_ID)
            elif mutation == "empty_capabilities":
                descriptors[0]["capabilities"] = {}
                self._registry.validate_raw(canonicalize(descriptors[0]), ADAPTER_SCHEMA_ID)
            elif mutation == "partial_capabilities":
                descriptors[0]["capabilities"].pop("settlement")
                self._registry.validate_raw(canonicalize(descriptors[0]), ADAPTER_SCHEMA_ID)
            elif mutation == "duplicate_adapter_identity":
                duplicate = _descriptor(
                    self._registry.validate_raw(canonicalize(descriptors[0]), ADAPTER_SCHEMA_ID)
                )
                MarketContractPublication(
                    registry=self._registry,
                    fixtures=self._fixtures,
                    adapters=(duplicate, duplicate),
                    base_record=self._base_record,
                    bundle_projection_sha256=self.bundle_projection_sha256,
                    fixture_index_projection_sha256=(
                        self.fixture_index_projection_sha256
                    ),
                    token=_CONTRACT_TOKEN,
                )
            elif mutation == "forbidden_execution_surface":
                descriptors[0]["order"] = {"submit": True}
                self._registry.validate_raw(canonicalize(descriptors[0]), ADAPTER_SCHEMA_ID)
            else:
                raise MarketContractRejection("poison_identity_mismatch")
        except (CanonicalizationError, ValidationError, MarketContractRejection):
            rejected = True
        if not rejected:
            raise MarketContractRejection("poison_not_rejected")
        raise MarketContractRejection(expected.value, subject_id=str(record.get("id")))
