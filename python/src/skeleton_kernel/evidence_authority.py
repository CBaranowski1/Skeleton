"""Real-service lawful evidence authority over the sole SQLite writer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import os
import sqlite3
import stat
import tempfile
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .canonical import canonicalize, parse_raw_json, sha256_hex
from .bitemporal import BitemporalService, KnowledgeTime, WorldTime
from .evidence_health import EvidenceHealthProvider, EvidenceHealthSnapshot
from .evidence_store import EvidenceStore
from .identity import IdentityRegistry
from .lineage import ArtifactEdge, ArtifactNode, LineageGraph, TraceResult
from .manifests import ManifestArtifact, ManifestBuilder, ManifestRebuilder
from .object_store import ObjectStore
from .schema_registry import SchemaRegistry, ValidatedDocument
from .rights import (
    RightsDecision,
    RightsEvaluator,
    RightsRejection,
    UseBoundary,
)
from .store import KernelStore


PHASE07_BUNDLE_PROJECTION_SHA256 = "5fc064f9fd5da4cc01e2f48461768c4803c1e9054e3eb679412f79c14764e7c4"
PHASE07_FIXTURE_PROJECTION_SHA256 = "cccc658627f54934c88304a2552078a57b8a1051e974d396d334d4ad83b49506"
PHASE07_SCHEMA_PATHS = frozenset(
    {
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
        "schemas/legal-terms-record.schema.json",
        "schemas/lifecycle-event.schema.json",
        "schemas/lineage-record.schema.json",
        "schemas/lobe-package.schema.json",
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
PHASE07_MANIFEST_FIXTURE_PATHS = frozenset(
    {
        "fixtures/core-fixtures.jsonl",
        "fixtures/envelope-fixtures.jsonl",
        "fixtures/jcs-rfc8785-vectors.jsonl",
        "fixtures/phase07-fixtures.jsonl",
        "fixtures/phase07-poison-fixtures.jsonl",
        "fixtures/protocol-fixtures.jsonl",
    }
)
PHASE07_INDEX_SOURCE_PATHS = PHASE07_MANIFEST_FIXTURE_PATHS | {
    "fixtures/adversarial/duplicate-member.json"
}
PHASE08_SCHEMA_PATHS = frozenset(
    {
        "schemas/adapter-descriptor.schema.json",
        "schemas/kernel-status-v3.schema.json",
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
    }
)
PHASE08_FIXTURE_PATHS = frozenset(
    {
        "fixtures/phase08-activation-fixtures.jsonl",
        "fixtures/phase08-activation-poison-fixtures.jsonl",
        "fixtures/phase08-family-fixtures.jsonl",
        "fixtures/phase08-family-poison-fixtures.jsonl",
        "fixtures/phase08-poison-fixtures.jsonl",
        "fixtures/phase08-tracer-fixtures.jsonl",
        "fixtures/phase08-value-fixtures.jsonl",
        "fixtures/phase08-value-poison-fixtures.jsonl",
    }
)
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
EVIDENCE_AUTHORITY_CONFIG_SHA256 = "e054b6925bbd63d4ff37c9ff44e2fcbe3f7b58ff1e2843945b6074e1cf7dbd2c"
EVIDENCE_AUTHORITY_CONFIG_VERSION = "skeleton.evidence-authority.v1"
EVIDENCE_AUTHORITY_ID = "d5e3b1f2c53684498d5d21eeb669544db7532c0069625f69b77cc408139562d6"

USE_BOUNDARIES = (
    "ingest", "retrieval", "prompt", "training", "evaluation", "export",
    "backup", "activation",
)

CANONICAL_EVENT_SCHEMA = "https://schemas.skeleton.local/v1/canonical-event.schema.json"
EVIDENCE_HEALTH_SCHEMA = "https://schemas.skeleton.local/v1/evidence-health.schema.json"
EVIDENCE_MANIFEST_SCHEMA = "https://schemas.skeleton.local/v1/evidence-manifest.schema.json"
LEGAL_TERMS_SCHEMA = "https://schemas.skeleton.local/v1/legal-terms-record.schema.json"
LINEAGE_SCHEMA = "https://schemas.skeleton.local/v1/lineage-record.schema.json"
RIGHTS_DECISION_SCHEMA = "https://schemas.skeleton.local/v1/rights-use-decision.schema.json"
RIGHTS_RECORD_SCHEMA = "https://schemas.skeleton.local/v1/rights-record.schema.json"
STABLE_IDENTITY_SCHEMA = "https://schemas.skeleton.local/v1/stable-identity.schema.json"

SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"
EVIDENCE_EGRESS_CAPABILITY_COUNT = 0

NON_AUDIT_TABLES = (
    "artifact_edges",
    "artifact_nodes",
    "artifact_rights",
    "canonical_events",
    "content_objects",
    "dataset_manifests",
    "dataset_partitions",
    "evidence_health_snapshots",
    "identity_versions",
    "legal_terms_records",
    "lineage_records",
    "rights_records",
    "stable_identities",
)

IMMUTABLE_EVIDENCE_TABLES = (
    "artifact_edges",
    "artifact_nodes",
    "artifact_rights",
    "canonical_events",
    "content_objects",
    "dataset_manifests",
    "dataset_partitions",
    "deletion_preview_items",
    "deletion_previews",
    "evidence_health_snapshots",
    "identity_alias_facts",
    "identity_versions",
    "legal_holds",
    "legal_terms_records",
    "lineage_records",
    "reference_facts",
    "rights_alerts",
    "rights_decisions",
    "rights_records",
    "rights_status_events",
    "schema_migrations",
    "stable_identities",
    "universe_events",
)


@dataclass(slots=True)
class EvidenceRejection(ValueError):
    """Closed, redacted evidence failure."""

    code: str
    redacted: bool = True

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True, slots=True)
class EvidenceAuthoritySnapshot:
    rights_decisions: int
    rights_alerts: int
    non_audit_relations: tuple[tuple[str, int], ...]
    fixture_root_sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceTracerResult:
    raw_content_id: str
    event_id: str
    stable_identity_id: str
    partition_id: str
    dataset_id: str
    manifest_id: str
    lineage_id: str
    rights_decision_id: str
    health_snapshot_id: str
    manifest_canonical_bytes: bytes
    raw_lineage_closed: bool
    quarantine: str
    evidence_readiness: str
    boundary: UseBoundary = UseBoundary.INGEST
    request_id: str = ""
    artifact_id: str = ""
    rights_record_ids: tuple[str, ...] = ()
    rights_decision_ids: tuple[str, ...] = ()
    retained_ids: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceUseResult:
    artifact_id: str
    source_artifact_id: str
    boundary: UseBoundary
    request_id: str
    rights_decision_id: str
    rights_record_ids: tuple[str, ...]
    rights_decision_ids: tuple[str, ...]
    payload: bytes
    processing_boundary: str
    destination: str


class EvidenceAuthority:
    """Orchestrate one authenticated, rights-first evidence ingest transaction."""

    def __init__(
        self,
        store: KernelStore,
        *,
        evidence_root: Path,
        registry: SchemaRegistry,
        records: Sequence[Mapping[str, Any]],
        rights_evaluator: RightsEvaluator,
        bitemporal_service: BitemporalService,
        identity_registry: IdentityRegistry,
        object_store: ObjectStore,
        manifest_builder: ManifestBuilder,
        manifest_rebuilder: ManifestRebuilder,
        lineage_graph: LineageGraph,
        health_provider: EvidenceHealthProvider,
    ) -> None:
        self._config = _load_authenticated_config()
        if not isinstance(store, KernelStore):
            raise TypeError("injected KernelStore required")
        if store.connection.in_transaction:
            raise EvidenceRejection("evidence_store_transaction_active")
        self._store = store
        self._root = _require_temporary_root(evidence_root)
        expected = (
            (rights_evaluator, RightsEvaluator, "rights_evaluator_required"),
            (bitemporal_service, BitemporalService, "bitemporal_service_required"),
            (identity_registry, IdentityRegistry, "identity_registry_required"),
            (object_store, ObjectStore, "object_store_required"),
            (manifest_builder, ManifestBuilder, "manifest_builder_required"),
            (manifest_rebuilder, ManifestRebuilder, "manifest_rebuilder_required"),
            (lineage_graph, LineageGraph, "lineage_graph_required"),
            (health_provider, EvidenceHealthProvider, "health_provider_required"),
        )
        for value, expected_type, code in expected:
            if not isinstance(value, expected_type):
                raise TypeError(code)
        if (
            bitemporal_service.connection is not store.connection
            or lineage_graph.connection is not store.connection
            or health_provider.store.connection is not store.connection
            or object_store.root != self._root
            or manifest_builder.object_store is not object_store
            or manifest_rebuilder.object_store is not object_store
        ):
            raise EvidenceRejection("evidence_service_identity_mismatch")
        self._registry = registry
        self._records = MappingProxyType(
            _authenticate_fixture_records(registry, records)
        )
        self._rights = rights_evaluator
        self._bitemporal = bitemporal_service
        self._identity = identity_registry
        self._objects = object_store
        self._manifest_builder = manifest_builder
        self._manifest_rebuilder = manifest_rebuilder
        self._lineage = lineage_graph
        self._health = health_provider
        self._evidence_store: EvidenceStore = bitemporal_service.evidence_store
        self._manifests: dict[str, ManifestArtifact] = {}
        self._health_snapshots: dict[str, EvidenceHealthSnapshot] = {}
        self._flows: dict[str, EvidenceTracerResult] = {}
        self.shared_store_verified = True
        self.network_request_count = 0

    @property
    def store(self) -> KernelStore:
        return self._store

    def service_inventory(self) -> tuple[str, ...]:
        """Return the exact closed set of injected integration services."""

        return tuple(
            sorted(
                type(service).__name__
                for service in (
                    self._rights,
                    self._bitemporal,
                    self._identity,
                    self._objects,
                    self._manifest_builder,
                    self._manifest_rebuilder,
                    self._lineage,
                    self._health,
                )
            )
        )

    def logical_snapshot(self) -> EvidenceAuthoritySnapshot:
        connection = self._store.connection
        return EvidenceAuthoritySnapshot(
            rights_decisions=_count(connection, "rights_decisions"),
            rights_alerts=_count(connection, "rights_alerts"),
            non_audit_relations=tuple(
                (table, _count(connection, table)) for table in NON_AUDIT_TABLES
            ),
            fixture_root_sha256=_root_sha256(self._root),
        )

    def immutable_guard_inventory(self) -> tuple[tuple[str, bool, bool], ...]:
        """Report the executable UPDATE/DELETE fence pair for each immutable table."""

        trigger_names = {
            str(row[0])
            for row in self._store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        return tuple(
            (
                table,
                f"{table}_no_update" in trigger_names,
                f"{table}_no_delete" in trigger_names,
            )
            for table in IMMUTABLE_EVIDENCE_TABLES
        )

    def ingest_denied(self, fixture_id: str) -> None:
        """Exercise the fixed revoked-rights sibling before protected persistence."""

        event = self._validated_fixture(fixture_id, CANONICAL_EVENT_SCHEMA)
        rights = self._validated_fixture("rights-record-valid", RIGHTS_RECORD_SCHEMA)
        legal = self._validated_fixture("legal-terms-record-valid", LEGAL_TERMS_SCHEMA)
        request_id = _digest_label("denied-request", event.canonical_sha256)
        decision = _rights_decision(
            request_id=request_id,
            legal_terms_id=str(legal.value["legal_terms_id"]),
            rights_record_id=str(rights.value["rights_record_id"]),
            disposition="deny",
            reason_code="rights_revoked",
        )
        validated = self._registry.validate_raw(
            canonicalize(decision), RIGHTS_DECISION_SCHEMA
        )
        alert_id = _digest_label("rights-alert", validated.canonical_sha256)
        alert = canonicalize(
            {
                "alert_id": alert_id,
                "decision_id": decision["decision_id"],
                "emitted_at": decision["decided_at"],
                "reason_code": decision["reason_code"],
            }
        )
        try:
            with self._store.transaction() as connection:
                connection.execute(
                    "INSERT INTO rights_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        decision["decision_id"],
                        decision["request_id"],
                        decision["legal_terms_id"],
                        decision["rights_record_id"],
                        decision["boundary"],
                        decision["decision"],
                        decision["reason_code"],
                        decision["decided_at"],
                        validated.canonical_bytes,
                    ),
                )
                connection.execute(
                    "INSERT INTO rights_alerts VALUES (?, ?, ?, ?, ?)",
                    (
                        alert_id,
                        decision["decision_id"],
                        decision["reason_code"],
                        decision["decided_at"],
                        alert,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise EvidenceRejection("evidence_denial_replay") from error
        raise EvidenceRejection("rights_revoked")

    def ingest(self, fixture_id: str) -> EvidenceTracerResult:
        """Run one rights-first ingest through every injected real service."""

        event_document = self._validated_fixture(fixture_id, CANONICAL_EVENT_SCHEMA)
        rights_document = self._validated_fixture(
            "rights-record-valid", RIGHTS_RECORD_SCHEMA
        )
        raw_bytes = event_document.canonical_bytes
        raw_content_sha256 = sha256_hex(raw_bytes)
        request = self._rights.default_request(
            boundary=UseBoundary.INGEST,
            evidence_sha256=raw_content_sha256,
        )
        try:
            decision = self._rights.evaluate(
                request,
                rights_record_id=str(rights_document.value["rights_record_id"]),
            )
        except RightsRejection as error:
            raise EvidenceRejection(error.code) from error

        identity = self._identity.identity("stable-identity-valid")
        identity_fact = self._identity.append_alias(
            identity.stable_identity_id,
            "integrated_fixture",
            fixture_id,
        )
        stored_raw = self._objects.put_verified(raw_bytes)
        if stored_raw.content_sha256 != raw_content_sha256:
            raise EvidenceRejection("evidence_object_identity_mismatch")

        event = dict(event_document.value)
        event.update(
            {
                "raw_sha256": stored_raw.content_sha256,
                "rights_record_id": decision.rights_record_id,
                "rights_decision_id": decision.decision_id,
                "stable_identity_id": identity.stable_identity_id,
                "stable_identity_version": identity.version,
            }
        )
        event["event_id"] = _digest_value(
            "canonical-event", _without(event, "event_id")
        )
        event_document = self._registry.validate_raw(
            canonicalize(event), CANONICAL_EVENT_SCHEMA
        )
        identity_version_id = _digest_value(
            "identity-version",
            {
                "stable_identity_id": identity.stable_identity_id,
                "version": identity.version,
            },
        )
        with self._evidence_store.transaction() as connection:
            self._evidence_store.insert(
                "stable_identities",
                (
                    "stable_identity_id",
                    "genesis_content_sha256",
                    "identity_kind",
                    "genesis_time",
                    "canonical_identity",
                ),
                (
                    identity.stable_identity_id,
                    identity.genesis_content_sha256,
                    identity.identity_kind,
                    identity.genesis_time,
                    identity.canonical_bytes,
                ),
                connection=connection,
            )
            self._evidence_store.insert(
                "identity_versions",
                (
                    "identity_version_id",
                    "stable_identity_id",
                    "version",
                    "available_at",
                    "canonical_version",
                ),
                (
                    identity_version_id,
                    identity.stable_identity_id,
                    identity.version,
                    str(event["available_at"]),
                    identity.canonical_bytes,
                ),
                connection=connection,
            )
            self._evidence_store.insert(
                "identity_alias_facts",
                (
                    "fact_id",
                    "stable_identity_id",
                    "fact_kind",
                    "effective_from",
                    "effective_to",
                    "available_at",
                    "canonical_fact",
                ),
                (
                    identity_fact.fact_id,
                    identity_fact.stable_identity_id,
                    identity_fact.fact_kind,
                    identity_fact.effective_from,
                    identity_fact.effective_to,
                    identity_fact.available_at,
                    identity_fact.canonical_bytes,
                ),
                connection=connection,
            )
        event_id = self._bitemporal.append_canonical_event(
            event,
            raw_byte_length=stored_raw.byte_length,
        )

        manifest = self._manifest_builder.build(objects=(raw_bytes,))
        self._manifest_rebuilder.rebuild(manifest)
        dataset_id = _digest_value(
            "integrated-dataset",
            {
                "event_id": event_id,
                "manifest_sha256": manifest.canonical_sha256,
            },
        )
        partition_value = {
            "dataset_id": dataset_id,
            "event_id": event_id,
            "ordinal": 0,
            "partition_key": "2026-08-01",
        }
        partition_bytes = canonicalize(partition_value)
        partition_content_sha256 = sha256_hex(partition_bytes)
        partition_id = _digest_value("integrated-partition", partition_value)
        with self._evidence_store.transaction() as connection:
            self._evidence_store.insert(
                "dataset_partitions",
                (
                    "partition_id",
                    "dataset_id",
                    "source_event_id",
                    "partition_key",
                    "content_sha256",
                    "ordinal",
                    "available_at",
                    "canonical_partition",
                ),
                (
                    partition_id,
                    dataset_id,
                    event_id,
                    "2026-08-01",
                    partition_content_sha256,
                    0,
                    str(event["available_at"]),
                    partition_bytes,
                ),
                connection=connection,
            )
            self._evidence_store.insert(
                "dataset_manifests",
                (
                    "manifest_id",
                    "declared_manifest_id",
                    "dataset_id",
                    "rights_record_id",
                    "rights_decision_id",
                    "source_commit",
                    "available_at",
                    "canonical_manifest",
                ),
                (
                    manifest.canonical_sha256,
                    manifest.manifest_id,
                    dataset_id,
                    decision.rights_record_id,
                    decision.decision_id,
                    SOURCE_COMMIT,
                    str(event["available_at"]),
                    manifest.canonical_bytes,
                ),
                connection=connection,
            )

        nodes = (
            ArtifactNode(
                dataset_id,
                "dataset",
                manifest.canonical_sha256,
                decision.rights_record_id,
                decision.decision_id,
                "verified",
                "clean",
            ),
            ArtifactNode(
                partition_id,
                "partition",
                partition_content_sha256,
                decision.rights_record_id,
                decision.decision_id,
                "verified",
                "clean",
            ),
            ArtifactNode(
                event_id,
                "canonical_event",
                event_document.canonical_sha256,
                decision.rights_record_id,
                decision.decision_id,
                "verified",
                "clean",
            ),
            ArtifactNode(
                stored_raw.content_sha256,
                "raw_evidence",
                stored_raw.content_sha256,
                decision.rights_record_id,
                decision.decision_id,
                "verified",
                "clean",
            ),
        )
        for node in nodes:
            self._lineage.add_node(node)
        for edge in (
            ArtifactEdge(
                "derived_from", dataset_id, "dataset", partition_id, "partition"
            ),
            ArtifactEdge(
                "materialized_from",
                partition_id,
                "partition",
                event_id,
                "canonical_event",
            ),
            ArtifactEdge(
                "materialized_from",
                event_id,
                "canonical_event",
                stored_raw.content_sha256,
                "raw_evidence",
            ),
        ):
            self._lineage.add_edge(edge)
        trace = self._lineage.trace(dataset_id)
        with self._evidence_store.transaction() as connection:
            self._evidence_store.insert(
                "lineage_records",
                (
                    "lineage_id",
                    "subject_artifact_id",
                    "graph_sha256",
                    "canonical_lineage",
                ),
                (
                    trace.trace_sha256,
                    dataset_id,
                    trace.graph_snapshot_sha256,
                    trace.canonical_bytes,
                ),
                connection=connection,
            )

        source_ids = {
            "raw": stored_raw.content_sha256,
            "event": event_id,
            "stable_identity": identity.stable_identity_id,
            "identity_fact": identity_fact.fact_id,
            "manifest": manifest.canonical_sha256,
            "dataset": dataset_id,
            "partition": partition_id,
            "claim": trace.trace_sha256,
            "use_decision": decision.decision_id,
        }
        health = self._health.snapshot_for_stored_ids(source_ids)
        with self._evidence_store.transaction() as connection:
            self._evidence_store.insert(
                "evidence_health_snapshots",
                (
                    "snapshot_id",
                    "source_state_sha256",
                    "readiness",
                    "observed_at",
                    "canonical_snapshot",
                ),
                (
                    health.snapshot_sha256,
                    health.source_state_sha256,
                    health.readiness,
                    health.observed_at,
                    health.canonical_bytes,
                ),
                connection=connection,
            )

        retained_ids = tuple((*source_ids.items(), ("health", health.snapshot_sha256)))
        result = EvidenceTracerResult(
            raw_content_id=stored_raw.content_sha256,
            event_id=event_id,
            stable_identity_id=identity.stable_identity_id,
            partition_id=partition_id,
            dataset_id=dataset_id,
            manifest_id=manifest.canonical_sha256,
            lineage_id=trace.trace_sha256,
            rights_decision_id=decision.decision_id,
            health_snapshot_id=health.snapshot_sha256,
            manifest_canonical_bytes=manifest.canonical_bytes,
            raw_lineage_closed=True,
            quarantine="clean",
            evidence_readiness=health.readiness,
            boundary=UseBoundary.INGEST,
            request_id=decision.request_id,
            artifact_id=dataset_id,
            rights_record_ids=(decision.rights_record_id,),
            rights_decision_ids=(decision.decision_id,),
            retained_ids=retained_ids,
        )
        self._manifests[dataset_id] = manifest
        self._health_snapshots[dataset_id] = health
        self._flows[dataset_id] = result
        return result

    def retrieve(
        self,
        dataset_id: str,
        *,
        known_at: str | None = None,
    ) -> EvidenceTracerResult:
        """Evaluate retrieval, then read the stored prefix through real services."""

        seeded = self._flows.get(dataset_id)
        if seeded is None:
            raise EvidenceRejection("evidence_artifact_not_found")
        explicit_known_at = known_at is not None
        selected_time = known_at or "9999-12-31T23:59:59Z"
        snapshot = self._bitemporal.as_known_at(
            KnowledgeTime(selected_time),
            WorldTime(selected_time),
        )
        if seeded.event_id not in snapshot.event_ids:
            raise EvidenceRejection("evidence_not_available_at_known_time")
        use = self._authorize_boundary(dataset_id, UseBoundary.RETRIEVAL)
        manifest = self._manifest_rebuilder.rebuild(self._manifests[dataset_id])
        self._objects.get_verified(seeded.raw_content_id)
        trace = self._lineage.trace(dataset_id)
        health = self._health_snapshots[dataset_id]
        return EvidenceTracerResult(
            raw_content_id=seeded.raw_content_id,
            event_id=seeded.event_id,
            stable_identity_id=seeded.stable_identity_id,
            partition_id=seeded.partition_id,
            dataset_id=seeded.dataset_id,
            manifest_id=manifest.canonical_sha256,
            lineage_id=trace.trace_sha256,
            rights_decision_id=(
                seeded.rights_decision_id
                if explicit_known_at
                else use.rights_decision_id
            ),
            health_snapshot_id=health.snapshot_sha256,
            manifest_canonical_bytes=manifest.canonical_bytes,
            raw_lineage_closed=trace.terminal_kinds == frozenset({"raw_evidence"}),
            quarantine="clean",
            evidence_readiness=health.readiness,
            boundary=UseBoundary.RETRIEVAL,
            request_id=use.request_id,
            artifact_id=dataset_id,
            rights_record_ids=use.rights_record_ids,
            rights_decision_ids=use.rights_decision_ids,
            retained_ids=seeded.retained_ids,
        )

    def rebuild(self, dataset_id: str) -> ManifestArtifact:
        try:
            manifest = self._manifests[dataset_id]
        except KeyError as error:
            raise EvidenceRejection("evidence_artifact_not_found") from error
        return self._manifest_rebuilder.rebuild(manifest)

    def trace(self, dataset_id: str) -> TraceResult:
        if dataset_id not in self._flows:
            raise EvidenceRejection("evidence_artifact_not_found")
        return self._lineage.trace(dataset_id)

    def health(self, dataset_id: str) -> EvidenceHealthSnapshot:
        try:
            return self._health_snapshots[dataset_id]
        except KeyError as error:
            raise EvidenceRejection("evidence_artifact_not_found") from error

    def persisted_id_chain(self, dataset_id: str) -> tuple[tuple[str, str], ...]:
        try:
            result = self._flows[dataset_id]
        except KeyError as error:
            raise EvidenceRejection("evidence_artifact_not_found") from error
        present = {
            "event": {str(row[0]) for row in self._evidence_store.fetch_all("canonical_events")},
            "manifest": {str(row[0]) for row in self._evidence_store.fetch_all("dataset_manifests")},
            "dataset": {str(row[1]) for row in self._evidence_store.fetch_all("dataset_partitions")},
            "partition": {str(row[0]) for row in self._evidence_store.fetch_all("dataset_partitions")},
            "claim": {str(row[0]) for row in self._evidence_store.fetch_all("lineage_records")},
            "health": {str(row[0]) for row in self._evidence_store.fetch_all("evidence_health_snapshots")},
            "identity_fact": {str(row[0]) for row in self._evidence_store.fetch_all("identity_alias_facts")},
            "stable_identity": {str(row[0]) for row in self._evidence_store.fetch_all("stable_identities")},
            "use_decision": {str(row[0]) for row in self._evidence_store.fetch_all("rights_decisions")},
            "raw": {str(row[0]) for row in self._evidence_store.fetch_all("content_objects")},
        }
        for name, identity in result.retained_ids:
            if identity not in present[name]:
                raise EvidenceRejection("evidence_persisted_id_missing")
        return result.retained_ids

    def construct_prompt(
        self,
        artifact_id: str,
        *,
        purpose: str | None = None,
        processing_boundary: str = "approved_local_boundary",
        destination: str = "approved_local_model",
    ) -> EvidenceUseResult:
        return self._authorize_boundary(
            artifact_id,
            UseBoundary.PROMPT,
            purpose=purpose,
            processing_boundary=processing_boundary,
            destination=destination,
            derived_kind="derived_artifact",
        )

    def train(
        self,
        artifact_id: str,
        *,
        purpose: str | None = None,
    ) -> EvidenceUseResult:
        return self._authorize_boundary(
            artifact_id,
            UseBoundary.TRAINING,
            purpose=purpose,
            derived_kind="model",
        )

    def evaluate(
        self,
        artifact_id: str,
        *,
        purpose: str | None = None,
    ) -> EvidenceUseResult:
        return self._authorize_boundary(
            artifact_id,
            UseBoundary.EVALUATION,
            purpose=purpose,
            derived_kind="decision",
        )

    def export(
        self,
        artifact_id: str,
        *,
        purpose: str | None = None,
        processing_boundary: str = "local_only",
        destination: str = "export_recipient",
    ) -> EvidenceUseResult:
        return self._authorize_boundary(
            artifact_id,
            UseBoundary.EXPORT,
            purpose=purpose,
            processing_boundary=processing_boundary,
            destination=destination,
            derived_kind="export",
        )

    def backup(
        self,
        artifact_id: str,
        *,
        purpose: str | None = None,
    ) -> EvidenceUseResult:
        return self._authorize_boundary(
            artifact_id,
            UseBoundary.BACKUP,
            purpose=purpose,
            destination="backup_repository",
            derived_kind="backup",
        )

    def assess_activation(
        self,
        artifact_id: str,
        *,
        purpose: str | None = None,
    ) -> EvidenceUseResult:
        return self.assess_promotion(
            artifact_id,
            purpose=purpose,
        )

    def assess_promotion(
        self,
        artifact_id: str,
        *,
        purpose: str | None = None,
        manual_override: bool = False,
    ) -> EvidenceUseResult:
        """Recompute current rights and quarantine; caller optimism is ignored."""

        del manual_override
        pairs = self._artifact_rights(artifact_id)
        if not pairs:
            raise EvidenceRejection("evidence_artifact_not_found")
        rights_ids = tuple(sorted({item[0] for item in pairs}))
        if len(rights_ids) != 1:
            raise EvidenceRejection("rights_lineage_ambiguous")
        row = self._store.connection.execute(
            "SELECT authentication, quarantine FROM artifact_nodes "
            "WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise EvidenceRejection("evidence_artifact_not_found")
        rights_status = self._current_persisted_rights_status(rights_ids[0])
        quarantine = () if str(row[1]) == "clean" else (str(row[1]),)
        try:
            self._rights.assert_promotion_eligible(
                quarantine=quarantine,
                rights_status=rights_status,
                identity_resolved=str(row[0]) == "verified",
                available=True,
                reproducible=str(row[0]) == "verified",
                manual_override=False,
            )
        except RightsRejection as error:
            request = self._rights.default_request(
                boundary=UseBoundary.ACTIVATION,
                evidence_sha256=artifact_id,
                purpose=purpose,
            )
            try:
                self._rights.record_policy_denial(
                    request,
                    rights_record_id=rights_ids[0],
                    code=error.code,
                )
            except RightsRejection as recorded:
                if recorded.decision_id is None:
                    raise EvidenceRejection(recorded.code) from recorded
                self._persist_denied_decision(
                    self._rights.decision(recorded.decision_id)
                )
                raise EvidenceRejection(recorded.code) from recorded
            raise AssertionError("policy denial unexpectedly returned")
        return self._authorize_boundary(
            artifact_id,
            UseBoundary.ACTIVATION,
            purpose=purpose,
            derived_kind="decision",
        )

    def _current_persisted_rights_status(self, rights_record_id: str) -> str:
        row = self._store.connection.execute(
            "SELECT status FROM rights_records WHERE rights_record_id = ?",
            (rights_record_id,),
        ).fetchone()
        if row is None:
            return "unknown"
        event = self._store.connection.execute(
            "SELECT status FROM rights_status_events "
            "WHERE rights_record_id = ? "
            "ORDER BY available_at DESC, status_event_id DESC LIMIT 1",
            (rights_record_id,),
        ).fetchone()
        if event is None:
            return str(row[0])
        status = str(event[0])
        return "active" if status == "enabled" else status

    def _authorize_boundary(
        self,
        source_artifact_id: str,
        boundary: UseBoundary,
        *,
        purpose: str | None = None,
        processing_boundary: str = "local_only",
        destination: str = "local_owner_system",
        derived_kind: str | None = None,
    ) -> EvidenceUseResult:
        ancestor_pairs = self._artifact_rights(source_artifact_id)
        if not ancestor_pairs:
            raise EvidenceRejection("evidence_artifact_not_found")
        rights_record_ids = tuple(sorted({item[0] for item in ancestor_pairs}))
        if len(rights_record_ids) != 1:
            raise EvidenceRejection("rights_lineage_ambiguous")
        request = self._rights.default_request(
            boundary=boundary,
            evidence_sha256=source_artifact_id,
            purpose=purpose,
            processing_boundary=processing_boundary,
            destination=destination,
        )
        try:
            decision = self._rights.evaluate(
                request,
                rights_record_id=rights_record_ids[0],
            )
        except RightsRejection as error:
            if error.decision_id is None:
                raise EvidenceRejection(error.code) from error
            denied = self._rights.decision(error.decision_id)
            self._persist_denied_decision(denied)
            raise EvidenceRejection(error.code) from error

        prior_decision_ids = tuple(sorted({item[1] for item in ancestor_pairs}))
        decision_ids = tuple(sorted({*prior_decision_ids, decision.decision_id}))
        artifact_id = source_artifact_id
        if derived_kind is not None:
            artifact_id = _digest_value(
                "rights-derived-artifact",
                {
                    "boundary": boundary.value,
                    "decision_id": decision.decision_id,
                    "source_artifact_id": source_artifact_id,
                },
            )
        try:
            with self._store.transaction() as connection:
                self._insert_use_decision(connection, decision)
                if derived_kind is None:
                    connection.execute(
                        "INSERT INTO artifact_rights VALUES (?, ?, ?)",
                        (artifact_id, rights_record_ids[0], decision.decision_id),
                    )
                else:
                    node = {
                        "artifact_id": artifact_id,
                        "authentication": "verified",
                        "content_sha256": artifact_id,
                        "node_kind": derived_kind,
                        "quarantine": "clean",
                    }
                    connection.execute(
                        "INSERT INTO artifact_nodes VALUES (?, ?, ?, 'verified', 'clean', ?)",
                        (artifact_id, derived_kind, artifact_id, canonicalize(node)),
                    )
                    edge = {
                        "edge_kind": "derived_from",
                        "from": artifact_id,
                        "to": source_artifact_id,
                    }
                    connection.execute(
                        "INSERT INTO artifact_edges VALUES (?, ?, 'derived_from', ?)",
                        (artifact_id, source_artifact_id, canonicalize(edge)),
                    )
                    for rights_id in rights_record_ids:
                        for decision_id in decision_ids:
                            connection.execute(
                                "INSERT INTO artifact_rights VALUES (?, ?, ?)",
                                (artifact_id, rights_id, decision_id),
                            )
        except sqlite3.IntegrityError as error:
            raise EvidenceRejection("rights_use_persistence_conflict") from error

        payload = canonicalize(
            {
                "artifact_id": artifact_id,
                "boundary": boundary.value,
                "decision_id": decision.decision_id,
                "source_artifact_id": source_artifact_id,
            }
        )
        return EvidenceUseResult(
            artifact_id=artifact_id,
            source_artifact_id=source_artifact_id,
            boundary=boundary,
            request_id=decision.request_id,
            rights_decision_id=decision.decision_id,
            rights_record_ids=rights_record_ids,
            rights_decision_ids=decision_ids,
            payload=payload,
            processing_boundary=processing_boundary,
            destination=destination,
        )

    def _artifact_rights(self, artifact_id: str) -> tuple[tuple[str, str], ...]:
        return tuple(
            (str(row[0]), str(row[1]))
            for row in self._store.connection.execute(
                "SELECT rights_record_id, rights_decision_id "
                "FROM artifact_rights WHERE artifact_id = ? "
                "ORDER BY rights_record_id, rights_decision_id",
                (artifact_id,),
            ).fetchall()
        )

    def _insert_use_decision(
        self,
        connection: sqlite3.Connection,
        decision: RightsDecision,
    ) -> None:
        connection.execute(
            "INSERT INTO rights_decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                decision.decision_id,
                decision.request_id,
                decision.legal_terms_id,
                decision.rights_record_id,
                decision.boundary.value,
                decision.disposition,
                decision.reason_code,
                decision.decided_at,
                _decision_bytes(decision, redacted=False),
            ),
        )

    def _persist_denied_decision(self, decision: RightsDecision) -> None:
        alert_id = _digest_label("rights-alert", decision.decision_id)
        alert = canonicalize(
            {
                "alert_id": alert_id,
                "boundary": decision.boundary.value,
                "decision_id": decision.decision_id,
                "emitted_at": decision.decided_at,
                "reason_code": decision.reason_code,
            }
        )
        try:
            with self._store.transaction() as connection:
                connection.execute(
                    "INSERT INTO rights_decisions VALUES (?, ?, ?, ?, ?, 'deny', ?, ?, ?)",
                    (
                        decision.decision_id,
                        decision.request_id,
                        decision.legal_terms_id,
                        decision.rights_record_id,
                        decision.boundary.value,
                        decision.reason_code,
                        decision.decided_at,
                        _decision_bytes(decision, redacted=True),
                    ),
                )
                connection.execute(
                    "INSERT INTO rights_alerts VALUES (?, ?, ?, ?, ?)",
                    (
                        alert_id,
                        decision.decision_id,
                        decision.reason_code,
                        decision.decided_at,
                        alert,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise EvidenceRejection("evidence_denial_replay") from error

    def _validated_fixture(
        self, fixture_id: str, expected_schema_id: str
    ) -> ValidatedDocument:
        record = self._records.get(fixture_id)
        if record is None or record.get("schema_id") != expected_schema_id:
            raise EvidenceRejection("authenticated_fixture_not_found")
        return self._registry.validate_raw(
            canonicalize(record["payload"]), expected_schema_id
        )


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_projection_path(path: object, code: str) -> str:
    if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
        raise EvidenceRejection(code)
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise EvidenceRejection(code)
    return path


def _classify_projection_path(
    path: object,
    *,
    phase07_paths: frozenset[str],
    phase08_paths: frozenset[str],
    phase09_paths: frozenset[str],
    phase10_paths: frozenset[str],
    phase11_paths: frozenset[str],
    phase12_paths: frozenset[str] = frozenset(),
    phase13_paths: frozenset[str] = frozenset(),
    code: str,
) -> str:
    normalized = _require_projection_path(path, code)
    memberships = tuple(
        name
        for name, paths in (
            ("phase07", phase07_paths),
            ("phase08", phase08_paths),
            ("phase09", phase09_paths),
            ("phase10", phase10_paths),
            ("phase11", phase11_paths),
            ("phase12", phase12_paths),
            ("phase13", phase13_paths),
        )
        if normalized in paths
    )
    if len(memberships) != 1:
        raise EvidenceRejection(code)
    return memberships[0]


def _require_complete_inventory(
    observed: Mapping[str, set[str]],
    *,
    phase07_paths: frozenset[str],
    phase08_paths: frozenset[str],
    phase09_paths: frozenset[str],
    phase10_paths: frozenset[str],
    phase11_paths: frozenset[str],
    phase12_paths: frozenset[str],
    phase13_paths: frozenset[str] = frozenset(),
    code: str,
) -> None:
    if observed["phase07"] != phase07_paths or observed["phase08"] != phase08_paths:
        raise EvidenceRejection(code)
    if observed["phase09"] not in (set(), set(phase09_paths)):
        raise EvidenceRejection(code)
    if observed["phase10"] not in (set(), set(phase10_paths)):
        raise EvidenceRejection(code)
    if observed["phase11"] not in (set(), set(phase11_paths)):
        raise EvidenceRejection(code)
    if observed["phase12"] not in (set(), set(phase12_paths)):
        raise EvidenceRejection(code)
    if observed["phase13"] not in (set(), set(phase13_paths)):
        raise EvidenceRejection(code)


def _project_manifest_section(
    entries: object,
    *,
    entry_kind: str,
    phase07_paths: frozenset[str],
    phase08_paths: frozenset[str],
    phase09_paths: frozenset[str],
    phase10_paths: frozenset[str],
    phase11_paths: frozenset[str],
    phase12_paths: frozenset[str],
    phase13_paths: frozenset[str] = frozenset(),
    code: str,
) -> list[dict[str, Any]]:
    if not isinstance(entries, list):
        raise EvidenceRejection(code)
    observed = {
        "phase07": set(),
        "phase08": set(),
        "phase09": set(),
        "phase10": set(),
        "phase11": set(),
        "phase12": set(),
        "phase13": set(),
    }
    projection: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    ordered_paths: list[str] = []
    seen_schema_ids: set[str] = set()
    expected_fields = (
        {"path", "schema_id", "sha256"}
        if entry_kind == "schema"
        else {"path", "record_count", "sha256"}
    )
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected_fields:
            raise EvidenceRejection(code)
        path = _require_projection_path(entry.get("path"), code)
        if path in seen_paths or not _is_sha256(entry.get("sha256")):
            raise EvidenceRejection(code)
        seen_paths.add(path)
        ordered_paths.append(path)
        if entry_kind == "schema":
            schema_id = entry.get("schema_id")
            expected_schema_id = (
                "https://schemas.skeleton.local/v1/"
                + path.removeprefix("schemas/")
            )
            if (
                not path.startswith("schemas/")
                or schema_id != expected_schema_id
                or schema_id in seen_schema_ids
            ):
                raise EvidenceRejection(code)
            seen_schema_ids.add(schema_id)
        else:
            record_count = entry.get("record_count")
            if (
                not path.startswith("fixtures/")
                or isinstance(record_count, bool)
                or not isinstance(record_count, int)
                or record_count < 0
            ):
                raise EvidenceRejection(code)
        owner = _classify_projection_path(
            path,
            phase07_paths=phase07_paths,
            phase08_paths=phase08_paths,
            phase09_paths=phase09_paths,
            phase10_paths=phase10_paths,
            phase11_paths=phase11_paths,
            phase12_paths=phase12_paths,
            phase13_paths=phase13_paths,
            code=code,
        )
        observed[owner].add(path)
        if owner == "phase07":
            projection.append(entry)
    _require_complete_inventory(
        observed,
        phase07_paths=phase07_paths,
        phase08_paths=phase08_paths,
        phase09_paths=phase09_paths,
        phase10_paths=phase10_paths,
        phase11_paths=phase11_paths,
        phase12_paths=phase12_paths,
        phase13_paths=phase13_paths,
        code=code,
    )
    if ordered_paths != sorted(ordered_paths):
        raise EvidenceRejection(code)
    return projection


def _project_fixture_sources(entries: object) -> list[dict[str, Any]]:
    code = "fixture_index_identity_mismatch"
    if not isinstance(entries, list):
        raise EvidenceRejection(code)
    observed = {
        "phase07": set(),
        "phase08": set(),
        "phase09": set(),
        "phase10": set(),
        "phase11": set(),
        "phase12": set(),
        "phase13": set(),
    }
    projection: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    ordered_paths: list[str] = []
    expected_fields = {"cases", "format", "path", "record_count", "sha256"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected_fields:
            raise EvidenceRejection(code)
        path = _require_projection_path(entry.get("path"), code)
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
            raise EvidenceRejection(code)
        seen_paths.add(path)
        ordered_paths.append(path)
        owner = _classify_projection_path(
            path,
            phase07_paths=PHASE07_INDEX_SOURCE_PATHS,
            phase08_paths=PHASE08_FIXTURE_PATHS,
            phase09_paths=PHASE09_FIXTURE_PATHS,
            phase10_paths=PHASE10_FIXTURE_PATHS,
            phase11_paths=PHASE11_FIXTURE_PATHS,
            phase12_paths=PHASE12_FIXTURE_PATHS,
            phase13_paths=PHASE13_FIXTURE_PATHS,
            code=code,
        )
        observed[owner].add(path)
        if owner == "phase07":
            projection.append(entry)
    _require_complete_inventory(
        observed,
        phase07_paths=PHASE07_INDEX_SOURCE_PATHS,
        phase08_paths=PHASE08_FIXTURE_PATHS,
        phase09_paths=PHASE09_FIXTURE_PATHS,
        phase10_paths=PHASE10_FIXTURE_PATHS,
        phase11_paths=PHASE11_FIXTURE_PATHS,
        phase12_paths=PHASE12_FIXTURE_PATHS,
        phase13_paths=PHASE13_FIXTURE_PATHS,
        code=code,
    )
    if ordered_paths != sorted(ordered_paths):
        raise EvidenceRejection(code)
    return projection


def _require_phase10_fixture_cross_match(
    manifest_entries: object,
    source_entries: object,
) -> None:
    code = "fixture_index_identity_mismatch"
    if not isinstance(manifest_entries, list) or not isinstance(source_entries, list):
        raise EvidenceRejection(code)
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
        raise EvidenceRejection(code)
    for path in manifest:
        if (
            manifest[path].get("record_count") != sources[path].get("record_count")
            or manifest[path].get("sha256") != sources[path].get("sha256")
        ):
            raise EvidenceRejection(code)


def _require_phase11_fixture_cross_match(
    manifest_entries: object,
    source_entries: object,
) -> None:
    code = "fixture_index_identity_mismatch"
    if not isinstance(manifest_entries, list) or not isinstance(source_entries, list):
        raise EvidenceRejection(code)
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
        raise EvidenceRejection(code)
    for path in manifest:
        if (
            manifest[path].get("record_count") != sources[path].get("record_count")
            or manifest[path].get("sha256") != sources[path].get("sha256")
        ):
            raise EvidenceRejection(code)


def _require_phase12_fixture_cross_match(
    manifest_entries: object,
    source_entries: object,
) -> None:
    code = "fixture_index_identity_mismatch"
    if not isinstance(manifest_entries, list) or not isinstance(source_entries, list):
        raise EvidenceRejection(code)
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
        raise EvidenceRejection(code)
    for path in manifest:
        if (
            manifest[path].get("record_count") != sources[path].get("record_count")
            or manifest[path].get("sha256") != sources[path].get("sha256")
        ):
            raise EvidenceRejection(code)


def _require_phase13_fixture_cross_match(
    manifest_entries: object,
    source_entries: object,
) -> None:
    code = "fixture_index_identity_mismatch"
    if not isinstance(manifest_entries, list) or not isinstance(source_entries, list):
        raise EvidenceRejection(code)
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
        raise EvidenceRejection(code)
    for path in manifest:
        if (
            manifest[path].get("record_count") != sources[path].get("record_count")
            or manifest[path].get("sha256") != sources[path].get("sha256")
        ):
            raise EvidenceRejection(code)


def _authenticated_repository_root() -> Path:
    root = Path.cwd().resolve(strict=True)
    contracts_root = root / "contracts" / "v1"
    try:
        manifest = parse_raw_json((contracts_root / "bundle-manifest.json").read_bytes())
        fixture_index = parse_raw_json((contracts_root / "fixture-index.json").read_bytes())
    except Exception as error:
        raise EvidenceRejection("contract_bundle_identity_mismatch") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "bundle_version",
        "fixtures",
        "schema_version",
        "schemas",
    }:
        raise EvidenceRejection("contract_bundle_identity_mismatch")
    phase07_manifest = {
        **manifest,
        "schemas": _project_manifest_section(
            manifest["schemas"],
            entry_kind="schema",
            phase07_paths=PHASE07_SCHEMA_PATHS,
            phase08_paths=PHASE08_SCHEMA_PATHS,
            phase09_paths=PHASE09_SCHEMA_PATHS,
            phase10_paths=PHASE10_SCHEMA_PATHS,
            phase11_paths=PHASE11_SCHEMA_PATHS,
            phase12_paths=PHASE12_SCHEMA_PATHS,
            phase13_paths=PHASE13_SCHEMA_PATHS,
            code="contract_bundle_identity_mismatch",
        ),
        "fixtures": _project_manifest_section(
            manifest["fixtures"],
            entry_kind="fixture",
            phase07_paths=PHASE07_MANIFEST_FIXTURE_PATHS,
            phase08_paths=PHASE08_FIXTURE_PATHS,
            phase09_paths=PHASE09_FIXTURE_PATHS,
            phase10_paths=PHASE10_FIXTURE_PATHS,
            phase11_paths=PHASE11_FIXTURE_PATHS,
            phase12_paths=PHASE12_FIXTURE_PATHS,
            phase13_paths=PHASE13_FIXTURE_PATHS,
            code="contract_bundle_identity_mismatch",
        ),
    }
    if sha256_hex(canonicalize(phase07_manifest)) != PHASE07_BUNDLE_PROJECTION_SHA256:
        raise EvidenceRejection("contract_bundle_identity_mismatch")
    if not isinstance(fixture_index, dict) or set(fixture_index) != {
        "schema_version",
        "sources",
    }:
        raise EvidenceRejection("fixture_index_identity_mismatch")
    projected_sources = _project_fixture_sources(fixture_index["sources"])
    _require_phase10_fixture_cross_match(manifest["fixtures"], fixture_index["sources"])
    _require_phase11_fixture_cross_match(manifest["fixtures"], fixture_index["sources"])
    _require_phase12_fixture_cross_match(manifest["fixtures"], fixture_index["sources"])
    _require_phase13_fixture_cross_match(manifest["fixtures"], fixture_index["sources"])
    phase07_index = {
        **fixture_index,
        "sources": projected_sources,
    }
    if sha256_hex(canonicalize(phase07_index)) != PHASE07_FIXTURE_PROJECTION_SHA256:
        raise EvidenceRejection("fixture_index_identity_mismatch")
    return root


def _load_authenticated_config() -> Mapping[str, Any]:
    repository_root = _authenticated_repository_root()
    path = repository_root / "config" / "evidence-authority.json"
    try:
        raw = path.resolve(strict=True).read_bytes()
    except OSError as error:
        raise EvidenceRejection("evidence_config_unavailable") from error
    return _validate_evidence_config(raw)


def _validate_evidence_config(raw: bytes) -> Mapping[str, Any]:
    try:
        value = parse_raw_json(raw)
    except Exception as error:
        raise EvidenceRejection("evidence_config_invalid") from error
    if sha256_hex(canonicalize(value)) != EVIDENCE_AUTHORITY_CONFIG_SHA256:
        raise EvidenceRejection("evidence_config_identity_mismatch")
    if (
        not isinstance(value, dict)
        or set(value)
        != {"allowed_root_mode", "authority_id", "boundaries", "schema_version"}
        or value.get("schema_version") != EVIDENCE_AUTHORITY_CONFIG_VERSION
        or value.get("authority_id") != EVIDENCE_AUTHORITY_ID
        or value.get("allowed_root_mode") != "os_temporary_fixture_only"
        or value.get("boundaries") != list(USE_BOUNDARIES)
    ):
        raise EvidenceRejection("evidence_config_invalid")
    return MappingProxyType(
        {
            "allowed_root_mode": value["allowed_root_mode"],
            "authority_id": value["authority_id"],
            "boundaries": tuple(value["boundaries"]),
            "schema_version": value["schema_version"],
        }
    )


def _authenticate_fixture_records(
    registry: SchemaRegistry,
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    authenticated: dict[str, Mapping[str, Any]] = {}
    for record in records:
        identifier = record.get("id")
        schema_id = record.get("schema_id")
        payload = record.get("payload")
        if not isinstance(identifier, str) or not isinstance(schema_id, str) or not isinstance(payload, dict):
            raise EvidenceRejection("fixture_record_malformed")
        try:
            published = registry.fixture(identifier)
        except KeyError as error:
            raise EvidenceRejection("fixture_record_unauthenticated") from error
        if canonicalize(dict(record)) != canonicalize(dict(published)):
            raise EvidenceRejection("fixture_record_identity_mismatch")
        document = registry.validate_raw(canonicalize(payload), schema_id)
        if document.canonical_sha256 != record.get("source_sha256"):
            raise EvidenceRejection("fixture_payload_identity_mismatch")
        copied = parse_raw_json(canonicalize(dict(record)))
        if not isinstance(copied, dict):
            raise EvidenceRejection("fixture_record_malformed")
        authenticated[identifier] = MappingProxyType(copied)
    return authenticated


def _assert_permitted_ingest(
    rights: Mapping[str, Any], legal: Mapping[str, Any]
) -> None:
    if legal.get("automation_grant") != "local_processing_only":
        raise EvidenceRejection("acquisition_not_authorized")
    if rights.get("status") != "active":
        raise EvidenceRejection("rights_revoked")
    boundaries = rights.get("boundaries")
    if not isinstance(boundaries, dict) or set(boundaries) != {
        "activation", "backup", "evaluation", "export", "ingest", "prompt", "retrieval", "training"
    }:
        raise EvidenceRejection("rights_record_incomplete")
    if boundaries.get("ingest") is not True:
        raise EvidenceRejection("rights_incompatible")
    if rights.get("processing_boundary") != "local_only" or rights.get("destination") != "local_owner_system":
        raise EvidenceRejection("external_transmission_not_authorized")


def _rights_decision(
    *,
    request_id: str,
    legal_terms_id: str,
    rights_record_id: str,
    disposition: str,
    reason_code: str,
) -> dict[str, Any]:
    decision: dict[str, Any] = {
        "schema_version": "skeleton.rights-use-decision.v1",
        "decision_id": "0" * 64,
        "request_id": request_id,
        "legal_terms_id": legal_terms_id,
        "rights_record_id": rights_record_id,
        "boundary": "ingest",
        "processing_boundary": "local_only",
        "destination": "local_owner_system",
        "decision": disposition,
        "reason_code": reason_code,
        "decided_at": "2026-08-01T12:00:00Z",
    }
    decision["decision_id"] = _digest_value(
        "rights-decision", _without(decision, "decision_id")
    )
    return decision


def _decision_bytes(decision: RightsDecision, *, redacted: bool) -> bytes:
    value: dict[str, Any] = {
        "schema_version": "skeleton.internal-rights-decision.v1",
        "decision_id": decision.decision_id,
        "request_id": decision.request_id,
        "legal_terms_id": decision.legal_terms_id,
        "rights_record_id": decision.rights_record_id,
        "boundary": decision.boundary.value,
        "decision": decision.disposition,
        "reason_code": decision.reason_code,
        "decided_at": decision.decided_at,
        "evaluator_version": decision.evaluator_version,
    }
    if not redacted:
        value.update(
            {
                "subject_sha256": decision.subject_sha256,
                "evidence_sha256": decision.evidence_sha256,
                "purpose": decision.purpose,
                "territory": decision.territory,
                "display": decision.display,
                "storage": decision.storage,
                "derivation": decision.derivation,
                "training": decision.training,
                "transmission": decision.transmission,
                "backup": decision.backup,
                "attribution": decision.attribution,
                "retention": decision.retention,
                "deletion": decision.deletion,
                "audit": decision.audit,
                "termination": decision.termination,
                "acquisition_method": decision.acquisition_method,
                "processing_boundary": decision.processing_boundary,
                "destination": decision.destination,
            }
        )
    return canonicalize(value)


def _without(value: Mapping[str, Any], key: str) -> dict[str, Any]:
    return {name: item for name, item in value.items() if name != key}


def _digest_value(domain: str, value: Any) -> str:
    return sha256_hex(domain.encode("ascii") + b"\0" + canonicalize(value))


def _digest_label(domain: str, value: str) -> str:
    return sha256_hex(domain.encode("ascii") + b"\0" + value.encode("utf-8"))


def _count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])


def _require_temporary_root(root: Path) -> Path:
    temporary = Path(tempfile.gettempdir()).resolve(strict=True)
    candidate = Path(root).resolve(strict=True)
    if candidate == temporary or temporary not in candidate.parents:
        raise EvidenceRejection("evidence_root_not_temporary_child")
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current /= part
        metadata = current.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if current.is_symlink() or getattr(os.path, "isjunction", lambda _: False)(current) or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise EvidenceRejection("evidence_root_reparse_forbidden")
    if not candidate.is_dir():
        raise EvidenceRejection("evidence_root_not_directory")
    return candidate


def _root_sha256(root: Path) -> str:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink() or getattr(os.path, "isjunction", lambda _: False)(path):
            raise EvidenceRejection("evidence_root_reparse_forbidden")
        if path.is_file():
            raw = path.read_bytes()
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": len(raw),
                    "sha256": sha256_hex(raw),
                }
            )
    return sha256_hex(canonicalize(records))
