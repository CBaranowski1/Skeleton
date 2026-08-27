// Generated deterministically from contracts/v1/bundle-manifest.json.
// Do not edit by hand.

export type CanonicalUint64 = string & { readonly __canonicalUint64: unique symbol };
export type Ed25519Signature = string & { readonly __ed25519Signature: unique symbol };

export interface SkeletonAdvisoryProposalEnvelopeV1 {
  readonly "signature_protocol_version": 1;
  readonly "object_class": "advisory_proposal";
  readonly "signature_domain": "skeleton.advisory-proposal.v1";
  readonly "signer_key_id": unknown;
  readonly "signer_set_epoch": unknown;
  readonly "body": unknown;
  readonly "signature": unknown;
}

export interface SkeletonAuthorityCommandV1 {
  readonly "schema_version": "skeleton.authority-command.v1";
  readonly "authority_domain": unknown;
  readonly "command_id": unknown;
  readonly "expected_state_sha256": unknown;
  readonly "lifecycle_effect": "activate" | "deactivate" | "pause" | "resume" | "revoke";
  readonly "authorization_id": unknown;
  readonly "requested_at": string;
}

export interface SkeletonD25AuthorityResultEnvelopeV1 {
  readonly "signature_protocol_version": 1;
  readonly "object_class": "authority_result";
  readonly "signature_domain": "skeleton.authority-result.v1";
  readonly "signer_key_id": unknown;
  readonly "signer_set_epoch": unknown;
  readonly "body": unknown;
  readonly "signature": unknown;
}

export interface SkeletonCanonicalEventV1 {
  readonly "schema_version": "skeleton.canonical-event.v1";
  readonly "event_id": unknown;
  readonly "source_time": unknown;
  readonly "received_at": unknown;
  readonly "ingested_at": unknown;
  readonly "available_at": unknown;
  readonly "effective_at": unknown;
  readonly "stable_identity_id": unknown;
  readonly "stable_identity_version": unknown;
  readonly "venue": unknown;
  readonly "market": unknown;
  readonly "sequence_state": "resolved" | "unresolved";
  readonly "sequence": unknown;
  readonly "correction_of": unknown;
  readonly "quality": "backfilled" | "contaminated" | "corrected" | "legacy" | "provider_reported" | "synthetic" | "unknown";
  readonly "mode": "evaluation" | "fixture" | "historical" | "paper" | "simulation";
  readonly "rights_record_id": unknown;
  readonly "rights_decision_id": unknown;
  readonly "parser_version": unknown;
  readonly "parser_code_sha256": unknown;
  readonly "raw_sha256": unknown;
  readonly "payload_sha256": unknown;
}

export interface SkeletonConstitutionEnvelopeV1 {
  readonly "signature_protocol_version": 1;
  readonly "object_class": "constitution";
  readonly "signature_domain": "skeleton.constitution.v1";
  readonly "signer_key_id": unknown;
  readonly "signer_set_epoch": unknown;
  readonly "body": unknown;
  readonly "signature": unknown;
}

export interface SkeletonAuthorizedRecoverableDeletionExecutionV1 {
  readonly "schema_version": "skeleton.deletion-execution.v1";
  readonly "execution_id": unknown;
  readonly "preview_sha256": unknown;
  readonly "graph_sha256": unknown;
  readonly "pre_state_sha256": unknown;
  readonly "authorization": unknown;
  readonly "authorization_decision_sha256": unknown;
  readonly "reauthentication_proof_sha256": unknown;
  readonly "hold_verdict": "clear" | "active" | "unknown";
  readonly "backup_disposition": "destroy_authorized_copy" | "retain_under_hold" | "not_applicable" | "unknown";
  readonly "recovery_state": "received" | "in_progress" | "incomplete" | "terminal";
  readonly "items": readonly unknown[];
  readonly "completion_result": unknown;
  readonly "completed_result_sha256": unknown;
}

export interface SkeletonNonMutatingDeletionPreviewV1 {
  readonly "schema_version": "skeleton.deletion-preview.v1";
  readonly "preview_id": unknown;
  readonly "preview_bytes_sha256": unknown;
  readonly "subject_content_sha256": unknown;
  readonly "graph_sha256": unknown;
  readonly "pre_state_sha256": unknown;
  readonly "descendant_classes": readonly unknown[];
  readonly "descendants": readonly unknown[];
  readonly "blockers": readonly unknown[];
  readonly "holds": readonly unknown[];
  readonly "backup_requirements": readonly unknown[];
  readonly "canonical_order": unknown;
}

export interface SkeletonRedactedEvidenceHealthSnapshotV1 {
  readonly "schema_version": "skeleton.evidence-health.v1";
  readonly "snapshot_sha256": unknown;
  readonly "source_state_sha256": unknown;
  readonly "readiness": "ready" | "degraded" | "unknown" | "unavailable";
  readonly "observed_at": string;
  readonly "signals": unknown;
}

export interface SkeletonExactEvidenceManifestV1 {
  readonly "schema_version": unknown;
  readonly "manifest_id": unknown;
  readonly "objects": unknown;
  readonly "partitions": unknown;
  readonly "schema_bindings": unknown;
  readonly "calendar_facts": unknown;
  readonly "identities": unknown;
  readonly "universe_events": unknown;
  readonly "reference_facts": unknown;
  readonly "corrections": unknown;
  readonly "exclusions": unknown;
  readonly "rights_decisions"?: unknown;
  readonly "rights_bindings": unknown;
  readonly "code": unknown;
  readonly "compression": unknown;
  readonly "reconstruction": unknown;
  readonly "outputs": unknown;
  readonly "canonical_order": unknown;
}

export interface SkeletonExperienceEnvelopeV1 {
  readonly "schema_version": "skeleton.experience-envelope.v1";
  readonly "experience_id": unknown;
  readonly "project_id": unknown;
  readonly "work_id": unknown;
  readonly "observed_at": unknown;
  readonly "outcome": "abstained" | "completed" | "failed" | "partial";
  readonly "observations": readonly unknown[];
}

export interface SkeletonIdentityFactV1 {
  readonly "schema_version": "skeleton.identity-fact.v1";
  readonly "fact_id": unknown;
  readonly "stable_identity_id": unknown;
  readonly "fact_kind": "alias" | "contract" | "corporate_action" | "fork" | "lifecycle" | "name" | "provider_identifier" | "roll" | "team" | "venue";
  readonly "fact_state": "resolved" | "superseded";
  readonly "provider": unknown;
  readonly "value": unknown;
  readonly "effective_from": unknown;
  readonly "effective_to": unknown;
  readonly "available_at": unknown;
  readonly "supersedes_fact_id"?: unknown;
}

export interface SkeletonAdditiveReadOnlyKernelStatusV2 {
  readonly "schema_version": "skeleton.kernel-status.v2";
  readonly "kernel_status_v1_sha256": unknown;
  readonly "evidence_health": unknown;
  readonly "observed_at": unknown;
}

export interface SkeletonTruthfulKernelStatusV1 {
  readonly "schema_version": "skeleton.kernel-status.v1";
  readonly "product_identity": "skeleton.private-single-owner";
  readonly "bundle_sha256": unknown;
  readonly "semantic_state_hash": unknown;
  readonly "journal_state_hash": unknown;
  readonly "authority_snapshot_hash": unknown;
  readonly "incomplete_journal_disposition": "idle" | "RECEIVED" | "EFFECT_COMMITTED" | "RESULT_COMMITTED";
  readonly "authority_process_health": "available" | "degraded" | "unavailable";
  readonly "cognition_process_health": "available" | "degraded" | "unavailable";
  readonly "lobe_count": number;
  readonly "capabilities": readonly unknown[];
  readonly "observed_at": string;
}

export interface SkeletonLegalTermsRecordV1 {
  readonly "schema_version": "skeleton.legal-terms-record.v1";
  readonly "legal_terms_id": unknown;
  readonly "provider": unknown;
  readonly "jurisdiction": string;
  readonly "acquisition_method": "documented_api" | "licensed_file" | "owner_download" | "provided_fixture" | "public_viewable" | "undocumented_endpoint";
  readonly "automation_grant": "exact_recorded_automation" | "local_processing_only" | "prohibited";
  readonly "effective_from": unknown;
  readonly "effective_to": unknown;
  readonly "recorded_at"?: unknown;
  readonly "terms_sha256": unknown;
}

export interface SkeletonLifecycleEventV1 {
  readonly "schema_version": "skeleton.lifecycle-event.v1";
  readonly "event_id": unknown;
  readonly "subject": unknown;
  readonly "prior_state": unknown;
  readonly "new_state": unknown;
  readonly "cause": unknown;
  readonly "authorization": unknown;
  readonly "occurred_at": unknown;
  readonly "event_sha256": unknown;
}

export interface SkeletonClosedArtifactLineageRecordV1 {
  readonly "schema_version": "skeleton.lineage-record.v1";
  readonly "lineage_id": unknown;
  readonly "subject_artifact_id": unknown;
  readonly "graph_sha256": unknown;
  readonly "nodes": readonly unknown[];
  readonly "edges": readonly unknown[];
  readonly "canonical_order": unknown;
}

export interface SkeletonLobePackageV1 {
  readonly "schema_version": "skeleton.lobe-package.v1";
  readonly "package_id": unknown;
  readonly "package_version": string;
  readonly "package_sha256": unknown;
  readonly "contracts": readonly unknown[];
  readonly "senses": unknown;
  readonly "tools": unknown;
  readonly "capabilities": readonly unknown[];
  readonly "permissions": Readonly<Record<string, unknown>>;
  readonly "memory_namespaces": unknown;
  readonly "evaluators": unknown;
  readonly "workflows": unknown;
  readonly "migrations": readonly unknown[];
  readonly "uninstall": Readonly<Record<string, unknown>>;
}

export interface SkeletonD25MaterialAuthorizationEnvelopeV1 {
  readonly "signature_protocol_version": 1;
  readonly "object_class": "authority_grant";
  readonly "signature_domain": "skeleton.authority-grant.v1";
  readonly "signer_key_id": unknown;
  readonly "signer_set_epoch": unknown;
  readonly "body": unknown;
  readonly "signature": unknown;
}

export interface SkeletonContractPrimitivesV1 {
}

export interface SkeletonProjectManifestV1 {
  readonly "schema_version": "skeleton.project-manifest.v1";
  readonly "project_id": unknown;
  readonly "constitution_sha256": unknown;
  readonly "lobe_set_sha256": unknown;
  readonly "lobe_packages": readonly unknown[];
  readonly "environment_identity": Readonly<Record<string, unknown>>;
  readonly "goals": readonly unknown[];
  readonly "dependencies": readonly unknown[];
  readonly "state_namespace": unknown;
  readonly "requested_capabilities": readonly unknown[];
}

export interface SkeletonPointInTimeReferenceFactV1 {
  readonly "schema_version": "skeleton.reference-fact.v1";
  readonly "fact_id": unknown;
  readonly "stable_identity_id": unknown;
  readonly "fact_kind": "calendar" | "corporate_action" | "currency" | "early_close" | "fork" | "holiday" | "lifecycle" | "lot_size" | "multiplier" | "resolution_rule" | "roll" | "session" | "settlement" | "tick_size" | "timezone" | "unit" | "void_rule";
  readonly "fact_state": "resolved" | "superseded" | "unresolved";
  readonly "applicability": "applicable" | "not_applicable" | "unresolved";
  readonly "value": unknown;
  readonly "reason_code"?: "not_applicable_by_definition" | "not_applicable_for_identity" | "unresolved_calendar" | "unresolved_clock" | "unresolved_currency" | "unresolved_identity_mapping" | "unresolved_lifecycle" | "unresolved_sequence" | "unresolved_settlement" | "unresolved_timezone" | "unresolved_unit";
  readonly "effective_from": unknown;
  readonly "effective_to": unknown;
  readonly "available_at": unknown;
  readonly "supersedes_fact_id"?: unknown;
}

export interface SkeletonTypedRejectionV1 {
  readonly "schema_version": "skeleton.rejection.v1";
  readonly "rejection_id": unknown;
  readonly "subject_class": "advisory_proposal" | "authority_grant" | "authority_result" | "constitution" | "experience_envelope" | "lifecycle_event" | "unknown" | "work_object";
  readonly "subject_id": unknown;
  readonly "reason_code": "authorization_denied" | "cross_class" | "expired" | "framing_ambiguous" | "hash_mismatch" | "malformed_signature_wire" | "replayed" | "schema_invalid" | "signature_invalid" | "signer_epoch_mismatch" | "signer_key_mismatch" | "signer_revoked" | "state_conflict" | "unknown_signature_protocol";
  readonly "validation_stage": "authorization" | "framing" | "freshness" | "raw_bytes" | "replay" | "schema" | "signature" | "state";
  readonly "occurred_at": unknown;
  readonly "retryable": boolean;
}

export interface SkeletonRightsRecordV1 {
  readonly "schema_version": "skeleton.rights-record.v1";
  readonly "rights_record_id": unknown;
  readonly "legal_terms_id": unknown;
  readonly "status": "active" | "expired" | "revoked" | "superseded" | "terminated" | "unknown";
  readonly "effective_from": unknown;
  readonly "effective_to": unknown;
  readonly "boundaries": unknown;
  readonly "processing_boundary": unknown;
  readonly "destination": unknown;
}

export interface SkeletonRightsUseDecisionV1 {
  readonly "schema_version": "skeleton.rights-use-decision.v1";
  readonly "decision_id": unknown;
  readonly "request_id": unknown;
  readonly "legal_terms_id": unknown;
  readonly "rights_record_id": unknown;
  readonly "boundary": unknown;
  readonly "processing_boundary": unknown;
  readonly "destination": unknown;
  readonly "decision": "deny" | "permit";
  readonly "reason_code": "acquisition_not_authorized" | "decision_ambiguous" | "external_transmission_not_authorized" | "rights_decision_boundary_mismatch" | "rights_expired" | "rights_incompatible" | "rights_record_incomplete" | "rights_record_missing" | "rights_revoked" | "rights_unknown" | "terms_and_rights_match" | "unresolved_counsel_question";
  readonly "decided_at": unknown;
}

export interface SkeletonRightsUseRequestV1 {
  readonly "schema_version": "skeleton.rights-use-request.v1";
  readonly "request_id": unknown;
  readonly "subject": unknown;
  readonly "evidence_sha256": unknown;
  readonly "boundary": unknown;
  readonly "processing_boundary": unknown;
  readonly "destination": unknown;
  readonly "requested_at": unknown;
}

export interface SkeletonStableIdentityV1 {
  readonly "schema_version": "skeleton.stable-identity.v1";
  readonly "stable_identity_id": unknown;
  readonly "genesis_content_sha256": unknown;
  readonly "genesis_time": unknown;
  readonly "identity_kind": "asset" | "contract" | "instrument" | "organization" | "team" | "venue";
  readonly "version": unknown;
}

export interface SkeletonPointInTimeUniverseEventV1 {
  readonly "schema_version": "skeleton.universe-event.v1";
  readonly "event_id": unknown;
  readonly "universe_id": unknown;
  readonly "stable_identity_id": unknown;
  readonly "action": "delist" | "enter" | "exit" | "rename" | "restore" | "unavailable";
  readonly "reason": unknown;
  readonly "effective_at": unknown;
  readonly "available_at": unknown;
  readonly "supersedes_event_id"?: unknown;
}

export interface SkeletonWorkObjectV1 {
  readonly "schema_version": "skeleton.work-object.v1";
  readonly "work_id": unknown;
  readonly "project_id": unknown;
  readonly "work_kind": "evaluate" | "observe" | "plan" | "review" | "transform";
  readonly "objective": string;
  readonly "input_evidence": readonly unknown[];
}

export type SkeletonSchemaId = "https://schemas.skeleton.local/v1/advisory-proposal.schema.json" | "https://schemas.skeleton.local/v1/authority-command.schema.json" | "https://schemas.skeleton.local/v1/authority-result.schema.json" | "https://schemas.skeleton.local/v1/canonical-event.schema.json" | "https://schemas.skeleton.local/v1/constitution.schema.json" | "https://schemas.skeleton.local/v1/deletion-execution.schema.json" | "https://schemas.skeleton.local/v1/deletion-preview.schema.json" | "https://schemas.skeleton.local/v1/evidence-health.schema.json" | "https://schemas.skeleton.local/v1/evidence-manifest.schema.json" | "https://schemas.skeleton.local/v1/experience-envelope.schema.json" | "https://schemas.skeleton.local/v1/identity-fact.schema.json" | "https://schemas.skeleton.local/v1/kernel-status-v2.schema.json" | "https://schemas.skeleton.local/v1/kernel-status.schema.json" | "https://schemas.skeleton.local/v1/legal-terms-record.schema.json" | "https://schemas.skeleton.local/v1/lifecycle-event.schema.json" | "https://schemas.skeleton.local/v1/lineage-record.schema.json" | "https://schemas.skeleton.local/v1/lobe-package.schema.json" | "https://schemas.skeleton.local/v1/material-authorization.schema.json" | "https://schemas.skeleton.local/v1/primitives.schema.json" | "https://schemas.skeleton.local/v1/project-manifest.schema.json" | "https://schemas.skeleton.local/v1/reference-fact.schema.json" | "https://schemas.skeleton.local/v1/rejection.schema.json" | "https://schemas.skeleton.local/v1/rights-record.schema.json" | "https://schemas.skeleton.local/v1/rights-use-decision.schema.json" | "https://schemas.skeleton.local/v1/rights-use-request.schema.json" | "https://schemas.skeleton.local/v1/stable-identity.schema.json" | "https://schemas.skeleton.local/v1/universe-event.schema.json" | "https://schemas.skeleton.local/v1/work-object.schema.json";

export interface SkeletonContractBySchemaId {
  readonly "https://schemas.skeleton.local/v1/advisory-proposal.schema.json": SkeletonAdvisoryProposalEnvelopeV1;
  readonly "https://schemas.skeleton.local/v1/authority-command.schema.json": SkeletonAuthorityCommandV1;
  readonly "https://schemas.skeleton.local/v1/authority-result.schema.json": SkeletonD25AuthorityResultEnvelopeV1;
  readonly "https://schemas.skeleton.local/v1/canonical-event.schema.json": SkeletonCanonicalEventV1;
  readonly "https://schemas.skeleton.local/v1/constitution.schema.json": SkeletonConstitutionEnvelopeV1;
  readonly "https://schemas.skeleton.local/v1/deletion-execution.schema.json": SkeletonAuthorizedRecoverableDeletionExecutionV1;
  readonly "https://schemas.skeleton.local/v1/deletion-preview.schema.json": SkeletonNonMutatingDeletionPreviewV1;
  readonly "https://schemas.skeleton.local/v1/evidence-health.schema.json": SkeletonRedactedEvidenceHealthSnapshotV1;
  readonly "https://schemas.skeleton.local/v1/evidence-manifest.schema.json": SkeletonExactEvidenceManifestV1;
  readonly "https://schemas.skeleton.local/v1/experience-envelope.schema.json": SkeletonExperienceEnvelopeV1;
  readonly "https://schemas.skeleton.local/v1/identity-fact.schema.json": SkeletonIdentityFactV1;
  readonly "https://schemas.skeleton.local/v1/kernel-status-v2.schema.json": SkeletonAdditiveReadOnlyKernelStatusV2;
  readonly "https://schemas.skeleton.local/v1/kernel-status.schema.json": SkeletonTruthfulKernelStatusV1;
  readonly "https://schemas.skeleton.local/v1/legal-terms-record.schema.json": SkeletonLegalTermsRecordV1;
  readonly "https://schemas.skeleton.local/v1/lifecycle-event.schema.json": SkeletonLifecycleEventV1;
  readonly "https://schemas.skeleton.local/v1/lineage-record.schema.json": SkeletonClosedArtifactLineageRecordV1;
  readonly "https://schemas.skeleton.local/v1/lobe-package.schema.json": SkeletonLobePackageV1;
  readonly "https://schemas.skeleton.local/v1/material-authorization.schema.json": SkeletonD25MaterialAuthorizationEnvelopeV1;
  readonly "https://schemas.skeleton.local/v1/primitives.schema.json": SkeletonContractPrimitivesV1;
  readonly "https://schemas.skeleton.local/v1/project-manifest.schema.json": SkeletonProjectManifestV1;
  readonly "https://schemas.skeleton.local/v1/reference-fact.schema.json": SkeletonPointInTimeReferenceFactV1;
  readonly "https://schemas.skeleton.local/v1/rejection.schema.json": SkeletonTypedRejectionV1;
  readonly "https://schemas.skeleton.local/v1/rights-record.schema.json": SkeletonRightsRecordV1;
  readonly "https://schemas.skeleton.local/v1/rights-use-decision.schema.json": SkeletonRightsUseDecisionV1;
  readonly "https://schemas.skeleton.local/v1/rights-use-request.schema.json": SkeletonRightsUseRequestV1;
  readonly "https://schemas.skeleton.local/v1/stable-identity.schema.json": SkeletonStableIdentityV1;
  readonly "https://schemas.skeleton.local/v1/universe-event.schema.json": SkeletonPointInTimeUniverseEventV1;
  readonly "https://schemas.skeleton.local/v1/work-object.schema.json": SkeletonWorkObjectV1;
}

export type KernelStatus = SkeletonTruthfulKernelStatusV1;
export type Constitution = SkeletonConstitutionEnvelopeV1;
export type AdvisoryProposal = SkeletonAdvisoryProposalEnvelopeV1;
export type AuthorityResult = SkeletonD25AuthorityResultEnvelopeV1;
export type AuthorityGrant = SkeletonD25MaterialAuthorizationEnvelopeV1;
export type KernelStatusV2 = SkeletonAdditiveReadOnlyKernelStatusV2;
