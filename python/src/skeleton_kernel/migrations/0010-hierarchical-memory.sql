CREATE TABLE memory_records (
 memory_id TEXT PRIMARY KEY CHECK(length(memory_id)=64 AND memory_id NOT GLOB '*[^0-9a-f]*'),
 memory_kind TEXT NOT NULL CHECK(memory_kind IN ('working','episodic','semantic','procedural','model','audit')),
 semantic_identity_id TEXT NOT NULL CHECK(length(semantic_identity_id)=64 AND semantic_identity_id NOT GLOB '*[^0-9a-f]*'),
 namespace TEXT NOT NULL, lobe_id TEXT NOT NULL, project_id TEXT NOT NULL,
 quality_class TEXT NOT NULL CHECK(quality_class IN ('verified','corrected','provider_reported','backfilled','synthetic','simulated','contaminated','legacy','unknown')),
 provenance_class TEXT NOT NULL CHECK(provenance_class IN ('verified_real','derived_real','owner_asserted','seeded_test','fixture','simulated','synthetic','unknown')),
 initial_quarantine_state TEXT NOT NULL CHECK(initial_quarantine_state IN ('clean','legacy','synthetic','stale','revoked_rights','contaminated','unverifiable')),
 operating_mode TEXT NOT NULL CHECK(operating_mode IN ('evaluation','fixture','historical','offline','paper','research','simulation')),
 model_stage TEXT NOT NULL CHECK(model_stage IN ('none','candidate','challenger','shadow','paper')),
 effective_from TEXT NOT NULL, effective_to TEXT NOT NULL, available_at TEXT NOT NULL, recorded_at TEXT NOT NULL,
 ingest_rights_decision_id TEXT NOT NULL CHECK(length(ingest_rights_decision_id)=64 AND ingest_rights_decision_id NOT GLOB '*[^0-9a-f]*'),
 canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_memory BLOB NOT NULL
) STRICT;

CREATE TABLE memory_evidence_links (
 memory_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0), evidence_id TEXT NOT NULL CHECK(length(evidence_id)=64 AND evidence_id NOT GLOB '*[^0-9a-f]*'),
 PRIMARY KEY(memory_id,ordinal), UNIQUE(memory_id,evidence_id), FOREIGN KEY(memory_id) REFERENCES memory_records(memory_id)
) STRICT;

CREATE TABLE memory_lineage_links (
 memory_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0), lineage_id TEXT NOT NULL CHECK(length(lineage_id)=64 AND lineage_id NOT GLOB '*[^0-9a-f]*'),
 PRIMARY KEY(memory_id,ordinal), UNIQUE(memory_id,lineage_id), FOREIGN KEY(memory_id) REFERENCES memory_records(memory_id)
) STRICT;

CREATE TABLE memory_corrections (
 child_memory_id TEXT PRIMARY KEY, parent_memory_id TEXT NOT NULL,
 canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_correction BLOB NOT NULL,
 CHECK(child_memory_id<>parent_memory_id), FOREIGN KEY(child_memory_id) REFERENCES memory_records(memory_id), FOREIGN KEY(parent_memory_id) REFERENCES memory_records(memory_id)
) STRICT;

CREATE TABLE memory_contradiction_members (
 contradiction_set_id TEXT NOT NULL CHECK(length(contradiction_set_id)=64 AND contradiction_set_id NOT GLOB '*[^0-9a-f]*'), memory_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 PRIMARY KEY(contradiction_set_id,memory_id), UNIQUE(contradiction_set_id,ordinal), FOREIGN KEY(memory_id) REFERENCES memory_records(memory_id)
) STRICT;

CREATE TABLE memory_working_set_events (
 event_id TEXT PRIMARY KEY CHECK(length(event_id)=64 AND event_id NOT GLOB '*[^0-9a-f]*'), run_id TEXT NOT NULL CHECK(length(run_id)=64 AND run_id NOT GLOB '*[^0-9a-f]*'),
 ordinal INTEGER NOT NULL CHECK(ordinal>=0), memory_id TEXT NOT NULL, event_kind TEXT NOT NULL CHECK(event_kind IN ('opened','item_admitted','sealed','discarded')),
 previous_event_id TEXT, canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_event BLOB NOT NULL,
 UNIQUE(run_id,ordinal), CHECK(previous_event_id IS NULL OR previous_event_id<>event_id), FOREIGN KEY(memory_id) REFERENCES memory_records(memory_id), FOREIGN KEY(previous_event_id) REFERENCES memory_working_set_events(event_id)
) STRICT;

CREATE TABLE memory_audit_chain (
 audit_id TEXT PRIMARY KEY CHECK(length(audit_id)=64 AND audit_id NOT GLOB '*[^0-9a-f]*'), memory_id TEXT NOT NULL UNIQUE, sequence INTEGER NOT NULL UNIQUE CHECK(sequence>=0),
 previous_audit_id TEXT NOT NULL CHECK(length(previous_audit_id)=64 AND previous_audit_id NOT GLOB '*[^0-9a-f]*'),
 operation_kind TEXT NOT NULL CHECK(operation_kind IN ('owner_authorization','tool_call','policy_decision','proposal','risk_result','execution_outcome','incident','restore')),
 canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_audit BLOB NOT NULL,
 CHECK(previous_audit_id<>audit_id), FOREIGN KEY(memory_id) REFERENCES memory_records(memory_id)
) STRICT;

CREATE TABLE memory_rejection_events (
 rejection_id TEXT PRIMARY KEY CHECK(length(rejection_id)=64 AND rejection_id NOT GLOB '*[^0-9a-f]*'), source_event_id TEXT NOT NULL CHECK(length(source_event_id)=64 AND source_event_id NOT GLOB '*[^0-9a-f]*'),
 category TEXT NOT NULL, detector_version TEXT NOT NULL, rule_id TEXT NOT NULL, disposition TEXT NOT NULL CHECK(disposition IN ('rejected','quarantined')),
 writer_sequence INTEGER NOT NULL UNIQUE CHECK(writer_sequence>=0), nonce_id TEXT NOT NULL CHECK(length(nonce_id)=64 AND nonce_id NOT GLOB '*[^0-9a-f]*'), recorded_at TEXT NOT NULL
) STRICT;

CREATE TABLE memory_operation_ledger (
 operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=64 AND operation_id NOT GLOB '*[^0-9a-f]*'),
 operation_kind TEXT NOT NULL CHECK(operation_kind IN ('admission','correction','working_terminal','audit','rejection','retrieval','quarantine','integrity','rebuild')),
 subject_id TEXT NOT NULL CHECK(length(subject_id)=64 AND subject_id NOT GLOB '*[^0-9a-f]*'), operation_root TEXT NOT NULL CHECK(length(operation_root)=64 AND operation_root NOT GLOB '*[^0-9a-f]*'),
 item_count INTEGER NOT NULL CHECK(item_count>=0), canonical_operation BLOB NOT NULL
) STRICT;

CREATE TABLE memory_quarantine_decisions (
 decision_id TEXT PRIMARY KEY CHECK(length(decision_id)=64 AND decision_id NOT GLOB '*[^0-9a-f]*'), subject_memory_id TEXT NOT NULL,
 decision_kind TEXT NOT NULL CHECK(decision_kind IN ('quarantined','recovery_descendant_verified')), finding_id TEXT NOT NULL CHECK(length(finding_id)=64 AND finding_id NOT GLOB '*[^0-9a-f]*'),
 run_id TEXT NOT NULL CHECK(length(run_id)=64 AND run_id NOT GLOB '*[^0-9a-f]*'), descendant_memory_id TEXT,
 canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_decision BLOB NOT NULL,
 CHECK((decision_kind='quarantined' AND descendant_memory_id IS NULL) OR (decision_kind='recovery_descendant_verified' AND descendant_memory_id IS NOT NULL AND descendant_memory_id<>subject_memory_id)),
 FOREIGN KEY(subject_memory_id) REFERENCES memory_records(memory_id), FOREIGN KEY(descendant_memory_id) REFERENCES memory_records(memory_id)
) STRICT;

CREATE TABLE memory_integrity_runs (
 run_id TEXT PRIMARY KEY CHECK(length(run_id)=64 AND run_id NOT GLOB '*[^0-9a-f]*'), subject_manifest_root TEXT NOT NULL CHECK(length(subject_manifest_root)=64 AND subject_manifest_root NOT GLOB '*[^0-9a-f]*'),
 terminal_count INTEGER NOT NULL CHECK(terminal_count>=0), canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_run BLOB NOT NULL
) STRICT;

CREATE TABLE memory_integrity_findings (
 finding_id TEXT PRIMARY KEY CHECK(length(finding_id)=64 AND finding_id NOT GLOB '*[^0-9a-f]*'), run_id TEXT NOT NULL, subject_memory_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 finding_status TEXT NOT NULL CHECK(finding_status IN ('healthy','exact_duplicate','contradiction_member','quarantined')), defect_code TEXT NOT NULL,
 canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_finding BLOB NOT NULL,
 UNIQUE(run_id,ordinal), UNIQUE(run_id,subject_memory_id), FOREIGN KEY(run_id) REFERENCES memory_integrity_runs(run_id), FOREIGN KEY(subject_memory_id) REFERENCES memory_records(memory_id)
) STRICT;

CREATE TABLE memory_candidate_snapshots (
 snapshot_id TEXT PRIMARY KEY CHECK(length(snapshot_id)=64 AND snapshot_id NOT GLOB '*[^0-9a-f]*'), candidate_root TEXT NOT NULL CHECK(length(candidate_root)=64 AND candidate_root NOT GLOB '*[^0-9a-f]*'),
 candidate_count INTEGER NOT NULL CHECK(candidate_count>=0), canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_snapshot BLOB NOT NULL
) STRICT;

CREATE TABLE memory_candidate_members (
 snapshot_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0), memory_id TEXT NOT NULL,
 PRIMARY KEY(snapshot_id,ordinal), UNIQUE(snapshot_id,memory_id), FOREIGN KEY(snapshot_id) REFERENCES memory_candidate_snapshots(snapshot_id), FOREIGN KEY(memory_id) REFERENCES memory_records(memory_id)
) STRICT;

CREATE TABLE memory_retrieval_results (
 result_id TEXT PRIMARY KEY CHECK(length(result_id)=64 AND result_id NOT GLOB '*[^0-9a-f]*'), snapshot_id TEXT NOT NULL,
 query_root TEXT NOT NULL CHECK(length(query_root)=64 AND query_root NOT GLOB '*[^0-9a-f]*'), integrity_snapshot_id TEXT NOT NULL CHECK(length(integrity_snapshot_id)=64 AND integrity_snapshot_id NOT GLOB '*[^0-9a-f]*'),
 rank_profile_id TEXT NOT NULL, included_count INTEGER NOT NULL CHECK(included_count>=0), excluded_count INTEGER NOT NULL CHECK(excluded_count>=0), used_items INTEGER NOT NULL CHECK(used_items>=0), used_bytes INTEGER NOT NULL CHECK(used_bytes>=0),
 ledger_root TEXT NOT NULL CHECK(length(ledger_root)=64 AND ledger_root NOT GLOB '*[^0-9a-f]*'), canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_result BLOB NOT NULL,
 FOREIGN KEY(snapshot_id) REFERENCES memory_candidate_snapshots(snapshot_id)
) STRICT;

CREATE TABLE memory_retrieval_ledger_items (
 result_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0), memory_id TEXT NOT NULL,
 disposition TEXT NOT NULL CHECK(disposition IN ('included','excluded')), reason_code TEXT NOT NULL, rank_factors BLOB NOT NULL,
 PRIMARY KEY(result_id,ordinal), UNIQUE(result_id,memory_id), FOREIGN KEY(result_id) REFERENCES memory_retrieval_results(result_id), FOREIGN KEY(memory_id) REFERENCES memory_records(memory_id)
) STRICT;

CREATE TABLE memory_rebuild_runs (
 run_id TEXT PRIMARY KEY CHECK(length(run_id)=64 AND run_id NOT GLOB '*[^0-9a-f]*'), terminal_status TEXT NOT NULL CHECK(terminal_status IN ('verified','failed')),
 source_manifest_root TEXT NOT NULL CHECK(length(source_manifest_root)=64 AND source_manifest_root NOT GLOB '*[^0-9a-f]*'), result_root TEXT NOT NULL CHECK(length(result_root)=64 AND result_root NOT GLOB '*[^0-9a-f]*'),
 first_divergence_code TEXT NOT NULL, metric_count INTEGER NOT NULL CHECK(metric_count>=0), canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'), canonical_run BLOB NOT NULL
) STRICT;

CREATE TABLE memory_rebuild_metrics (
 run_id TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 metric_name TEXT NOT NULL CHECK(metric_name IN ('candidate_count','included_count','excluded_count','used_items','used_bytes','latency_microseconds','coverage_basis_points')),
 expected_value TEXT NOT NULL, observed_value TEXT NOT NULL, absolute_difference TEXT NOT NULL, tolerance TEXT NOT NULL, verdict TEXT NOT NULL CHECK(verdict IN ('pass','fail')),
 PRIMARY KEY(run_id,ordinal), UNIQUE(run_id,metric_name), FOREIGN KEY(run_id) REFERENCES memory_rebuild_runs(run_id)
) STRICT;

CREATE TRIGGER memory_records_no_update BEFORE UPDATE ON memory_records BEGIN SELECT RAISE(ABORT,'append_only:memory_records'); END;
CREATE TRIGGER memory_records_no_delete BEFORE DELETE ON memory_records BEGIN SELECT RAISE(ABORT,'append_only:memory_records'); END;
CREATE TRIGGER memory_evidence_links_no_update BEFORE UPDATE ON memory_evidence_links BEGIN SELECT RAISE(ABORT,'append_only:memory_evidence_links'); END;
CREATE TRIGGER memory_evidence_links_no_delete BEFORE DELETE ON memory_evidence_links BEGIN SELECT RAISE(ABORT,'append_only:memory_evidence_links'); END;
CREATE TRIGGER memory_lineage_links_no_update BEFORE UPDATE ON memory_lineage_links BEGIN SELECT RAISE(ABORT,'append_only:memory_lineage_links'); END;
CREATE TRIGGER memory_lineage_links_no_delete BEFORE DELETE ON memory_lineage_links BEGIN SELECT RAISE(ABORT,'append_only:memory_lineage_links'); END;
CREATE TRIGGER memory_corrections_no_update BEFORE UPDATE ON memory_corrections BEGIN SELECT RAISE(ABORT,'append_only:memory_corrections'); END;
CREATE TRIGGER memory_corrections_no_delete BEFORE DELETE ON memory_corrections BEGIN SELECT RAISE(ABORT,'append_only:memory_corrections'); END;
CREATE TRIGGER memory_contradiction_members_no_update BEFORE UPDATE ON memory_contradiction_members BEGIN SELECT RAISE(ABORT,'append_only:memory_contradiction_members'); END;
CREATE TRIGGER memory_contradiction_members_no_delete BEFORE DELETE ON memory_contradiction_members BEGIN SELECT RAISE(ABORT,'append_only:memory_contradiction_members'); END;
CREATE TRIGGER memory_working_set_events_no_update BEFORE UPDATE ON memory_working_set_events BEGIN SELECT RAISE(ABORT,'append_only:memory_working_set_events'); END;
CREATE TRIGGER memory_working_set_events_no_delete BEFORE DELETE ON memory_working_set_events BEGIN SELECT RAISE(ABORT,'append_only:memory_working_set_events'); END;
CREATE TRIGGER memory_audit_chain_no_update BEFORE UPDATE ON memory_audit_chain BEGIN SELECT RAISE(ABORT,'append_only:memory_audit_chain'); END;
CREATE TRIGGER memory_audit_chain_no_delete BEFORE DELETE ON memory_audit_chain BEGIN SELECT RAISE(ABORT,'append_only:memory_audit_chain'); END;
CREATE TRIGGER memory_rejection_events_no_update BEFORE UPDATE ON memory_rejection_events BEGIN SELECT RAISE(ABORT,'append_only:memory_rejection_events'); END;
CREATE TRIGGER memory_rejection_events_no_delete BEFORE DELETE ON memory_rejection_events BEGIN SELECT RAISE(ABORT,'append_only:memory_rejection_events'); END;
CREATE TRIGGER memory_operation_ledger_no_update BEFORE UPDATE ON memory_operation_ledger BEGIN SELECT RAISE(ABORT,'append_only:memory_operation_ledger'); END;
CREATE TRIGGER memory_operation_ledger_no_delete BEFORE DELETE ON memory_operation_ledger BEGIN SELECT RAISE(ABORT,'append_only:memory_operation_ledger'); END;
CREATE TRIGGER memory_quarantine_decisions_no_update BEFORE UPDATE ON memory_quarantine_decisions BEGIN SELECT RAISE(ABORT,'append_only:memory_quarantine_decisions'); END;
CREATE TRIGGER memory_quarantine_decisions_no_delete BEFORE DELETE ON memory_quarantine_decisions BEGIN SELECT RAISE(ABORT,'append_only:memory_quarantine_decisions'); END;
CREATE TRIGGER memory_integrity_runs_no_update BEFORE UPDATE ON memory_integrity_runs BEGIN SELECT RAISE(ABORT,'append_only:memory_integrity_runs'); END;
CREATE TRIGGER memory_integrity_runs_no_delete BEFORE DELETE ON memory_integrity_runs BEGIN SELECT RAISE(ABORT,'append_only:memory_integrity_runs'); END;
CREATE TRIGGER memory_integrity_findings_no_update BEFORE UPDATE ON memory_integrity_findings BEGIN SELECT RAISE(ABORT,'append_only:memory_integrity_findings'); END;
CREATE TRIGGER memory_integrity_findings_no_delete BEFORE DELETE ON memory_integrity_findings BEGIN SELECT RAISE(ABORT,'append_only:memory_integrity_findings'); END;
CREATE TRIGGER memory_candidate_snapshots_no_update BEFORE UPDATE ON memory_candidate_snapshots BEGIN SELECT RAISE(ABORT,'append_only:memory_candidate_snapshots'); END;
CREATE TRIGGER memory_candidate_snapshots_no_delete BEFORE DELETE ON memory_candidate_snapshots BEGIN SELECT RAISE(ABORT,'append_only:memory_candidate_snapshots'); END;
CREATE TRIGGER memory_candidate_members_no_update BEFORE UPDATE ON memory_candidate_members BEGIN SELECT RAISE(ABORT,'append_only:memory_candidate_members'); END;
CREATE TRIGGER memory_candidate_members_no_delete BEFORE DELETE ON memory_candidate_members BEGIN SELECT RAISE(ABORT,'append_only:memory_candidate_members'); END;
CREATE TRIGGER memory_retrieval_results_no_update BEFORE UPDATE ON memory_retrieval_results BEGIN SELECT RAISE(ABORT,'append_only:memory_retrieval_results'); END;
CREATE TRIGGER memory_retrieval_results_no_delete BEFORE DELETE ON memory_retrieval_results BEGIN SELECT RAISE(ABORT,'append_only:memory_retrieval_results'); END;
CREATE TRIGGER memory_retrieval_ledger_items_no_update BEFORE UPDATE ON memory_retrieval_ledger_items BEGIN SELECT RAISE(ABORT,'append_only:memory_retrieval_ledger_items'); END;
CREATE TRIGGER memory_retrieval_ledger_items_no_delete BEFORE DELETE ON memory_retrieval_ledger_items BEGIN SELECT RAISE(ABORT,'append_only:memory_retrieval_ledger_items'); END;
CREATE TRIGGER memory_rebuild_runs_no_update BEFORE UPDATE ON memory_rebuild_runs BEGIN SELECT RAISE(ABORT,'append_only:memory_rebuild_runs'); END;
CREATE TRIGGER memory_rebuild_runs_no_delete BEFORE DELETE ON memory_rebuild_runs BEGIN SELECT RAISE(ABORT,'append_only:memory_rebuild_runs'); END;
CREATE TRIGGER memory_rebuild_metrics_no_update BEFORE UPDATE ON memory_rebuild_metrics BEGIN SELECT RAISE(ABORT,'append_only:memory_rebuild_metrics'); END;
CREATE TRIGGER memory_rebuild_metrics_no_delete BEFORE DELETE ON memory_rebuild_metrics BEGIN SELECT RAISE(ABORT,'append_only:memory_rebuild_metrics'); END;
