CREATE TABLE memory_capsules (
    capsule_id TEXT PRIMARY KEY CHECK(length(capsule_id)=64),
    lineage_id TEXT NOT NULL CHECK(length(lineage_id)=64),
    interpreting_model_id TEXT NOT NULL CHECK(length(interpreting_model_id)=64),
    provenance_class TEXT NOT NULL CHECK(provenance_class IN ('verified_real','derived_real','owner_asserted','seeded_test','fixture','simulated','synthetic','unknown')),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE memory_compression_lineage (
    lineage_id TEXT PRIMARY KEY CHECK(length(lineage_id)=64),
    child_id TEXT NOT NULL CHECK(length(child_id)=64),
    parent_count INTEGER NOT NULL CHECK(parent_count>=0),
    producing_stage TEXT NOT NULL CHECK(producing_stage IN ('lossless_deduplication','semantic_delta_encoding','prototype_exception_clustering','crystallization','retention_scoring','pressure_pruning')),
    gate_receipt_id TEXT NOT NULL CHECK(gate_receipt_id='none' OR length(gate_receipt_id)=64),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE memory_dispositions (
    disposition_id TEXT PRIMARY KEY CHECK(length(disposition_id)=64),
    encounter_id TEXT NOT NULL CHECK(length(encounter_id)=64),
    disposition TEXT NOT NULL CHECK(disposition IN ('resident_capsule','compressed_concept','compressed_procedure','statistical_residue','audited_erasure','disposition_deferred')),
    terminal INTEGER NOT NULL CHECK((disposition='disposition_deferred' AND terminal=0) OR (disposition<>'disposition_deferred' AND terminal=1)),
    cycle_ordinal INTEGER NOT NULL CHECK(cycle_ordinal>=0),
    cycle_input_root TEXT NOT NULL CHECK(length(cycle_input_root)=64),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=1),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE memory_quota_events (
    quota_event_id TEXT PRIMARY KEY CHECK(length(quota_event_id)=64),
    tier TEXT NOT NULL CHECK(tier IN ('hot','warm','adapter','fossil')),
    cause TEXT NOT NULL CHECK(cause IN ('admission','compression','tombstone','fossil_demotion','residue_eviction')),
    byte_delta INTEGER NOT NULL CHECK(byte_delta BETWEEN -9007199254740991 AND 9007199254740991),
    resulting_total INTEGER NOT NULL CHECK(resulting_total>=0),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE memory_recall_regret (
    regret_id TEXT PRIMARY KEY CHECK(length(regret_id)=64),
    packet_id TEXT NOT NULL CHECK(length(packet_id)=64),
    regret_class TEXT NOT NULL CHECK(regret_class IN ('missed_relevant','included_irrelevant','budget_starved','lens_absent')),
    lens TEXT NOT NULL CHECK(lens IN ('episodic','semantic','causal','procedural','contradiction','prospective','ancestral')),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE memory_residue_snapshots (
    residue_snapshot_id TEXT PRIMARY KEY CHECK(length(residue_snapshot_id)=64),
    statistic_family TEXT NOT NULL CHECK(statistic_family IN ('encounter','co_occurrence','retrieval_regret','novelty','failure')),
    cycle_ordinal INTEGER NOT NULL CHECK(cycle_ordinal>=0),
    item_count INTEGER NOT NULL CHECK(item_count>=0),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE metabolism_fences (
    fence_id TEXT PRIMARY KEY CHECK(length(fence_id)=64),
    stream_id TEXT NOT NULL CHECK(length(stream_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    writer_id TEXT NOT NULL CHECK(length(writer_id)=64),
    prior_fence_id TEXT NOT NULL CHECK(length(prior_fence_id)=64 AND prior_fence_id<>fence_id),
    acquired_at TEXT NOT NULL CHECK(length(acquired_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(stream_id,generation)
) STRICT;

CREATE TABLE metabolism_gate_receipts (
    gate_receipt_id TEXT PRIMARY KEY CHECK(length(gate_receipt_id)=64),
    artifact_id TEXT NOT NULL CHECK(length(artifact_id)=64),
    gate_name TEXT NOT NULL CHECK(gate_name IN ('reconstruction','decision_replay','counterevidence_preservation','provenance','future_model_readability')),
    verdict TEXT NOT NULL CHECK(verdict IN ('pass','fail')),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(artifact_id,gate_name)
) STRICT;

CREATE TABLE metabolism_operation_ledger (
    operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=64),
    operation_kind TEXT NOT NULL CHECK(operation_kind IN ('fence','capsule','disposition','lineage','stage_receipt','gate_receipt','residue_snapshot','quota_event','recall_regret')),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64),
    operation_root TEXT NOT NULL CHECK(length(operation_root)=64),
    item_count INTEGER NOT NULL CHECK(item_count>=1),
    result_sha256 TEXT NOT NULL CHECK(length(result_sha256)=64),
    result_bytes BLOB NOT NULL CHECK(length(result_bytes)>1)
) STRICT;

CREATE TABLE metabolism_stage_receipts (
    stage_receipt_id TEXT PRIMARY KEY CHECK(length(stage_receipt_id)=64),
    cycle_ordinal INTEGER NOT NULL CHECK(cycle_ordinal>=0),
    stage_name TEXT NOT NULL CHECK(stage_name IN ('lossless_deduplication','semantic_delta_encoding','prototype_exception_clustering','crystallization','retention_scoring','pressure_pruning')),
    input_root TEXT NOT NULL CHECK(length(input_root)=64),
    output_root TEXT NOT NULL CHECK(length(output_root)=64),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(cycle_ordinal,stage_name)
) STRICT;

CREATE UNIQUE INDEX memory_dispositions_one_terminal ON memory_dispositions(encounter_id) WHERE terminal=1;

CREATE TRIGGER memory_capsules_no_update BEFORE UPDATE ON memory_capsules BEGIN SELECT RAISE(ABORT,'append_only:memory_capsules'); END;
CREATE TRIGGER memory_capsules_no_delete BEFORE DELETE ON memory_capsules BEGIN SELECT RAISE(ABORT,'append_only:memory_capsules'); END;
CREATE TRIGGER memory_compression_lineage_no_update BEFORE UPDATE ON memory_compression_lineage BEGIN SELECT RAISE(ABORT,'append_only:memory_compression_lineage'); END;
CREATE TRIGGER memory_compression_lineage_no_delete BEFORE DELETE ON memory_compression_lineage BEGIN SELECT RAISE(ABORT,'append_only:memory_compression_lineage'); END;
CREATE TRIGGER memory_dispositions_no_update BEFORE UPDATE ON memory_dispositions BEGIN SELECT RAISE(ABORT,'append_only:memory_dispositions'); END;
CREATE TRIGGER memory_dispositions_no_delete BEFORE DELETE ON memory_dispositions BEGIN SELECT RAISE(ABORT,'append_only:memory_dispositions'); END;
CREATE TRIGGER memory_quota_events_no_update BEFORE UPDATE ON memory_quota_events BEGIN SELECT RAISE(ABORT,'append_only:memory_quota_events'); END;
CREATE TRIGGER memory_quota_events_no_delete BEFORE DELETE ON memory_quota_events BEGIN SELECT RAISE(ABORT,'append_only:memory_quota_events'); END;
CREATE TRIGGER memory_recall_regret_no_update BEFORE UPDATE ON memory_recall_regret BEGIN SELECT RAISE(ABORT,'append_only:memory_recall_regret'); END;
CREATE TRIGGER memory_recall_regret_no_delete BEFORE DELETE ON memory_recall_regret BEGIN SELECT RAISE(ABORT,'append_only:memory_recall_regret'); END;
CREATE TRIGGER memory_residue_snapshots_no_update BEFORE UPDATE ON memory_residue_snapshots BEGIN SELECT RAISE(ABORT,'append_only:memory_residue_snapshots'); END;
CREATE TRIGGER memory_residue_snapshots_no_delete BEFORE DELETE ON memory_residue_snapshots BEGIN SELECT RAISE(ABORT,'append_only:memory_residue_snapshots'); END;
CREATE TRIGGER metabolism_fences_no_update BEFORE UPDATE ON metabolism_fences BEGIN SELECT RAISE(ABORT,'append_only:metabolism_fences'); END;
CREATE TRIGGER metabolism_fences_no_delete BEFORE DELETE ON metabolism_fences BEGIN SELECT RAISE(ABORT,'append_only:metabolism_fences'); END;
CREATE TRIGGER metabolism_gate_receipts_no_update BEFORE UPDATE ON metabolism_gate_receipts BEGIN SELECT RAISE(ABORT,'append_only:metabolism_gate_receipts'); END;
CREATE TRIGGER metabolism_gate_receipts_no_delete BEFORE DELETE ON metabolism_gate_receipts BEGIN SELECT RAISE(ABORT,'append_only:metabolism_gate_receipts'); END;
CREATE TRIGGER metabolism_operation_ledger_no_update BEFORE UPDATE ON metabolism_operation_ledger BEGIN SELECT RAISE(ABORT,'append_only:metabolism_operation_ledger'); END;
CREATE TRIGGER metabolism_operation_ledger_no_delete BEFORE DELETE ON metabolism_operation_ledger BEGIN SELECT RAISE(ABORT,'append_only:metabolism_operation_ledger'); END;
CREATE TRIGGER metabolism_stage_receipts_no_update BEFORE UPDATE ON metabolism_stage_receipts BEGIN SELECT RAISE(ABORT,'append_only:metabolism_stage_receipts'); END;
CREATE TRIGGER metabolism_stage_receipts_no_delete BEFORE DELETE ON metabolism_stage_receipts BEGIN SELECT RAISE(ABORT,'append_only:metabolism_stage_receipts'); END;
