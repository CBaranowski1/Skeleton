PRAGMA foreign_keys = ON;
PRAGMA journal_mode = DELETE;
PRAGMA synchronous = FULL;

CREATE TABLE subjects (
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL CHECK (
        length(subject_id) = 64
        AND subject_id NOT GLOB '*[^0-9a-f]*'
    ),
    lifecycle_state TEXT NOT NULL CHECK (
        lifecycle_state IN (
            'absent', 'active', 'completed', 'failed', 'pending',
            'rejected', 'removed', 'suspended'
        )
    ),
    state_sha256 TEXT NOT NULL CHECK (
        length(state_sha256) = 64
        AND state_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    last_event_id TEXT NOT NULL CHECK (
        length(last_event_id) = 64
        AND last_event_id NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (subject_type, subject_id)
) STRICT;

CREATE TABLE lifecycle_events (
    event_id TEXT PRIMARY KEY CHECK (
        length(event_id) = 64
        AND event_id NOT GLOB '*[^0-9a-f]*'
    ),
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    prior_state TEXT NOT NULL,
    new_state TEXT NOT NULL,
    prior_state_sha256 TEXT NOT NULL,
    event_sha256 TEXT NOT NULL UNIQUE,
    cause_code TEXT NOT NULL,
    cause_evidence_sha256 TEXT NOT NULL,
    authorization_mode TEXT NOT NULL,
    authorization_evidence_sha256 TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    canonical_event BLOB NOT NULL,
    FOREIGN KEY (subject_type, subject_id)
        REFERENCES subjects(subject_type, subject_id)
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE proposal_replay_ids (
    proposal_id TEXT PRIMARY KEY,
    accepted_sha256 TEXT NOT NULL,
    accepted_at TEXT NOT NULL
) STRICT;

CREATE TABLE authorizations (
    authorization_id TEXT PRIMARY KEY,
    signer_set_epoch TEXT NOT NULL,
    decision_sha256 TEXT NOT NULL UNIQUE,
    canonical_grant BLOB NOT NULL,
    reusable INTEGER NOT NULL CHECK (reusable IN (0, 1)),
    used_at TEXT
) STRICT;

CREATE TABLE authorization_revocations (
    authorization_id TEXT NOT NULL,
    revocation_sha256 TEXT NOT NULL UNIQUE,
    revoked_at TEXT NOT NULL,
    PRIMARY KEY (authorization_id, revocation_sha256),
    FOREIGN KEY (authorization_id) REFERENCES authorizations(authorization_id)
) STRICT;

CREATE TABLE authorization_decisions (
    decision_sha256 TEXT PRIMARY KEY,
    authorization_id TEXT,
    decision_code TEXT NOT NULL,
    canonical_input BLOB NOT NULL,
    decided_at TEXT NOT NULL
) STRICT;

CREATE TABLE status_snapshots (
    status_sha256 TEXT PRIMARY KEY,
    observed_at TEXT NOT NULL,
    canonical_status BLOB NOT NULL
) STRICT;

CREATE TABLE writer_leases (
    authority_domain TEXT PRIMARY KEY,
    writer_id TEXT NOT NULL,
    fence_epoch INTEGER NOT NULL CHECK (fence_epoch >= 0)
) STRICT;

CREATE TABLE command_receipts (
    authority_domain TEXT NOT NULL,
    command_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    received_at TEXT NOT NULL,
    PRIMARY KEY (authority_domain, command_id)
) STRICT;

CREATE TABLE command_effects (
    authority_domain TEXT NOT NULL,
    command_id TEXT NOT NULL,
    effect_sha256 TEXT NOT NULL UNIQUE,
    pre_state_sha256 TEXT NOT NULL,
    post_state_sha256 TEXT NOT NULL,
    fence_epoch INTEGER NOT NULL CHECK (fence_epoch >= 0),
    committed_at TEXT NOT NULL,
    PRIMARY KEY (authority_domain, command_id),
    FOREIGN KEY (authority_domain, command_id)
        REFERENCES command_receipts(authority_domain, command_id)
) STRICT;

CREATE TABLE command_results (
    authority_domain TEXT NOT NULL,
    command_id TEXT NOT NULL,
    result_sha256 TEXT NOT NULL UNIQUE,
    fence_epoch INTEGER NOT NULL CHECK (fence_epoch >= 0),
    committed_at TEXT NOT NULL,
    PRIMARY KEY (authority_domain, command_id),
    FOREIGN KEY (authority_domain, command_id)
        REFERENCES command_effects(authority_domain, command_id)
) STRICT;

CREATE TABLE signer_set_epochs (
    signer_set_epoch TEXT PRIMARY KEY CHECK (
        signer_set_epoch = '0'
        OR (
            signer_set_epoch NOT GLOB '*[^0-9]*'
            AND substr(signer_set_epoch, 1, 1) BETWEEN '1' AND '9'
        )
    ),
    constitution_epoch TEXT NOT NULL UNIQUE CHECK (
        constitution_epoch = '0'
        OR (
            constitution_epoch NOT GLOB '*[^0-9]*'
            AND substr(constitution_epoch, 1, 1) BETWEEN '1' AND '9'
        )
    ),
    constitution_sha256 TEXT NOT NULL UNIQUE,
    transition_id TEXT NOT NULL UNIQUE,
    previous_constitution_sha256 TEXT,
    previous_signer_set_epoch TEXT,
    root_fingerprint_sha256 TEXT NOT NULL,
    canonical_transition BLOB NOT NULL,
    FOREIGN KEY (previous_signer_set_epoch)
        REFERENCES signer_set_epochs(signer_set_epoch),
    FOREIGN KEY (previous_constitution_sha256)
        REFERENCES signer_set_epochs(constitution_sha256)
) STRICT;

CREATE TABLE signer_set_members (
    signer_set_epoch TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    member_status TEXT NOT NULL CHECK (member_status IN ('active', 'revoked')),
    PRIMARY KEY (signer_set_epoch, key_id),
    UNIQUE (signer_set_epoch, public_key),
    FOREIGN KEY (signer_set_epoch)
        REFERENCES signer_set_epochs(signer_set_epoch)
) STRICT;

CREATE TABLE signer_revocations (
    signer_set_epoch TEXT NOT NULL,
    key_id TEXT NOT NULL,
    PRIMARY KEY (signer_set_epoch, key_id),
    FOREIGN KEY (signer_set_epoch)
        REFERENCES signer_set_epochs(signer_set_epoch)
) STRICT;

CREATE TRIGGER lifecycle_events_no_update
BEFORE UPDATE ON lifecycle_events
BEGIN
    SELECT RAISE(ABORT, 'append_only:lifecycle_events');
END;

CREATE TRIGGER lifecycle_events_no_delete
BEFORE DELETE ON lifecycle_events
BEGIN
    SELECT RAISE(ABORT, 'append_only:lifecycle_events');
END;

CREATE TRIGGER signer_set_epochs_no_update
BEFORE UPDATE ON signer_set_epochs
BEGIN
    SELECT RAISE(ABORT, 'append_only:signer_set_epochs');
END;

CREATE TRIGGER signer_set_epochs_no_delete
BEFORE DELETE ON signer_set_epochs
BEGIN
    SELECT RAISE(ABORT, 'append_only:signer_set_epochs');
END;

CREATE TRIGGER signer_set_members_no_update
BEFORE UPDATE ON signer_set_members
BEGIN
    SELECT RAISE(ABORT, 'append_only:signer_set_members');
END;

CREATE TRIGGER signer_set_members_no_delete
BEFORE DELETE ON signer_set_members
BEGIN
    SELECT RAISE(ABORT, 'append_only:signer_set_members');
END;

CREATE TRIGGER signer_revocations_no_update
BEFORE UPDATE ON signer_revocations
BEGIN
    SELECT RAISE(ABORT, 'append_only:signer_revocations');
END;

CREATE TRIGGER signer_revocations_no_delete
BEFORE DELETE ON signer_revocations
BEGIN
    SELECT RAISE(ABORT, 'append_only:signer_revocations');
END;

CREATE TRIGGER command_receipts_no_update
BEFORE UPDATE ON command_receipts
BEGIN
    SELECT RAISE(ABORT, 'append_only:command_receipts');
END;

CREATE TRIGGER command_receipts_no_delete
BEFORE DELETE ON command_receipts
BEGIN
    SELECT RAISE(ABORT, 'append_only:command_receipts');
END;

CREATE TRIGGER command_effects_no_update
BEFORE UPDATE ON command_effects
BEGIN
    SELECT RAISE(ABORT, 'append_only:command_effects');
END;

CREATE TRIGGER command_effects_no_delete
BEFORE DELETE ON command_effects
BEGIN
    SELECT RAISE(ABORT, 'append_only:command_effects');
END;

CREATE TRIGGER command_results_no_update
BEFORE UPDATE ON command_results
BEGIN
    SELECT RAISE(ABORT, 'append_only:command_results');
END;

CREATE TRIGGER command_results_no_delete
BEFORE DELETE ON command_results
BEGIN
    SELECT RAISE(ABORT, 'append_only:command_results');
END;

CREATE TRIGGER authorizations_immutable_grant
BEFORE UPDATE ON authorizations
WHEN NOT (
    OLD.authorization_id = NEW.authorization_id
    AND OLD.signer_set_epoch = NEW.signer_set_epoch
    AND OLD.decision_sha256 = NEW.decision_sha256
    AND OLD.canonical_grant = NEW.canonical_grant
    AND OLD.reusable = NEW.reusable
    AND OLD.used_at IS NULL
    AND NEW.used_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'append_only:authorizations');
END;

CREATE TRIGGER authorizations_no_delete
BEFORE DELETE ON authorizations
BEGIN
    SELECT RAISE(ABORT, 'append_only:authorizations');
END;

CREATE TRIGGER authorization_revocations_no_update
BEFORE UPDATE ON authorization_revocations
BEGIN
    SELECT RAISE(ABORT, 'append_only:authorization_revocations');
END;

CREATE TRIGGER authorization_revocations_no_delete
BEFORE DELETE ON authorization_revocations
BEGIN
    SELECT RAISE(ABORT, 'append_only:authorization_revocations');
END;

CREATE TRIGGER authorization_decisions_no_update
BEFORE UPDATE ON authorization_decisions
BEGIN
    SELECT RAISE(ABORT, 'append_only:authorization_decisions');
END;

CREATE TRIGGER authorization_decisions_no_delete
BEFORE DELETE ON authorization_decisions
BEGIN
    SELECT RAISE(ABORT, 'append_only:authorization_decisions');
END;

CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_id TEXT PRIMARY KEY,
    sql_sha256 TEXT NOT NULL CHECK (
        length(sql_sha256) = 64 AND sql_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS legal_terms_records (
    legal_terms_id TEXT PRIMARY KEY,
    authority_class TEXT NOT NULL CHECK (
        authority_class IN ('documented_law', 'venue_contract', 'owner_policy', 'unresolved_counsel_question')
    ),
    effective_from TEXT NOT NULL,
    effective_to TEXT,
    recorded_at TEXT NOT NULL,
    canonical_record BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS rights_records (
    rights_record_id TEXT PRIMARY KEY,
    legal_terms_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'revoked', 'terminated', 'unknown')),
    effective_from TEXT NOT NULL,
    effective_to TEXT,
    canonical_record BLOB NOT NULL,
    FOREIGN KEY (legal_terms_id) REFERENCES legal_terms_records(legal_terms_id)
) STRICT;

CREATE TABLE IF NOT EXISTS rights_status_events (
    status_event_id TEXT PRIMARY KEY,
    rights_record_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('enabled', 'expired', 'revoked', 'terminated', 'superseded')),
    available_at TEXT NOT NULL,
    canonical_event BLOB NOT NULL,
    FOREIGN KEY (rights_record_id) REFERENCES rights_records(rights_record_id)
) STRICT;

CREATE TABLE IF NOT EXISTS rights_decisions (
    decision_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    legal_terms_id TEXT NOT NULL,
    rights_record_id TEXT NOT NULL,
    boundary TEXT NOT NULL CHECK (boundary IN ('ingest', 'retrieval', 'prompt', 'training', 'evaluation', 'export', 'backup', 'activation')),
    disposition TEXT NOT NULL CHECK (disposition IN ('permit', 'deny')),
    reason_code TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    canonical_decision BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS rights_alerts (
    alert_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL UNIQUE,
    reason_code TEXT NOT NULL,
    emitted_at TEXT NOT NULL,
    canonical_alert BLOB NOT NULL,
    FOREIGN KEY (decision_id) REFERENCES rights_decisions(decision_id)
) STRICT;

CREATE TABLE IF NOT EXISTS content_objects (
    content_sha256 TEXT PRIMARY KEY CHECK (
        length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    media_type TEXT NOT NULL,
    rights_record_id TEXT NOT NULL,
    rights_decision_id TEXT NOT NULL,
    quarantine TEXT NOT NULL CHECK (quarantine IN ('clean', 'legacy', 'synthetic', 'stale', 'revoked_rights', 'contaminated')),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (rights_record_id) REFERENCES rights_records(rights_record_id),
    FOREIGN KEY (rights_decision_id) REFERENCES rights_decisions(decision_id)
) STRICT;

CREATE TABLE IF NOT EXISTS stable_identities (
    stable_identity_id TEXT PRIMARY KEY,
    genesis_content_sha256 TEXT NOT NULL UNIQUE,
    identity_kind TEXT NOT NULL,
    genesis_time TEXT NOT NULL,
    canonical_identity BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS identity_versions (
    identity_version_id TEXT PRIMARY KEY,
    stable_identity_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    available_at TEXT NOT NULL,
    canonical_version BLOB NOT NULL,
    UNIQUE (stable_identity_id, version),
    FOREIGN KEY (stable_identity_id) REFERENCES stable_identities(stable_identity_id)
) STRICT;

CREATE TABLE IF NOT EXISTS identity_alias_facts (
    fact_id TEXT PRIMARY KEY,
    stable_identity_id TEXT NOT NULL,
    fact_kind TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    effective_to TEXT,
    available_at TEXT NOT NULL,
    canonical_fact BLOB NOT NULL,
    FOREIGN KEY (stable_identity_id) REFERENCES stable_identities(stable_identity_id)
) STRICT;

CREATE TABLE IF NOT EXISTS universe_events (
    event_id TEXT PRIMARY KEY,
    universe_id TEXT NOT NULL,
    stable_identity_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('enter', 'exit', 'delist', 'unavailable', 'restore', 'rename')),
    effective_at TEXT NOT NULL,
    available_at TEXT NOT NULL,
    canonical_event BLOB NOT NULL,
    FOREIGN KEY (stable_identity_id) REFERENCES stable_identities(stable_identity_id)
) STRICT;

CREATE TABLE IF NOT EXISTS reference_facts (
    fact_id TEXT PRIMARY KEY,
    stable_identity_id TEXT NOT NULL,
    fact_kind TEXT NOT NULL,
    fact_state TEXT NOT NULL CHECK (fact_state IN ('resolved', 'unresolved', 'not_applicable')),
    effective_from TEXT NOT NULL,
    effective_to TEXT,
    available_at TEXT NOT NULL,
    canonical_fact BLOB NOT NULL,
    FOREIGN KEY (stable_identity_id) REFERENCES stable_identities(stable_identity_id)
) STRICT;

CREATE TABLE IF NOT EXISTS canonical_events (
    event_id TEXT PRIMARY KEY,
    logical_series_id TEXT NOT NULL,
    raw_content_sha256 TEXT NOT NULL,
    stable_identity_id TEXT NOT NULL,
    stable_identity_version INTEGER NOT NULL,
    rights_record_id TEXT NOT NULL,
    rights_decision_id TEXT NOT NULL,
    source_time TEXT NOT NULL,
    received_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    available_at TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    correction_of TEXT,
    sequence_state TEXT NOT NULL CHECK (sequence_state IN ('resolved', 'unresolved')),
    sequence_value INTEGER,
    quality TEXT NOT NULL,
    quarantine TEXT NOT NULL CHECK (quarantine IN ('clean', 'legacy', 'synthetic', 'stale', 'revoked_rights', 'contaminated')),
    canonical_event BLOB NOT NULL,
    FOREIGN KEY (raw_content_sha256) REFERENCES content_objects(content_sha256),
    FOREIGN KEY (stable_identity_id) REFERENCES stable_identities(stable_identity_id),
    FOREIGN KEY (rights_record_id) REFERENCES rights_records(rights_record_id),
    FOREIGN KEY (rights_decision_id) REFERENCES rights_decisions(decision_id),
    FOREIGN KEY (correction_of) REFERENCES canonical_events(event_id),
    CHECK ((sequence_state = 'resolved' AND sequence_value IS NOT NULL) OR (sequence_state = 'unresolved' AND sequence_value IS NULL))
) STRICT;

CREATE TABLE IF NOT EXISTS dataset_partitions (
    partition_id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    partition_key TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    available_at TEXT NOT NULL,
    canonical_partition BLOB NOT NULL,
    UNIQUE (dataset_id, partition_key),
    UNIQUE (dataset_id, ordinal),
    FOREIGN KEY (source_event_id) REFERENCES canonical_events(event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS dataset_manifests (
    manifest_id TEXT PRIMARY KEY,
    declared_manifest_id TEXT NOT NULL,
    dataset_id TEXT NOT NULL UNIQUE,
    rights_record_id TEXT NOT NULL,
    rights_decision_id TEXT NOT NULL,
    source_commit TEXT NOT NULL CHECK (length(source_commit) = 40 AND source_commit NOT GLOB '*[^0-9a-f]*'),
    available_at TEXT NOT NULL,
    canonical_manifest BLOB NOT NULL,
    FOREIGN KEY (rights_record_id) REFERENCES rights_records(rights_record_id),
    FOREIGN KEY (rights_decision_id) REFERENCES rights_decisions(decision_id)
) STRICT;

CREATE TABLE IF NOT EXISTS artifact_nodes (
    artifact_id TEXT PRIMARY KEY,
    node_kind TEXT NOT NULL CHECK (node_kind IN ('outcome', 'decision', 'proposal', 'model', 'procedure', 'feature', 'dataset', 'partition', 'canonical_event', 'raw_evidence', 'derived_artifact', 'memory', 'backup', 'manifest', 'export')),
    content_sha256 TEXT NOT NULL,
    authentication TEXT NOT NULL CHECK (authentication IN ('verified', 'unverified', 'unknown')),
    quarantine TEXT NOT NULL CHECK (quarantine IN ('clean', 'legacy', 'synthetic', 'stale', 'revoked_rights', 'contaminated')),
    canonical_node BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS artifact_edges (
    parent_id TEXT NOT NULL,
    child_id TEXT NOT NULL,
    edge_kind TEXT NOT NULL CHECK (edge_kind IN ('supported_by', 'derived_from', 'produced_by', 'trained_on', 'partition_of', 'materialized_from', 'backed_up_as', 'manifested_by', 'exported_as')),
    canonical_edge BLOB NOT NULL,
    PRIMARY KEY (parent_id, child_id, edge_kind),
    CHECK (parent_id <> child_id),
    FOREIGN KEY (parent_id) REFERENCES artifact_nodes(artifact_id),
    FOREIGN KEY (child_id) REFERENCES artifact_nodes(artifact_id)
) STRICT;

CREATE TABLE IF NOT EXISTS artifact_rights (
    artifact_id TEXT NOT NULL,
    rights_record_id TEXT NOT NULL,
    rights_decision_id TEXT NOT NULL,
    PRIMARY KEY (artifact_id, rights_record_id, rights_decision_id),
    FOREIGN KEY (artifact_id) REFERENCES artifact_nodes(artifact_id),
    FOREIGN KEY (rights_record_id) REFERENCES rights_records(rights_record_id),
    FOREIGN KEY (rights_decision_id) REFERENCES rights_decisions(decision_id)
) STRICT;

CREATE TABLE IF NOT EXISTS lineage_records (
    lineage_id TEXT PRIMARY KEY,
    subject_artifact_id TEXT NOT NULL UNIQUE,
    graph_sha256 TEXT NOT NULL,
    canonical_lineage BLOB NOT NULL,
    FOREIGN KEY (subject_artifact_id) REFERENCES artifact_nodes(artifact_id)
) STRICT;

CREATE TABLE IF NOT EXISTS legal_holds (
    hold_id TEXT PRIMARY KEY,
    subject_artifact_id TEXT NOT NULL,
    hold_state TEXT NOT NULL CHECK (hold_state IN ('active', 'released', 'unresolved')),
    recorded_at TEXT NOT NULL,
    canonical_hold BLOB NOT NULL,
    FOREIGN KEY (subject_artifact_id) REFERENCES artifact_nodes(artifact_id)
) STRICT;

CREATE TABLE IF NOT EXISTS deletion_previews (
    preview_id TEXT PRIMARY KEY,
    subject_content_sha256 TEXT NOT NULL,
    graph_sha256 TEXT NOT NULL,
    pre_state_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    canonical_preview BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS deletion_preview_items (
    preview_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    artifact_id TEXT NOT NULL,
    item_class TEXT NOT NULL,
    PRIMARY KEY (preview_id, ordinal),
    UNIQUE (preview_id, artifact_id),
    FOREIGN KEY (preview_id) REFERENCES deletion_previews(preview_id),
    FOREIGN KEY (artifact_id) REFERENCES artifact_nodes(artifact_id)
) STRICT;

CREATE TABLE IF NOT EXISTS deletion_executions (
    execution_id TEXT PRIMARY KEY,
    preview_id TEXT NOT NULL,
    authorization_decision_sha256 TEXT NOT NULL,
    graph_sha256 TEXT NOT NULL,
    pre_state_sha256 TEXT NOT NULL,
    execution_state TEXT NOT NULL CHECK (execution_state IN ('pending', 'in_progress', 'incomplete', 'terminal')),
    completed_result_sha256 TEXT,
    canonical_execution BLOB NOT NULL,
    FOREIGN KEY (preview_id) REFERENCES deletion_previews(preview_id)
) STRICT;

CREATE TABLE IF NOT EXISTS deletion_execution_items (
    execution_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    content_sha256 TEXT NOT NULL,
    item_state TEXT NOT NULL CHECK (item_state IN ('pending', 'delete_started', 'absence_verified', 'absence_recovered', 'retained_hold')),
    PRIMARY KEY (execution_id, ordinal),
    UNIQUE (execution_id, content_sha256),
    FOREIGN KEY (execution_id) REFERENCES deletion_executions(execution_id)
) STRICT;

CREATE TABLE IF NOT EXISTS evidence_health_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    source_state_sha256 TEXT NOT NULL,
    readiness TEXT NOT NULL CHECK (readiness IN ('ready', 'degraded', 'unknown', 'unavailable')),
    observed_at TEXT NOT NULL,
    canonical_snapshot BLOB NOT NULL
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS canonical_events_one_correction
ON canonical_events(correction_of) WHERE correction_of IS NOT NULL;
CREATE INDEX IF NOT EXISTS canonical_events_known_prefix
ON canonical_events(available_at, effective_at, stable_identity_id, event_id);
CREATE INDEX IF NOT EXISTS identity_alias_visible_prefix
ON identity_alias_facts(available_at, effective_from, stable_identity_id, fact_id);
CREATE INDEX IF NOT EXISTS universe_events_visible_prefix
ON universe_events(universe_id, available_at, effective_at, event_id);
CREATE INDEX IF NOT EXISTS reference_facts_visible_prefix
ON reference_facts(stable_identity_id, fact_kind, available_at, effective_from, fact_id);
CREATE INDEX IF NOT EXISTS artifact_edges_child
ON artifact_edges(child_id, edge_kind, parent_id);
CREATE INDEX IF NOT EXISTS rights_decisions_boundary_time
ON rights_decisions(boundary, decided_at, decision_id);

CREATE TRIGGER IF NOT EXISTS deletion_executions_monotonic_update
BEFORE UPDATE ON deletion_executions
WHEN NOT (
    OLD.execution_state = NEW.execution_state OR
    (OLD.execution_state = 'pending' AND NEW.execution_state IN ('in_progress', 'incomplete')) OR
    (OLD.execution_state = 'in_progress' AND NEW.execution_state IN ('incomplete', 'terminal')) OR
    (OLD.execution_state = 'incomplete' AND NEW.execution_state IN ('in_progress', 'terminal'))
)
BEGIN
    SELECT RAISE(ABORT, 'illegal_journal_transition:deletion_executions');
END;

CREATE TRIGGER IF NOT EXISTS deletion_execution_items_monotonic_update
BEFORE UPDATE ON deletion_execution_items
WHEN NOT (
    OLD.item_state = NEW.item_state OR
    (OLD.item_state = 'pending' AND NEW.item_state IN ('delete_started', 'retained_hold')) OR
    (OLD.item_state = 'delete_started' AND NEW.item_state IN ('absence_verified', 'absence_recovered'))
)
BEGIN
    SELECT RAISE(ABORT, 'illegal_journal_transition:deletion_execution_items');
END;

CREATE TRIGGER IF NOT EXISTS deletion_executions_no_delete
BEFORE DELETE ON deletion_executions BEGIN
    SELECT RAISE(ABORT, 'append_only:deletion_executions');
END;
CREATE TRIGGER IF NOT EXISTS deletion_execution_items_no_delete
BEFORE DELETE ON deletion_execution_items BEGIN
    SELECT RAISE(ABORT, 'append_only:deletion_execution_items');
END;

CREATE TRIGGER IF NOT EXISTS schema_migrations_no_update BEFORE UPDATE ON schema_migrations BEGIN SELECT RAISE(ABORT, 'append_only:schema_migrations'); END;
CREATE TRIGGER IF NOT EXISTS schema_migrations_no_delete BEFORE DELETE ON schema_migrations BEGIN SELECT RAISE(ABORT, 'append_only:schema_migrations'); END;
CREATE TRIGGER IF NOT EXISTS legal_terms_records_no_update BEFORE UPDATE ON legal_terms_records BEGIN SELECT RAISE(ABORT, 'append_only:legal_terms_records'); END;
CREATE TRIGGER IF NOT EXISTS legal_terms_records_no_delete BEFORE DELETE ON legal_terms_records BEGIN SELECT RAISE(ABORT, 'append_only:legal_terms_records'); END;
CREATE TRIGGER IF NOT EXISTS rights_records_no_update BEFORE UPDATE ON rights_records BEGIN SELECT RAISE(ABORT, 'append_only:rights_records'); END;
CREATE TRIGGER IF NOT EXISTS rights_records_no_delete BEFORE DELETE ON rights_records BEGIN SELECT RAISE(ABORT, 'append_only:rights_records'); END;
CREATE TRIGGER IF NOT EXISTS rights_status_events_no_update BEFORE UPDATE ON rights_status_events BEGIN SELECT RAISE(ABORT, 'append_only:rights_status_events'); END;
CREATE TRIGGER IF NOT EXISTS rights_status_events_no_delete BEFORE DELETE ON rights_status_events BEGIN SELECT RAISE(ABORT, 'append_only:rights_status_events'); END;
CREATE TRIGGER IF NOT EXISTS rights_decisions_no_update BEFORE UPDATE ON rights_decisions BEGIN SELECT RAISE(ABORT, 'append_only:rights_decisions'); END;
CREATE TRIGGER IF NOT EXISTS rights_decisions_no_delete BEFORE DELETE ON rights_decisions BEGIN SELECT RAISE(ABORT, 'append_only:rights_decisions'); END;
CREATE TRIGGER IF NOT EXISTS rights_alerts_no_update BEFORE UPDATE ON rights_alerts BEGIN SELECT RAISE(ABORT, 'append_only:rights_alerts'); END;
CREATE TRIGGER IF NOT EXISTS rights_alerts_no_delete BEFORE DELETE ON rights_alerts BEGIN SELECT RAISE(ABORT, 'append_only:rights_alerts'); END;
CREATE TRIGGER IF NOT EXISTS content_objects_no_update BEFORE UPDATE ON content_objects BEGIN SELECT RAISE(ABORT, 'append_only:content_objects'); END;
CREATE TRIGGER IF NOT EXISTS content_objects_no_delete BEFORE DELETE ON content_objects BEGIN SELECT RAISE(ABORT, 'append_only:content_objects'); END;
CREATE TRIGGER IF NOT EXISTS stable_identities_no_update BEFORE UPDATE ON stable_identities BEGIN SELECT RAISE(ABORT, 'append_only:stable_identities'); END;
CREATE TRIGGER IF NOT EXISTS stable_identities_no_delete BEFORE DELETE ON stable_identities BEGIN SELECT RAISE(ABORT, 'append_only:stable_identities'); END;
CREATE TRIGGER IF NOT EXISTS identity_versions_no_update BEFORE UPDATE ON identity_versions BEGIN SELECT RAISE(ABORT, 'append_only:identity_versions'); END;
CREATE TRIGGER IF NOT EXISTS identity_versions_no_delete BEFORE DELETE ON identity_versions BEGIN SELECT RAISE(ABORT, 'append_only:identity_versions'); END;
CREATE TRIGGER IF NOT EXISTS identity_alias_facts_no_update BEFORE UPDATE ON identity_alias_facts BEGIN SELECT RAISE(ABORT, 'append_only:identity_alias_facts'); END;
CREATE TRIGGER IF NOT EXISTS identity_alias_facts_no_delete BEFORE DELETE ON identity_alias_facts BEGIN SELECT RAISE(ABORT, 'append_only:identity_alias_facts'); END;
CREATE TRIGGER IF NOT EXISTS universe_events_no_update BEFORE UPDATE ON universe_events BEGIN SELECT RAISE(ABORT, 'append_only:universe_events'); END;
CREATE TRIGGER IF NOT EXISTS universe_events_no_delete BEFORE DELETE ON universe_events BEGIN SELECT RAISE(ABORT, 'append_only:universe_events'); END;
CREATE TRIGGER IF NOT EXISTS reference_facts_no_update BEFORE UPDATE ON reference_facts BEGIN SELECT RAISE(ABORT, 'append_only:reference_facts'); END;
CREATE TRIGGER IF NOT EXISTS reference_facts_no_delete BEFORE DELETE ON reference_facts BEGIN SELECT RAISE(ABORT, 'append_only:reference_facts'); END;
CREATE TRIGGER IF NOT EXISTS canonical_events_no_update BEFORE UPDATE ON canonical_events BEGIN SELECT RAISE(ABORT, 'append_only:canonical_events'); END;
CREATE TRIGGER IF NOT EXISTS canonical_events_no_delete BEFORE DELETE ON canonical_events BEGIN SELECT RAISE(ABORT, 'append_only:canonical_events'); END;
CREATE TRIGGER IF NOT EXISTS dataset_partitions_no_update BEFORE UPDATE ON dataset_partitions BEGIN SELECT RAISE(ABORT, 'append_only:dataset_partitions'); END;
CREATE TRIGGER IF NOT EXISTS dataset_partitions_no_delete BEFORE DELETE ON dataset_partitions BEGIN SELECT RAISE(ABORT, 'append_only:dataset_partitions'); END;
CREATE TRIGGER IF NOT EXISTS dataset_manifests_no_update BEFORE UPDATE ON dataset_manifests BEGIN SELECT RAISE(ABORT, 'append_only:dataset_manifests'); END;
CREATE TRIGGER IF NOT EXISTS dataset_manifests_no_delete BEFORE DELETE ON dataset_manifests BEGIN SELECT RAISE(ABORT, 'append_only:dataset_manifests'); END;
CREATE TRIGGER IF NOT EXISTS artifact_nodes_no_update BEFORE UPDATE ON artifact_nodes BEGIN SELECT RAISE(ABORT, 'append_only:artifact_nodes'); END;
CREATE TRIGGER IF NOT EXISTS artifact_nodes_no_delete BEFORE DELETE ON artifact_nodes BEGIN SELECT RAISE(ABORT, 'append_only:artifact_nodes'); END;
CREATE TRIGGER IF NOT EXISTS artifact_edges_no_update BEFORE UPDATE ON artifact_edges BEGIN SELECT RAISE(ABORT, 'append_only:artifact_edges'); END;
CREATE TRIGGER IF NOT EXISTS artifact_edges_no_delete BEFORE DELETE ON artifact_edges BEGIN SELECT RAISE(ABORT, 'append_only:artifact_edges'); END;
CREATE TRIGGER IF NOT EXISTS artifact_rights_no_update BEFORE UPDATE ON artifact_rights BEGIN SELECT RAISE(ABORT, 'append_only:artifact_rights'); END;
CREATE TRIGGER IF NOT EXISTS artifact_rights_no_delete BEFORE DELETE ON artifact_rights BEGIN SELECT RAISE(ABORT, 'append_only:artifact_rights'); END;
CREATE TRIGGER IF NOT EXISTS lineage_records_no_update BEFORE UPDATE ON lineage_records BEGIN SELECT RAISE(ABORT, 'append_only:lineage_records'); END;
CREATE TRIGGER IF NOT EXISTS lineage_records_no_delete BEFORE DELETE ON lineage_records BEGIN SELECT RAISE(ABORT, 'append_only:lineage_records'); END;
CREATE TRIGGER IF NOT EXISTS legal_holds_no_update BEFORE UPDATE ON legal_holds BEGIN SELECT RAISE(ABORT, 'append_only:legal_holds'); END;
CREATE TRIGGER IF NOT EXISTS legal_holds_no_delete BEFORE DELETE ON legal_holds BEGIN SELECT RAISE(ABORT, 'append_only:legal_holds'); END;
CREATE TRIGGER IF NOT EXISTS deletion_previews_no_update BEFORE UPDATE ON deletion_previews BEGIN SELECT RAISE(ABORT, 'append_only:deletion_previews'); END;
CREATE TRIGGER IF NOT EXISTS deletion_previews_no_delete BEFORE DELETE ON deletion_previews BEGIN SELECT RAISE(ABORT, 'append_only:deletion_previews'); END;
CREATE TRIGGER IF NOT EXISTS deletion_preview_items_no_update BEFORE UPDATE ON deletion_preview_items BEGIN SELECT RAISE(ABORT, 'append_only:deletion_preview_items'); END;
CREATE TRIGGER IF NOT EXISTS deletion_preview_items_no_delete BEFORE DELETE ON deletion_preview_items BEGIN SELECT RAISE(ABORT, 'append_only:deletion_preview_items'); END;
CREATE TRIGGER IF NOT EXISTS evidence_health_snapshots_no_update BEFORE UPDATE ON evidence_health_snapshots BEGIN SELECT RAISE(ABORT, 'append_only:evidence_health_snapshots'); END;
CREATE TRIGGER IF NOT EXISTS evidence_health_snapshots_no_delete BEFORE DELETE ON evidence_health_snapshots BEGIN SELECT RAISE(ABORT, 'append_only:evidence_health_snapshots'); END;
