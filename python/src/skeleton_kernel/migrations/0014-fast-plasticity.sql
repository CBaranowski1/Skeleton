CREATE TABLE admission_receipts (
    admission_id TEXT PRIMARY KEY CHECK(length(admission_id)=64),
    delta_id TEXT NOT NULL CHECK(length(delta_id)=64),
    provider_snapshot_id TEXT NOT NULL CHECK(length(provider_snapshot_id)=64),
    channel_update_id TEXT NOT NULL CHECK(length(channel_update_id)=64),
    probe_battery_root TEXT NOT NULL CHECK(length(probe_battery_root)=64),
    scope_id TEXT NOT NULL CHECK(length(scope_id)=64),
    expiry_ordinal INTEGER NOT NULL CHECK(expiry_ordinal>=0),
    current_ordinal INTEGER NOT NULL CHECK(current_ordinal>=0 AND current_ordinal<=expiry_ordinal),
    homeostasis_event_id TEXT NOT NULL CHECK(length(homeostasis_event_id)=64),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    FOREIGN KEY(delta_id) REFERENCES parameter_deltas(delta_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE candidate_versions (
    version_id TEXT PRIMARY KEY CHECK(length(version_id)=64),
    change_kind TEXT NOT NULL CHECK(change_kind IN ('model','prompt','calibration','tool','feature','threshold','policy')),
    prior_version_id TEXT NOT NULL CHECK(length(prior_version_id)=64),
    artifact_root_count INTEGER NOT NULL CHECK(artifact_root_count>=1),
    verification_receipt_id TEXT NOT NULL CHECK(length(verification_receipt_id)=64),
    version_ordinal INTEGER NOT NULL CHECK(version_ordinal>=0),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE channel_updates (
    channel_update_id TEXT PRIMARY KEY CHECK(length(channel_update_id)=64),
    gradient_id TEXT NOT NULL CHECK(length(gradient_id)=64),
    channel TEXT NOT NULL CHECK(channel IN ('fast_weights','uncertainty','retrieval','routing','experiment_selection')),
    delta_id TEXT NOT NULL CHECK((channel='fast_weights' AND length(delta_id)=64) OR (channel<>'fast_weights' AND delta_id='none')),
    reference_version_id TEXT NOT NULL CHECK((channel='fast_weights' AND reference_version_id='none') OR (channel<>'fast_weights' AND length(reference_version_id)=64)),
    adjustment INTEGER CHECK((channel='fast_weights' AND adjustment IS NULL) OR (channel<>'fast_weights' AND adjustment IS NOT NULL AND adjustment BETWEEN -9007199254740991 AND 9007199254740991 AND (channel NOT IN ('uncertainty','retrieval') OR adjustment BETWEEN 0 AND 1000))),
    producer_organ TEXT NOT NULL CHECK(producer_organ IN ('recall','planning','simulation','falsification','execution_preparation','outcome_judgment','learning_compilation','sleep')),
    grader_organ TEXT NOT NULL CHECK(grader_organ IN ('recall','planning','simulation','falsification','execution_preparation','outcome_judgment','learning_compilation','sleep') AND grader_organ<>producer_organ),
    update_ordinal INTEGER NOT NULL CHECK(update_ordinal>=0),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=1),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(gradient_id),
    FOREIGN KEY(gradient_id) REFERENCES experience_gradients(gradient_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE delta_applications (
    application_id TEXT PRIMARY KEY CHECK(length(application_id)=64),
    delta_id TEXT NOT NULL CHECK(length(delta_id)=64),
    application_event TEXT NOT NULL CHECK(application_event IN ('apply','reverse')),
    application_ordinal INTEGER NOT NULL CHECK(application_ordinal>=1),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE experience_gradients (
    gradient_id TEXT PRIMARY KEY CHECK(length(gradient_id)=64),
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('kernel','identity','lobe_coding','lobe_trading','lobe_research','project')),
    project_id TEXT NOT NULL CHECK((scope_kind='project' AND length(project_id)=64) OR (scope_kind<>'project' AND project_id='none')),
    outcome TEXT NOT NULL CHECK(outcome IN ('success','failure','unresolved')),
    producer_organ TEXT NOT NULL CHECK(producer_organ IN ('recall','planning','simulation','falsification','execution_preparation','outcome_judgment','learning_compilation','sleep')),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE learning_attempts (
    attempt_id TEXT PRIMARY KEY CHECK(length(attempt_id)=64),
    gradient_id TEXT NOT NULL UNIQUE CHECK(length(gradient_id)=64),
    channel_update_id TEXT NOT NULL UNIQUE CHECK(length(channel_update_id)=64),
    FOREIGN KEY(gradient_id) REFERENCES experience_gradients(gradient_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(channel_update_id) REFERENCES channel_updates(channel_update_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE homeostasis_events (
    event_id TEXT PRIMARY KEY CHECK(length(event_id)=64),
    scope_id TEXT NOT NULL CHECK(scope_id='global' OR length(scope_id)=64),
    budget_kind TEXT NOT NULL CHECK(budget_kind IN ('rank','drift','kl_divergence','regression_loss','storage_bytes','training_compute','delta_magnitude','delta_count','application_frequency')),
    append_class TEXT NOT NULL CHECK(append_class IN ('delta_admission','receipt_append','rollback_append','audit_append','placeholder_append')),
    pressure_exempt INTEGER NOT NULL CHECK((append_class='delta_admission' AND pressure_exempt=0) OR (append_class<>'delta_admission' AND pressure_exempt=1)),
    cap_amount INTEGER NOT NULL CHECK(cap_amount>=0),
    amount_before INTEGER NOT NULL CHECK(amount_before>=0),
    attempted_amount INTEGER NOT NULL CHECK(attempted_amount>=0),
    committed_amount INTEGER NOT NULL CHECK(committed_amount>=0),
    amount_after INTEGER NOT NULL CHECK(amount_after>=0 AND amount_after=amount_before+committed_amount),
    utilization_permille INTEGER NOT NULL CHECK(utilization_permille BETWEEN 0 AND 1000),
    band TEXT NOT NULL CHECK(band IN ('nominal','elevated','high','ceiling')),
    action TEXT NOT NULL CHECK((pressure_exempt=1 AND action='admit') OR (pressure_exempt=0 AND ((action='admit' AND band IN ('nominal','elevated')) OR (action='clamp_magnitude' AND band IN ('elevated','high')) OR (action='defer_admission' AND band='high' AND committed_amount=0) OR (action='quarantine_pressure' AND band IN ('high','ceiling') AND committed_amount=0) OR (action='homeostasis_clamped' AND band='ceiling' AND committed_amount=0)))),
    window_ordinal INTEGER NOT NULL CHECK(window_ordinal>=0),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=1),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE mixture_records (
    mixture_id TEXT PRIMARY KEY CHECK(length(mixture_id)=64),
    invocation_id TEXT NOT NULL CHECK(length(invocation_id)=64),
    genome_snapshot_id TEXT NOT NULL CHECK(length(genome_snapshot_id)=64),
    active_layer_count INTEGER NOT NULL CHECK(active_layer_count BETWEEN 0 AND 256),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=1),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(invocation_id),
    FOREIGN KEY(invocation_id) REFERENCES invocation_receipts(invocation_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE invocation_receipts (
    invocation_id TEXT PRIMARY KEY CHECK(length(invocation_id)=64),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=1),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE parameter_deltas (
    delta_id TEXT PRIMARY KEY CHECK(length(delta_id)=64),
    parent_delta_id TEXT NOT NULL CHECK(length(parent_delta_id)=64),
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('kernel','identity','lobe_coding','lobe_trading','lobe_research','project')),
    project_id TEXT NOT NULL CHECK((scope_kind='project' AND length(project_id)=64) OR (scope_kind<>'project' AND project_id='none')),
    base_snapshot_id TEXT NOT NULL CHECK(length(base_snapshot_id)=64 AND base_snapshot_id<>'0000000000000000000000000000000000000000000000000000000000000000'),
    expiry_ordinal INTEGER NOT NULL CHECK(expiry_ordinal>=0),
    scale_log2 INTEGER NOT NULL CHECK(scale_log2 BETWEEN 0 AND 62),
    declared_rank INTEGER NOT NULL CHECK(declared_rank>=0),
    tensor_payload_root TEXT NOT NULL CHECK(length(tensor_payload_root)=64),
    inverse_payload_root TEXT NOT NULL CHECK(length(inverse_payload_root)=64),
    pre_apply_payload_root TEXT NOT NULL CHECK(length(pre_apply_payload_root)=64),
    post_apply_payload_root TEXT NOT NULL CHECK(length(post_apply_payload_root)=64),
    roundtrip_payload_root TEXT NOT NULL CHECK(length(roundtrip_payload_root)=64 AND roundtrip_payload_root=pre_apply_payload_root),
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes>=0),
    version_ordinal INTEGER NOT NULL CHECK(version_ordinal>=0),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE pending_owner_hardware (
    placeholder_id TEXT PRIMARY KEY CHECK(length(placeholder_id)=64),
    reason TEXT NOT NULL CHECK(reason IN ('dgx_absent','owner_authorization_pending','arm64_parity_unverified')),
    bound_requirement TEXT NOT NULL CHECK(bound_requirement IN ('real_training_run','real_model_probe','real_model_kl_drift','provider_conformance')),
    bound_artifact_id TEXT NOT NULL CHECK(length(bound_artifact_id)=64),
    obligation_kind TEXT NOT NULL CHECK((bound_requirement='real_training_run' AND obligation_kind='reproduce_training_step_receipts') OR (bound_requirement='real_model_probe' AND obligation_kind='reproduce_probe_receipt') OR (bound_requirement='real_model_kl_drift' AND obligation_kind='reproduce_kl_drift_measurement') OR (bound_requirement='provider_conformance' AND obligation_kind='reproduce_fixture_conformance_receipts')),
    conformance_oracle_root TEXT NOT NULL CHECK(length(conformance_oracle_root)=64),
    expected_receipt_count INTEGER NOT NULL CHECK(expected_receipt_count>=1),
    recorded_ordinal INTEGER NOT NULL CHECK(recorded_ordinal>=0),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE plasticity_fences (
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

CREATE TABLE plasticity_operation_ledger (
    operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=64),
    operation_kind TEXT NOT NULL CHECK(operation_kind IN ('fence','scope','gradient','channel_update','learning_attempt','delta','delta_application','admission_application','probe_receipt','homeostasis_event','placeholder','mixture','invocation_mixture','candidate_version','provider_lifecycle')),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64),
    operation_root TEXT NOT NULL CHECK(length(operation_root)=64),
    item_count INTEGER NOT NULL CHECK(item_count>=1),
    result_sha256 TEXT NOT NULL CHECK(length(result_sha256)=64),
    result_bytes BLOB NOT NULL CHECK(length(result_bytes)>1)
) STRICT;

CREATE TABLE plasticity_scopes (
    scope_id TEXT PRIMARY KEY CHECK(length(scope_id)=64),
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('kernel','identity','lobe','project')),
    scope_name TEXT NOT NULL CHECK((scope_kind='kernel' AND scope_name='kernel') OR (scope_kind='identity' AND scope_name='identity') OR (scope_kind='lobe' AND scope_name IN ('coding','trading','research')) OR (scope_kind='project' AND length(scope_name)>=1 AND length(scope_name)<=128 AND scope_name NOT IN ('kernel','identity','coding','trading','research'))),
    owner_configuration_id TEXT NOT NULL CHECK(length(owner_configuration_id)=64),
    registered_ordinal INTEGER NOT NULL CHECK(registered_ordinal>=0),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE provider_lifecycle_receipts (
    receipt_id TEXT PRIMARY KEY CHECK(length(receipt_id)=64),
    lifecycle_event TEXT NOT NULL CHECK(lifecycle_event IN ('training','stage','verification','activation','unload','restoration')),
    operation_id TEXT NOT NULL CHECK(length(operation_id)=64),
    base_snapshot_id TEXT NOT NULL CHECK(length(base_snapshot_id)=64),
    observed_snapshot_id TEXT NOT NULL CHECK(length(observed_snapshot_id)=64),
    adapter_root TEXT NOT NULL CHECK(length(adapter_root)=64),
    evidence_root TEXT NOT NULL CHECK(length(evidence_root)=64),
    authorization_sha256 TEXT NOT NULL CHECK(length(authorization_sha256)=64),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=1),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(operation_id,lifecycle_event)
) STRICT;

CREATE TABLE probe_batteries (
    battery_id TEXT PRIMARY KEY CHECK(length(battery_id)=64),
    delta_id TEXT NOT NULL CHECK(length(delta_id)=64),
    ledger_state_root TEXT NOT NULL CHECK(length(ledger_state_root)=64),
    status TEXT NOT NULL CHECK(status IN ('cpu_battery_passed_with_placeholders','quarantine_intent','battery_incomplete')),
    code TEXT NOT NULL CHECK(length(code)>=1),
    completeness TEXT NOT NULL CHECK(completeness IN ('complete','partial')),
    failing_receipt_row_id TEXT NOT NULL CHECK(failing_receipt_row_id='none' OR length(failing_receipt_row_id)=64),
    receipt_count INTEGER NOT NULL CHECK(receipt_count BETWEEN 0 AND 5),
    placeholder_count INTEGER NOT NULL CHECK(placeholder_count BETWEEN 0 AND 5),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=1),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(delta_id,attempt_ordinal)
) STRICT;

CREATE TABLE probe_receipts (
    receipt_id TEXT PRIMARY KEY CHECK(length(receipt_id)=64),
    delta_id TEXT NOT NULL CHECK(length(delta_id)=64),
    probe_kind TEXT NOT NULL CHECK(probe_kind IN ('domain','general_capability','calibration','safety','prior_regression')),
    probe_ordinal INTEGER NOT NULL CHECK((probe_kind='domain' AND probe_ordinal=0) OR (probe_kind='general_capability' AND probe_ordinal=1) OR (probe_kind='calibration' AND probe_ordinal=2) OR (probe_kind='safety' AND probe_ordinal=3) OR (probe_kind='prior_regression' AND probe_ordinal=4)),
    evaluation_basis TEXT NOT NULL CHECK(evaluation_basis IN ('reference_kernel','fixture_battery','real_model')),
    passed_count INTEGER NOT NULL CHECK(passed_count>=0),
    failed_count INTEGER NOT NULL CHECK(failed_count>=0),
    total_count INTEGER NOT NULL CHECK(total_count>=1 AND total_count=passed_count+failed_count),
    status TEXT NOT NULL CHECK((status='passed' AND failed_count=0) OR (status='failed' AND failed_count>=1)),
    placeholder_id TEXT NOT NULL CHECK((evaluation_basis IN ('reference_kernel','fixture_battery') AND placeholder_id='none') OR (evaluation_basis='real_model' AND length(placeholder_id)=64)),
    fence_id TEXT NOT NULL CHECK(length(fence_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=1),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(delta_id,probe_kind)
) STRICT;

CREATE UNIQUE INDEX delta_applications_one_ordinal ON delta_applications(delta_id,application_ordinal);

CREATE TRIGGER admission_receipts_no_update BEFORE UPDATE ON admission_receipts BEGIN SELECT RAISE(ABORT,'append_only:admission_receipts'); END;
CREATE TRIGGER admission_receipts_no_delete BEFORE DELETE ON admission_receipts BEGIN SELECT RAISE(ABORT,'append_only:admission_receipts'); END;
CREATE TRIGGER candidate_versions_no_update BEFORE UPDATE ON candidate_versions BEGIN SELECT RAISE(ABORT,'append_only:candidate_versions'); END;
CREATE TRIGGER candidate_versions_no_delete BEFORE DELETE ON candidate_versions BEGIN SELECT RAISE(ABORT,'append_only:candidate_versions'); END;
CREATE TRIGGER channel_updates_no_update BEFORE UPDATE ON channel_updates BEGIN SELECT RAISE(ABORT,'append_only:channel_updates'); END;
CREATE TRIGGER channel_updates_no_delete BEFORE DELETE ON channel_updates BEGIN SELECT RAISE(ABORT,'append_only:channel_updates'); END;
CREATE TRIGGER delta_applications_no_update BEFORE UPDATE ON delta_applications BEGIN SELECT RAISE(ABORT,'append_only:delta_applications'); END;
CREATE TRIGGER delta_applications_no_delete BEFORE DELETE ON delta_applications BEGIN SELECT RAISE(ABORT,'append_only:delta_applications'); END;
CREATE TRIGGER experience_gradients_no_update BEFORE UPDATE ON experience_gradients BEGIN SELECT RAISE(ABORT,'append_only:experience_gradients'); END;
CREATE TRIGGER experience_gradients_no_delete BEFORE DELETE ON experience_gradients BEGIN SELECT RAISE(ABORT,'append_only:experience_gradients'); END;
CREATE TRIGGER learning_attempts_no_update BEFORE UPDATE ON learning_attempts BEGIN SELECT RAISE(ABORT,'append_only:learning_attempts'); END;
CREATE TRIGGER learning_attempts_no_delete BEFORE DELETE ON learning_attempts BEGIN SELECT RAISE(ABORT,'append_only:learning_attempts'); END;
CREATE TRIGGER homeostasis_events_no_update BEFORE UPDATE ON homeostasis_events BEGIN SELECT RAISE(ABORT,'append_only:homeostasis_events'); END;
CREATE TRIGGER homeostasis_events_no_delete BEFORE DELETE ON homeostasis_events BEGIN SELECT RAISE(ABORT,'append_only:homeostasis_events'); END;
CREATE TRIGGER mixture_records_no_update BEFORE UPDATE ON mixture_records BEGIN SELECT RAISE(ABORT,'append_only:mixture_records'); END;
CREATE TRIGGER mixture_records_no_delete BEFORE DELETE ON mixture_records BEGIN SELECT RAISE(ABORT,'append_only:mixture_records'); END;
CREATE TRIGGER invocation_receipts_no_update BEFORE UPDATE ON invocation_receipts BEGIN SELECT RAISE(ABORT,'append_only:invocation_receipts'); END;
CREATE TRIGGER invocation_receipts_no_delete BEFORE DELETE ON invocation_receipts BEGIN SELECT RAISE(ABORT,'append_only:invocation_receipts'); END;
CREATE TRIGGER parameter_deltas_no_update BEFORE UPDATE ON parameter_deltas BEGIN SELECT RAISE(ABORT,'append_only:parameter_deltas'); END;
CREATE TRIGGER parameter_deltas_no_delete BEFORE DELETE ON parameter_deltas BEGIN SELECT RAISE(ABORT,'append_only:parameter_deltas'); END;
CREATE TRIGGER pending_owner_hardware_no_update BEFORE UPDATE ON pending_owner_hardware BEGIN SELECT RAISE(ABORT,'append_only:pending_owner_hardware'); END;
CREATE TRIGGER pending_owner_hardware_no_delete BEFORE DELETE ON pending_owner_hardware BEGIN SELECT RAISE(ABORT,'append_only:pending_owner_hardware'); END;
CREATE TRIGGER plasticity_fences_no_update BEFORE UPDATE ON plasticity_fences BEGIN SELECT RAISE(ABORT,'append_only:plasticity_fences'); END;
CREATE TRIGGER plasticity_fences_no_delete BEFORE DELETE ON plasticity_fences BEGIN SELECT RAISE(ABORT,'append_only:plasticity_fences'); END;
CREATE TRIGGER plasticity_operation_ledger_no_update BEFORE UPDATE ON plasticity_operation_ledger BEGIN SELECT RAISE(ABORT,'append_only:plasticity_operation_ledger'); END;
CREATE TRIGGER plasticity_operation_ledger_no_delete BEFORE DELETE ON plasticity_operation_ledger BEGIN SELECT RAISE(ABORT,'append_only:plasticity_operation_ledger'); END;
CREATE TRIGGER plasticity_scopes_no_update BEFORE UPDATE ON plasticity_scopes BEGIN SELECT RAISE(ABORT,'append_only:plasticity_scopes'); END;
CREATE TRIGGER plasticity_scopes_no_delete BEFORE DELETE ON plasticity_scopes BEGIN SELECT RAISE(ABORT,'append_only:plasticity_scopes'); END;
CREATE TRIGGER provider_lifecycle_receipts_no_update BEFORE UPDATE ON provider_lifecycle_receipts BEGIN SELECT RAISE(ABORT,'append_only:provider_lifecycle_receipts'); END;
CREATE TRIGGER provider_lifecycle_receipts_no_delete BEFORE DELETE ON provider_lifecycle_receipts BEGIN SELECT RAISE(ABORT,'append_only:provider_lifecycle_receipts'); END;
CREATE TRIGGER probe_batteries_no_update BEFORE UPDATE ON probe_batteries BEGIN SELECT RAISE(ABORT,'append_only:probe_batteries'); END;
CREATE TRIGGER probe_batteries_no_delete BEFORE DELETE ON probe_batteries BEGIN SELECT RAISE(ABORT,'append_only:probe_batteries'); END;
CREATE TRIGGER probe_receipts_no_update BEFORE UPDATE ON probe_receipts BEGIN SELECT RAISE(ABORT,'append_only:probe_receipts'); END;
CREATE TRIGGER probe_receipts_no_delete BEFORE DELETE ON probe_receipts BEGIN SELECT RAISE(ABORT,'append_only:probe_receipts'); END;
