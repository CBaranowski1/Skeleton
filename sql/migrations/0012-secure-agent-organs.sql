CREATE TABLE agent_identity_events (
    identity_event_id TEXT PRIMARY KEY CHECK(length(identity_event_id)=64),
    work_identity_id TEXT NOT NULL CHECK(length(work_identity_id)=64),
    generation INTEGER NOT NULL CHECK(generation>=0),
    prior_identity_event_id TEXT NOT NULL CHECK(length(prior_identity_event_id)=64 AND prior_identity_event_id<>identity_event_id),
    parent_lifecycle_event_id TEXT NOT NULL CHECK(length(parent_lifecycle_event_id)=64),
    memory_snapshot_id TEXT NOT NULL CHECK(length(memory_snapshot_id)=64),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(work_identity_id,generation)
) STRICT;

CREATE TABLE agent_invocations (
    invocation_id TEXT PRIMARY KEY CHECK(length(invocation_id)=64),
    identity_event_id TEXT NOT NULL REFERENCES agent_identity_events(identity_event_id),
    organ_contract_id TEXT NOT NULL CHECK(length(organ_contract_id)=64),
    input_root TEXT NOT NULL CHECK(length(input_root)=64),
    context_root TEXT NOT NULL CHECK(length(context_root)=64),
    evidence_root TEXT NOT NULL CHECK(length(evidence_root)=64),
    memory_root TEXT NOT NULL CHECK(length(memory_root)=64),
    provider_capability_root TEXT NOT NULL CHECK(length(provider_capability_root)=64),
    budget_allocation_root TEXT NOT NULL CHECK(length(budget_allocation_root)=64),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE agent_coordinator_fences (
    fence_id TEXT PRIMARY KEY CHECK(length(fence_id)=64),
    invocation_id TEXT NOT NULL REFERENCES agent_invocations(invocation_id),
    generation INTEGER NOT NULL CHECK(generation>=0),
    writer_id TEXT NOT NULL CHECK(length(writer_id)=64),
    prior_fence_id TEXT NOT NULL CHECK(length(prior_fence_id)=64 AND prior_fence_id<>fence_id),
    acquired_at TEXT NOT NULL CHECK(length(acquired_at)>=20),
    lease_deadline TEXT NOT NULL CHECK(length(lease_deadline)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(invocation_id,generation)
) STRICT;

CREATE TABLE agent_lifecycle_events (
    lifecycle_event_id TEXT PRIMARY KEY CHECK(length(lifecycle_event_id)=64),
    invocation_id TEXT NOT NULL REFERENCES agent_invocations(invocation_id),
    ordinal INTEGER NOT NULL CHECK(ordinal>=0),
    prior_lifecycle_event_id TEXT NOT NULL CHECK(length(prior_lifecycle_event_id)=64 AND prior_lifecycle_event_id<>lifecycle_event_id),
    state TEXT NOT NULL CHECK(state IN ('received','running','awaiting_falsification','recovering','terminal','abandoned')),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    fence_id TEXT NOT NULL REFERENCES agent_coordinator_fences(fence_id),
    reason_code TEXT NOT NULL CHECK(length(reason_code)>0),
    terminal_result_id TEXT NOT NULL CHECK(length(terminal_result_id)=64),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(invocation_id,ordinal)
) STRICT;

CREATE TABLE agent_activation_triggers (
    trigger_id TEXT PRIMARY KEY CHECK(length(trigger_id)=64),
    invocation_id TEXT NOT NULL REFERENCES agent_invocations(invocation_id),
    fence_id TEXT NOT NULL REFERENCES agent_coordinator_fences(fence_id),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    threshold_profile_id TEXT NOT NULL CHECK(length(threshold_profile_id)>0),
    specialist_role TEXT NOT NULL CHECK(specialist_role IN ('market_mechanics','fundamentals','filings_news','cross_market_context','causal_hypothesis','execution_feasibility','uncertainty','adversarial_falsification')),
    measurement_root TEXT NOT NULL CHECK(length(measurement_root)=64),
    child_budget_root TEXT NOT NULL CHECK(length(child_budget_root)=64),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(invocation_id,attempt_ordinal,specialist_role)
) STRICT;

CREATE TABLE agent_budget_events (
    budget_event_id TEXT PRIMARY KEY CHECK(length(budget_event_id)=64),
    invocation_id TEXT NOT NULL REFERENCES agent_invocations(invocation_id),
    fence_id TEXT NOT NULL REFERENCES agent_coordinator_fences(fence_id),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    event_kind TEXT NOT NULL CHECK(event_kind IN ('allocation','reservation','reconciliation','uncertain')),
    input_tokens_delta INTEGER NOT NULL CHECK(input_tokens_delta>=0),
    output_tokens_delta INTEGER NOT NULL CHECK(output_tokens_delta>=0),
    elapsed_ms_delta INTEGER NOT NULL CHECK(elapsed_ms_delta>=0),
    memory_items_delta INTEGER NOT NULL CHECK(memory_items_delta>=0),
    memory_bytes_delta INTEGER NOT NULL CHECK(memory_bytes_delta>=0),
    tool_calls_delta INTEGER NOT NULL CHECK(tool_calls_delta>=0),
    accelerator_ms_delta INTEGER NOT NULL CHECK(accelerator_ms_delta>=0),
    predecessor_budget_root TEXT NOT NULL CHECK(length(predecessor_budget_root)=64),
    result_budget_root TEXT NOT NULL CHECK(length(result_budget_root)=64),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(invocation_id,attempt_ordinal,event_kind,result_budget_root)
) STRICT;

CREATE TABLE agent_model_attempts (
    attempt_id TEXT PRIMARY KEY CHECK(length(attempt_id)=64),
    invocation_id TEXT NOT NULL REFERENCES agent_invocations(invocation_id),
    fence_id TEXT NOT NULL REFERENCES agent_coordinator_fences(fence_id),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    provider_descriptor_id TEXT NOT NULL CHECK(length(provider_descriptor_id)=64),
    snapshot_id TEXT NOT NULL CHECK(length(snapshot_id)=64),
    capability_root TEXT NOT NULL CHECK(length(capability_root)=64),
    context_root TEXT NOT NULL CHECK(length(context_root)=64),
    usage_receipt_root TEXT NOT NULL CHECK(length(usage_receipt_root)=64),
    attempt_status TEXT NOT NULL CHECK(attempt_status IN ('reserved','uncertain','completed','rejected')),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(invocation_id,attempt_ordinal)
) STRICT;

CREATE TABLE agent_tool_receipts (
    tool_receipt_id TEXT PRIMARY KEY CHECK(length(tool_receipt_id)=64),
    invocation_id TEXT NOT NULL REFERENCES agent_invocations(invocation_id),
    fence_id TEXT NOT NULL REFERENCES agent_coordinator_fences(fence_id),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    operation_id TEXT NOT NULL CHECK(length(operation_id)=64),
    argument_root TEXT NOT NULL CHECK(length(argument_root)=64),
    result_root TEXT NOT NULL CHECK(length(result_root)=64),
    egress_class TEXT NOT NULL CHECK(egress_class='none'),
    external_effect_count INTEGER NOT NULL CHECK(external_effect_count=0),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1),
    UNIQUE(invocation_id,attempt_ordinal,operation_id)
) STRICT;

CREATE TABLE agent_objections (
    objection_id TEXT PRIMARY KEY CHECK(length(objection_id)=64),
    invocation_id TEXT NOT NULL REFERENCES agent_invocations(invocation_id),
    fence_id TEXT NOT NULL REFERENCES agent_coordinator_fences(fence_id),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    candidate_result_id TEXT NOT NULL CHECK(length(candidate_result_id)=64),
    falsifier_result_id TEXT NOT NULL CHECK(length(falsifier_result_id)=64 AND falsifier_result_id<>candidate_result_id),
    candidate_context_root TEXT NOT NULL CHECK(length(candidate_context_root)=64),
    falsifier_context_root TEXT NOT NULL CHECK(length(falsifier_context_root)=64 AND falsifier_context_root<>candidate_context_root),
    candidate_capability_root TEXT NOT NULL CHECK(length(candidate_capability_root)=64),
    falsifier_capability_root TEXT NOT NULL CHECK(length(falsifier_capability_root)=64 AND falsifier_capability_root<>candidate_capability_root),
    disposition TEXT NOT NULL CHECK(disposition IN ('resolved_material','resolved_non_material','unresolved_material','unresolved_non_material')),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE agent_incidents (
    incident_id TEXT PRIMARY KEY CHECK(length(incident_id)=64),
    invocation_id TEXT NOT NULL REFERENCES agent_invocations(invocation_id),
    fence_id TEXT NOT NULL REFERENCES agent_coordinator_fences(fence_id),
    generation INTEGER NOT NULL CHECK(generation>=0),
    attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=0),
    recorded_at TEXT NOT NULL CHECK(length(recorded_at)>=20),
    detector_category TEXT NOT NULL CHECK(length(detector_category)>0),
    detector_version TEXT NOT NULL CHECK(length(detector_version)>0),
    rule_id TEXT NOT NULL CHECK(length(rule_id)>0),
    boundary TEXT NOT NULL CHECK(length(boundary)>0),
    disposition TEXT NOT NULL CHECK(length(disposition)>0),
    lineage_root TEXT NOT NULL CHECK(length(lineage_root)=64),
    nonce TEXT NOT NULL CHECK(length(nonce)=64),
    retention_disposition TEXT NOT NULL CHECK(length(retention_disposition)>0),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE agent_results (
    result_id TEXT PRIMARY KEY CHECK(length(result_id)=64),
    invocation_id TEXT NOT NULL UNIQUE REFERENCES agent_invocations(invocation_id),
    fence_id TEXT NOT NULL REFERENCES agent_coordinator_fences(fence_id),
    attempt_id TEXT NOT NULL REFERENCES agent_model_attempts(attempt_id),
    status TEXT NOT NULL CHECK(status IN ('abstain','need_more_data','research_only','shadow_eligible','proposal_eligible','invalid')),
    evidence_root TEXT NOT NULL CHECK(length(evidence_root)=64),
    memory_root TEXT NOT NULL CHECK(length(memory_root)=64),
    budget_root TEXT NOT NULL CHECK(length(budget_root)=64),
    receipt_root TEXT NOT NULL CHECK(length(receipt_root)=64),
    objection_root TEXT NOT NULL CHECK(length(objection_root)=64),
    terminal_reason TEXT NOT NULL CHECK(length(terminal_reason)>0),
    external_effect_count INTEGER NOT NULL CHECK(external_effect_count=0),
    canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
    canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)>1)
) STRICT;

CREATE TABLE agent_operation_ledger (
    operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=64),
    invocation_id TEXT NOT NULL REFERENCES agent_invocations(invocation_id),
    operation_kind TEXT NOT NULL CHECK(operation_kind IN ('identity','receive','fence','lifecycle','trigger','budget','attempt','tool','objection','incident','terminal','abandon')),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64),
    operation_root TEXT NOT NULL CHECK(length(operation_root)=64),
    item_count INTEGER NOT NULL CHECK(item_count>=1),
    result_sha256 TEXT NOT NULL CHECK(length(result_sha256)=64),
    result_bytes BLOB NOT NULL CHECK(length(result_bytes)>1)
) STRICT;

CREATE TRIGGER agent_identity_events_no_update BEFORE UPDATE ON agent_identity_events BEGIN SELECT RAISE(ABORT,'append_only:agent_identity_events'); END;
CREATE TRIGGER agent_identity_events_no_delete BEFORE DELETE ON agent_identity_events BEGIN SELECT RAISE(ABORT,'append_only:agent_identity_events'); END;
CREATE TRIGGER agent_invocations_no_update BEFORE UPDATE ON agent_invocations BEGIN SELECT RAISE(ABORT,'append_only:agent_invocations'); END;
CREATE TRIGGER agent_invocations_no_delete BEFORE DELETE ON agent_invocations BEGIN SELECT RAISE(ABORT,'append_only:agent_invocations'); END;
CREATE TRIGGER agent_coordinator_fences_no_update BEFORE UPDATE ON agent_coordinator_fences BEGIN SELECT RAISE(ABORT,'append_only:agent_coordinator_fences'); END;
CREATE TRIGGER agent_coordinator_fences_no_delete BEFORE DELETE ON agent_coordinator_fences BEGIN SELECT RAISE(ABORT,'append_only:agent_coordinator_fences'); END;
CREATE TRIGGER agent_lifecycle_events_no_update BEFORE UPDATE ON agent_lifecycle_events BEGIN SELECT RAISE(ABORT,'append_only:agent_lifecycle_events'); END;
CREATE TRIGGER agent_lifecycle_events_no_delete BEFORE DELETE ON agent_lifecycle_events BEGIN SELECT RAISE(ABORT,'append_only:agent_lifecycle_events'); END;
CREATE TRIGGER agent_activation_triggers_no_update BEFORE UPDATE ON agent_activation_triggers BEGIN SELECT RAISE(ABORT,'append_only:agent_activation_triggers'); END;
CREATE TRIGGER agent_activation_triggers_no_delete BEFORE DELETE ON agent_activation_triggers BEGIN SELECT RAISE(ABORT,'append_only:agent_activation_triggers'); END;
CREATE TRIGGER agent_budget_events_no_update BEFORE UPDATE ON agent_budget_events BEGIN SELECT RAISE(ABORT,'append_only:agent_budget_events'); END;
CREATE TRIGGER agent_budget_events_no_delete BEFORE DELETE ON agent_budget_events BEGIN SELECT RAISE(ABORT,'append_only:agent_budget_events'); END;
CREATE TRIGGER agent_model_attempts_no_update BEFORE UPDATE ON agent_model_attempts BEGIN SELECT RAISE(ABORT,'append_only:agent_model_attempts'); END;
CREATE TRIGGER agent_model_attempts_no_delete BEFORE DELETE ON agent_model_attempts BEGIN SELECT RAISE(ABORT,'append_only:agent_model_attempts'); END;
CREATE TRIGGER agent_tool_receipts_no_update BEFORE UPDATE ON agent_tool_receipts BEGIN SELECT RAISE(ABORT,'append_only:agent_tool_receipts'); END;
CREATE TRIGGER agent_tool_receipts_no_delete BEFORE DELETE ON agent_tool_receipts BEGIN SELECT RAISE(ABORT,'append_only:agent_tool_receipts'); END;
CREATE TRIGGER agent_objections_no_update BEFORE UPDATE ON agent_objections BEGIN SELECT RAISE(ABORT,'append_only:agent_objections'); END;
CREATE TRIGGER agent_objections_no_delete BEFORE DELETE ON agent_objections BEGIN SELECT RAISE(ABORT,'append_only:agent_objections'); END;
CREATE TRIGGER agent_incidents_no_update BEFORE UPDATE ON agent_incidents BEGIN SELECT RAISE(ABORT,'append_only:agent_incidents'); END;
CREATE TRIGGER agent_incidents_no_delete BEFORE DELETE ON agent_incidents BEGIN SELECT RAISE(ABORT,'append_only:agent_incidents'); END;
CREATE TRIGGER agent_results_no_update BEFORE UPDATE ON agent_results BEGIN SELECT RAISE(ABORT,'append_only:agent_results'); END;
CREATE TRIGGER agent_results_no_delete BEFORE DELETE ON agent_results BEGIN SELECT RAISE(ABORT,'append_only:agent_results'); END;
CREATE TRIGGER agent_operation_ledger_no_update BEFORE UPDATE ON agent_operation_ledger BEGIN SELECT RAISE(ABORT,'append_only:agent_operation_ledger'); END;
CREATE TRIGGER agent_operation_ledger_no_delete BEFORE DELETE ON agent_operation_ledger BEGIN SELECT RAISE(ABORT,'append_only:agent_operation_ledger'); END;
