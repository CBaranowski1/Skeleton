CREATE TABLE simulation_model_profiles (
    model_profile_id TEXT PRIMARY KEY CHECK (
        length(model_profile_id) = 64 AND model_profile_id NOT GLOB '*[^0-9a-f]*'
    ),
    family TEXT NOT NULL,
    prior_model_profile_id TEXT,
    model_version TEXT NOT NULL,
    algorithm_id TEXT NOT NULL,
    canonical_sha256 TEXT NOT NULL CHECK (
        length(canonical_sha256) = 64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_profile BLOB NOT NULL,
    CHECK (prior_model_profile_id IS NULL OR model_profile_id <> prior_model_profile_id),
    FOREIGN KEY (prior_model_profile_id) REFERENCES simulation_model_profiles(model_profile_id)
) STRICT;

CREATE TABLE simulation_calibrations (
    calibration_id TEXT PRIMARY KEY CHECK (
        length(calibration_id) = 64 AND calibration_id NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_id TEXT NOT NULL,
    prior_model_profile_id TEXT NOT NULL,
    output_model_profile_id TEXT NOT NULL UNIQUE,
    evaluation_request_id TEXT NOT NULL,
    observation_inventory_sha256 TEXT NOT NULL,
    rights_exclusion_inventory_sha256 TEXT NOT NULL,
    algorithm_id TEXT NOT NULL,
    code_sha256 TEXT NOT NULL,
    parameter_delta_sha256 TEXT NOT NULL,
    diagnostics_sha256 TEXT NOT NULL,
    canonical_sha256 TEXT NOT NULL,
    canonical_calibration BLOB NOT NULL,
    CHECK (prior_model_profile_id <> output_model_profile_id),
    FOREIGN KEY (prior_model_profile_id) REFERENCES simulation_model_profiles(model_profile_id),
    FOREIGN KEY (output_model_profile_id) REFERENCES simulation_model_profiles(model_profile_id)
) STRICT;

CREATE TABLE simulation_runs (
    run_id TEXT PRIMARY KEY CHECK (
        length(run_id) = 64 AND run_id NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_id TEXT NOT NULL,
    trace_root TEXT NOT NULL,
    terminal_status TEXT NOT NULL CHECK (
        terminal_status IN ('completed', 'unresolved', 'abstained', 'rolled_back', 'corrected', 'voided', 'settled')
    ),
    canonical_sha256 TEXT NOT NULL CHECK (
        length(canonical_sha256) = 64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_run BLOB NOT NULL,
    UNIQUE (manifest_id, trace_root, terminal_status)
) STRICT;

CREATE TABLE simulation_transitions (
    transition_id TEXT PRIMARY KEY CHECK (
        length(transition_id) = 64 AND transition_id NOT GLOB '*[^0-9a-f]*'
    ),
    run_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    event_id TEXT NOT NULL,
    prior_transition_id TEXT,
    canonical_sha256 TEXT NOT NULL CHECK (
        length(canonical_sha256) = 64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_transition BLOB NOT NULL,
    UNIQUE (run_id, ordinal),
    FOREIGN KEY (run_id) REFERENCES simulation_runs(run_id),
    FOREIGN KEY (prior_transition_id) REFERENCES simulation_transitions(transition_id)
) STRICT;

CREATE TABLE simulation_run_ancestry (
    child_run_id TEXT PRIMARY KEY,
    parent_run_id TEXT NOT NULL,
    changed_input_inventory_sha256 TEXT NOT NULL,
    superseded_report_id TEXT NOT NULL,
    canonical_sha256 TEXT NOT NULL,
    canonical_ancestry BLOB NOT NULL,
    CHECK (child_run_id <> parent_run_id),
    FOREIGN KEY (child_run_id) REFERENCES simulation_runs(run_id),
    FOREIGN KEY (parent_run_id) REFERENCES simulation_runs(run_id),
    FOREIGN KEY (superseded_report_id) REFERENCES simulation_reports(report_id)
) STRICT;

CREATE TABLE simulation_reports (
    report_id TEXT PRIMARY KEY CHECK (
        length(report_id) = 64 AND report_id NOT GLOB '*[^0-9a-f]*'
    ),
    run_id TEXT NOT NULL UNIQUE,
    trace_root TEXT NOT NULL,
    canonical_sha256 TEXT NOT NULL CHECK (
        length(canonical_sha256) = 64 AND canonical_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_report BLOB NOT NULL,
    FOREIGN KEY (run_id) REFERENCES simulation_runs(run_id)
) STRICT;

CREATE TRIGGER simulation_model_profiles_no_update
BEFORE UPDATE ON simulation_model_profiles
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_model_profiles');
END;

CREATE TRIGGER simulation_model_profiles_no_delete
BEFORE DELETE ON simulation_model_profiles
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_model_profiles');
END;

CREATE TRIGGER simulation_calibrations_no_update
BEFORE UPDATE ON simulation_calibrations
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_calibrations');
END;

CREATE TRIGGER simulation_calibrations_no_delete
BEFORE DELETE ON simulation_calibrations
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_calibrations');
END;

CREATE TRIGGER simulation_runs_no_update
BEFORE UPDATE ON simulation_runs
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_runs');
END;

CREATE TRIGGER simulation_runs_no_delete
BEFORE DELETE ON simulation_runs
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_runs');
END;

CREATE TRIGGER simulation_transitions_no_update
BEFORE UPDATE ON simulation_transitions
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_transitions');
END;

CREATE TRIGGER simulation_transitions_no_delete
BEFORE DELETE ON simulation_transitions
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_transitions');
END;

CREATE TRIGGER simulation_run_ancestry_no_update
BEFORE UPDATE ON simulation_run_ancestry
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_run_ancestry');
END;

CREATE TRIGGER simulation_run_ancestry_no_delete
BEFORE DELETE ON simulation_run_ancestry
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_run_ancestry');
END;

CREATE TRIGGER simulation_reports_no_update
BEFORE UPDATE ON simulation_reports
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_reports');
END;

CREATE TRIGGER simulation_reports_no_delete
BEFORE DELETE ON simulation_reports
BEGIN
    SELECT RAISE(ABORT, 'append_only:simulation_reports');
END;
