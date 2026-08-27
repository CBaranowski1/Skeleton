CREATE TABLE market_adapter_descriptors (
    adapter_identity TEXT PRIMARY KEY,
    family TEXT NOT NULL,
    venue TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    environment TEXT NOT NULL CHECK (environment IN ('fixture', 'paper', 'simulation')),
    version TEXT NOT NULL,
    descriptor_sha256 TEXT NOT NULL CHECK (
        length(descriptor_sha256) = 64 AND descriptor_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_descriptor BLOB NOT NULL,
    UNIQUE (family, venue, jurisdiction, environment, version)
) STRICT;

CREATE TABLE market_events (
    market_event_id TEXT PRIMARY KEY CHECK (
        length(market_event_id) = 64 AND market_event_id NOT GLOB '*[^0-9a-f]*'
    ),
    adapter_identity TEXT NOT NULL,
    canonical_event_id TEXT NOT NULL,
    stable_identity_id TEXT NOT NULL,
    rights_record_id TEXT NOT NULL,
    rights_decision_id TEXT NOT NULL,
    family TEXT NOT NULL,
    payload_schema_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (
        length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    envelope_sha256 TEXT NOT NULL CHECK (
        length(envelope_sha256) = 64 AND envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_envelope BLOB NOT NULL,
    recorded_at TEXT NOT NULL,
    UNIQUE (adapter_identity, canonical_event_id),
    FOREIGN KEY (adapter_identity) REFERENCES market_adapter_descriptors(adapter_identity),
    FOREIGN KEY (canonical_event_id) REFERENCES canonical_events(event_id),
    FOREIGN KEY (stable_identity_id) REFERENCES stable_identities(stable_identity_id),
    FOREIGN KEY (rights_record_id) REFERENCES rights_records(rights_record_id),
    FOREIGN KEY (rights_decision_id) REFERENCES rights_decisions(decision_id)
) STRICT;

CREATE TABLE market_event_corrections (
    market_event_id TEXT PRIMARY KEY,
    correction_of_market_event_id TEXT NOT NULL UNIQUE,
    canonical_correction BLOB NOT NULL,
    CHECK (market_event_id <> correction_of_market_event_id),
    FOREIGN KEY (market_event_id) REFERENCES market_events(market_event_id),
    FOREIGN KEY (correction_of_market_event_id) REFERENCES market_events(market_event_id)
) STRICT;

CREATE TABLE market_activation_evaluations (
    activation_id TEXT PRIMARY KEY CHECK (
        length(activation_id) = 64 AND activation_id NOT GLOB '*[^0-9a-f]*'
    ),
    adapter_identity TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (disposition = 'inactive'),
    dossier_sha256 TEXT NOT NULL CHECK (
        length(dossier_sha256) = 64 AND dossier_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    canonical_evaluation BLOB NOT NULL,
    evaluated_at TEXT NOT NULL,
    FOREIGN KEY (adapter_identity) REFERENCES market_adapter_descriptors(adapter_identity)
) STRICT;

CREATE TRIGGER market_adapter_descriptors_no_update
BEFORE UPDATE ON market_adapter_descriptors
BEGIN
    SELECT RAISE(ABORT, 'append_only:market_adapter_descriptors');
END;

CREATE TRIGGER market_adapter_descriptors_no_delete
BEFORE DELETE ON market_adapter_descriptors
BEGIN
    SELECT RAISE(ABORT, 'append_only:market_adapter_descriptors');
END;

CREATE TRIGGER market_events_no_update
BEFORE UPDATE ON market_events
BEGIN
    SELECT RAISE(ABORT, 'append_only:market_events');
END;

CREATE TRIGGER market_events_no_delete
BEFORE DELETE ON market_events
BEGIN
    SELECT RAISE(ABORT, 'append_only:market_events');
END;

CREATE TRIGGER market_event_corrections_no_update
BEFORE UPDATE ON market_event_corrections
BEGIN
    SELECT RAISE(ABORT, 'append_only:market_event_corrections');
END;

CREATE TRIGGER market_event_corrections_no_delete
BEFORE DELETE ON market_event_corrections
BEGIN
    SELECT RAISE(ABORT, 'append_only:market_event_corrections');
END;

CREATE TRIGGER market_activation_evaluations_no_update
BEFORE UPDATE ON market_activation_evaluations
BEGIN
    SELECT RAISE(ABORT, 'append_only:market_activation_evaluations');
END;

CREATE TRIGGER market_activation_evaluations_no_delete
BEFORE DELETE ON market_activation_evaluations
BEGIN
    SELECT RAISE(ABORT, 'append_only:market_activation_evaluations');
END;
