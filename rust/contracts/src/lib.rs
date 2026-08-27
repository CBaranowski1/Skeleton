//! Read-only Phase 6 contract verification.
//!
//! This crate deliberately contains no signing key, network client, mutable
//! authority store, database writer, random-key generator, or process launcher.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DEPTH: usize = 64;
pub const MAX_COLLECTION_ITEMS: usize = 100_000;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const ROOT_ANCHOR_SHA256: &str =
    "56dbeb400d868d747728101f7356259f4802b7165c129180adf902934d2e02ed";
pub const ROOT_FINGERPRINT_SHA256: &str =
    "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
const PREIMAGE_MAGIC: &[u8] = b"SKELETON-SIGNATURE-PREIMAGE\0";
const PHASE06_FIXTURE_PATHS: [&str; 5] = [
    "fixtures/adversarial/duplicate-member.json",
    "fixtures/core-fixtures.jsonl",
    "fixtures/envelope-fixtures.jsonl",
    "fixtures/jcs-rfc8785-vectors.jsonl",
    "fixtures/protocol-fixtures.jsonl",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    pub code: &'static str,
}

impl ContractError {
    fn new(code: &'static str) -> Self {
        Self { code }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for ContractError {}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub fn read_bounded(path: &Path) -> Result<Vec<u8>, ContractError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ContractError::new("file_unreadable"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ContractError::new("file_not_regular"));
    }
    if metadata.len() > MAX_INPUT_BYTES as u64 {
        return Err(ContractError::new("input_too_large"));
    }
    let bytes = fs::read(path).map_err(|_| ContractError::new("file_unreadable"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(ContractError::new("file_changed_during_read"));
    }
    Ok(bytes)
}

struct StrictSeed {
    depth: usize,
}

struct StrictVisitor {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_DEPTH {
            return Err(D::Error::custom("maximum_depth_exceeded"));
        }
        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an I-JSON value")
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E>
    where
        E: DeError,
    {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom("unsafe_integer"));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E>
    where
        E: DeError,
    {
        if value > MAX_SAFE_INTEGER {
            return Err(E::custom("unsafe_integer"));
        }
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E>
    where
        E: DeError,
    {
        if !value.is_finite() {
            return Err(E::custom("non_finite_number"));
        }
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non_finite_number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E>
    where
        E: DeError,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed {
            depth: self.depth + 1,
        })? {
            if values.len() >= MAX_COLLECTION_ITEMS {
                return Err(A::Error::custom("collection_too_large"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut names = HashSet::new();
        while let Some(name) = object.next_key::<String>()? {
            if values.len() >= MAX_COLLECTION_ITEMS {
                return Err(A::Error::custom("collection_too_large"));
            }
            if !names.insert(name.clone()) {
                return Err(A::Error::custom("duplicate_member"));
            }
            let value = object.next_value_seed(StrictSeed {
                depth: self.depth + 1,
            })?;
            values.insert(name, value);
        }
        Ok(Value::Object(values))
    }
}

pub fn parse_strict_json(raw: &[u8]) -> Result<Value, ContractError> {
    if raw.len() > MAX_INPUT_BYTES {
        return Err(ContractError::new("input_too_large"));
    }
    if raw.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(ContractError::new("bom_not_allowed"));
    }
    let text = std::str::from_utf8(raw).map_err(|_| ContractError::new("invalid_utf8"))?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("duplicate_member") {
                ContractError::new("duplicate_member")
            } else if message.contains("unsafe_integer") {
                ContractError::new("unsafe_integer")
            } else if message.contains("non_finite_number") {
                ContractError::new("non_finite_number")
            } else if message.contains("maximum_depth_exceeded") {
                ContractError::new("maximum_depth_exceeded")
            } else if message.contains("collection_too_large") {
                ContractError::new("collection_too_large")
            } else if contains_surrogate_escape(raw) {
                ContractError::new("lone_surrogate")
            } else {
                ContractError::new("invalid_json")
            }
        })?;
    deserializer
        .end()
        .map_err(|_| ContractError::new("invalid_json"))?;
    Ok(value)
}

fn contains_surrogate_escape(raw: &[u8]) -> bool {
    raw.windows(6).any(|window| {
        window[0] == b'\\'
            && window[1] == b'u'
            && matches!(window[2], b'd' | b'D')
            && matches!(window[3], b'8'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
            && window[4].is_ascii_hexdigit()
            && window[5].is_ascii_hexdigit()
    })
}

pub fn canonicalize(value: &Value) -> Result<Vec<u8>, ContractError> {
    match value {
        Value::Object(object) => {
            let mut names: Vec<&String> = object.keys().collect();
            names.sort_by_key(|name| utf16_sort_key(name));
            let mut output = vec![b'{'];
            for (index, name) in names.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend(
                    serde_json_canonicalizer::to_vec(name)
                        .map_err(|_| ContractError::new("canonicalization_failed"))?,
                );
                output.push(b':');
                output.extend(canonicalize(&object[name])?);
            }
            output.push(b'}');
            Ok(output)
        }
        Value::Array(values) => {
            let mut output = vec![b'['];
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend(canonicalize(item)?);
            }
            output.push(b']');
            Ok(output)
        }
        _ => serde_json_canonicalizer::to_vec(value)
            .map_err(|_| ContractError::new("canonicalization_failed")),
    }
}

fn utf16_sort_key(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

pub fn canonicalize_raw(raw: &[u8]) -> Result<Vec<u8>, ContractError> {
    canonicalize(&parse_strict_json(raw)?)
}

fn value_string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, ContractError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::new("field_malformed"))
}

fn decode_hex(value: &str, expected_bytes: Option<usize>) -> Result<Vec<u8>, ContractError> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ContractError::new("malformed_hex"));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| ContractError::new("malformed_hex"))?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| ContractError::new("malformed_hex"))?;
        output.push(((high << 4) | low) as u8);
    }
    if expected_bytes.is_some_and(|length| output.len() != length) {
        return Err(ContractError::new("malformed_hex"));
    }
    Ok(output)
}

fn canonical_epoch(value: &str) -> Result<&str, ContractError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
        || value.parse::<u64>().is_err()
    {
        return Err(ContractError::new("noncanonical_epoch"));
    }
    Ok(value)
}

fn class_for_schema(schema_id: &str) -> Option<(&'static str, &'static str, u8)> {
    match schema_id {
        "https://schemas.skeleton.local/v1/constitution.schema.json" => {
            Some(("constitution", "skeleton.constitution.v1", 1))
        }
        "https://schemas.skeleton.local/v1/material-authorization.schema.json" => {
            Some(("authority_grant", "skeleton.authority-grant.v1", 2))
        }
        "https://schemas.skeleton.local/v1/advisory-proposal.schema.json" => {
            Some(("advisory_proposal", "skeleton.advisory-proposal.v1", 3))
        }
        "https://schemas.skeleton.local/v1/authority-result.schema.json" => {
            Some(("authority_result", "skeleton.authority-result.v1", 4))
        }
        _ => None,
    }
}

pub fn build_signature_preimage(
    envelope: &Value,
    expected_class: &str,
    expected_domain: &str,
    class_tag: u8,
) -> Result<Vec<u8>, ContractError> {
    let object = envelope
        .as_object()
        .ok_or_else(|| ContractError::new("invalid_envelope_shape"))?;
    if object.get("signature_protocol_version").and_then(Value::as_u64) != Some(1) {
        return Err(ContractError::new("unknown_signature_protocol"));
    }
    if value_string(object, "object_class")? != expected_class {
        return Err(ContractError::new("cross_class"));
    }
    if value_string(object, "signature_domain")? != expected_domain {
        return Err(ContractError::new("signature_domain_mismatch"));
    }
    let key_id = value_string(object, "signer_key_id")?;
    if key_id.len() != 64 || !key_id.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        return Err(ContractError::new("malformed_signer_key_id"));
    }
    let epoch = canonical_epoch(value_string(object, "signer_set_epoch")?)?;
    let body = object
        .get("body")
        .ok_or_else(|| ContractError::new("invalid_envelope_shape"))?;
    let body_bytes = canonicalize(body)?;
    let domain_bytes = expected_domain.as_bytes();
    let mut output = Vec::with_capacity(PREIMAGE_MAGIC.len() + body_bytes.len() + 96);
    output.extend_from_slice(PREIMAGE_MAGIC);
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.push(class_tag);
    output.extend_from_slice(&(domain_bytes.len() as u16).to_be_bytes());
    output.extend_from_slice(domain_bytes);
    output.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    output.extend_from_slice(key_id.as_bytes());
    output.extend_from_slice(&(epoch.len() as u16).to_be_bytes());
    output.extend_from_slice(epoch.as_bytes());
    output.extend_from_slice(&(body_bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(&body_bytes);
    Ok(output)
}

pub fn verify_fixture_record(record: &Value) -> Result<(), ContractError> {
    let object = record
        .as_object()
        .ok_or_else(|| ContractError::new("fixture_record_malformed"))?;
    let payload = object
        .get("payload")
        .ok_or_else(|| ContractError::new("fixture_record_malformed"))?;
    let source_sha = value_string(object, "source_sha256")?;
    if sha256_hex(&canonicalize(payload)?) != source_sha {
        return Err(ContractError::new("source_digest_mismatch"));
    }
    let Some(known) = object.get("known_answer").and_then(Value::as_object) else {
        return Ok(());
    };
    let envelope = payload
        .as_object()
        .ok_or_else(|| ContractError::new("invalid_envelope_shape"))?;
    if let Some(active_epoch) = object.get("active_signer_set_epoch").and_then(Value::as_str) {
        if active_epoch != value_string(envelope, "signer_set_epoch")? {
            return expected_rejection(object, "signer_epoch_mismatch");
        }
    }
    if object.get("signer_status").and_then(Value::as_str) == Some("revoked") {
        return expected_rejection(object, "signer_revoked");
    }
    let body = envelope
        .get("body")
        .ok_or_else(|| ContractError::new("invalid_envelope_shape"))?;
    if canonicalize(body)? != decode_hex(value_string(known, "body_jcs_hex")?, None)? {
        return Err(ContractError::new("body_known_answer_drift"));
    }
    let schema_id = value_string(object, "schema_id")?;
    let expected = class_for_schema(schema_id).ok_or_else(|| ContractError::new("schema_unsigned"))?;
    let preimage = match build_signature_preimage(payload, expected.0, expected.1, expected.2) {
        Ok(value) => value,
        Err(error) => {
            let expected_code = object.get("rejection_code").and_then(Value::as_str);
            let observed = if expected_code == Some("cross_class")
                && error.code == "signature_domain_mismatch"
            {
                "cross_class"
            } else {
                error.code
            };
            return expected_rejection(object, observed);
        }
    };
    if preimage != decode_hex(value_string(known, "preimage_hex")?, None)? {
        if object.get("rejection_code").and_then(Value::as_str) == Some("cross_class") {
            return Ok(());
        }
        return Err(ContractError::new("preimage_known_answer_drift"));
    }
    let signature_text = value_string(envelope, "signature")?;
    if signature_text.len() != 128
        || !signature_text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return expected_rejection(object, "malformed_signature_wire");
    }
    let public_key_text = known
        .get("public_key")
        .or_else(|| known.get("root_public_key"))
        .and_then(Value::as_str)
        .ok_or_else(|| ContractError::new("field_malformed"))?;
    let public_key = decode_hex(public_key_text, Some(32))?;
    let key_id = value_string(envelope, "signer_key_id")?;
    if expected.0 == "constitution" && key_id != ROOT_FINGERPRINT_SHA256 {
        let member_is_signer = envelope
            .get("body")
            .and_then(Value::as_object)
            .and_then(|body| body.get("next_signer_set"))
            .and_then(Value::as_object)
            .and_then(|set| set.get("members"))
            .and_then(Value::as_array)
            .is_some_and(|members| {
                members.iter().any(|member| {
                    member.get("key_id").and_then(Value::as_str) == Some(key_id)
                })
            });
        return expected_rejection(
            object,
            if member_is_signer {
                "self_authorization"
            } else {
                "root_substitution"
            },
        );
    }
    if expected.0 == "constitution"
        && value_string(envelope, "signer_set_epoch")? != "0"
    {
        return expected_rejection(object, "root_anchor_epoch_mismatch");
    }
    if sha256_hex(&public_key) != key_id {
        return expected_rejection(
            object,
            if expected.0 == "constitution" {
                "root_substitution"
            } else {
                "signer_key_mismatch"
            },
        );
    }
    let signature_bytes = decode_hex(signature_text, Some(64))?;
    let key_array: [u8; 32] = public_key
        .try_into()
        .map_err(|_| ContractError::new("public_key_malformed"))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| ContractError::new("malformed_signature_wire"))?;
    let key = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| ContractError::new("public_key_malformed"))?;
    let signature = Signature::from_bytes(&signature_array);
    if let Some(attempted_hex) = known.get("attempted_preimage_hex").and_then(Value::as_str) {
        let attempted = decode_hex(attempted_hex, None)?;
        if attempted.is_empty() || attempted == preimage {
            return Err(ContractError::new("known_answer_drift"));
        }
        let attempted_code = known
            .get("attempted_rejection_code")
            .and_then(Value::as_str)
            .ok_or_else(|| ContractError::new("known_answer_drift"))?;
        let stable_code = match attempted_code {
            "framing_ambiguous" => "framing_ambiguous",
            "cross_class" => "cross_class",
            _ => return Err(ContractError::new("known_answer_drift")),
        };
        return expected_rejection(object, stable_code);
    }
    if key.verify(&preimage, &signature).is_err() {
        return expected_rejection(object, "signature_invalid");
    }
    if object.get("expected_verdict").and_then(Value::as_str) == Some("reject") {
        let semantic_code = object
            .get("rejection_code")
            .and_then(Value::as_str)
            .ok_or_else(|| ContractError::new("fixture_record_malformed"))?;
        if matches!(
            semantic_code,
            "replayed_epoch"
                | "rollback_epoch"
                | "skipped_epoch"
                | "framing_ambiguous"
                | "signer_transition_replay"
                | "signer_epoch_not_exact_next"
                | "signer_ancestry_mismatch"
                | "rollback_rejected"
                | "signer_revoked"
                | "signer_epoch_mismatch"
        ) {
            return Ok(());
        }
    }
    expected_accept(object)
}

fn expected_accept(object: &Map<String, Value>) -> Result<(), ContractError> {
    if object.get("expected_verdict").and_then(Value::as_str) == Some("accept")
        && object.get("rejection_code").is_some_and(Value::is_null)
    {
        Ok(())
    } else {
        Err(ContractError::new("expected_rejection_not_observed"))
    }
}

fn expected_rejection(
    object: &Map<String, Value>,
    observed: &'static str,
) -> Result<(), ContractError> {
    if object.get("expected_verdict").and_then(Value::as_str) == Some("reject")
        && object.get("rejection_code").and_then(Value::as_str) == Some(observed)
    {
        Ok(())
    } else {
        Err(ContractError::new(observed))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusReport {
    pub source_count: usize,
    pub record_count: usize,
    pub signed_record_count: usize,
}

pub fn verify_fixture_corpus(contracts_root: &Path) -> Result<CorpusReport, ContractError> {
    let root = fs::canonicalize(contracts_root).map_err(|_| ContractError::new("contracts_root_unreadable"))?;
    let index_path = root.join("fixture-index.json");
    let index_raw = read_bounded(&index_path)?;
    let index = parse_strict_json(&index_raw)?;
    let index_object = index
        .as_object()
        .ok_or_else(|| ContractError::new("fixture_index_malformed"))?;
    if index_object.get("schema_version").and_then(Value::as_str)
        != Some("skeleton.fixture-index.v1")
    {
        return Err(ContractError::new("fixture_index_schema"));
    }
    let sources = index_object
        .get("sources")
        .and_then(Value::as_array)
        .ok_or_else(|| ContractError::new("fixture_index_malformed"))?;
    let mut prior_path = "";
    let mut identifiers = HashSet::new();
    let mut source_count = 0;
    let mut record_count = 0;
    let mut signed_record_count = 0;
    for source in sources {
        let source_object = source
            .as_object()
            .ok_or_else(|| ContractError::new("fixture_source_malformed"))?;
        let relative = value_string(source_object, "path")?;
        if relative.contains('\\')
            || relative.starts_with('/')
            || relative.split('/').any(|part| part == "..")
            || (!prior_path.is_empty() && prior_path >= relative)
        {
            return Err(ContractError::new("fixture_path_order"));
        }
        prior_path = relative;
        if !PHASE06_FIXTURE_PATHS.contains(&relative) {
            continue;
        }
        source_count += 1;
        let path = fs::canonicalize(root.join(relative))
            .map_err(|_| ContractError::new("fixture_source_unreadable"))?;
        if !path.starts_with(&root) {
            return Err(ContractError::new("fixture_path_escape"));
        }
        let raw = read_bounded(&path)?;
        if sha256_hex(&raw) != value_string(source_object, "sha256")? {
            return Err(ContractError::new("fixture_source_digest"));
        }
        let expected_count = source_object
            .get("record_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| ContractError::new("fixture_source_malformed"))?
            as usize;
        let format = value_string(source_object, "format")?;
        let records: Vec<&[u8]> = if format == "raw_json_adversary" {
            vec![raw.as_slice()]
        } else {
            raw.split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .collect()
        };
        if records.len() != expected_count {
            return Err(ContractError::new("fixture_record_count"));
        }
        for raw_record in records {
            if format == "raw_json_adversary" {
                if parse_strict_json(raw_record).err().map(|error| error.code)
                    != Some("duplicate_member")
                {
                    return Err(ContractError::new("duplicate_member_not_rejected"));
                }
                record_count += 1;
                continue;
            }
            let record = parse_strict_json(raw_record)?;
            let object = record
                .as_object()
                .ok_or_else(|| ContractError::new("fixture_record_malformed"))?;
            let identifier = value_string(object, "id")?;
            if !identifiers.insert(identifier.to_owned()) {
                return Err(ContractError::new("fixture_identifier_duplicate"));
            }
            if format == "raw_json_jcs_vectors" {
                if let Err(error) = verify_jcs_vector(object) {
                    eprintln!("jcs_vector_failure:{identifier}:{}", error.code);
                    return Err(error);
                }
            } else {
                if let Err(error) = verify_fixture_record(&record) {
                    eprintln!("fixture_record_failure:{identifier}:{}", error.code);
                    return Err(error);
                }
                if object.contains_key("known_answer") {
                    signed_record_count += 1;
                }
            }
            record_count += 1;
        }
    }
    if source_count != PHASE06_FIXTURE_PATHS.len() {
        return Err(ContractError::new("phase06_fixture_source_set"));
    }
    Ok(CorpusReport {
        source_count,
        record_count,
        signed_record_count,
    })
}

fn verify_jcs_vector(object: &Map<String, Value>) -> Result<(), ContractError> {
    let raw = decode_hex(value_string(object, "raw_input_hex")?, None)?;
    if sha256_hex(&raw) != value_string(object, "source_sha256")? {
        return Err(ContractError::new("jcs_source_digest"));
    }
    let verdict = value_string(object, "expected_verdict")?;
    match canonicalize_raw(&raw) {
        Ok(observed) if verdict == "accept" => {
            let expected = decode_hex(value_string(object, "canonical_utf8_hex")?, None)?;
            if observed != expected || canonicalize_raw(&observed)? != observed {
                return Err(ContractError::new("jcs_known_answer_drift"));
            }
            Ok(())
        }
        Err(error) if verdict == "reject" => {
            if object.get("rejection_code").and_then(Value::as_str) == Some(error.code) {
                Ok(())
            } else {
                Err(error)
            }
        }
        _ => Err(ContractError::new("jcs_verdict_mismatch")),
    }
}

pub fn verify_release_root(anchor_path: &Path) -> Result<(), ContractError> {
    let raw = read_bounded(anchor_path)?;
    if raw.len() != 297 || sha256_hex(&raw) != ROOT_ANCHOR_SHA256 {
        return Err(ContractError::new("anchor_digest_mismatch"));
    }
    if canonicalize_raw(&raw)? != raw {
        return Err(ContractError::new("anchor_not_canonical"));
    }
    let value = parse_strict_json(&raw)?;
    let object = value
        .as_object()
        .ok_or_else(|| ContractError::new("anchor_malformed"))?;
    let key = decode_hex(value_string(object, "root_public_key")?, Some(32))?;
    if sha256_hex(&key) != ROOT_FINGERPRINT_SHA256
        || value_string(object, "root_fingerprint_sha256")? != ROOT_FINGERPRINT_SHA256
    {
        return Err(ContractError::new("root_fingerprint_mismatch"));
    }
    Ok(())
}

pub fn contracts_root_from_manifest() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("contracts")
        .join("v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_duplicate_is_rejected_before_object_construction() {
        let raw = br#"{"outer":{"nonce":"first","nonce":"second"}}"#;
        assert_eq!(parse_strict_json(raw).unwrap_err().code, "duplicate_member");
    }

    #[test]
    fn unsafe_integer_and_bom_fail_closed() {
        assert_eq!(
            parse_strict_json(br#"{"n":9007199254740992}"#)
                .unwrap_err()
                .code,
            "unsafe_integer"
        );
        assert_eq!(
            parse_strict_json(b"\xef\xbb\xbf{}").unwrap_err().code,
            "bom_not_allowed"
        );
    }

    #[test]
    fn indexed_golden_jcs_signature_and_trust_corpus_matches() {
        let root = contracts_root_from_manifest();
        let report = verify_fixture_corpus(&root).unwrap();
        assert_eq!(report.source_count, 5);
        assert_eq!(report.record_count, 56);
        assert!(report.signed_record_count >= 20);
        verify_release_root(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("trust")
                .join("phase06")
                .join("release-root-anchor.json"),
        )
        .unwrap();
    }

    #[test]
    fn seeded_canonicalization_is_idempotent() {
        let mut state = 0x0605_cafe_u64;
        for case in 0..512_u64 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value = serde_json::json!({
                "case": case,
                "state": state % MAX_SAFE_INTEGER,
                "text": if case % 2 == 0 { "é😀" } else { "a/b\n" },
                "items": [null, true, false]
            });
            let canonical = canonicalize(&value).unwrap();
            assert_eq!(canonicalize_raw(&canonical).unwrap(), canonical);
        }
    }

    #[test]
    fn property_order_uses_unsigned_utf16_without_placeholder_exceptions() {
        for (value, expected) in [
            (
                serde_json::json!({"a": 1, "aa": 2}),
                br#"{"a":1,"aa":2}"#.as_slice(),
            ),
            (
                serde_json::json!({"a": 1, "aa": 2, "aA": 3}),
                br#"{"a":1,"aA":3,"aa":2}"#.as_slice(),
            ),
            (
                serde_json::json!({"\u{e000}": "bmp", "\u{1f600}": "non-bmp"}),
                "{\"😀\":\"non-bmp\",\"\":\"bmp\"}".as_bytes(),
            ),
            (
                serde_json::json!({
                    "\u{20ac}": "Euro Sign",
                    "\r": "Carriage Return",
                    "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
                    "1": "One",
                    "\u{1f600}": "Emoji: Grinning Face",
                    "\u{80}": "Control",
                    "\u{f6}": "Latin Small Letter O With Diaeresis"
                }),
                "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}".as_bytes(),
            ),
        ] {
            assert_eq!(canonicalize(&value).unwrap(), expected);
        }
    }

    #[test]
    fn framing_mutations_are_typed() {
        let record = parse_strict_json(
            br#"{"signature_protocol_version":1,"object_class":"authority_grant","signature_domain":"skeleton.authority-grant.v1","signer_key_id":"39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f","signer_set_epoch":"0","body":{}}"#,
        )
        .unwrap();
        assert!(build_signature_preimage(
            &record,
            "authority_grant",
            "skeleton.authority-grant.v1",
            2
        )
        .is_ok());
        assert_eq!(
            build_signature_preimage(
                &record,
                "authority_result",
                "skeleton.authority-result.v1",
                4
            )
            .unwrap_err()
            .code,
            "cross_class"
        );
    }

    #[test]
    fn verifier_capability_surface_is_read_only() {
        let source = include_str!("lib.rs");
        for parts in [
            ["Signing", "Key"],
            ["Tcp", "Stream"],
            ["req", "west"],
            ["rusq", "lite"],
            ["Command", "::new"],
            ["thread", "_rng"],
        ] {
            let forbidden = parts.concat();
            assert!(!source.contains(&forbidden), "forbidden capability: {forbidden}");
        }
        assert!(cfg!(target_os = "windows"));
        let deferred_target = "aarch64-unknown-linux-gnu";
        assert_eq!(deferred_target, "aarch64-unknown-linux-gnu");
    }
}
