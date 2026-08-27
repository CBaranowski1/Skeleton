//! Fail-closed support for the owner-built Foundation bootstrap candidate.
//!
//! The local candidate is intentionally non-promotable.  It authenticates its
//! own byte inventory and exposes closed operation names, but it cannot create
//! or use an authority key.

use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const PACKAGE_SCHEMA: &str = "skeleton.foundation-bootstrap-package.v1";
pub const PACKAGE_NAME: &str = "FoundationBootstrapPackageV1";
pub const PACKAGE_VERSION: &str = "0.1.0-local-candidate";
pub const BUILD_CLASS: &str = "owner_built_local_candidate";
pub const MANIFEST_NAME: &str = "package-manifest.json";
pub const ROOT_NAME: &str = "package-root.txt";
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_FILES: usize = 1_024;
const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_COLLECTION_ITEMS: usize = 100_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const INVENTORY_DOMAIN: &[u8] = b"SKEL-FOUNDATION-INVENTORY-V1\0";

pub const PROMOTION_BLOCKERS: &[&str] = &[
    "independent_vendor_provenance_missing",
    "trusted_authenticode_chain_missing",
    "independent_custody_history_missing",
    "owner_present_cng_provisioning_disabled",
    "independent_source_review_missing",
    "clean_host_reproduction_missing",
];

pub const APPROVED_OPERATIONS: &[&str] = &[
    "Describe",
    "FoundationBootstrapSign",
    "FoundationTerminalVerify",
    "PackageSelfKAT",
    "PostGenesisSafeBootstrapVerify",
    "PreGenesisSafeBootstrapVerify",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapError {
    pub code: &'static str,
    pub detail: String,
}

impl BootstrapError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for BootstrapError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRecord {
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageLimits {
    pub max_file_bytes: u64,
    pub max_files: usize,
    pub max_total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageManifest {
    pub schema: String,
    pub package_name: String,
    pub package_version: String,
    pub build_class: String,
    pub promotion_eligible: bool,
    pub promotion_blockers: Vec<String>,
    pub approved_operations: Vec<String>,
    pub limits: PackageLimits,
    pub files: Vec<FileRecord>,
    pub inventory_root_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageReport {
    pub file_count: usize,
    pub inventory_root_sha256: String,
    pub package_root_sha256: String,
    pub promotion_blockers: Vec<String>,
    pub promotion_eligible: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KatReport {
    pub failed: usize,
    pub passed: usize,
    pub status: String,
    pub tests: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderObservation {
    pub platform_ksp_available: bool,
    pub software_ksp_available: bool,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_bytes(&digest)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn frame_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

pub fn inventory_root(records: &[FileRecord]) -> Result<String, BootstrapError> {
    let mut prior = None;
    let mut hasher = Sha256::new();
    hasher.update(INVENTORY_DOMAIN);
    hasher.update((records.len() as u64).to_be_bytes());
    for record in records {
        validate_relative_path(&record.path)?;
        if prior
            .as_ref()
            .is_some_and(|value: &String| value >= &record.path)
        {
            return Err(BootstrapError::new(
                "inventory_order_invalid",
                "file paths must be unique and strictly sorted",
            ));
        }
        validate_sha256(&record.sha256)?;
        frame_bytes(&mut hasher, record.path.as_bytes());
        hasher.update(record.length.to_be_bytes());
        frame_bytes(&mut hasher, record.sha256.as_bytes());
        prior = Some(record.path.clone());
    }
    Ok(hex_bytes(&hasher.finalize()))
}

fn validate_sha256(value: &str) -> Result<(), BootstrapError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BootstrapError::new(
            "sha256_invalid",
            "digest must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

pub fn validate_relative_path(value: &str) -> Result<(), BootstrapError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains(':')
        || value.as_bytes().contains(&0)
    {
        return Err(BootstrapError::new(
            "path_invalid",
            "manifest paths must be non-empty portable relative paths",
        ));
    }
    let path = Path::new(value);
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(BootstrapError::new(
            "path_invalid",
            "dot, parent, root, and prefix components are forbidden",
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BootstrapError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| BootstrapError::new("file_unreadable", path.display().to_string()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(BootstrapError::new(
            "file_not_regular",
            path.display().to_string(),
        ));
    }
    if metadata.len() > maximum {
        return Err(BootstrapError::new(
            "file_too_large",
            path.display().to_string(),
        ));
    }
    let bytes = fs::read(path)
        .map_err(|_| BootstrapError::new("file_unreadable", path.display().to_string()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(BootstrapError::new(
            "file_changed_during_read",
            path.display().to_string(),
        ));
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

pub fn parse_strict_json(raw: &[u8]) -> Result<Value, BootstrapError> {
    if raw.len() > MAX_JSON_BYTES {
        return Err(BootstrapError::new("json_too_large", "input exceeds limit"));
    }
    if raw.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(BootstrapError::new(
            "bom_not_allowed",
            "UTF-8 BOM is forbidden",
        ));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| BootstrapError::new("invalid_utf8", "JSON must be UTF-8"))?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| {
            let message = error.to_string();
            for (needle, code) in [
                ("duplicate_member", "duplicate_member"),
                ("unsafe_integer", "unsafe_integer"),
                ("non_finite_number", "non_finite_number"),
                ("maximum_depth_exceeded", "maximum_depth_exceeded"),
                ("collection_too_large", "collection_too_large"),
            ] {
                if message.contains(needle) {
                    return BootstrapError::new(code, message);
                }
            }
            BootstrapError::new("invalid_json", message)
        })?;
    deserializer
        .end()
        .map_err(|error| BootstrapError::new("trailing_json", error.to_string()))?;
    Ok(value)
}

pub fn canonical_json(value: &Value) -> Result<Vec<u8>, BootstrapError> {
    fn write_value(value: &Value, output: &mut String) -> Result<(), BootstrapError> {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(true) => output.push_str("true"),
            Value::Bool(false) => output.push_str("false"),
            Value::Number(number) => {
                if let Some(value) = number.as_i64() {
                    if value.unsigned_abs() > MAX_SAFE_INTEGER {
                        return Err(BootstrapError::new(
                            "unsafe_integer",
                            "canonical integers must be within the I-JSON safe range",
                        ));
                    }
                    output.push_str(&value.to_string());
                } else if let Some(value) = number.as_u64() {
                    if value > MAX_SAFE_INTEGER {
                        return Err(BootstrapError::new(
                            "unsafe_integer",
                            "canonical integers must be within the I-JSON safe range",
                        ));
                    }
                    output.push_str(&value.to_string());
                } else {
                    return Err(BootstrapError::new(
                        "floating_point_forbidden",
                        "the package canonical profile accepts safe integers only",
                    ));
                }
            }
            Value::String(value) => {
                output.push_str(&serde_json::to_string(value).map_err(|error| {
                    BootstrapError::new("string_serialization_failed", error.to_string())
                })?)
            }
            Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write_value(value, output)?;
                }
                output.push(']');
            }
            Value::Object(object) => {
                let mut names: Vec<&String> = object.keys().collect();
                names.sort();
                output.push('{');
                for (index, name) in names.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(name).map_err(|error| {
                        BootstrapError::new("member_serialization_failed", error.to_string())
                    })?);
                    output.push(':');
                    write_value(
                        object.get(*name).expect("name originated from object keys"),
                        output,
                    )?;
                }
                output.push('}');
            }
        }
        Ok(())
    }

    let mut output = String::new();
    write_value(value, &mut output)?;
    Ok(output.into_bytes())
}

fn manifest_from_bytes(raw: &[u8]) -> Result<(PackageManifest, Vec<u8>), BootstrapError> {
    let value = parse_strict_json(raw)?;
    let canonical = canonical_json(&value)?;
    if raw != canonical {
        return Err(BootstrapError::new(
            "manifest_not_canonical",
            "package-manifest.json must be exact canonical JSON with no trailing newline",
        ));
    }
    let manifest: PackageManifest = serde_json::from_value(value)
        .map_err(|error| BootstrapError::new("manifest_shape_invalid", error.to_string()))?;
    Ok((manifest, canonical))
}

fn portable_relative(root: &Path, path: &Path) -> Result<String, BootstrapError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| BootstrapError::new("path_outside_root", path.display().to_string()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(BootstrapError::new(
                "path_invalid",
                path.display().to_string(),
            ));
        };
        parts.push(name.to_string_lossy().into_owned());
    }
    let value = parts.join("/");
    validate_relative_path(&value)?;
    Ok(value)
}

fn walk_files(
    root: &Path,
    current: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), BootstrapError> {
    let metadata = fs::symlink_metadata(current)
        .map_err(|_| BootstrapError::new("path_unreadable", current.display().to_string()))?;
    if metadata.file_type().is_symlink() {
        return Err(BootstrapError::new(
            "reparse_or_symlink_forbidden",
            current.display().to_string(),
        ));
    }
    if metadata.is_file() {
        output.push(current.to_path_buf());
        if output.len() > MAX_FILES + 2 {
            return Err(BootstrapError::new(
                "too_many_files",
                root.display().to_string(),
            ));
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(BootstrapError::new(
            "unsupported_file_type",
            current.display().to_string(),
        ));
    }
    let mut children = fs::read_dir(current)
        .map_err(|_| BootstrapError::new("directory_unreadable", current.display().to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BootstrapError::new("directory_unreadable", current.display().to_string()))?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        walk_files(root, &child.path(), output)?;
    }
    Ok(())
}

pub fn collect_inventory(root: &Path) -> Result<Vec<FileRecord>, BootstrapError> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|_| BootstrapError::new("package_root_unreadable", root.display().to_string()))?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(BootstrapError::new(
            "package_root_invalid",
            root.display().to_string(),
        ));
    }
    let mut paths = Vec::new();
    walk_files(root, root, &mut paths)?;
    let mut records = Vec::new();
    let mut total = 0u64;
    for path in paths {
        let relative = portable_relative(root, &path)?;
        if matches!(relative.as_str(), MANIFEST_NAME | ROOT_NAME) {
            continue;
        }
        let bytes = read_bounded(&path, MAX_FILE_BYTES)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| BootstrapError::new("total_size_overflow", relative.clone()))?;
        if total > MAX_TOTAL_BYTES {
            return Err(BootstrapError::new(
                "package_too_large",
                root.display().to_string(),
            ));
        }
        records.push(FileRecord {
            path: relative,
            length: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        });
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    if records.is_empty() {
        return Err(BootstrapError::new(
            "package_empty",
            root.display().to_string(),
        ));
    }
    if records.len() > MAX_FILES {
        return Err(BootstrapError::new(
            "too_many_files",
            root.display().to_string(),
        ));
    }
    Ok(records)
}

pub fn new_local_candidate_manifest(
    records: Vec<FileRecord>,
) -> Result<PackageManifest, BootstrapError> {
    let root = inventory_root(&records)?;
    Ok(PackageManifest {
        schema: PACKAGE_SCHEMA.to_owned(),
        package_name: PACKAGE_NAME.to_owned(),
        package_version: PACKAGE_VERSION.to_owned(),
        build_class: BUILD_CLASS.to_owned(),
        promotion_eligible: false,
        promotion_blockers: PROMOTION_BLOCKERS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        approved_operations: APPROVED_OPERATIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        limits: PackageLimits {
            max_file_bytes: MAX_FILE_BYTES,
            max_files: MAX_FILES,
            max_total_bytes: MAX_TOTAL_BYTES,
        },
        files: records,
        inventory_root_sha256: root,
    })
}

pub fn canonical_manifest_bytes(manifest: &PackageManifest) -> Result<Vec<u8>, BootstrapError> {
    let value = serde_json::to_value(manifest)
        .map_err(|error| BootstrapError::new("manifest_serialization_failed", error.to_string()))?;
    canonical_json(&value)
}

fn validate_manifest_policy(manifest: &PackageManifest) -> Result<(), BootstrapError> {
    if manifest.schema != PACKAGE_SCHEMA
        || manifest.package_name != PACKAGE_NAME
        || manifest.package_version != PACKAGE_VERSION
        || manifest.build_class != BUILD_CLASS
    {
        return Err(BootstrapError::new(
            "manifest_identity_invalid",
            "schema, name, version, or build class differs",
        ));
    }
    if manifest.promotion_eligible {
        return Err(BootstrapError::new(
            "local_candidate_cannot_promote",
            "this source version must remain non-promotable",
        ));
    }
    let expected_blockers: Vec<String> = PROMOTION_BLOCKERS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let expected_operations: Vec<String> = APPROVED_OPERATIONS
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    if manifest.promotion_blockers != expected_blockers
        || manifest.approved_operations != expected_operations
    {
        return Err(BootstrapError::new(
            "manifest_policy_invalid",
            "blocker or operation inventory differs",
        ));
    }
    if manifest.limits
        != (PackageLimits {
            max_file_bytes: MAX_FILE_BYTES,
            max_files: MAX_FILES,
            max_total_bytes: MAX_TOTAL_BYTES,
        })
    {
        return Err(BootstrapError::new(
            "manifest_limits_invalid",
            "package limits differ",
        ));
    }
    Ok(())
}

pub fn verify_package(root: &Path) -> Result<PackageReport, BootstrapError> {
    let manifest_raw = read_bounded(&root.join(MANIFEST_NAME), MAX_JSON_BYTES as u64)?;
    let (manifest, canonical_manifest) = manifest_from_bytes(&manifest_raw)?;
    validate_manifest_policy(&manifest)?;
    let observed = collect_inventory(root)?;
    if observed != manifest.files {
        return Err(BootstrapError::new(
            "package_inventory_mismatch",
            "manifest file inventory does not equal live bytes",
        ));
    }
    let observed_inventory_root = inventory_root(&observed)?;
    if observed_inventory_root != manifest.inventory_root_sha256 {
        return Err(BootstrapError::new(
            "inventory_root_mismatch",
            "declared inventory root does not equal live inventory",
        ));
    }
    let expected_package_root = sha256_hex(&canonical_manifest);
    let root_raw = read_bounded(&root.join(ROOT_NAME), 128)?;
    let expected_root_file = format!("{expected_package_root}\n");
    if root_raw != expected_root_file.as_bytes() {
        return Err(BootstrapError::new(
            "package_root_mismatch",
            "package-root.txt does not bind the canonical manifest",
        ));
    }
    Ok(PackageReport {
        file_count: observed.len(),
        inventory_root_sha256: observed_inventory_root,
        package_root_sha256: expected_package_root,
        promotion_blockers: manifest.promotion_blockers,
        promotion_eligible: false,
        status: "verified_local_candidate".to_owned(),
    })
}

pub fn package_root_from_current_exe() -> Result<PathBuf, BootstrapError> {
    let executable = std::env::current_exe()
        .map_err(|_| BootstrapError::new("executable_path_unavailable", "current_exe failed"))?;
    executable.parent().map(Path::to_path_buf).ok_or_else(|| {
        BootstrapError::new("package_root_unavailable", executable.display().to_string())
    })
}

pub fn parse_operation_args() -> Result<String, BootstrapError> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 || arguments[0] != "--operation" {
        return Err(BootstrapError::new(
            "arguments_invalid",
            "expected exactly --operation <closed-name>",
        ));
    }
    arguments[1]
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| BootstrapError::new("operation_invalid_utf8", "operation must be UTF-8"))
}

pub fn run_builtin_kats() -> Result<KatReport, BootstrapError> {
    let mut tests = Vec::new();
    let canonical = canonical_json(&parse_strict_json(br#"{"b":2,"a":1}"#)?)?;
    if canonical != br#"{"a":1,"b":2}"# {
        return Err(BootstrapError::new("kat_failed", "canonical JSON vector"));
    }
    tests.push("canonical_json_order".to_owned());

    if sha256_hex(b"abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
        return Err(BootstrapError::new("kat_failed", "SHA-256 abc vector"));
    }
    tests.push("sha256_abc".to_owned());

    for (name, raw, code) in [
        (
            "duplicate_member_rejected",
            br#"{"a":1,"a":2}"#.as_slice(),
            "duplicate_member",
        ),
        (
            "bom_rejected",
            b"\xef\xbb\xbf{}".as_slice(),
            "bom_not_allowed",
        ),
        (
            "unsafe_integer_rejected",
            br#"{"n":9007199254740992}"#.as_slice(),
            "unsafe_integer",
        ),
    ] {
        let error = parse_strict_json(raw).expect_err("hostile KAT must reject");
        if error.code != code {
            return Err(BootstrapError::new(
                "kat_failed",
                format!("{name} returned {}", error.code),
            ));
        }
        tests.push(name.to_owned());
    }

    for hostile in ["../escape", "/absolute", "C:/drive", "a\\b", "./dot"] {
        if validate_relative_path(hostile).is_ok() {
            return Err(BootstrapError::new(
                "kat_failed",
                format!("hostile path accepted: {hostile}"),
            ));
        }
    }
    tests.push("hostile_paths_rejected".to_owned());

    let records = vec![
        FileRecord {
            path: "a.txt".to_owned(),
            length: 3,
            sha256: sha256_hex(b"abc"),
        },
        FileRecord {
            path: "z.txt".to_owned(),
            length: 0,
            sha256: sha256_hex(b""),
        },
    ];
    let root_one = inventory_root(&records)?;
    let root_two = inventory_root(&records)?;
    if root_one != root_two {
        return Err(BootstrapError::new(
            "kat_failed",
            "inventory root stability",
        ));
    }
    tests.push("inventory_root_stable".to_owned());

    Ok(KatReport {
        failed: 0,
        passed: tests.len(),
        status: "passed".to_owned(),
        tests,
    })
}

#[cfg(windows)]
fn open_provider(name: windows_sys::core::PCWSTR) -> bool {
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_PROV_HANDLE, NCryptFreeObject, NCryptOpenStorageProvider,
    };
    let mut handle: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: NCrypt receives a valid out-pointer, a static NUL-terminated
    // provider name supplied by windows-sys, and zero flags.  A successful
    // handle is immediately released and is never used for key operations.
    let status = unsafe { NCryptOpenStorageProvider(&mut handle, name, 0) };
    if status != 0 || handle == 0 {
        return false;
    }
    // SAFETY: handle was returned successfully by NCryptOpenStorageProvider
    // and is released exactly once.
    let free_status = unsafe { NCryptFreeObject(handle) };
    free_status == 0
}

pub fn observe_cng_providers() -> ProviderObservation {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{
            MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER,
        };
        ProviderObservation {
            platform_ksp_available: open_provider(MS_PLATFORM_CRYPTO_PROVIDER),
            software_ksp_available: open_provider(MS_KEY_STORAGE_PROVIDER),
        }
    }
    #[cfg(not(windows))]
    {
        ProviderObservation {
            platform_ksp_available: false,
            software_ksp_available: false,
        }
    }
}

pub fn success_json(operation: &str, report: Option<&PackageReport>) -> Value {
    json!({
        "build_class": BUILD_CLASS,
        "operation": operation,
        "package": report,
        "promotion_eligible": false,
        "status": "passed"
    })
}

pub fn blocked_json(operation: &str, code: &str, report: Option<&PackageReport>) -> Value {
    json!({
        "build_class": BUILD_CLASS,
        "code": code,
        "operation": operation,
        "package": report,
        "promotion_eligible": false,
        "status": "blocked"
    })
}

pub fn error_json(error: &BootstrapError) -> Value {
    json!({
        "code": error.code,
        "detail": error.detail,
        "promotion_eligible": false,
        "status": "rejected"
    })
}

pub fn print_canonical(value: &Value) -> Result<(), BootstrapError> {
    let bytes = canonical_json(value)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| BootstrapError::new("canonical_utf8_failed", "internal encoding error"))?;
    println!("{text}");
    Ok(())
}

pub fn exact_inventory_paths(records: &[FileRecord]) -> BTreeSet<String> {
    records.iter().map(|record| record.path.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "skeleton-foundation-bootstrap-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn create_package(root: &Path) -> PackageManifest {
        fs::create_dir_all(root.join("source")).expect("create test package");
        fs::write(root.join("source/example.txt"), b"example").expect("write test file");
        let records = collect_inventory(root).expect("collect test inventory");
        let manifest = new_local_candidate_manifest(records).expect("create manifest");
        let bytes = canonical_manifest_bytes(&manifest).expect("canonical manifest");
        fs::write(root.join(MANIFEST_NAME), &bytes).expect("write manifest");
        fs::write(root.join(ROOT_NAME), format!("{}\n", sha256_hex(&bytes))).expect("write root");
        manifest
    }

    #[test]
    fn builtin_kats_pass() {
        let report = run_builtin_kats().expect("KATs pass");
        assert_eq!(report.failed, 0);
        assert!(report.passed >= 7);
    }

    #[test]
    fn package_verification_accepts_exact_candidate() {
        let root = temp_root("exact");
        create_package(&root);
        let report = verify_package(&root).expect("exact package verifies");
        assert_eq!(report.status, "verified_local_candidate");
        assert!(!report.promotion_eligible);
        fs::remove_dir_all(root).expect("remove test package");
    }

    #[test]
    fn package_verification_rejects_tamper() {
        let root = temp_root("tamper");
        create_package(&root);
        fs::write(root.join("source/example.txt"), b"changed").expect("tamper test file");
        assert_eq!(
            verify_package(&root).expect_err("tamper rejects").code,
            "package_inventory_mismatch"
        );
        fs::remove_dir_all(root).expect("remove test package");
    }

    #[test]
    fn package_verification_rejects_extra_file() {
        let root = temp_root("extra");
        create_package(&root);
        fs::write(root.join("extra.txt"), b"extra").expect("write extra file");
        assert_eq!(
            verify_package(&root).expect_err("extra rejects").code,
            "package_inventory_mismatch"
        );
        fs::remove_dir_all(root).expect("remove test package");
    }

    #[test]
    fn package_verification_rejects_noncanonical_manifest() {
        let root = temp_root("noncanonical");
        let manifest = create_package(&root);
        let pretty = serde_json::to_vec_pretty(&manifest).expect("pretty manifest");
        fs::write(root.join(MANIFEST_NAME), pretty).expect("replace manifest");
        assert_eq!(
            verify_package(&root)
                .expect_err("noncanonical rejects")
                .code,
            "manifest_not_canonical"
        );
        fs::remove_dir_all(root).expect("remove test package");
    }

    #[test]
    fn inventory_rejects_unsorted_records() {
        let records = vec![
            FileRecord {
                path: "z".to_owned(),
                length: 0,
                sha256: sha256_hex(b""),
            },
            FileRecord {
                path: "a".to_owned(),
                length: 0,
                sha256: sha256_hex(b""),
            },
        ];
        assert_eq!(
            inventory_root(&records).expect_err("unsorted rejects").code,
            "inventory_order_invalid"
        );
    }
}
