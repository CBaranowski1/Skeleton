use serde_json::json;
use skeleton_foundation_bootstrap::{
    BootstrapError, MANIFEST_NAME, ROOT_NAME, canonical_manifest_bytes, collect_inventory,
    error_json, new_local_candidate_manifest, print_canonical, sha256_hex, verify_package,
};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

fn parse_args() -> Result<PathBuf, BootstrapError> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments.len() != 4
        || arguments[0] != "--operation"
        || arguments[1] != "FinalizePackage"
        || arguments[2] != "--package-root"
    {
        return Err(BootstrapError::new(
            "arguments_invalid",
            "expected --operation FinalizePackage --package-root <PATH>",
        ));
    }
    Ok(PathBuf::from(&arguments[3]))
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), BootstrapError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| BootstrapError::new("output_create_failed", error.to_string()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| BootstrapError::new("output_write_failed", error.to_string()))
}

fn run() -> Result<(), BootstrapError> {
    let root = parse_args()?;
    if root.join(MANIFEST_NAME).exists() || root.join(ROOT_NAME).exists() {
        return Err(BootstrapError::new(
            "package_already_finalized",
            root.display().to_string(),
        ));
    }
    let records = collect_inventory(&root)?;
    let manifest = new_local_candidate_manifest(records)?;
    let manifest_bytes = canonical_manifest_bytes(&manifest)?;
    let package_root = sha256_hex(&manifest_bytes);
    write_new_file(&root.join(MANIFEST_NAME), &manifest_bytes)?;
    if let Err(error) = write_new_file(
        &root.join(ROOT_NAME),
        format!("{package_root}\n").as_bytes(),
    ) {
        let _ = fs::remove_file(root.join(MANIFEST_NAME));
        return Err(error);
    }
    let report = verify_package(&root)?;
    print_canonical(&json!({
        "operation": "FinalizePackage",
        "package": report,
        "status": "passed"
    }))
}

fn main() {
    if let Err(error) = run() {
        let _ = print_canonical(&error_json(&error));
        std::process::exit(1);
    }
}
