use serde_json::json;
use skeleton_foundation_bootstrap::{
    APPROVED_OPERATIONS, BUILD_CLASS, BootstrapError, blocked_json, error_json,
    observe_cng_providers, package_root_from_current_exe, parse_operation_args, print_canonical,
    run_builtin_kats, success_json, verify_package,
};

fn run() -> Result<i32, BootstrapError> {
    let operation = parse_operation_args()?;
    match operation.as_str() {
        "Describe" => {
            print_canonical(&json!({
                "approved_operations": APPROVED_OPERATIONS,
                "authority_mutation_enabled": false,
                "build_class": BUILD_CLASS,
                "cng_providers": observe_cng_providers(),
                "component": "FoundationBootstrapSigner",
                "promotion_eligible": false,
                "status": "described"
            }))?;
            Ok(0)
        }
        "PackageSelfKAT" => {
            let kats = run_builtin_kats()?;
            let root = package_root_from_current_exe()?;
            let manifest_present = root.join("package-manifest.json").is_file();
            let report = if manifest_present {
                Some(verify_package(&root)?)
            } else {
                None
            };
            let mut value = success_json(&operation, report.as_ref());
            value["built_in_kats"] = serde_json::to_value(kats).map_err(|error| {
                BootstrapError::new("kat_serialization_failed", error.to_string())
            })?;
            value["cng_providers"] =
                serde_json::to_value(observe_cng_providers()).map_err(|error| {
                    BootstrapError::new("provider_serialization_failed", error.to_string())
                })?;
            value["package_manifest_present"] = json!(manifest_present);
            print_canonical(&value)?;
            Ok(0)
        }
        "FoundationBootstrapSign" => {
            let root = package_root_from_current_exe()?;
            let report = verify_package(&root)?;
            print_canonical(&blocked_json(
                &operation,
                "owner_present_cng_provisioning_disabled",
                Some(&report),
            ))?;
            Ok(78)
        }
        _ => Err(BootstrapError::new(
            "operation_unknown",
            "signer accepts only Describe, PackageSelfKAT, or FoundationBootstrapSign",
        )),
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            let _ = print_canonical(&error_json(&error));
            std::process::exit(64);
        }
    }
}
