use clap::{Arg, Command};
use serde_json::json;
use sha2::{Digest, Sha256};
use skeleton_contracts::{read_bounded, verify_fixture_corpus};
use std::path::Path;

fn digest(bytes: &[u8]) -> String {
    let value = Sha256::digest(bytes);
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let command = Command::new("skeleton-contracts")
        .disable_help_subcommand(true)
        .subcommand_required(true)
        .subcommand(
            Command::new("verify-fixtures").arg(
                Arg::new("contracts-root")
                    .long("contracts-root")
                    .required(true)
                    .value_name("PATH"),
            ),
        )
        .subcommand(
            Command::new("verify-transfer")
                .arg(
                    Arg::new("bundle")
                        .long("bundle")
                        .required(true)
                        .value_name("PATH"),
                )
                .arg(
                    Arg::new("evidence")
                        .long("evidence")
                        .required(true)
                        .value_name("PATH"),
                ),
        );
    let matches = command.get_matches();
    let result = match matches.subcommand() {
        Some(("verify-fixtures", arguments)) => {
            let root = arguments
                .get_one::<String>("contracts-root")
                .expect("required by clap");
            verify_fixture_corpus(Path::new(root)).map(|report| {
                json!({
                    "mode": "verify-fixtures",
                    "record_count": report.record_count,
                    "signed_record_count": report.signed_record_count,
                    "source_count": report.source_count,
                    "status": "passed"
                })
            })
        }
        Some(("verify-transfer", arguments)) => {
            let bundle_path = arguments
                .get_one::<String>("bundle")
                .expect("required by clap");
            let evidence_path = arguments
                .get_one::<String>("evidence")
                .expect("required by clap");
            read_bounded(Path::new(bundle_path)).and_then(|bundle| {
                read_bounded(Path::new(evidence_path)).map(|evidence| {
                    json!({
                        "bundle_sha256": digest(&bundle),
                        "evidence_sha256": digest(&evidence),
                        "mode": "verify-transfer",
                        "status": "observed"
                    })
                })
            })
        }
        _ => unreachable!("subcommand_required"),
    };
    match result {
        Ok(value) => println!(
            "{}",
            serde_json_canonicalizer::to_string(&value)
                .expect("bounded observation JSON is canonicalizable")
        ),
        Err(error) => {
            eprintln!("{}", json!({"error": error.code, "status": "rejected"}));
            std::process::exit(1);
        }
    }
}
