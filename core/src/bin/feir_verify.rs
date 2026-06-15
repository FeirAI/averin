//! `feir-verify` — offline verify CLI (wraps decision-core). Full bundle verification (records +
//! checkpoint history + TSA tokens + public keys) is wired in M1 piece 5. This entrypoint
//! verifies a single record and is **honest about what it proves**:
//!   * `record <file>`              → internal consistency only (hash recomputes) — NOT authentic
//!   * `record <file> <pubkey>`     → full authenticity (shape + content_hash + signature)

use feir_decision_core::record::{validate_record_shape, verify_content_hash, verify_sealed};
use feir_decision_core::sign::decode_pubkey;
use feir_decision_core::CanonValue;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "record" {
        eprintln!("usage: feir-verify record <record.json> [ed25519pub:<key>]");
        eprintln!("  without a key: checks internal consistency only (NOT authenticity)");
        eprintln!("  with a key:    full authenticity (shape + content_hash + signature)");
        return ExitCode::from(2);
    }
    let text = match std::fs::read_to_string(&args[2]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", args[2]);
            return ExitCode::from(2);
        }
    };
    let value = match CanonValue::parse(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return ExitCode::from(1);
        }
    };

    match args.get(3) {
        Some(pubkey) => {
            let vk = match decode_pubkey(pubkey) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: bad public key: {e}");
                    return ExitCode::from(2);
                }
            };
            match verify_sealed(&value, &vk) {
                Ok(()) => {
                    println!("PASS (authentic): shape + content_hash + signature verified");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("FAIL: {e}");
                    ExitCode::from(1)
                }
            }
        }
        None => match validate_record_shape(&value).and_then(|()| verify_content_hash(&value)) {
            Ok(()) => {
                println!(
                    "PASS (integrity only): content_hash recomputes and shape is valid.\n\
                     NOTE: not authenticated — pass the signer's ed25519pub: key to verify the signature."
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("FAIL: {e}");
                ExitCode::from(1)
            }
        },
    }
}
