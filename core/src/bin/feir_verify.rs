//! `feir-verify` — offline verify CLI (wraps decision-core). Full bundle verification is wired
//! in M1 piece 5; this entrypoint currently verifies a single record's content_hash.

use feir_decision_core::{verify_content_hash, CanonValue};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "record" {
        eprintln!("usage: feir-verify record <record.json>");
        return ExitCode::from(2);
    }
    let path = &args[2];
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
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
    match verify_content_hash(&value) {
        Ok(()) => {
            println!("PASS: content_hash verified");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::from(1)
        }
    }
}
