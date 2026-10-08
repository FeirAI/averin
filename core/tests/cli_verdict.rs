//! SB-27: the `averin-verify bundle` headline word and exit code equal `claimVerdict`
//! (PASS / CONSISTENT / INSUFFICIENT / FAIL), the same rule as `verifier/claim-verdict.js`.
//! Exit codes: 0 = PASS, 2 = CONSISTENT, 1 = FAIL or INSUFFICIENT. Usage and unreadable-file
//! errors also exit 2 but print no `RESULT:` line (they write to stderr only).

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn bundle_path() -> PathBuf {
    root().join("spec/fixtures/bundle-valid.json")
}

/// Runs the CLI; returns (RESULT word, exit code).
fn run(bundle: &std::path::Path, opts: Option<&std::path::Path>) -> (String, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_averin-verify"));
    cmd.arg("bundle").arg(bundle);
    if let Some(o) = opts {
        cmd.arg(o);
    }
    let out = cmd.output().expect("run averin-verify");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let word = stdout
        .lines()
        .find_map(|l| l.strip_prefix("RESULT: "))
        .map(|rest| {
            rest.split(|c: char| !c.is_ascii_uppercase())
                .next()
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    (word, out.status.code().expect("exit code"))
}

fn tmp(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("averin-cli-verdict-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

const PINNED: &str =
    r#"{"signing_keys":["ed25519pub:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"]}"#;

#[test]
fn unpinned_self_keyed_bundle_is_consistent_not_pass() {
    assert_eq!(run(&bundle_path(), None), ("CONSISTENT".to_string(), 2));
}

#[test]
fn pinned_bundle_is_pass_exit_zero() {
    let opts = tmp("pinned.json", PINNED);
    assert_eq!(run(&bundle_path(), Some(&opts)), ("PASS".to_string(), 0));
}

#[test]
fn unsatisfied_requested_claim_is_insufficient_exit_one() {
    let opts = tmp(
        "complete.json",
        r#"{"signing_keys":["ed25519pub:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"],"claim_policy":{"requested":"complete_brokered"}}"#,
    );
    assert_eq!(
        run(&bundle_path(), Some(&opts)),
        ("INSUFFICIENT".to_string(), 1)
    );
}

#[test]
fn tampered_bundle_is_fail_exit_one() {
    let text = std::fs::read_to_string(bundle_path()).unwrap();
    let tampered = text.replacen("proj-001", "proj-002", 1);
    assert_ne!(text, tampered);
    let path = tmp("tampered.json", &tampered);
    let (word, code) = run(&path, None);
    assert_eq!((word.as_str(), code), ("FAIL", 1));
}
