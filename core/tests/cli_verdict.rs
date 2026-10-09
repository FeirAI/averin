//! SB-27: the `averin-verify bundle` headline word and exit code equal `claimVerdict`
//! (PASS / CONSISTENT / INSUFFICIENT / FAIL), the same rule as `verifier/claim-verdict.js`.
//! Exit codes: 0 = PASS, 2 = CONSISTENT, 1 = FAIL or INSUFFICIENT. Usage and unreadable-file
//! errors also exit 2 but print no `RESULT:` line (they write to stderr only). `averin-verify
//! record` uses the same words and exit codes: no PASS without a key the caller passed.

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
    let mut args = vec![bundle.as_os_str()];
    args.extend(opts.map(|o| o.as_os_str()));
    run_cli("bundle", &args).0
}

/// Runs `averin-verify <sub> <args>`; returns ((RESULT word, exit code), stdout).
fn run_cli(sub: &str, args: &[&std::ffi::OsStr]) -> ((String, i32), String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_averin-verify"));
    cmd.arg(sub).args(args);
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
    (
        (word, out.status.code().expect("exit code")),
        stdout.into_owned(),
    )
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

/// The first record of the shipped fixture, written alone; signed by the `PINNED` key.
fn record_path(name: &str, edit: impl Fn(String) -> String) -> PathBuf {
    let text = std::fs::read_to_string(bundle_path()).unwrap();
    let bundle = averin_decision_core::CanonValue::parse(&text).unwrap();
    let record = &bundle.get("records").unwrap().as_array().unwrap()[0];
    tmp(name, &edit(record.serialize()))
}

const SIGNER: &str = "ed25519pub:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
const OTHER_KEY: &str = "ed25519pub:l__Ig8gL7nI375XZubcD1K1j5goh5gWGdoK3W4s_QwM";

fn run_record(record: &std::path::Path, key: Option<&str>) -> ((String, i32), String) {
    let mut args = vec![record.as_os_str()];
    args.extend(key.map(std::ffi::OsStr::new));
    run_cli("record", &args)
}

#[test]
fn keyless_record_is_consistent_not_pass() {
    let record = record_path("record.json", |t| t);
    let (verdict, stdout) = run_record(&record, None);
    assert_eq!(verdict, ("CONSISTENT".to_string(), 2), "{stdout}");
    assert!(!stdout.contains("PASS"), "{stdout}");
}

#[test]
fn record_under_the_signer_key_is_pass_exit_zero() {
    let record = record_path("record-keyed.json", |t| t);
    assert_eq!(run_record(&record, Some(SIGNER)).0, ("PASS".to_string(), 0));
}

#[test]
fn record_fails_under_another_key_or_when_tampered() {
    let record = record_path("record-other.json", |t| t);
    assert_eq!(
        run_record(&record, Some(OTHER_KEY)).0,
        ("FAIL".to_string(), 1)
    );
    let tampered = record_path("record-tampered.json", |t| {
        let edited = t.replacen("proj-001", "proj-002", 1);
        assert_ne!(t, edited);
        edited
    });
    for key in [None, Some(SIGNER)] {
        assert_eq!(
            run_record(&tampered, key).0,
            ("FAIL".to_string(), 1),
            "{key:?}"
        );
    }
    let not_json = tmp("record-not-json.json", "{");
    assert_eq!(run_record(&not_json, None).0, ("FAIL".to_string(), 1));
}

#[test]
fn record_usage_errors_exit_two_without_a_result_line() {
    let record = record_path("record-usage.json", |t| t);
    assert_eq!(run_record(&record, Some("not-a-key")).0, (String::new(), 2));
    let missing = std::env::temp_dir().join("averin-cli-verdict-no-such-record.json");
    assert_eq!(run_record(&missing, None).0, (String::new(), 2));
}
