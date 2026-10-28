//! Manual perf/golden harness (ignored by default): verifies the bundle named by `AVERIN_PERF_BUNDLE` with the
//! options file `AVERIN_PERF_OPTS` and writes the full report JSON to `AVERIN_PERF_OUT`, so the report of two
//! builds can be compared byte for byte (`sha256sum`) and timed on the same input.
//! `AVERIN_PERF_BUNDLE=b.json AVERIN_PERF_OPTS=o.json AVERIN_PERF_OUT=r.json \
//!    cargo test -p averin-decision-core --test perf_report_dump -- --ignored`

#[test]
#[ignore]
fn dump_report_json() {
    let (Ok(b), Ok(o), Ok(out)) = (
        std::env::var("AVERIN_PERF_BUNDLE"),
        std::env::var("AVERIN_PERF_OPTS"),
        std::env::var("AVERIN_PERF_OUT"),
    ) else {
        panic!("set AVERIN_PERF_BUNDLE, AVERIN_PERF_OPTS and AVERIN_PERF_OUT");
    };
    let bundle = std::fs::read_to_string(b).expect("read bundle");
    let opts = std::fs::read_to_string(o).expect("read opts");
    let json = averin_decision_core::verify::verify_bundle_with_json(&bundle, &opts);
    std::fs::write(out, json).expect("write report");
}
