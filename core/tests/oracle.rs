//! Differential test against the executable Lean model (formal/lean/Oracle/Main.lean).
//!
//! `formal/oracle/expected.json` is produced by running the Lean definitions the proofs are about
//! (`Canon.ser`, `escChar`, `serInt`, `lp`, `be32`/`be64`, `Family.msg` for every preimage family,
//! the `Seal` record/checkpoint hash preimages) over `formal/oracle/inputs.json`; CI regenerates it
//! and fails on any diff. This test asserts that the real Rust functions produce the *same bytes*.
//! Preimages are compared before SHA-256, including the production broker/resource builders.
//!
//! Corpus values: JSON with objects written `{"obj": [[key, value], ...]}` (explicit, unsorted member
//! order). They are decoded with `CanonValue::parse` (as the golden-vector tests do) and rebuilt with
//! the raw constructors, so the serializer under test sees members in the file's order.

use averin_decision_core::canon::CanonValue;
use averin_decision_core::checkpoint::{
    checkpoint_hash_preimage, compute_checkpoint_hash, seal_checkpoint, verify_checkpoint_sealed,
};
use averin_decision_core::commit::{commit, commit_preimage, FieldDomain};
use averin_decision_core::hashx::{hex_lower, lp_into, sha256, sha256_prefixed};
use averin_decision_core::record::{
    compute_content_hash, content_hash_preimage, verify_content_hash, RecordError,
};
use averin_decision_core::{anchor, authority, sign, verify};
use std::path::PathBuf;

fn oracle_file(name: &str) -> CanonValue {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("formal")
        .join("oracle")
        .join(name);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p:?}: {e}"));
    CanonValue::parse(&text).unwrap_or_else(|e| panic!("parse {p:?}: {e}"))
}

fn arr<'a>(v: &'a CanonValue, k: &str) -> &'a Vec<CanonValue> {
    v.get(k)
        .and_then(|x| x.as_array())
        .unwrap_or_else(|| panic!("missing array {k}"))
}

fn s<'a>(v: &'a CanonValue, k: &str) -> &'a str {
    v.get(k)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("missing string {k}"))
}

fn unhex(h: &str) -> Vec<u8> {
    assert!(h.len() % 2 == 0, "odd hex length");
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Pairs each input row with the model's output row for a section.
fn section(k: &str) -> Vec<(CanonValue, CanonValue)> {
    let (inp, exp) = (oracle_file("inputs.json"), oracle_file("expected.json"));
    let (i, e) = (arr(&inp, k), arr(&exp, k));
    assert_eq!(i.len(), e.len(), "{k}: expected.json is stale (row count)");
    assert!(!i.is_empty(), "{k}: empty corpus section");
    i.iter().cloned().zip(e.iter().cloned()).collect()
}

/// Corpus encoding -> CanonValue, keeping the file's member order (no sorting, no NFC pass).
fn value(v: &CanonValue) -> CanonValue {
    match v {
        CanonValue::Array(xs) => CanonValue::Array(xs.iter().map(value).collect()),
        CanonValue::Object(_) => {
            let members = v.get("obj").and_then(|m| m.as_array()).expect("obj");
            CanonValue::Object(
                members
                    .iter()
                    .map(|p| {
                        let p = p.as_array().expect("[key, value]");
                        (p[0].as_str().expect("key").to_string(), value(&p[1]))
                    })
                    .collect(),
            )
        }
        other => other.clone(),
    }
}

fn check(what: &str, got: &[u8], want_hex: &str) {
    assert_eq!(
        hex_lower(got),
        want_hex,
        "{what}: Rust bytes differ from the Lean model"
    );
}

#[test]
fn canonical_serialization_matches_model() {
    for (i, e) in section("canon") {
        assert_eq!(s(&i, "name"), s(&e, "name"));
        let v = value(i.get("value").unwrap());
        check(s(&i, "name"), v.serialize().as_bytes(), s(&e, "hex"));
    }
}

#[test]
fn string_escape_matches_model_esc_char() {
    for (i, e) in section("esc") {
        let cp = i.as_int().unwrap();
        assert_eq!(Some(cp), e.get("cp").and_then(|c| c.as_int()));
        let c = char::from_u32(cp as u32).expect("scalar value");
        let text = CanonValue::Str(c.to_string()).serialize();
        let inner = &text.as_bytes()[1..text.len() - 1];
        check(&format!("escChar U+{cp:04X}"), inner, s(&e, "hex"));
    }
}

#[test]
fn integer_serialization_matches_model_ser_int() {
    for (i, e) in section("ints") {
        let n = i.as_int().unwrap();
        assert_eq!(Some(n), e.get("int").and_then(|c| c.as_int()));
        check(
            &format!("serInt {n}"),
            CanonValue::Int(n).serialize().as_bytes(),
            s(&e, "hex"),
        );
    }
}

#[test]
fn length_prefix_matches_model_lp() {
    for (i, e) in section("lp") {
        let b = unhex(i.as_str().unwrap());
        let mut out = vec![0xAA]; // lp_into appends: a prefix byte must survive untouched
        assert!(lp_into(&mut out, &b));
        assert_eq!(out[0], 0xAA);
        check(&format!("lp {}", hex_lower(&b)), &out[1..], s(&e, "hex"));
    }
    for (i, e) in section("be32") {
        let n = u32::try_from(i.as_int().unwrap()).unwrap();
        check(&format!("be32 {n}"), &n.to_be_bytes(), s(&e, "hex"));
    }
    for (i, e) in section("be64") {
        // Decimal strings: values above i64::MAX are not RCP integers.
        let n: u64 = i.as_str().unwrap().parse().unwrap();
        check(&format!("be64 {n}"), &n.to_be_bytes(), s(&e, "hex"));
    }
}

enum F {
    S(String),
    U(u64),
    Hex(Vec<u8>),
}

fn field(v: &CanonValue) -> F {
    if let Some(x) = v.get("s").and_then(|x| x.as_str()) {
        F::S(x.to_string())
    } else if let Some(n) = v.get("u64").and_then(|x| x.as_int()) {
        F::U(n as u64)
    } else if let Some(h) = v.get("hex").and_then(|x| x.as_str()) {
        F::Hex(unhex(h))
    } else {
        panic!("bad field")
    }
}

fn st(f: &F) -> &str {
    match f {
        F::S(x) => x,
        _ => panic!("expected a string field"),
    }
}
fn int(f: &F) -> i64 {
    match f {
        F::U(n) => *n as i64,
        _ => panic!("expected a u64 field"),
    }
}
fn raw(f: &F) -> &[u8] {
    match f {
        F::Hex(b) => b,
        _ => panic!("expected a hex field"),
    }
}

#[test]
fn every_preimage_family_matches_model() {
    let mut seen = Vec::new();
    let first_step = section("families")
        .into_iter()
        .find(|(i, _)| s(i, "family") == "grant head step")
        .unwrap()
        .0;
    let first_fields: Vec<F> = arr(&first_step, "fields").iter().map(field).collect();
    let first_grant = (int(&first_fields[1]), st(&first_fields[2]).to_string());
    for (i, e) in section("families")
        .into_iter()
        .chain(section("preimage_variants"))
    {
        let name = s(&i, "family");
        assert_eq!(name, s(&e, "family"));
        let want = s(&e, "hex");
        let f: Vec<F> = arr(&i, "fields").iter().map(field).collect();
        let tail = i.get("tail").filter(|t| !t.is_null()).map(field);
        let tail = || st(tail.as_ref().expect("tail"));
        match name {
            "record sig" => check(name, &sign::preimage(sign::RECORD_SIG_TAG, tail()), want),
            "checkpoint sig" => check(
                name,
                &sign::preimage(sign::CHECKPOINT_SIG_TAG, tail()),
                want,
            ),
            // verify.rs verifies these through sign::verify with a literal tag; the literals are
            // inventoried against Preimage.lean by formal/check-refinement.py.
            "taxonomy statement" => {
                check(name, &sign::preimage("averin.taxonomy.v1", tail()), want)
            }
            "revocation statement" => {
                check(name, &sign::preimage("averin.revocation.v1", tail()), want)
            }
            "revocation merkle root" => check(
                name,
                &sign::preimage("averin.broker.revocation.merkleroot.v1", tail()),
                want,
            ),
            "attestation" => check(name, &sign::preimage("averin.attestation.v1", tail()), want),
            "authority evidence" => check(
                name,
                &authority::preimage(st(&f[0]), st(&f[1]), st(&f[2]), tail()),
                want,
            ),
            "test anchor" => check(name, &anchor::anchor_preimage(st(&f[0]), st(&f[1])), want),
            "use PoP" => check(
                name,
                &verify::use_pop_preimage(
                    st(&f[0]),
                    st(&f[1]),
                    st(&f[2]),
                    st(&f[3]),
                    st(&f[4]),
                    st(&f[5]),
                ),
                want,
            ),
            "cosig approval" => check(
                name,
                &verify::cosig_approval_preimage(
                    st(&f[0]),
                    st(&f[1]),
                    st(&f[2]),
                    int(&f[3]),
                    int(&f[4]),
                ),
                want,
            ),
            "delegation hop" => check(
                name,
                &verify::delegation_hop_preimage(
                    st(&f[0]),
                    int(&f[1]),
                    st(&f[2]),
                    st(&f[3]),
                    st(&f[4]),
                    st(&f[5]),
                    st(&f[6]),
                    int(&f[7]),
                ),
                want,
            ),
            "introspection transcript" => check(
                name,
                &verify::introspection_transcript_preimage(
                    st(&f[0]),
                    st(&f[1]),
                    st(&f[2]),
                    st(&f[3]),
                    int(&f[4]),
                    int(&f[5]),
                ),
                want,
            ),
            "federation cert" => check(
                name,
                &verify::federation_cert_preimage(
                    st(&f[0]),
                    st(&f[1]),
                    st(&f[2]),
                    st(&f[3]),
                    st(&f[4]),
                    int(&f[5]),
                ),
                want,
            ),
            "hiding commitment" => {
                let dom = FieldDomain::parse(st(&f[0])).expect("field domain");
                let (nonce, v) = (raw(&f[1]), raw(&f[2]));
                check(name, &commit_preimage(dom, v, nonce).unwrap(), want);
                assert_eq!(
                    commit(dom, v, nonce).unwrap(),
                    sha256_prefixed(&unhex(want))
                );
            }
            "use ledger" => check(
                name,
                &verify::ledger_commitment_preimage(st(&f[0]), st(&f[1]), int(&f[2])),
                want,
            ),
            "grant head seed" => check(name, &verify::grant_head_seed_preimage(), want),
            "grant head step" => {
                let acc: [u8; 32] = raw(&f[0]).try_into().unwrap();
                check(
                    name,
                    &verify::grant_head_step_preimage(&acc, int(&f[1]), st(&f[2])),
                    want,
                );
                let prefix = if hex_lower(&acc)
                    == verify::grant_head_root(&[]).trim_start_matches("sha256:")
                {
                    Vec::new()
                } else {
                    assert_eq!(
                        hex_lower(&acc),
                        verify::grant_head_root(&[first_grant.clone()])
                            .trim_start_matches("sha256:"),
                        "step accumulator must come from the actual prior production fold"
                    );
                    vec![first_grant.clone()]
                };
                let mut grants = prefix;
                grants.push((int(&f[1]), st(&f[2]).to_string()));
                assert_eq!(
                    verify::grant_head_root(&grants),
                    sha256_prefixed(&unhex(want)),
                    "{name}: root != SHA-256 of the Lean model's step preimage {want}"
                );
            }
            "revocation leaf" => check(name, &verify::revocation_leaf_preimage(st(&f[0])), want),
            other => panic!("no Rust builder mapped for Lean family {other:?}: add one here"),
        }
        // Check the production hash result separately from its production preimage bytes.
        // A caller that stops using the checked byte helper must fail this assertion.
        let digest: Option<Vec<u8>> = match name {
            "use PoP" => Some(
                verify::use_pop_challenge(
                    st(&f[0]),
                    st(&f[1]),
                    st(&f[2]),
                    st(&f[3]),
                    st(&f[4]),
                    st(&f[5]),
                )
                .to_vec(),
            ),
            "cosig approval" => Some(
                verify::cosig_approval_challenge(
                    st(&f[0]),
                    st(&f[1]),
                    st(&f[2]),
                    int(&f[3]),
                    int(&f[4]),
                )
                .to_vec(),
            ),
            "delegation hop" => Some(
                verify::delegation_hop_challenge(
                    st(&f[0]),
                    int(&f[1]),
                    st(&f[2]),
                    st(&f[3]),
                    st(&f[4]),
                    st(&f[5]),
                    st(&f[6]),
                    int(&f[7]),
                )
                .to_vec(),
            ),
            "introspection transcript" => Some(
                verify::introspection_transcript_challenge(
                    st(&f[0]),
                    st(&f[1]),
                    st(&f[2]),
                    st(&f[3]),
                    int(&f[4]),
                    int(&f[5]),
                )
                .to_vec(),
            ),
            "federation cert" => Some(
                verify::federation_cert_challenge(
                    st(&f[0]),
                    st(&f[1]),
                    st(&f[2]),
                    st(&f[3]),
                    st(&f[4]),
                    int(&f[5]),
                )
                .to_vec(),
            ),
            "revocation leaf" => Some(verify::revocation_leaf(st(&f[0])).to_vec()),
            "use ledger" => Some(unhex(
                verify::ledger_commitment(st(&f[0]), st(&f[1]), int(&f[2]))
                    .trim_start_matches("sha256:"),
            )),
            "grant head seed" => Some(unhex(
                verify::grant_head_root(&[]).trim_start_matches("sha256:"),
            )),
            _ => None,
        };
        if let Some(digest) = digest {
            assert_eq!(
                digest,
                sha256(&unhex(want)).to_vec(),
                "{name}: production digest differs from Lean preimage hash"
            );
        }
        seen.push(name.to_string());
    }
    assert!(seen.len() >= 18, "family samples went missing: {seen:?}");
}

#[test]
fn revocation_merkle_hash_inputs_match_model() {
    for (i, e) in section("merkle") {
        let kind = s(&i, "kind");
        assert_eq!(kind, s(&e, "kind"));
        let left: [u8; 32] = unhex(s(&i, "left")).try_into().unwrap();
        let pre = match kind {
            "leaf" => verify::merkle_leaf_preimage(&left),
            "node" => {
                let right: [u8; 32] = unhex(s(&i, "right")).try_into().unwrap();
                verify::merkle_node_preimage(&left, &right)
            }
            _ => panic!("unknown Merkle kind {kind}"),
        };
        check(kind, &pre, s(&e, "hex"));
    }

    // The actual empty-set producer folds the two sentinel leaves into one node.
    // The node inputs here are derived only from the independently modeled Lean
    // leaf bytes, so this catches a caller that stops using the checked helpers.
    let modeled = section("merkle");
    let min_leaf = sha256(&unhex(s(&modeled[0].1, "hex")));
    let max_leaf = sha256(&unhex(s(&modeled[1].1, "hex")));
    let expected = sha256(&[&[1u8][..], &min_leaf[..], &max_leaf[..]].concat());
    assert_eq!(
        verify::revocation_merkle_root(&[]),
        format!("sha256:{}", hex_lower(&expected))
    );
}

#[test]
fn opaque_challenge_fields_are_not_silently_normalized() {
    let composed = "é";
    let decomposed = "e\u{301}";
    let pairs = [
        (
            "ledger",
            verify::ledger_commitment_preimage(composed, "n", 1),
            verify::ledger_commitment_preimage(decomposed, "n", 1),
        ),
        (
            "grant head",
            verify::grant_head_step_preimage(&[0; 32], 1, composed),
            verify::grant_head_step_preimage(&[0; 32], 1, decomposed),
        ),
        (
            "revocation leaf",
            verify::revocation_leaf_preimage(composed),
            verify::revocation_leaf_preimage(decomposed),
        ),
        (
            "use PoP",
            verify::use_pop_preimage(composed, "r", "read", "p", "c", "n"),
            verify::use_pop_preimage(decomposed, "r", "read", "p", "c", "n"),
        ),
        (
            "cosig",
            verify::cosig_approval_preimage(composed, "kid", "cb", 1, 2),
            verify::cosig_approval_preimage(decomposed, "kid", "cb", 1, 2),
        ),
        (
            "delegation",
            verify::delegation_hop_preimage(composed, 0, "a", "b", "s", "read", "r", 2),
            verify::delegation_hop_preimage(decomposed, 0, "a", "b", "s", "read", "r", 2),
        ),
        (
            "introspection",
            verify::introspection_transcript_preimage(composed, "lease", "s", "r", 1, 2),
            verify::introspection_transcript_preimage(decomposed, "lease", "s", "r", 1, 2),
        ),
        (
            "federation",
            verify::federation_cert_preimage(composed, "subject", "kid", "s", "r", 2),
            verify::federation_cert_preimage(decomposed, "subject", "kid", "s", "r", 2),
        ),
    ];
    for (family, a, b) in pairs {
        assert_ne!(a, b, "{family} silently normalized an opaque field");
    }
    let pre_b = verify::use_pop_preimage(decomposed, "r", "read", "p", "c", "n");
    assert_eq!(
        verify::use_pop_challenge(decomposed, "r", "read", "p", "c", "n"),
        sha256(&pre_b)
    );
    assert_eq!(
        verify::ledger_commitment(decomposed, "n", 1),
        sha256_prefixed(&verify::ledger_commitment_preimage(decomposed, "n", 1))
    );
}

fn with_members(v: CanonValue, extra: &[(&str, CanonValue)]) -> CanonValue {
    let CanonValue::Object(mut m) = v else {
        panic!("body must be an object")
    };
    m.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
    CanonValue::Object(m)
}

fn digest_str(fill: u8) -> CanonValue {
    CanonValue::Str(format!("sha256:{}", hex_lower(&[fill; 32])))
}

#[test]
fn record_hash_preimage_matches_model() {
    for (i, e) in section("records") {
        let name = s(&i, "name");
        assert_eq!(name, s(&e, "name"));
        // RCP §9.1: content_hash and sig are the only keys excluded from the preimage. They are added
        // here (with arbitrary values) so a Rust strip list that drops anything else changes bytes.
        let rec = with_members(
            value(i.get("body").unwrap()),
            &[
                ("content_hash", digest_str(0xEE)),
                ("sig", CanonValue::Str("ed25519:AAAA".into())),
            ],
        );
        let want = s(&e, "hex");
        check(name, &content_hash_preimage(&rec).unwrap(), want);
        assert_eq!(
            compute_content_hash(&rec).unwrap(),
            sha256_prefixed(&unhex(want))
        );
    }
}

#[test]
fn checkpoint_hash_preimage_matches_model() {
    for (i, e) in section("checkpoints") {
        let name = s(&i, "name");
        assert_eq!(name, s(&e, "name"));
        // RCP §9.4: anchor, checkpoint_hash and sig are excluded from the checkpoint preimage.
        let anchor = CanonValue::Object(vec![("scheme".into(), CanonValue::Str("x".into()))]);
        let cp = with_members(
            value(i.get("body").unwrap()),
            &[
                ("anchor", anchor),
                ("checkpoint_hash", digest_str(0xDD)),
                ("sig", CanonValue::Str("ed25519:AAAA".into())),
            ],
        );
        let want = s(&e, "hex");
        check(name, &checkpoint_hash_preimage(&cp).unwrap(), want);
        assert_eq!(
            compute_checkpoint_hash(&cp).unwrap(),
            sha256_prefixed(&unhex(want))
        );
    }
}

fn set(v: &CanonValue, k: &str, x: CanonValue) -> CanonValue {
    let CanonValue::Object(m) = v else { panic!() };
    CanonValue::Object(
        m.iter()
            .map(|(mk, mv)| (mk.clone(), if mk == k { x.clone() } else { mv.clone() }))
            .collect(),
    )
}

/// `Seal.recordHashOf`/`checkpointHashOf` model the preimage with `canon_version = "rcp-1"` and the
/// v2 domain pinned. The oracle can only speak for bodies that satisfy those pins, so the verifier must
/// reject every body that does not, even when its stored hash is internally consistent.
#[test]
fn verifier_enforces_the_models_pinned_constants() {
    let (i, _) = &section("records")[0];
    let body = value(i.get("body").unwrap());
    for (k, bad) in [
        ("canon_version", "rcp-2"),
        ("domain", "flightrecorder.record.v3"),
    ] {
        let b = set(&body, k, CanonValue::Str(bad.into()));
        let rec = with_members(
            b.clone(),
            &[(
                "content_hash",
                CanonValue::Str(compute_content_hash(&b).unwrap()),
            )],
        );
        let err = verify_content_hash(&rec).expect_err("foreign pin must be rejected");
        assert!(
            matches!(
                err,
                RecordError::CanonVersionMismatch { .. } | RecordError::DomainMismatch { .. }
            ),
            "{k}={bad}: {err:?}"
        );
    }

    let (i, _) = &section("checkpoints")[0];
    let body = value(i.get("body").unwrap());
    let sk = sign::signing_key_from_seed(&[7u8; 32]);
    let vk = sk.verifying_key();
    let ok = seal_checkpoint(&body, &sk).unwrap();
    verify_checkpoint_sealed(&ok, &vk).expect("pinned checkpoint verifies");
    for (k, bad) in [
        ("canon_version", "rcp-2"),
        ("domain", "flightrecorder.checkpoint.v3"),
    ] {
        let sealed = seal_checkpoint(&set(&body, k, CanonValue::Str(bad.into())), &sk).unwrap();
        assert!(
            verify_checkpoint_sealed(&sealed, &vk).is_err(),
            "checkpoint with {k}={bad} must be rejected"
        );
    }
}
