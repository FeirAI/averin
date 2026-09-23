//! Authority evidence verification (spec §11, threat #4 — the moat's "authority gradient").
//!
//! `caller_declared` authority is forgeable; it is just an annotation. Authority becomes *verified*
//! only when an `evidence_sig` — a signature FROM the authority system (policy engine / approval /
//! token introspection) — verifies under a pinned authority key. This module makes that distinction
//! cryptographic instead of advisory, so the UI can honestly show "declared by agent" vs "verified
//! from policy engine".

use crate::b64;
use crate::canon::CanonValue;
use crate::hashx::{lp_str_into, parse_sha256, sha256_prefixed};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

// `v2` binds `project_id` into the preimage (tenant isolation; T7/adversarial review). It is a HARD cutover from `v1`:
// the verifier accepts ONLY v2, so a v1 signature (no project_id) does not verify. This is safe as a
// PRE-DEPLOYMENT break — averin has shipped no v1-signed records (the golden vectors carry no authority sig),
// so there is nothing to migrate and adding a v1-accept fallback would only reintroduce a (downgraded)
// cross-project replay surface for zero benefit. FORWARD-COMPAT POLICY (for any change AFTER deployment):
// because authority evidence is append-only and cannot be re-signed in place, a future preimage change must
// NOT hard-cutover — it must verify the newest version first and fall back to older versions under an
// explicitly downgraded/legacy status, never silently dropping historical authority verification.
pub const AUTHORITY_SIG_TAG: &str = "averin.authority.v2";
pub const AUTHORITY_SIG_TAG_V3: &str = "averin.authority.v3";
pub const SUBJECT_PROJECTION: &str = "averin.authority.subject.v1";
pub const SUBJECT_HASH_TAG: &str = "averin.authority.subject.digest.v1";

/// Only recorder-envelope and recursive proof fields are omitted. Every other
/// top-level field, including future admitted fields and all extensions, binds.
pub const SUBJECT_TOP_EXCLUSIONS: &[&str] = &[
    "received_ts",
    "display_seq",
    "causal_prev_hashes",
    "key",
    "content_hash",
    "sig",
];
const SUBJECT_AUTHORITY_EXCLUSIONS: &[&str] = &["evidence_sig", "subject_digest"];
const SUBJECT_REQUIRED: &[&str] = &[
    "schema_version",
    "canon_version",
    "domain",
    "record_id",
    "project_id",
    "agent_id",
    "agent_version",
    "session_id",
    "span_id",
    "parent_span_id",
    "agent_ts",
    "event_type",
    "action",
    "observed_via",
    "status",
    "authority",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityTrust {
    /// No authority block.
    None,
    /// `caller_declared` (or an unknown source) — forgeable, taken at face value.
    Declared,
    /// A v3 `evidence_sig` verified under a pinned key and bound to the semantic body.
    Verified,
    /// A valid historical v2 signature binds evidence identity but not record content.
    LegacyUnbound,
    /// A verified-source claim with evidence, but no authority keys were configured to check it —
    /// distinct from `Failed` so callers don't over-flag legitimately-signed evidence.
    Unverifiable,
    /// Claims a verified source but the evidence is missing/malformed, or its signature does not
    /// verify under any trusted authority key.
    Failed,
}

impl AuthorityTrust {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthorityTrust::None => "none",
            AuthorityTrust::Declared => "declared",
            AuthorityTrust::Verified => "verified",
            AuthorityTrust::LegacyUnbound => "legacy_unbound",
            AuthorityTrust::Unverifiable => "unverifiable",
            AuthorityTrust::Failed => "failed",
        }
    }
}

/// Construct the non-circular subject from a fully finalized semantic record.
/// The recorder may add only the enumerated excluded envelope after approval.
pub fn subject_projection(record: &CanonValue) -> Result<CanonValue, &'static str> {
    let members = record
        .as_object()
        .ok_or("authority subject must be an object")?;
    for required in SUBJECT_REQUIRED {
        if record.get(required).is_none() {
            return Err("authority subject is missing a required semantic field");
        }
    }
    if record.get("schema_version").and_then(CanonValue::as_str) != Some("2")
        || record.get("canon_version").and_then(CanonValue::as_str) != Some("rcp-1")
        || record.get("domain").and_then(CanonValue::as_str) != Some("flightrecorder.record.v2")
    {
        return Err("authority subject has an unsupported record profile");
    }
    for id in [
        "record_id",
        "project_id",
        "session_id",
        "span_id",
        "agent_ts",
    ] {
        if record
            .get(id)
            .and_then(CanonValue::as_str)
            .unwrap_or("")
            .is_empty()
        {
            return Err("authority subject has an empty required semantic value");
        }
    }
    for field in [
        "agent_id",
        "agent_version",
        "event_type",
        "action",
        "observed_via",
        "status",
    ] {
        if record.get(field).and_then(CanonValue::as_str).is_none() {
            return Err("authority subject has a non-string semantic field");
        }
    }
    if let Some(parent) = record.get("parent_span_id") {
        if !parent.is_null() && parent.as_str().is_none() {
            return Err("authority subject has an invalid parent span");
        }
    }
    let authority = record
        .get("authority")
        .and_then(CanonValue::as_object)
        .ok_or("authority subject is missing authority object")?;
    if record
        .get("authority")
        .and_then(|a| a.get("proof_version"))
        .and_then(CanonValue::as_str)
        != Some("v3")
        || record
            .get("authority")
            .and_then(|a| a.get("subject_projection"))
            .and_then(CanonValue::as_str)
            != Some(SUBJECT_PROJECTION)
    {
        return Err("authority subject has an unsupported proof profile");
    }
    let stripped_authority = CanonValue::Object(
        authority
            .iter()
            .filter(|(key, _)| !SUBJECT_AUTHORITY_EXCLUSIONS.contains(&key.as_str()))
            .cloned()
            .collect(),
    );
    Ok(CanonValue::Object(
        members
            .iter()
            .filter_map(|(key, value)| {
                if SUBJECT_TOP_EXCLUSIONS.contains(&key.as_str()) {
                    None
                } else if key == "authority" {
                    Some((key.clone(), stripped_authority.clone()))
                } else {
                    Some((key.clone(), value.clone()))
                }
            })
            .collect(),
    ))
}

/// Digest bytes: LP(subject-digest-domain) || LP(projection-id) || RCP(subject).
pub fn subject_digest(record: &CanonValue) -> Result<String, &'static str> {
    let subject = subject_projection(record)?;
    Ok(sha256_prefixed(&subject_digest_preimage(&subject)?))
}

/// Hidden byte helper for the executable Lean oracle. The caller supplies the
/// already-projected canonical subject; production callers use `subject_digest`.
#[doc(hidden)]
pub fn subject_digest_preimage(subject: &CanonValue) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    if !lp_str_into(&mut bytes, SUBJECT_HASH_TAG) || !lp_str_into(&mut bytes, SUBJECT_PROJECTION) {
        return Err("authority subject framing overflow");
    }
    bytes.extend_from_slice(subject.serialize().as_bytes());
    Ok(bytes)
}

/// Every v3 preimage member is length-framed, including the two digest strings.
pub fn preimage_v3(
    source: &str,
    project_id: &str,
    record_id: &str,
    evidence_hash: &str,
    digest: &str,
) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    for value in [
        AUTHORITY_SIG_TAG_V3,
        SUBJECT_PROJECTION,
        source,
        project_id,
        record_id,
        evidence_hash,
        digest,
    ] {
        if !lp_str_into(&mut bytes, value) {
            return Err("authority v3 preimage framing overflow");
        }
    }
    Ok(bytes)
}

/// Sign an actual structured subject; callers cannot supply a blind digest.
pub fn sign_evidence_v3(
    record: &CanonValue,
    sk: &SigningKey,
) -> Result<(String, String), &'static str> {
    use ed25519_dalek::Signer;
    let authority = record.get("authority").ok_or("missing authority")?;
    let source = authority
        .get("source")
        .and_then(CanonValue::as_str)
        .ok_or("missing source")?;
    let project = record
        .get("project_id")
        .and_then(CanonValue::as_str)
        .ok_or("missing project")?;
    let record_id = record
        .get("record_id")
        .and_then(CanonValue::as_str)
        .ok_or("missing record ID")?;
    let evidence_hash = authority
        .get("evidence_hash")
        .and_then(CanonValue::as_str)
        .ok_or("missing evidence hash")?;
    if !matches!(
        source,
        "policy_engine_signed" | "human_signed" | "delegate_signed" | "gateway_enforced"
    ) || parse_sha256(evidence_hash).is_none()
    {
        return Err("invalid authority source or evidence hash");
    }
    let digest = subject_digest(record)?;
    let sig = sk.sign(&preimage_v3(
        source,
        project,
        record_id,
        evidence_hash,
        &digest,
    )?);
    Ok((digest, format!("ed25519:{}", b64::encode(&sig.to_bytes()))))
}

/// Preimage the authority system signs:
/// `LP(tag) ‖ LP(source) ‖ LP(project_id) ‖ LP(record_id) ‖ utf8(evidence_hash)`.
/// Binding `source` prevents re-labelling; binding `project_id` AND `record_id` prevents replaying a valid
/// evidence triple onto an unrelated record OR a record in a DIFFERENT project (cross-tenant replay, adversarial review).
/// `record_id` alone is caller-chosen and the verifier's duplicate-record_id rejection is only WITHIN a
/// bundle, so `project_id` is the load-bearing tenant-isolation binding.
///
/// Hidden `pub` for the Lean-oracle differential test (`core/tests/oracle.rs`).
#[doc(hidden)]
pub fn preimage(source: &str, project_id: &str, record_id: &str, evidence_hash: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(
        56 + source.len() + project_id.len() + record_id.len() + evidence_hash.len(),
    );
    lp_str_into(&mut p, AUTHORITY_SIG_TAG);
    lp_str_into(&mut p, source);
    lp_str_into(&mut p, project_id);
    lp_str_into(&mut p, record_id);
    p.extend_from_slice(evidence_hash.as_bytes());
    p
}

/// Sign an authority evidence statement (for the policy engine / approval system, and fixtures).
pub fn sign_evidence(
    source: &str,
    project_id: &str,
    record_id: &str,
    evidence_hash: &str,
    sk: &SigningKey,
) -> String {
    use ed25519_dalek::Signer;
    let sig = sk.sign(&preimage(source, project_id, record_id, evidence_hash));
    format!("ed25519:{}", b64::encode(&sig.to_bytes()))
}

/// Classify a record's authority. `trusted` are the authority systems' public keys, pinned
/// out-of-band (a policy engine / approval service). Never elevates to `Verified` without a
/// signature that checks out.
pub fn verify_authority(record: &CanonValue, trusted: &[VerifyingKey]) -> AuthorityTrust {
    verify_authority_with_key(record, trusted).0
}

/// Like [`verify_authority`], but also returns WHICH trusted key verified the evidence signature
/// for either body-bound `Verified` or historical `LegacyUnbound`. The verifier uses the key to look
/// up its ROLE-key rotation lifecycle (ADR 0006 §1): elevation under a compromised/rotated key is
/// withdrawn for evidence not anchored before the status change. Other outcomes return `None`.
pub fn verify_authority_with_key(
    record: &CanonValue,
    trusted: &[VerifyingKey],
) -> (AuthorityTrust, Option<VerifyingKey>) {
    let authority = match record.get("authority") {
        Some(a) => a,
        None => return (AuthorityTrust::None, None),
    };
    let source = authority
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match source {
        "" => (AuthorityTrust::None, None),
        "caller_declared" => (AuthorityTrust::Declared, None),
        "policy_engine_signed" | "human_signed" | "delegate_signed" | "gateway_enforced" => {
            let record_id = record
                .get("record_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // The authority sig binds project_id (tenant isolation): a verified evidence triple from one
            // project must NOT verify when replayed into another (adversarial review). project_id is read from the record.
            let project_id = record
                .get("project_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let evidence_hash = authority.get("evidence_hash").and_then(|v| v.as_str());
            let evidence_sig = authority.get("evidence_sig").and_then(|v| v.as_str());
            let (eh, es) = match (evidence_hash, evidence_sig) {
                (Some(h), Some(s)) => (h, s),
                _ => return (AuthorityTrust::Failed, None), // claims verified but has no evidence
            };
            if parse_sha256(eh).is_none() || record_id.is_empty() || project_id.is_empty() {
                return (AuthorityTrust::Failed, None); // malformed evidence_hash or unbindable record/project
            }
            let raw = match es
                .strip_prefix("ed25519:")
                .and_then(|s| b64::decode_fixed::<64>(s).ok())
            {
                Some(r) => r,
                None => return (AuthorityTrust::Failed, None),
            };
            let proof_version = authority.get("proof_version");
            let v3_fields_present = authority.get("subject_projection").is_some()
                || authority.get("subject_digest").is_some();
            let (pre, trust) = match proof_version.and_then(CanonValue::as_str) {
                Some("v3") => {
                    if authority
                        .get("subject_projection")
                        .and_then(CanonValue::as_str)
                        != Some(SUBJECT_PROJECTION)
                    {
                        return (AuthorityTrust::Failed, None);
                    }
                    let Some(digest) = authority.get("subject_digest").and_then(CanonValue::as_str)
                    else {
                        return (AuthorityTrust::Failed, None);
                    };
                    if parse_sha256(digest).is_none()
                        || subject_digest(record).ok().as_deref() != Some(digest)
                    {
                        return (AuthorityTrust::Failed, None);
                    }
                    let Ok(pre) = preimage_v3(source, project_id, record_id, eh, digest) else {
                        return (AuthorityTrust::Failed, None);
                    };
                    (pre, AuthorityTrust::Verified)
                }
                None if proof_version.is_none() && !v3_fields_present => (
                    preimage(source, project_id, record_id, eh),
                    AuthorityTrust::LegacyUnbound,
                ),
                _ => return (AuthorityTrust::Failed, None),
            };
            // A malformed v3 claim fails even without pinned keys; a complete
            // claim with no key remains honestly unverifiable.
            if trusted.is_empty() {
                return (AuthorityTrust::Unverifiable, None);
            }
            let sig = Signature::from_bytes(&raw);
            for vk in trusted {
                if vk.verify_strict(&pre, &sig).is_ok() {
                    return (trust, Some(*vk));
                }
            }
            (AuthorityTrust::Failed, None)
        }
        _ => (AuthorityTrust::Declared, None), // unknown source: treat as declared, never verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::signing_key_from_seed;

    fn rec_with_authority(json: &str) -> CanonValue {
        CanonValue::parse(json).unwrap()
    }

    #[test]
    fn declared_and_none() {
        assert_eq!(
            verify_authority(&rec_with_authority("{}"), &[]),
            AuthorityTrust::None
        );
        assert_eq!(
            verify_authority(
                &rec_with_authority(r#"{"authority":{"source":"caller_declared"}}"#),
                &[]
            ),
            AuthorityTrust::Declared
        );
    }

    const EH: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const PROJ: &str = "proj-1";

    fn signed_record(source: &str, record_id: &str, sk: &ed25519_dalek::SigningKey) -> CanonValue {
        signed_record_p(source, PROJ, record_id, sk)
    }
    fn signed_record_p(
        source: &str,
        project_id: &str,
        record_id: &str,
        sk: &ed25519_dalek::SigningKey,
    ) -> CanonValue {
        let sig = sign_evidence(source, project_id, record_id, EH, sk);
        rec_with_authority(&format!(
            r#"{{"project_id":"{project_id}","record_id":"{record_id}","authority":{{"source":"{source}","evidence_hash":"{EH}","evidence_sig":"{sig}"}}}}"#
        ))
    }

    #[test]
    fn verified_requires_a_trusted_signature() {
        let k = signing_key_from_seed(&[77u8; 32]);
        let rec = signed_record("policy_engine_signed", "rec-1", &k);
        assert_eq!(
            verify_authority(&rec, &[k.verifying_key()]),
            AuthorityTrust::LegacyUnbound
        );
        // a configured-but-wrong key -> Failed; no keys -> Unverifiable (honest distinction)
        assert_eq!(
            verify_authority(&rec, &[signing_key_from_seed(&[1u8; 32]).verifying_key()]),
            AuthorityTrust::Failed
        );
        assert_eq!(verify_authority(&rec, &[]), AuthorityTrust::Unverifiable);
    }

    #[test]
    fn evidence_triple_cannot_be_copied_to_another_record() {
        let k = signing_key_from_seed(&[77u8; 32]);
        let rec_a = signed_record("policy_engine_signed", "rec-A", &k);
        // copy A's authority block verbatim onto a record with a DIFFERENT record_id (SAME project)
        let stolen = authority_of(&rec_a);
        let rec_b = rec_with_authority(&format!(
            r#"{{"project_id":"{PROJ}","record_id":"rec-B","authority":{stolen}}}"#
        ));
        assert_eq!(
            verify_authority(&rec_b, &[k.verifying_key()]),
            AuthorityTrust::Failed
        );
    }

    #[test]
    fn evidence_triple_cannot_be_replayed_to_another_project() {
        // adversarial review: a verified policy_engine_signed authority block from project P1 must NOT verify when replayed
        // into a DIFFERENT project P2 with the SAME record_id/evidence_hash/evidence_sig (cross-tenant replay).
        let k = signing_key_from_seed(&[77u8; 32]);
        let rec_p1 = signed_record_p("policy_engine_signed", "proj-1", "rec-X", &k);
        let stolen = authority_of(&rec_p1);
        let rec_p2 = rec_with_authority(&format!(
            r#"{{"project_id":"proj-2","record_id":"rec-X","authority":{stolen}}}"#
        ));
        assert_eq!(
            verify_authority(&rec_p2, &[k.verifying_key()]),
            AuthorityTrust::Failed,
            "a P1-signed authority block must not verify when replayed into P2"
        );
        // sanity: the SAME block in its OWN project still verifies.
        assert_eq!(
            verify_authority(&rec_p1, &[k.verifying_key()]),
            AuthorityTrust::LegacyUnbound
        );
    }

    fn authority_of(rec: &CanonValue) -> String {
        rec.get("authority").unwrap().serialize()
    }

    #[test]
    fn claims_verified_without_evidence_or_bad_hash_fails() {
        let rec = rec_with_authority(
            r#"{"record_id":"r","authority":{"source":"policy_engine_signed"}}"#,
        );
        assert_eq!(verify_authority(&rec, &[]), AuthorityTrust::Failed);
        // malformed evidence_hash
        let bad = rec_with_authority(
            r#"{"record_id":"r","authority":{"source":"human_signed","evidence_hash":"notahash","evidence_sig":"ed25519:AA"}}"#,
        );
        assert_eq!(verify_authority(&bad, &[]), AuthorityTrust::Failed);
    }

    #[test]
    fn source_is_bound_no_relabel() {
        let key = signing_key_from_seed(&[5u8; 32]);
        let human_sig = sign_evidence("human_signed", PROJ, "rec-1", EH, &key);
        let relabelled = rec_with_authority(&format!(
            r#"{{"project_id":"{PROJ}","record_id":"rec-1","authority":{{"source":"policy_engine_signed","evidence_hash":"{EH}","evidence_sig":"{human_sig}"}}}}"#
        ));
        assert_eq!(
            verify_authority(&relabelled, &[key.verifying_key()]),
            AuthorityTrust::Failed
        );
    }

    #[test]
    fn delegate_signed_elevates_like_other_verified_sources() {
        // Plan 031 D8: "delegate_signed" is a recognized verified-source — it elevates to Verified under a
        // pinned key (mirroring policy_engine_signed/human_signed), fails under a wrong key, and is Unverifiable
        // with no keys configured. A signature for delegate_signed must NOT verify under the preimage of
        // another source (re-label) — source is bound.
        let k = signing_key_from_seed(&[88u8; 32]);
        let rec = signed_record("delegate_signed", "rec-d1", &k);
        assert_eq!(
            verify_authority(&rec, &[k.verifying_key()]),
            AuthorityTrust::LegacyUnbound
        );
        assert_eq!(
            verify_authority(&rec, &[signing_key_from_seed(&[1u8; 32]).verifying_key()]),
            AuthorityTrust::Failed
        );
        assert_eq!(verify_authority(&rec, &[]), AuthorityTrust::Unverifiable);
        // re-label: a delegate_signed sig relabelled as policy_engine_signed must NOT verify.
        let ds_sig = sign_evidence("delegate_signed", PROJ, "rec-d2", EH, &k);
        let relabelled = rec_with_authority(&format!(
            r#"{{"project_id":"{PROJ}","record_id":"rec-d2","authority":{{"source":"policy_engine_signed","evidence_hash":"{EH}","evidence_sig":"{ds_sig}"}}}}"#
        ));
        assert_eq!(
            verify_authority(&relabelled, &[k.verifying_key()]),
            AuthorityTrust::Failed
        );
    }

    #[test]
    fn v3_binds_semantic_body_but_not_recorder_envelope() {
        let key = signing_key_from_seed(&[42u8; 32]);
        let unsigned = rec_with_authority(&format!(
            r#"{{
            "schema_version":"2","canon_version":"rcp-1","domain":"flightrecorder.record.v2",
            "record_id":"r1","project_id":"p1","session_id":"s1","agent_id":"a1",
            "agent_version":"1","span_id":"sp1","parent_span_id":null,
            "agent_ts":"2026-01-01T00:00:00.000Z","event_type":"decision",
            "action":"approve","observed_via":"sdk","status":"ok",
            "input_commit":{{"commitment":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}},
            "extensions":{{"govder":{{"body":{{"reason":"é"}}}}}},
            "authority":{{"source":"human_signed","enforcement_point":"sdk",
                "proof_version":"v3","subject_projection":"{SUBJECT_PROJECTION}",
                "evidence_hash":"{EH}"}},
            "received_ts":"2026-01-01T00:00:01.000Z","display_seq":1,
            "causal_prev_hashes":[],"key":{{"signing_key_id":"k1","key_epoch":0,"key_status":"active"}}
        }}"#
        ));
        let (digest, sig) = sign_evidence_v3(&unsigned, &key).unwrap();
        let sealed = rec_with_authority(&unsigned.serialize().replace(
            &format!("\"evidence_hash\":\"{EH}\""),
            &format!("\"evidence_hash\":\"{EH}\",\"subject_digest\":\"{digest}\",\"evidence_sig\":\"{sig}\""),
        ));
        assert_eq!(
            verify_authority(&sealed, &[key.verifying_key()]),
            AuthorityTrust::Verified
        );
        let recorder = signing_key_from_seed(&[43u8; 32]);
        let recorder_sealed = crate::record::seal(&sealed, &recorder).unwrap();
        assert!(crate::record::verify_sealed(&recorder_sealed, &recorder.verifying_key()).is_ok());
        for (name, from, to) in [
            (
                "received_ts",
                "\"received_ts\":\"2026-01-01T00:00:01.000Z\"",
                "\"received_ts\":\"2026-01-01T00:00:02.000Z\"",
            ),
            ("display_seq", "\"display_seq\":1", "\"display_seq\":2"),
            (
                "causal_prev_hashes",
                "\"causal_prev_hashes\":[]",
                "\"causal_prev_hashes\":[\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"]",
            ),
            (
                "key",
                "\"signing_key_id\":\"k1\"",
                "\"signing_key_id\":\"k2\"",
            ),
        ] {
            let original_json = recorder_sealed.serialize();
            let changed_json = original_json.replace(from, to);
            assert_ne!(changed_json, original_json, "{name} mutation was a no-op");
            let changed = rec_with_authority(&changed_json);
            assert_eq!(
                verify_authority(&changed, &[key.verifying_key()]),
                AuthorityTrust::Verified,
                "{name} is recorder-only envelope"
            );
            assert!(
                crate::record::verify_sealed(&changed, &recorder.verifying_key()).is_err(),
                "unsigned {name} tamper must fail record integrity"
            );
            let resealed = crate::record::seal(&changed, &recorder).unwrap();
            assert!(crate::record::verify_sealed(&resealed, &recorder.verifying_key()).is_ok());
            assert_eq!(
                verify_authority(&resealed, &[key.verifying_key()]),
                AuthorityTrust::Verified,
                "legitimate recorder re-seal of {name} preserves authority"
            );
        }
        for (from, to) in [
            ("\"action\":\"approve\"", "\"action\":\"deny\""),
            ("\"status\":\"ok\"", "\"status\":\"blocked\""),
            ("\"reason\":\"é\"", "\"reason\":\"different\""),
            ("\"enforcement_point\":\"sdk\"", "\"enforcement_point\":\"external\""),
            ("\"commitment\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"",
             "\"commitment\":\"sha256:3333333333333333333333333333333333333333333333333333333333333333\""),
        ] {
            let changed = rec_with_authority(&sealed.serialize().replace(from, to));
            assert_eq!(verify_authority(&changed, &[key.verifying_key()]), AuthorityTrust::Failed, "{from}");
        }
        let without_digest = rec_with_authority(
            &sealed
                .serialize()
                .replace(&format!(",\"subject_digest\":\"{digest}\""), ""),
        );
        assert_eq!(
            verify_authority(&without_digest, &[key.verifying_key()]),
            AuthorityTrust::Failed
        );
        let without_version =
            rec_with_authority(&sealed.serialize().replace("\"proof_version\":\"v3\",", ""));
        assert_eq!(
            verify_authority(&without_version, &[key.verifying_key()]),
            AuthorityTrust::Failed
        );
    }
}
