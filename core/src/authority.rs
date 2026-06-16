//! Authority evidence verification (spec §11, threat #4 — the moat's "authority gradient").
//!
//! `caller_declared` authority is forgeable; it is just an annotation. Authority becomes *verified*
//! only when an `evidence_sig` — a signature FROM the authority system (policy engine / approval /
//! token introspection) — verifies under a pinned authority key. This module makes that distinction
//! cryptographic instead of advisory, so the UI can honestly show "declared by agent" vs "verified
//! from policy engine".

use crate::b64;
use crate::canon::CanonValue;
use crate::hashx::{lp_str_into, parse_sha256};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

// `v2` binds `project_id` into the preimage (tenant isolation; T7/Codex). It is a HARD cutover from `v1`:
// the verifier accepts ONLY v2, so a v1 signature (no project_id) does not verify. This is safe as a
// PRE-DEPLOYMENT break — feir has shipped no v1-signed records (the golden vectors carry no authority sig),
// so there is nothing to migrate and adding a v1-accept fallback would only reintroduce a (downgraded)
// cross-project replay surface for zero benefit. FORWARD-COMPAT POLICY (for any change AFTER deployment):
// because authority evidence is append-only and cannot be re-signed in place, a future preimage change must
// NOT hard-cutover — it must verify the newest version first and fall back to older versions under an
// explicitly downgraded/legacy status, never silently dropping historical authority verification.
pub const AUTHORITY_SIG_TAG: &str = "feir.authority.v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityTrust {
    /// No authority block.
    None,
    /// `caller_declared` (or an unknown source) — forgeable, taken at face value.
    Declared,
    /// An `evidence_sig` verified under a pinned authority key.
    Verified,
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
            AuthorityTrust::Unverifiable => "unverifiable",
            AuthorityTrust::Failed => "failed",
        }
    }
}

/// Preimage the authority system signs:
/// `LP(tag) ‖ LP(source) ‖ LP(project_id) ‖ LP(record_id) ‖ utf8(evidence_hash)`.
/// Binding `source` prevents re-labelling; binding `project_id` AND `record_id` prevents replaying a valid
/// evidence triple onto an unrelated record OR a record in a DIFFERENT project (cross-tenant replay, Codex).
/// `record_id` alone is caller-chosen and the verifier's duplicate-record_id rejection is only WITHIN a
/// bundle, so `project_id` is the load-bearing tenant-isolation binding.
fn preimage(source: &str, project_id: &str, record_id: &str, evidence_hash: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(56 + source.len() + project_id.len() + record_id.len() + evidence_hash.len());
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
    let authority = match record.get("authority") {
        Some(a) => a,
        None => return AuthorityTrust::None,
    };
    let source = authority
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match source {
        "" => AuthorityTrust::None,
        "caller_declared" => AuthorityTrust::Declared,
        "policy_engine_signed" | "human_signed" | "gateway_enforced" => {
            let record_id = record
                .get("record_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // The authority sig binds project_id (tenant isolation): a verified evidence triple from one
            // project must NOT verify when replayed into another (Codex). project_id is read from the record.
            let project_id = record
                .get("project_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let evidence_hash = authority.get("evidence_hash").and_then(|v| v.as_str());
            let evidence_sig = authority.get("evidence_sig").and_then(|v| v.as_str());
            let (eh, es) = match (evidence_hash, evidence_sig) {
                (Some(h), Some(s)) => (h, s),
                _ => return AuthorityTrust::Failed, // claims verified but has no evidence
            };
            if parse_sha256(eh).is_none() || record_id.is_empty() || project_id.is_empty() {
                return AuthorityTrust::Failed; // malformed evidence_hash or unbindable record/project
            }
            let raw = match es
                .strip_prefix("ed25519:")
                .and_then(|s| b64::decode_fixed::<64>(s).ok())
            {
                Some(r) => r,
                None => return AuthorityTrust::Failed,
            };
            // honest: with no authority keys configured we cannot check the signature.
            if trusted.is_empty() {
                return AuthorityTrust::Unverifiable;
            }
            let sig = Signature::from_bytes(&raw);
            let pre = preimage(source, project_id, record_id, eh);
            for vk in trusted {
                if vk.verify_strict(&pre, &sig).is_ok() {
                    return AuthorityTrust::Verified;
                }
            }
            AuthorityTrust::Failed
        }
        _ => AuthorityTrust::Declared, // unknown source: treat as declared, never verified
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
    fn signed_record_p(source: &str, project_id: &str, record_id: &str, sk: &ed25519_dalek::SigningKey) -> CanonValue {
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
            AuthorityTrust::Verified
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
        let rec_b = rec_with_authority(&format!(r#"{{"project_id":"{PROJ}","record_id":"rec-B","authority":{stolen}}}"#));
        assert_eq!(
            verify_authority(&rec_b, &[k.verifying_key()]),
            AuthorityTrust::Failed
        );
    }

    #[test]
    fn evidence_triple_cannot_be_replayed_to_another_project() {
        // Codex: a verified policy_engine_signed authority block from project P1 must NOT verify when replayed
        // into a DIFFERENT project P2 with the SAME record_id/evidence_hash/evidence_sig (cross-tenant replay).
        let k = signing_key_from_seed(&[77u8; 32]);
        let rec_p1 = signed_record_p("policy_engine_signed", "proj-1", "rec-X", &k);
        let stolen = authority_of(&rec_p1);
        let rec_p2 = rec_with_authority(&format!(r#"{{"project_id":"proj-2","record_id":"rec-X","authority":{stolen}}}"#));
        assert_eq!(
            verify_authority(&rec_p2, &[k.verifying_key()]),
            AuthorityTrust::Failed,
            "a P1-signed authority block must not verify when replayed into P2"
        );
        // sanity: the SAME block in its OWN project still verifies.
        assert_eq!(verify_authority(&rec_p1, &[k.verifying_key()]), AuthorityTrust::Verified);
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
}
