//! Offline bundle verification (RCP §10.1) — the capstone the CLI and WASM verifier call.
//!
//! Given an export bundle (records + full checkpoint history + public keys + anchors), produce a
//! [`VerifyReport`]: per-record trust annotations, DAG validity, and checkpoint-chain soundness
//! (omission #1 / fork #2 detection), plus external-anchor checks (backdating #3, key-compromise
//! #9). Never panics on attacker-controlled input.
//!
//! **Trust roots.** The bundle's `keys` list and `anchor` tokens are *attacker-supplied*. Pass
//! externally-pinned signing keys via [`VerifyOptions::trusted_keys`] and trusted TSA keys via
//! [`VerifyOptions::trusted_tsa_keys`] (both obtained out-of-band). Without signing-key pinning the
//! report sets `keys_externally_pinned = false` and proves only *internal consistency under the
//! bundle's own key claims*. A `revoked`/`compromised` status (worst of record-asserted and bundle-
//! asserted) downgrades a record to `Untrusted` **unless** an anchored checkpoint with anchor-time
//! `≤ status_changed_at` transitively commits it (RCP §10.2, threat #9).

use crate::anchor::verify_anchor;
use crate::authority::{verify_authority, AuthorityTrust};
use crate::canon::CanonValue;
use crate::checkpoint::{validate_chain, verify_checkpoint_sealed};
use crate::dag;
use crate::record::{validate_record_shape, verify_content_hash, verify_sealed};
use crate::sign::decode_pubkey;
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// L1: bytes sealed by a valid (and, if pinning is in effect, externally-trusted) key and
    /// unchanged since — or sealed by a later-compromised key but anchored before the compromise.
    IntegrityProven,
    /// Integrity/signature failed, key unavailable/unpinned, or key revoked/compromised without a
    /// qualifying anchor — provenance is not trustworthy.
    Untrusted,
}

#[derive(Debug, Clone)]
pub struct RecordTrust {
    pub index: usize,
    pub record_id: String,
    pub content_hash: String,
    pub integrity_ok: bool,
    pub signature_ok: bool,
    pub key_status: String,
    pub observed_via: String,
    pub trust: TrustLevel,
    /// Authority gradient (threat #4): none|declared|verified|failed. `verified` = an evidence_sig
    /// checked out under a pinned authority key (for a broker/resource record, the ROLE-specific key
    /// set — ADR 0003 R2), not just the agent's claim.
    pub authority: AuthorityTrust,
    /// Broker/resource role (ADR 0003 R2): broker|resource|none. Surfaces which role's key set the
    /// authority was checked under, so an auditor sees broker-signed vs resource-signed provenance.
    pub broker_role: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub ok: bool,
    pub project_id: Option<String>,
    pub keys_externally_pinned: bool,
    pub records_total: usize,
    pub records_proven: usize,
    pub record_trust: Vec<RecordTrust>,
    pub dag_ok: bool,
    pub dag_heads: usize,
    pub collapsed_duplicates: usize,
    pub checkpoints_total: usize,
    pub checkpoints_verified: usize,
    pub checkpoints_anchored: usize,
    pub chain_ok: bool,
    /// Selective-disclosure entries in the bundle, and how many matched their record's commitment.
    pub disclosures_total: usize,
    pub disclosures_verified: usize,
    /// Credential-broker grants (`event_type=credential_grant`) and how many verified to
    /// `gateway_enforced` under a pinned authority key (Level 3 Tier-A grant accountability).
    pub grant_total: usize,
    pub grant_verified: usize,
    /// B11 denied-grant log: count of sealed `credential_grant_denied` records (a forbidden/invalid grant
    /// request that was refused AND recorded as evidence, opt-in producer side). NOT a grant (never folded
    /// into `grant_total`/`grant_accountability`); a generic BrokerRole::None record.
    pub denied_grants: usize,
    /// Tier-B use↔grant join (ADR 0003 step 5), computed over the CLOSED set (records committed by a
    /// verified, anchored checkpoint, R3). `uses_total` = resource-role use receipts; `uses_matched` =
    /// closed uses bound to a closed grant under the full predicate; `uses_action_unverified` = matched
    /// uses NOT action-verified — i.e. a non-`single_operation` grant, or no `validated`, in-window
    /// taxonomy listing the grant's `(resource_id, action)` (ADR 0004 D4; `0` ⇔ every matched use is
    /// action-verified); `unmatched_violation` = a closed use with no/again a matching grant, or one
    /// honoring a mis-scoped grant (hard fail); `unmatched_pending` = a use not yet closed (in-flight);
    /// `grants_unused` = closed grants with no matching use.
    pub uses_total: usize,
    pub uses_matched: usize,
    pub uses_action_unverified: usize,
    /// Matched uses whose Ed25519 PoP the verifier independently RE-RAN offline (ADR 0004 D2 — PoP off
    /// the shim TCB). A matched use that only carries the shim-asserted `pop_challenge_hash` (no
    /// cnf/use_sig) is counted in `uses_matched` but NOT here.
    pub uses_pop_reverified: usize,
    pub unmatched_violation: usize,
    pub unmatched_pending: usize,
    /// D5 (ADR 0004 F4): a CLOSED `use_intent` (recorded + anchored BEFORE the side effect, passing the full
    /// grant-match predicate) with NO matching closed `use_outcome` — the action started and was recorded but
    /// completion was not. A surfaced anomaly (NOT a violation, NOT a clean matched use): the crash-after-act
    /// case becomes detectable rather than invisible. It does NOT count toward `uses_matched` and does NOT
    /// consume a single-use grant. A non-zero count blocks the D8 capstone over the closed set.
    pub intent_without_outcome: usize,
    /// D8/MF3 (ADR 0004): true iff any MATCHED use is a one-phase ADR-0003 `use` receipt (not a two-phase
    /// `use_intent`+`use_outcome` pair). A one-phase receipt carries the record-after-action gap two-phase
    /// exists to reduce, so its presence forces `action_completeness` to stay `claimed_over_manifest` and can
    /// never reach the `attested_complete_over_brokered_surface` capstone.
    pub one_phase_use_present: bool,
    pub grants_unused: usize,
    /// M1 / ADR 0005 (`bounded_reuse` / N-Use). `bounded_reuse_grants` = closed grants whose
    /// `scope_class == "bounded_reuse"` (a credential bounded to N uses of the identical
    /// `(action, resource_id)`); `bounded_reuse_overspent` = matched-candidate uses rejected because
    /// `use_sequence_number` was outside `[1, use_limit]` or the grant was exercised more than `use_limit`
    /// times; `bounded_reuse_seq_replays` = uses rejected because their `(grant_id, use_sequence_number)`
    /// was already consumed. Both anomaly counts are also `unmatched_violation`s (so `!ok`); they are
    /// surfaced separately so the D8 capstone can require `== 0` self-documentingly.
    pub bounded_reuse_grants: usize,
    pub bounded_reuse_overspent: usize,
    pub bounded_reuse_seq_replays: usize,
    /// M6 / ADR 0005 (Cosig — M-of-N grant approval / dual control at issuance). `cosigned_grants_total` =
    /// closed, verified broker grants whose signed `grant_evidence.cosig_threshold >= 1` (they DECLARE a
    /// cosig requirement); `cosigned_grants_satisfied` = those for which ≥ `cosig_threshold` DISTINCT pinned
    /// `cosig_approver_keys` produced a valid `feir.broker.cosig.approval.v1` cosignature; `cosig_threshold_failures`
    /// = cosigned grants that fell short (each is also NOT indexed → its use is an `unmatched_violation`, so
    /// `!ok`; surfaced separately so the D8 capstone can require `== 0` self-documentingly). `cosig_status` ∈
    /// {`absent` (no cosigned grants), `satisfied` (every cosigned grant met threshold), `unsatisfied` (≥1
    /// short)}. The same approver key signing twice counts once (no threshold inflation).
    pub cosigned_grants_total: usize,
    pub cosigned_grants_satisfied: usize,
    pub cosig_threshold_failures: usize,
    pub cosig_status: String,
    /// M2 / ADR 0005 (Delegation — per-hop SIGNED re-delegation). `delegation_chains_total` = closed,
    /// verified broker grants whose signed `grant_evidence.delegation_assertions[]` is non-empty (they
    /// re-delegate the credential to a sub-agent); `delegation_chains_verified` = those whose chain fully
    /// re-walked from the broker-signed root cnf_kid — every hop signed by its delegator, linked to the prior
    /// hop's delegate, and scope/action/resource non-increasing (demonstrator: equality). A verified chain
    /// binds the use to the LEAF cnf_kid + the narrowed window `min(grant exp, hop exps)`, so PoP runs under
    /// the sub-agent's key; an invalid OR non-monotone chain is NOT indexed (its use → `unmatched_violation`).
    /// `delegation_monotonicity_violations` counts chains rejected specifically for widening (surfaced for the
    /// capstone). `delegation_status` ∈ {`absent`, `verified` (all chains re-walked), `unverified` (≥1 failed)}.
    pub delegation_chains_total: usize,
    pub delegation_chains_verified: usize,
    pub delegation_monotonicity_violations: usize,
    pub delegation_status: String,
    /// Pinned operation-taxonomy ARTIFACT trust (ADR 0004 D4 / MF5), one of: `absent` (none pinned in
    /// opts), `untrusted` (unsigned / wrong issuer / pinned digest|version mismatch / no pin supplied /
    /// malformed), `stale` (signed + pinned but a listed action fell outside the effective interval for
    /// some matched use), `validated` (signed under a pinned ROLE-SEPARATED issuer, digest+version pins
    /// match). This reports ARTIFACT trust ONLY — it does NOT assert every matched use was action-verified
    /// (an unlisted action or a non-`single_operation` grant leaves `validated` intact while incrementing
    /// `uses_action_unverified`). The per-use signal is `uses_action_unverified`; a correct D4/D8 gate
    /// requires BOTH `taxonomy_status == "validated"` AND `uses_action_unverified == 0`, never the status
    /// alone (Codex AREA 1).
    pub taxonomy_status: String,
    /// Grant-transparency trust (ADR 0004 D6 / MF2), one of: `assumed` (no `broker_grant_head` in any
    /// checkpoint — the bundle cannot prove the broker recorded every grant), `sequence_consistent_export`
    /// (a head is present and the recorded grant log is a gapless prefix whose cumulative_root + chain
    /// match it, but the head is NOT in a verified+anchored checkpoint — internal consistency only), or
    /// `sequence_verified` (those checks pass AND the head is bound into a verified, anchored checkpoint,
    /// so the broker cannot drop/renumber/fork a recorded grant without detection). A gap, tail omission,
    /// root mismatch, or broken prior-head chain is a hard `issues` violation (detectable suppression).
    pub broker_trust: String,
    /// D6.4 (ADR 0004 D6) — credential-descriptor cross-check, the SECOND `broker_trust` lever. D4's
    /// `action_verified` trusts the broker's grant LABELS; when the credential descriptor is DISCLOSED (its
    /// `credential_commit` opened + verified), the verifier additionally checks `sha256(descriptor) ==
    /// grant_evidence.credential_binding` and the descriptor's `act/aud/jti/cnf/exp/single_use` against the
    /// signed grant labels — proving the broker did not mislabel a broad credential as a benign single-op.
    /// `cred_label_checks` counts disclosed descriptors bound to a verified+closed broker grant (labels
    /// trusted); `cred_label_matched` counts those whose binding AND every field matched. A shortfall
    /// (`checks > matched`) is a broker-equivocation **violation** (pushed to `issues`). Absent the
    /// disclosure, label↔credential fidelity stays a `broker_trust` residual.
    pub cred_label_checks: usize,
    pub cred_label_matched: usize,
    /// Deployment-attestation evaluation (ADR 0004 D7), one of: `unevaluated` (no `deployment_attestation`
    /// in the bundle, or no `attestation_keys` pinned — the runtime claims are NOT assessed), `failed`
    /// (an attestation is present but its `sig`/issuer is bad, it is stale/out-of-window, or its signed
    /// `subject` does NOT match this bundle — a substitution/replay), or `attested_claims` (a fresh,
    /// pinned-issuer attestation whose `subject` binds THIS project/manifest/checkpoint/head/key-set/
    /// resource-set exists). This proves such an attestation EXISTS — NOT that the runtime obeyed it
    /// (real isolation/egress/non-transferability needs a TEE/remote-attestation chain, out of scope).
    /// The issuer kid, freshness window, claim types, and subject digest are surfaced alongside so a
    /// reader sees exactly what was attested, by whom, for when.
    pub attestation_status: String,
    pub attestation_issuer_kid: Option<String>,
    pub attestation_issued_at: Option<String>,
    pub attestation_not_after: Option<String>,
    pub attestation_claim_types: Vec<String>,
    pub attestation_subject_digest: Option<String>,
    /// D8/MF1 (ADR 0004): the IRREDUCIBLE resource-TCB conditional, ALWAYS `assumed_truthful`. The
    /// `attested_complete_over_brokered_surface` capstone proves every resource-signed receipt over the
    /// brokered surface is two-phase, PoP-re-verified, taxonomy-validated, replay-free, and committed to an
    /// anchored gapless broker log — **conditional on the resource having truthfully labeled what it did**.
    /// It does NOT prove the resource performed action A rather than B, nor that there were no undeclared
    /// side effects (the irreducible resource TCB, ADR 0004 D9). Surfaced alongside the capstone so a reader
    /// can never mistake it for "everything the agent did".
    pub resource_trust: String,
    /// The bundle's `coverage_manifest` echoed verbatim (the verifier does NOT trust it; it surfaces
    /// it so an auditor can evaluate the out-of-band attestations). `None` if absent.
    pub coverage_manifest: Option<CanonValue>,
    /// T6 (ADR 0002 open Q1, actionable half): `unclosed_side_effects` = resources the brokered surface
    /// touched (any grant/use `resource_id`) that fall within NO operator-declared `side_effect_closure`;
    /// `side_effect_closure_status` is `not_declared` (no closure in the manifest), `closed` (every touched
    /// resource declared), or `unclosed` (≥1 undeclared — a hard `issues` violation). Proves the manifest
    /// DECLARES a complete closure over the observed surface — NOT runtime obedience (the resource TCB, D9).
    pub unclosed_side_effects: usize,
    pub side_effect_closure_status: String,
    pub issues: Vec<String>,
    pub first_broken_link: Option<String>,
}

/// An out-of-band pinned key. Beyond the public-key bytes it may carry the *authoritative* key
/// status and compromise time (e.g. from a key-transparency record) — which the verifier trusts
/// over the bundle's self-asserted claims, closing the future-dated-compromise escalation.
pub struct TrustedKey {
    pub vk: VerifyingKey,
    pub status: Option<String>,
    pub status_changed_at: Option<String>,
}

impl From<VerifyingKey> for TrustedKey {
    fn from(vk: VerifyingKey) -> Self {
        TrustedKey {
            vk,
            status: None,
            status_changed_at: None,
        }
    }
}

#[derive(Default)]
pub struct VerifyOptions {
    /// If `Some`, a record is only `IntegrityProven` when its resolved key is in this set. When a
    /// pinned key carries `status`/`status_changed_at`, those authoritative values override the
    /// bundle's self-asserted claims (so an attacker cannot future-date a compromise to upgrade).
    pub trusted_keys: Option<Vec<TrustedKey>>,
    /// Trusted Ed25519 TSA keys for the hermetic `test-anchor` scheme (out-of-band).
    pub trusted_tsa_keys: Vec<VerifyingKey>,
    /// Trusted DER `SubjectPublicKeyInfo`s for real RFC 3161 TSAs (used with the `rfc3161` feature).
    pub trusted_tsa_spki: Vec<Vec<u8>>,
    /// Trusted authority-system public keys (policy engine / approval service) for NON-broker records.
    /// An `evidence_sig` that verifies under one of these elevates a record's authority to `verified`
    /// (threat #4). Broker/resource records are NOT elevated by this set — they use the role-specific
    /// sets below (ADR 0003 R2 role separation).
    pub trusted_authority_keys: Vec<VerifyingKey>,
    /// Trusted CREDENTIAL-BROKER recording keys. Only a `credential_broker`-role record (a grant)
    /// elevates under one of these (ADR 0003 R2). Must be disjoint from `resource_authority_keys`.
    pub broker_authority_keys: Vec<VerifyingKey>,
    /// Trusted RESOURCE recording keys. Only a `tool_gateway`-role record (a use receipt) elevates
    /// under one of these (ADR 0003 R2). Must be disjoint from `broker_authority_keys`.
    pub resource_authority_keys: Vec<VerifyingKey>,
    /// A pinned signed operation taxonomy (ADR 0004 D4): `{version, effective_from, effective_until,
    /// single_operation_actions:[{resource_id, action}…], escalating_actions:[{resource_id, action}…]?,
    /// sig}`. Entries are RESOURCE-BOUND. When present + signature-valid under `taxonomy_keys`, the pinned
    /// `taxonomy_digest`/`taxonomy_version` match, and in-window, a matched use against a single_operation
    /// grant whose `(resource_id, action)` it lists is action-VERIFIED; a single_operation grant for an
    /// `escalating_actions` pair is rejected as mis-scoped AT ISSUANCE (a hard `issues` failure, whether
    /// or not the grant is ever exercised). NOTE: `action_verified` trusts the broker's grant LABELS
    /// (action/resource/scope_class) — it proves the LABELED operation is taxonomy-single-op, not that the
    /// minted credential matches its label. That correspondence is REDUCIBLE, not irreducible: when the
    /// credential descriptor is disclosed, cross-checking `sha256(descriptor) == credential_binding` plus
    /// its `act/aud/jti/cnf/exp/single_use` against `grant_evidence` proves label↔credential consistency
    /// offline — implemented (D6.4) as the `cred_label_checks`/`cred_label_matched` cross-check; absent the
    /// disclosure, the gap rests on `broker_trust` (D6).
    pub taxonomy: Option<CanonValue>,
    /// Trusted operation-taxonomy authority keys (role-separated from broker/resource — enforced as a
    /// FATAL config error in `verify_bundle_with`). Pin to validate `taxonomy`.
    pub taxonomy_keys: Vec<VerifyingKey>,
    /// Pinned content digest the `taxonomy` must match to reach `validated` (MF5 — the operator vetted
    /// THIS artifact, by `sha256:`-prefixed RCP digest of the taxonomy minus `sig`). Absent ⇒ no
    /// taxonomy can reach `validated` (fail-closed; a signed-but-unpinned taxonomy is `untrusted`).
    pub taxonomy_digest: Option<String>,
    /// Pinned monotonic version the `taxonomy`'s `version` field must equal to reach `validated` (MF5
    /// rollback anchor). Absent ⇒ no taxonomy can reach `validated`.
    pub taxonomy_version: Option<i64>,
    /// Trusted DEPLOYMENT-ATTESTATION authority keys (ADR 0004 D7). A `deployment_attestation` whose `sig`
    /// verifies under one of these — AND whose signed `subject` matches this bundle (project / manifest /
    /// latest anchored checkpoint + head / authority key-id set / resource_id set), within its freshness
    /// window — elevates `attestation_status` to `attested_claims`. Must be role-separated (disjoint from
    /// broker/resource/taxonomy keys — enforced as a FATAL config error), so a broker cannot self-attest.
    /// Absent ⇒ `attestation_status` stays `unevaluated` (the attestation, if any, is not evaluated).
    pub attestation_keys: Vec<VerifyingKey>,
    /// Trusted COSIGNATURE-APPROVER keys (ADR 0005 M6 — M-of-N grant approval / dual control). A grant
    /// whose signed `grant_evidence.cosig_threshold >= 1` is Tier-B-eligible ONLY if at least that many
    /// DISTINCT keys in this set produced a valid `feir.broker.cosig.approval.v1` cosignature over it;
    /// otherwise the grant is NOT indexed (its use reads as `unmatched_violation`). Role-separated — a
    /// FATAL config error on overlap with ANY other role (broker/resource/taxonomy/attestation/tsa) and
    /// with the generic `authority_keys`, so an approver cannot self-approve via another hat. Absent ⇒ a
    /// cosigned grant has zero countable approvers and is fail-closed (the governance keys must be pinned
    /// to trust the governance).
    pub cosig_approver_keys: Vec<VerifyingKey>,
}

struct KeyEntry {
    vk: VerifyingKey,
    status: String,
    status_changed_at: Option<String>,
}

/// Provisional per-record state from pass 1, finalized in pass 2 after anchors are known.
struct Pending {
    index: usize,
    record_id: String,
    content_hash: String,
    observed_via: String,
    integrity_ok: bool,
    signature_ok: bool,
    pinned: bool,
    project_ok: bool,
    eff_status: String,
    status_changed_at: Option<String>,
    authority: AuthorityTrust,
    broker_role: BrokerRole,
    notes: Vec<String>,
}

/// A record's broker/resource role (ADR 0003 R2), classified fail-closed from the
/// `(extensions.broker.kind, authority.enforcement_point)` discriminator. `None` means the record
/// does not claim a recognized Tier-B role (a plain record, or a fail-closed misclassification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerRole {
    Broker,
    Resource,
    None,
}

impl BrokerRole {
    fn as_str(self) -> &'static str {
        match self {
            BrokerRole::Broker => "broker",
            BrokerRole::Resource => "resource",
            BrokerRole::None => "none",
        }
    }
}

/// Classify a record's role from `(extensions.broker.kind, authority.enforcement_point)` — fail-closed:
/// EXACTLY one recognized tuple maps to each role, and a `kind`/`enforcement_point` that point at
/// different roles (ambiguous), an unrecognized value, or an absent component all map to `None`
/// (ADR 0003 R2). `claims_role` is true iff the record carries a broker `kind` at all (so an
/// unclassifiable record that nonetheless *claims* a Tier-B role can be surfaced, not silently
/// dropped).
fn classify_role(rec: &CanonValue) -> (BrokerRole, bool) {
    let kind = rec
        .get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get("kind"))
        .and_then(|v| v.as_str());
    let ep = rec
        .get("authority")
        .and_then(|a| a.get("enforcement_point"))
        .and_then(|v| v.as_str());
    let role = match (kind, ep) {
        (Some("grant"), Some("credential_broker")) => BrokerRole::Broker,
        // D5 (ADR 0004): a two-phase use is a `use_intent` (recorded BEFORE the side effect) + a
        // `use_outcome` (AFTER); both are resource-signed records under the tool gateway, alongside the
        // one-phase `use` (ADR 0003, still accepted for back-compat).
        (Some("use"), Some("tool_gateway"))
        | (Some("use_intent"), Some("tool_gateway"))
        | (Some("use_outcome"), Some("tool_gateway")) => BrokerRole::Resource,
        _ => BrokerRole::None,
    };
    (role, kind.is_some())
}

fn s(v: &CanonValue, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string())
}

fn arr<'a>(
    bundle: &'a CanonValue,
    k: &str,
    empty: &'a [CanonValue],
    issues: &mut Vec<String>,
) -> &'a [CanonValue] {
    match bundle.get(k) {
        Some(v) => match v.as_array() {
            Some(a) => a.as_slice(),
            None => {
                issues.push(format!(
                    "bundle.{k} is present but not an array (malformed)"
                ));
                empty
            }
        },
        None => empty,
    }
}

fn status_rank(s: &str) -> u8 {
    match s {
        "active" => 0,
        "retired" => 1,
        "revoked" => 2,
        "compromised" => 3,
        _ => 4,
    }
}
fn worst_status(a: &str, b: &str) -> String {
    if status_rank(a) >= status_rank(b) {
        a
    } else {
        b
    }
    .to_string()
}

/// True iff `s` is a REAL canonical UTC timestamp `YYYY-MM-DDThh:mm:ss.mmmZ` (24 chars) with in-RANGE
/// fields (month 01-12, day 01-31, hour 00-23, min/sec 00-59) — not merely the right SHAPE. Lexical `<=`
/// on two such strings equals chronological order, an invariant that only holds for in-range fields
/// (a shape-only `2026-13-01` would lexically sort AFTER `2026-02-01` yet name no real month). Range
/// validation (Codex D7) also stops a signed-but-malformed attestation window like `2026-99-99T99:99:99.999Z`
/// from passing the freshness check. (Day is 01-31, not month-length/leap-aware — impossible values are
/// rejected; a harmless 02-30 is not, which does not affect ordering.)
fn is_canonical_ts(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 24 {
        return false;
    }
    let digit = |i: usize| b[i].is_ascii_digit();
    let shape = (0..4).all(digit)
        && b[4] == b'-' && digit(5) && digit(6)
        && b[7] == b'-' && digit(8) && digit(9)
        && b[10] == b'T' && digit(11) && digit(12)
        && b[13] == b':' && digit(14) && digit(15)
        && b[16] == b':' && digit(17) && digit(18)
        && b[19] == b'.' && digit(20) && digit(21) && digit(22)
        && b[23] == b'Z';
    if !shape {
        return false;
    }
    // shape guarantees these positions are ASCII digits, so each pair is in 0..=99 (no overflow).
    let two = |i: usize| (b[i] - b'0') * 10 + (b[i + 1] - b'0');
    let (month, day, hour, min, sec) = (two(5), two(8), two(11), two(14), two(17));
    (1..=12).contains(&month) && (1..=31).contains(&day) && hour <= 23 && min <= 59 && sec <= 59
}

/// All content_hashes reachable as causal ancestors of `frontier` (inclusive) — the set a
/// checkpoint commits to (RCP §10.2 "transitively commits").
fn committed_set(
    records: &[CanonValue],
    by_hash: &BTreeMap<String, usize>,
    frontier: &[String],
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = frontier.to_vec();
    while let Some(h) = stack.pop() {
        if !seen.insert(h.clone()) {
            continue;
        }
        if let Some(&idx) = by_hash.get(&h) {
            if let Some(parents) = records[idx]
                .get("causal_prev_hashes")
                .and_then(|v| v.as_array())
            {
                for p in parents {
                    if let Some(ps) = p.as_str() {
                        stack.push(ps.to_string());
                    }
                }
            }
        }
    }
    seen
}

/// Verify selective-disclosure entries against the per-record hiding commitments embedded in the
/// (signed) record bodies. A bundle MAY carry a top-level `disclosures` array; each entry reveals
/// `(value, nonce)` for one `<field>_commit` so an auditor can confirm the disclosed value is the
/// one that was committed at seal time (RCP §9.3). A mismatch is tamper (threat #6) and an `issue`,
/// which fails the bundle. The commitment lives in the signed body, so a passing disclosure is only
/// meaningful for a record that itself verifies — the per-record trust pass enforces that
/// separately; here we only check value↔commitment binding.
fn verify_disclosures(
    bundle: &CanonValue,
    records: &[CanonValue],
    issues: &mut Vec<String>,
) -> (usize, usize, Vec<(String, Vec<u8>)>) {
    let list = match bundle.get("disclosures") {
        // Absent, or an explicit JSON `null`, both mean "no disclosures" — an SDK that serializes an
        // empty Option as null must not brick an otherwise-valid bundle.
        None => return (0, 0, Vec::new()),
        Some(v) if v.is_null() => return (0, 0, Vec::new()),
        Some(v) => match v.as_array() {
            Some(a) => a,
            None => {
                issues.push("bundle.disclosures is present but not an array (malformed)".into());
                return (0, 0, Vec::new());
            }
        },
    };
    // record_id -> record body (first wins; duplicate ids are flagged separately in the trust pass).
    let mut by_id: BTreeMap<&str, &CanonValue> = BTreeMap::new();
    for rec in records {
        if let Some(id) = rec.get("record_id").and_then(|v| v.as_str()) {
            by_id.entry(id).or_insert(rec);
        }
    }
    let total = list.len();
    let mut verified = 0usize;
    // D6.4: VERIFIED credential descriptors (record_id, raw descriptor bytes) handed back for the
    // label↔credential cross-check against grant_evidence (only descriptors that opened their commitment).
    let mut cred_descriptors: Vec<(String, Vec<u8>)> = Vec::new();
    // (record_id, field) must be disclosed at most once — a second disclosure for the same slot is
    // either redundant (inflating the count) or a contradiction (one commitment, two values).
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for (i, d) in list.iter().enumerate() {
        let (rid, field, value_b64, nonce_hex) = match (
            d.get("record_id").and_then(|v| v.as_str()),
            d.get("field").and_then(|v| v.as_str()),
            d.get("value_b64").and_then(|v| v.as_str()),
            d.get("nonce_hex").and_then(|v| v.as_str()),
        ) {
            (Some(a), Some(b), Some(c), Some(e)) => (a, b, c, e),
            _ => {
                issues.push(format!(
                    "disclosure {i}: missing record_id/field/value_b64/nonce_hex"
                ));
                continue;
            }
        };
        if !seen.insert((rid, field)) {
            issues.push(format!(
                "disclosure {i}: duplicate disclosure for record '{rid}' field '{field}'"
            ));
            continue;
        }
        let domain = match crate::commit::FieldDomain::parse(field) {
            Some(dm) => dm,
            None => {
                issues.push(format!(
                    "disclosure {i}: field '{field}' not in input|output|rationale|credential"
                ));
                continue;
            }
        };
        let rec = match by_id.get(rid) {
            Some(r) => *r,
            None => {
                issues.push(format!("disclosure {i}: no record '{rid}' in bundle"));
                continue;
            }
        };
        let commitment = rec
            .get(&format!("{field}_commit"))
            .and_then(|c| c.get("commitment"))
            .and_then(|v| v.as_str());
        let commitment = match commitment {
            Some(c) => c,
            None => {
                issues.push(format!(
                    "disclosure {i}: record '{rid}' has no {field}_commit.commitment to check"
                ));
                continue;
            }
        };
        let value = match crate::b64::decode(value_b64) {
            Ok(v) => v,
            Err(_) => {
                issues.push(format!("disclosure {i}: value_b64 is not valid base64url"));
                continue;
            }
        };
        let nonce = match crate::hashx::hex32(nonce_hex) {
            Some(n) => n,
            None => {
                issues.push(format!(
                    "disclosure {i}: nonce must be 64 lowercase hex chars (32 bytes)"
                ));
                continue;
            }
        };
        if crate::commit::verify_commitment(commitment, domain, &value, &nonce) {
            verified += 1;
            // hand back the verified credential descriptor bytes for the D6.4 cross-check (value moves in —
            // it is not used after this point in the loop body).
            if field == "credential" {
                cred_descriptors.push((rid.to_string(), value));
            }
        } else {
            issues.push(format!(
                "disclosure {i}: revealed {field} does not match record '{rid}' commitment (tamper, threat #6)"
            ));
        }
    }
    (total, verified, cred_descriptors)
}

pub fn verify_bundle_json(text: &str) -> Result<VerifyReport, crate::canon::CanonError> {
    Ok(verify_bundle(&CanonValue::parse(text)?))
}

fn opt_str(o: &Option<String>) -> CanonValue {
    match o {
        Some(s) => CanonValue::string(s.clone()),
        None => CanonValue::Null,
    }
}
fn str_array(v: &[String]) -> CanonValue {
    CanonValue::Array(v.iter().map(|s| CanonValue::string(s.clone())).collect())
}
fn count(n: usize) -> CanonValue {
    CanonValue::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

/// Serialize a [`VerifyReport`] to a canonical JSON object (reuses the RCP serializer). Used by the
/// WASM and FFI surfaces so all three targets emit identical report bytes.
pub fn report_to_canon(r: &VerifyReport) -> CanonValue {
    let records: Vec<CanonValue> = r
        .record_trust
        .iter()
        .map(|t| {
            CanonValue::object(vec![
                ("record_id".into(), CanonValue::string(t.record_id.clone())),
                (
                    "content_hash".into(),
                    CanonValue::string(t.content_hash.clone()),
                ),
                ("integrity_ok".into(), CanonValue::Bool(t.integrity_ok)),
                ("signature_ok".into(), CanonValue::Bool(t.signature_ok)),
                (
                    "key_status".into(),
                    CanonValue::string(t.key_status.clone()),
                ),
                (
                    "observed_via".into(),
                    CanonValue::string(t.observed_via.clone()),
                ),
                (
                    "trust".into(),
                    CanonValue::string(match t.trust {
                        TrustLevel::IntegrityProven => "integrity_proven",
                        TrustLevel::Untrusted => "untrusted",
                    }),
                ),
                ("authority".into(), CanonValue::string(t.authority.as_str())),
                (
                    "broker_role".into(),
                    CanonValue::string(t.broker_role.clone()),
                ),
                ("notes".into(), str_array(&t.notes)),
            ])
            .unwrap()
        })
        .collect();
    CanonValue::object(vec![
        ("ok".into(), CanonValue::Bool(r.ok)),
        ("project_id".into(), opt_str(&r.project_id)),
        (
            "keys_externally_pinned".into(),
            CanonValue::Bool(r.keys_externally_pinned),
        ),
        ("records_total".into(), count(r.records_total)),
        ("records_proven".into(), count(r.records_proven)),
        ("dag_ok".into(), CanonValue::Bool(r.dag_ok)),
        ("dag_heads".into(), count(r.dag_heads)),
        ("collapsed_duplicates".into(), count(r.collapsed_duplicates)),
        ("checkpoints_total".into(), count(r.checkpoints_total)),
        ("checkpoints_verified".into(), count(r.checkpoints_verified)),
        ("checkpoints_anchored".into(), count(r.checkpoints_anchored)),
        ("chain_ok".into(), CanonValue::Bool(r.chain_ok)),
        ("disclosures_total".into(), count(r.disclosures_total)),
        ("disclosures_verified".into(), count(r.disclosures_verified)),
        ("grant_total".into(), count(r.grant_total)),
        ("grant_verified".into(), count(r.grant_verified)),
        ("denied_grants".into(), count(r.denied_grants)),
        ("uses_total".into(), count(r.uses_total)),
        ("uses_matched".into(), count(r.uses_matched)),
        (
            "uses_action_unverified".into(),
            count(r.uses_action_unverified),
        ),
        (
            "uses_pop_reverified".into(),
            count(r.uses_pop_reverified),
        ),
        (
            "unmatched_violation".into(),
            count(r.unmatched_violation),
        ),
        ("unmatched_pending".into(), count(r.unmatched_pending)),
        ("intent_without_outcome".into(), count(r.intent_without_outcome)),
        ("grants_unused".into(), count(r.grants_unused)),
        ("bounded_reuse_grants".into(), count(r.bounded_reuse_grants)),
        ("bounded_reuse_overspent".into(), count(r.bounded_reuse_overspent)),
        ("bounded_reuse_seq_replays".into(), count(r.bounded_reuse_seq_replays)),
        // M6 (ADR 0005): cosig (M-of-N grant approval) accounting + the artifact-level status.
        ("cosigned_grants_total".into(), count(r.cosigned_grants_total)),
        ("cosigned_grants_satisfied".into(), count(r.cosigned_grants_satisfied)),
        ("cosig_threshold_failures".into(), count(r.cosig_threshold_failures)),
        ("cosig_status".into(), CanonValue::string(r.cosig_status.clone())),
        // M2 (ADR 0005): delegation (per-hop signed re-delegation) accounting + artifact status.
        ("delegation_chains_total".into(), count(r.delegation_chains_total)),
        ("delegation_chains_verified".into(), count(r.delegation_chains_verified)),
        ("delegation_monotonicity_violations".into(), count(r.delegation_monotonicity_violations)),
        ("delegation_status".into(), CanonValue::string(r.delegation_status.clone())),
        (
            "taxonomy_status".into(),
            CanonValue::string(r.taxonomy_status.clone()),
        ),
        // Tier-A grant accountability: every grant verified to gateway_enforced under a pinned key.
        (
            "grant_accountability".into(),
            CanonValue::string(if r.grant_total == 0 {
                "not_applicable"
            } else if r.grant_verified == r.grant_total {
                "complete"
            } else {
                "incomplete"
            }),
        ),
        // Tier-A is grant accountability only; action completeness (Tier B / Level 3) additionally
        // needs use receipts + attestations and is NOT claimed here (ADR 0002). broker_trust (ADR 0004
        // D6) reduces `assumed` toward `sequence_verified` when an anchored grant-transparency head proves
        // the recorded grant log is gapless; attestation_status is `unevaluated` (manifest not evaluated).
        (
            "broker_trust".into(),
            CanonValue::string(r.broker_trust.clone()),
        ),
        ("cred_label_checks".into(), count(r.cred_label_checks)),
        ("cred_label_matched".into(), count(r.cred_label_matched)),
        // D7 (ADR 0004): the attestation verdict + what/by-whom/for-when, so a reader sees the claims were
        // attested by a pinned issuer for a window — never rendered as TEE-style runtime enforcement.
        (
            "attestation_status".into(),
            CanonValue::string(r.attestation_status.clone()),
        ),
        ("attestation_issuer_kid".into(), opt_str(&r.attestation_issuer_kid)),
        ("attestation_issued_at".into(), opt_str(&r.attestation_issued_at)),
        ("attestation_not_after".into(), opt_str(&r.attestation_not_after)),
        ("attestation_claim_types".into(), str_array(&r.attestation_claim_types)),
        ("attestation_subject_digest".into(), opt_str(&r.attestation_subject_digest)),
        // D8 (ADR 0004) — the `attested_complete` capstone: the CONJUNCTION of every reduction. The label
        // `attested_complete_over_brokered_surface` is emitted ONLY when ALL hold: the bundle verified
        // (`ok` — all in-scope records L2-proven, DAG + chain valid, no issues); there is a brokered surface
        // (`uses_matched > 0`); EVERY matched use is a closed two-phase pair (MF3 — `!one_phase_use_present`,
        // and `intent_without_outcome == 0` so no recorded-but-incomplete intent); every matched use is
        // taxonomy-`validated` AND action-verified (D4 — `taxonomy_status=="validated"` ∧
        // `uses_action_unverified == 0`); every matched use was PoP-RE-verified offline (D2 —
        // `uses_pop_reverified == uses_matched`, never the shim-asserted path); the grant log is anchored +
        // gapless (D6 — `broker_trust=="sequence_verified"`); a fresh pinned-issuer deployment attestation
        // binds this bundle (D7 — `attestation_status=="attested_claims"`); and there is no unmatched
        // violation or unexplained in-flight use (`unmatched_violation == 0` ∧ `unmatched_pending == 0`).
        // The capstone is asserted over a `coverage_manifest`; absent one it is at most `claimed_over_manifest`.
        // It is ALWAYS qualified by `resource_trust:"assumed_truthful"` (MF1 — the irreducible resource TCB).
        ("action_completeness".into(), {
            // a JSON `"coverage_manifest": null` deserializes to `Some(Null)`, which is NOT a real manifest
            // (D7 already treats null as the empty digest) — the capstone must be asserted OVER a real scope
            // claim, so require a NON-NULL manifest.
            let has_manifest = r.coverage_manifest.as_ref().is_some_and(|m| !m.is_null());
            let capstone = r.ok
                && has_manifest
                && r.uses_matched > 0
                && !r.one_phase_use_present
                && r.intent_without_outcome == 0
                && r.taxonomy_status == "validated"
                && r.uses_action_unverified == 0
                && r.uses_pop_reverified == r.uses_matched
                && r.broker_trust == "sequence_verified"
                && r.attestation_status == "attested_claims"
                && r.unmatched_violation == 0
                && r.unmatched_pending == 0
                // M1 (ADR 0005): no bounded_reuse grant was overspent or had a replayed sequence number.
                // Surfacing-redundant with unmatched_violation (each anomaly is also a violation, so !ok),
                // but kept explicit so the capstone's meaning is self-documenting over the N-Use surface.
                && r.bounded_reuse_overspent == 0
                && r.bounded_reuse_seq_replays == 0
                // M6 (ADR 0005): every cosigned grant met its M-of-N approval threshold. A short cosigned
                // grant is also NOT indexed (its use → unmatched_violation, so !ok), but the conjunct is kept
                // explicit so the capstone self-documents that dual-control was satisfied over the surface.
                && r.cosig_threshold_failures == 0
                && (r.cosigned_grants_total == 0 || r.cosigned_grants_satisfied == r.cosigned_grants_total)
                // M2 (ADR 0005): every present delegation chain fully re-walked (sigs + links + monotonic).
                // A failed/non-monotone chain also un-indexes the grant (its use → unmatched_violation, so !ok),
                // but the conjuncts are explicit so the capstone self-documents that re-delegation was verified.
                && (r.delegation_chains_total == 0 || r.delegation_chains_verified == r.delegation_chains_total)
                && r.delegation_monotonicity_violations == 0
                // T6: the brokered surface stayed within the operator's AFFIRMATIVELY-declared side-effect
                // closure. This is load-bearing beyond `r.ok`: an `unclosed` surface already forces `!ok`, but
                // a `not_declared` manifest (no closure asserted) does NOT — so without this conjunct an
                // otherwise-perfect bundle that declares ZERO closure would reach the capstone. Requiring
                // `closed` makes attested_complete mean "complete over the surface AND that surface is within
                // the declared closure" (still bounded by resource_trust:assumed_truthful — declaration, not obedience).
                && r.side_effect_closure_status == "closed";
            CanonValue::string(if capstone {
                "attested_complete_over_brokered_surface"
            } else if has_manifest {
                "claimed_over_manifest"
            } else {
                "not_claimed"
            })
        }),
        // MF1: the resource-truthful-labeling conditional, ALWAYS present so the capstone can never be read
        // as "everything the agent did" — only "everything over the brokered surface, IF the resource
        // labeled it truthfully" (the irreducible resource TCB, D9).
        ("resource_trust".into(), CanonValue::string(r.resource_trust.clone())),
        (
            "coverage_manifest".into(),
            r.coverage_manifest.clone().unwrap_or(CanonValue::Null),
        ),
        ("unclosed_side_effects".into(), count(r.unclosed_side_effects)),
        ("side_effect_closure_status".into(), CanonValue::string(r.side_effect_closure_status.clone())),
        ("issues".into(), str_array(&r.issues)),
        ("first_broken_link".into(), opt_str(&r.first_broken_link)),
        ("record_trust".into(), CanonValue::Array(records)),
    ])
    .unwrap()
}

pub fn report_to_json(r: &VerifyReport) -> String {
    report_to_canon(r).serialize()
}

/// Verify a bundle JSON string and return the report as a JSON string (the shape WASM/FFI return).
pub fn verify_bundle_to_json(text: &str) -> String {
    match verify_bundle_json(text) {
        Ok(r) => report_to_json(&r),
        Err(e) => CanonValue::object(vec![
            ("ok".into(), CanonValue::Bool(false)),
            ("error".into(), CanonValue::string(e.to_string())),
        ])
        .unwrap()
        .serialize(),
    }
}

pub fn verify_bundle(bundle: &CanonValue) -> VerifyReport {
    verify_bundle_with(bundle, &VerifyOptions::default())
}

/// Verify a bundle (JSON) with out-of-band pinned trust roots supplied as a JSON options object, and
/// return the report JSON — the shape the FFI/CLI use to pass pinned keys for authority elevation
/// (the broker recording key for `gateway_enforced` grants) and key/TSA pinning. All option keys are
/// optional arrays: `authority_keys`/`signing_keys`/`tsa_keys` are `ed25519pub:` strings;
/// `tsa_spki_b64` are base64url-no-pad DER SubjectPublicKeyInfos.
pub fn verify_bundle_with_json(bundle_text: &str, opts_text: &str) -> String {
    let bundle = match CanonValue::parse(bundle_text) {
        Ok(b) => b,
        Err(e) => return error_report(&format!("bundle parse: {e}")),
    };
    let opts_val = match CanonValue::parse(opts_text) {
        Ok(o) => o,
        Err(e) => return error_report(&format!("options parse: {e}")),
    };
    // Parse pinned keys FAIL-CLOSED: any malformed entry is an error, never a silent drop — a caller
    // who supplied keys must not be downgraded to unpinned verification (signing keys) or get a
    // confusing grant_verified:0 (authority keys) because a key was pasted in the wrong encoding.
    let authority = match parse_pubkeys(&opts_val, "authority_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let broker_authority = match parse_pubkeys(&opts_val, "broker_authority_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let resource_authority = match parse_pubkeys(&opts_val, "resource_authority_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let taxonomy_keys = match parse_pubkeys(&opts_val, "taxonomy_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    // The taxonomy provenance pins (MF5). Optional, but present-but-wrong-type is an error (fail-closed:
    // a typo'd pin must not silently degrade to "no pin" → a forever-`untrusted` taxonomy with no signal).
    let taxonomy_digest = match opts_val.get("taxonomy_digest") {
        None | Some(CanonValue::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => Some(s.to_string()),
            None => return error_report("taxonomy_digest must be a string"),
        },
    };
    let taxonomy_version = match opts_val.get("taxonomy_version") {
        None | Some(CanonValue::Null) => None,
        Some(v) => match v.as_int() {
            Some(n) => Some(n),
            None => return error_report("taxonomy_version must be an integer"),
        },
    };
    let tsa_keys = match parse_pubkeys(&opts_val, "tsa_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let tsa_spki = match parse_spki(&opts_val, "tsa_spki_b64") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let signing = match parse_pubkeys(&opts_val, "signing_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    // D7.2: pinned deployment-attestation issuer keys (so the JSON/FFI path — used by the Go server and any
    // external auditor — can elevate `attestation_status` to `attested_claims`, not just the direct Rust API).
    let attestation_keys = match parse_pubkeys(&opts_val, "attestation_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    // M6 (ADR 0005): pinned cosignature-approver keys, so the JSON/FFI path (the Go server + any external
    // auditor) can enforce M-of-N grant approval, not just the direct Rust API.
    let cosig_approver_keys = match parse_pubkeys(&opts_val, "cosig_approver_keys") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let mut opts = VerifyOptions {
        trusted_authority_keys: authority,
        broker_authority_keys: broker_authority,
        resource_authority_keys: resource_authority,
        taxonomy: opts_val.get("taxonomy").cloned(),
        taxonomy_keys,
        taxonomy_digest,
        taxonomy_version,
        trusted_tsa_keys: tsa_keys,
        trusted_tsa_spki: tsa_spki,
        attestation_keys,
        cosig_approver_keys,
        ..Default::default()
    };
    if !signing.is_empty() {
        // No out-of-band status/compromise override here — that is the richer Rust API's job.
        opts.trusted_keys = Some(signing.into_iter().map(TrustedKey::from).collect());
    }
    report_to_json(&verify_bundle_with(&bundle, &opts))
}

/// Parse an optional array of `ed25519pub:` strings. Absent ⇒ empty; present-but-malformed ⇒ Err
/// (fail-closed, with the offending index + reason — never a silent drop).
fn parse_pubkeys(opts: &CanonValue, key: &str) -> Result<Vec<VerifyingKey>, String> {
    let arr = match opts.get(key) {
        None | Some(CanonValue::Null) => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| format!("{key} must be an array of ed25519pub: strings"))?,
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| format!("{key}[{i}] must be a string"))?;
        let vk = decode_pubkey(s)
            .map_err(|e| format!("{key}[{i}] is not a valid ed25519pub key: {e}"))?;
        out.push(vk);
    }
    Ok(out)
}

/// Parse an optional array of base64url DER SPKIs. Absent ⇒ empty; present-but-malformed ⇒ Err.
fn parse_spki(opts: &CanonValue, key: &str) -> Result<Vec<Vec<u8>>, String> {
    let arr = match opts.get(key) {
        None | Some(CanonValue::Null) => return Ok(Vec::new()),
        Some(v) => v
            .as_array()
            .ok_or_else(|| format!("{key} must be an array of base64url DER strings"))?,
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| format!("{key}[{i}] must be a string"))?;
        let der =
            crate::b64::decode(s).map_err(|e| format!("{key}[{i}] is not valid base64url: {e}"))?;
        out.push(der);
    }
    Ok(out)
}

fn error_report(msg: &str) -> String {
    CanonValue::object(vec![
        ("ok".into(), CanonValue::Bool(false)),
        ("error".into(), CanonValue::string(msg)),
    ])
    .unwrap()
    .serialize()
}

/// A fatal-configuration `VerifyReport` (ok=false) returned BEFORE any record is evaluated — used for
/// the R2 disjoint-key-set check, so an ambiguous key universe never proceeds to a "clean" verdict.
fn fatal_config_report(project_id: Option<String>, msg: &str) -> VerifyReport {
    VerifyReport {
        ok: false,
        project_id,
        keys_externally_pinned: false,
        records_total: 0,
        records_proven: 0,
        record_trust: Vec::new(),
        dag_ok: false,
        dag_heads: 0,
        collapsed_duplicates: 0,
        checkpoints_total: 0,
        checkpoints_verified: 0,
        checkpoints_anchored: 0,
        chain_ok: false,
        disclosures_total: 0,
        disclosures_verified: 0,
        grant_total: 0,
        grant_verified: 0,
        denied_grants: 0,
        uses_total: 0,
        uses_matched: 0,
        uses_action_unverified: 0,
        uses_pop_reverified: 0,
        unmatched_violation: 0,
        unmatched_pending: 0,
        intent_without_outcome: 0,
        one_phase_use_present: false,
        grants_unused: 0,
        bounded_reuse_grants: 0,
        bounded_reuse_overspent: 0,
        bounded_reuse_seq_replays: 0,
        cosigned_grants_total: 0,
        cosigned_grants_satisfied: 0,
        cosig_threshold_failures: 0,
        cosig_status: "absent".to_string(),
        delegation_chains_total: 0,
        delegation_chains_verified: 0,
        delegation_monotonicity_violations: 0,
        delegation_status: "absent".to_string(),
        taxonomy_status: "absent".to_string(),
        broker_trust: "assumed".to_string(),
        cred_label_checks: 0,
        cred_label_matched: 0,
        attestation_status: "unevaluated".to_string(),
        attestation_issuer_kid: None,
        attestation_issued_at: None,
        attestation_not_after: None,
        attestation_claim_types: Vec::new(),
        attestation_subject_digest: None,
        resource_trust: "assumed_truthful".to_string(),
        coverage_manifest: None,
        unclosed_side_effects: 0,
        side_effect_closure_status: "not_declared".to_string(),
        issues: vec![msg.to_string()],
        first_broken_link: Some(msg.to_string()),
    }
}

/// Re-derive a broker record's `evidence_hash` from the canonical evidence payload it embeds at
/// `extensions.broker.<payload_key>` and confirm it equals the signed `authority.evidence_hash`
/// (ADR 0003 R1). `verify_authority` only proves a signature over the opaque `evidence_hash`, so a
/// `Verified` authority alone does NOT prove the signer committed to the semantic match fields. Unless
/// the verifier reads those fields from a payload whose RCP hash equals the signed hash, the match
/// would fire on unverified values. Returns false if the payload or the signed hash is absent, or the
/// two differ. The embedded payload is part of the signed body, so this binds it to the seal.
fn evidence_rederivable(rec: &CanonValue, payload_key: &str) -> bool {
    let signed = match rec
        .get("authority")
        .and_then(|a| a.get("evidence_hash"))
        .and_then(|v| v.as_str())
    {
        Some(h) => h,
        None => return false,
    };
    let payload = match rec
        .get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get(payload_key))
    {
        Some(p) => p,
        None => return false,
    };
    crate::hashx::sha256_prefixed(payload.serialize().as_bytes()) == signed
}

/// Read a string field from a record's canonical evidence payload at `extensions.broker.<payload_key>`
/// (ADR 0003 — the verifier reads match inputs ONLY from the proven payload).
fn ev_str(rec: &CanonValue, payload_key: &str, field: &str) -> Option<String> {
    rec.get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get(payload_key))
        .and_then(|p| p.get(field))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Re-derive the resource ledger_commitment (ADR 0003 R5 / ADR 0004 D3) the SAME way the resource
/// shim does: `sha256( LP4("feir.broker.use.ledger.v1") ‖ LP4(jti) ‖ LP4(nonce) ‖ BE8(used_at) )`,
/// where LP4 is a 4-byte big-endian length prefix and BE8 an 8-byte big-endian integer. Returns
/// `sha256:<lowercase hex>`. Kept byte-identical to Go `resourceshim.ledgerCommitment` via the SHARED
/// golden vector `spec/golden-vectors/broker-preimages.json` — loaded by BOTH Go
/// `TestLedgerCommitmentGoldenVector` and Rust `ledger_commitment_golden_vector`, so a drift in either
/// implementation breaks both suites against the one file (not two independently-hardcoded copies).
pub fn ledger_commitment(jti: &str, nonce: &str, used_at: i64) -> String {
    let mut pre = Vec::new();
    for part in ["feir.broker.use.ledger.v1", jti, nonce] {
        pre.extend_from_slice(&(part.len() as u32).to_be_bytes());
        pre.extend_from_slice(part.as_bytes());
    }
    pre.extend_from_slice(&(used_at as u64).to_be_bytes());
    crate::hashx::sha256_prefixed(&pre)
}

/// Cumulative grant-transparency root (ADR 0004 D6 / MF2): a hash-CHAIN over a broker's grant log,
/// folding `(broker_seq, grant content_hash)` pairs **in ascending `broker_seq` order**. Byte-identical
/// to Go `broker.GrantHeadRoot`, so the offline verifier re-derives the `cumulative_root` an anchored
/// checkpoint's `broker_grant_head` carries and a dropped/renumbered/forked grant fails the match.
///
/// `acc_0 = sha256( LP4(tag) )`; `acc_i = sha256( LP4(tag) ‖ acc_{i-1}(32 raw bytes) ‖ BE8(seq_i) ‖
/// LP4(content_hash_i) )`, tag = "feir.broker.grant_head.v1". The caller MUST pass the pairs already
/// sorted by `broker_seq` (the verifier sorts the closed grant set; the producer folds in issue order).
/// Returns `sha256:<hex>` of the final accumulator. The empty log has a well-defined non-zero root.
pub fn grant_head_root(grants: &[(i64, String)]) -> String {
    const TAG: &str = "feir.broker.grant_head.v1";
    let lp4 = |pre: &mut Vec<u8>, b: &[u8]| {
        pre.extend_from_slice(&(b.len() as u32).to_be_bytes());
        pre.extend_from_slice(b);
    };
    // acc_0 = sha256(LP4(tag)) — a fixed non-zero seed so an empty log is distinguishable from a forged one.
    let mut seed = Vec::new();
    lp4(&mut seed, TAG.as_bytes());
    let mut acc = crate::hashx::sha256(&seed);
    for (seq, content_hash) in grants {
        let mut pre = Vec::new();
        lp4(&mut pre, TAG.as_bytes());
        pre.extend_from_slice(&acc);
        pre.extend_from_slice(&(*seq as u64).to_be_bytes());
        lp4(&mut pre, content_hash.as_bytes());
        acc = crate::hashx::sha256(&pre);
    }
    format!("sha256:{}", crate::hashx::hex_lower(&acc))
}

/// Re-derive the use-time PoP challenge digest the resource shim signs over (ADR 0003 R4 / ADR 0004
/// D2), byte-identically to Go `resourceshim.usePoPChallenge`: `sha256( LP4(tag) ‖ LP4(grant_id) ‖
/// LP4(resource_id) ‖ LP4(action) ‖ LP4(params_commitment) ‖ LP4(credential_binding) ‖ LP4(nonce) )`,
/// tag = "feir.broker.use.pop.v1". Returns the 32-byte digest the agent signs. Kept in sync with Go via
/// a shared golden vector.
pub fn use_pop_challenge(
    grant_id: &str,
    resource_id: &str,
    action: &str,
    params_commitment: &str,
    credential_binding: &str,
    nonce: &str,
) -> [u8; 32] {
    let mut pre = Vec::new();
    for part in [
        "feir.broker.use.pop.v1",
        grant_id,
        resource_id,
        action,
        params_commitment,
        credential_binding,
        nonce,
    ] {
        pre.extend_from_slice(&(part.len() as u32).to_be_bytes());
        pre.extend_from_slice(part.as_bytes());
    }
    crate::hashx::sha256(&pre)
}

/// Re-derive the cosignature-approval challenge an approver signs (ADR 0005 M6), byte-identically to the
/// Go producer: `sha256( LP4(tag) ‖ LP4(grant_id) ‖ LP4(approver_kid) ‖ LP4(credential_binding) ‖
/// BE8(threshold_m) ‖ BE8(exp) )`, tag = "feir.broker.cosig.approval.v1". Binding `approver_kid` makes an
/// approval non-transferable to a different approver; binding `credential_binding` + `threshold_m` + `exp`
/// makes it non-replayable onto a re-minted grant, a different threshold, or a different expiry. Returns the
/// 32-byte digest the approver signs (raw, like `use_pop_challenge`). Kept in sync with Go via the shared
/// golden vector `spec/golden-vectors/broker-preimages.json`.
pub fn cosig_approval_challenge(
    grant_id: &str,
    approver_kid: &str,
    credential_binding: &str,
    threshold_m: i64,
    exp: i64,
) -> [u8; 32] {
    let mut pre = Vec::new();
    for part in [
        "feir.broker.cosig.approval.v1",
        grant_id,
        approver_kid,
        credential_binding,
    ] {
        pre.extend_from_slice(&(part.len() as u32).to_be_bytes());
        pre.extend_from_slice(part.as_bytes());
    }
    pre.extend_from_slice(&(threshold_m as u64).to_be_bytes());
    pre.extend_from_slice(&(exp as u64).to_be_bytes());
    crate::hashx::sha256(&pre)
}

/// The `grant_evidence.cosignatures[]` array of a broker record, if present (ADR 0005 M6). Borrowed from the
/// record's signed payload (integrity-bound), so a reader cannot strip/add entries without breaking the seal.
fn cosignatures_of(rec: &CanonValue) -> Option<&Vec<CanonValue>> {
    rec.get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get("grant_evidence"))
        .and_then(|g| g.get("cosignatures"))
        .and_then(|v| v.as_array())
}

/// M6 (ADR 0005): count the DISTINCT pinned approver keys that produced a valid cosignature over this grant.
/// Each entry in the signed `grant_evidence.cosignatures[]` is `{approver_kid, sig}` (`sig` a base64url-no-pad
/// 64-byte Ed25519 signature, like `use_sig`). For each entry the verifier selects the pinned approver key
/// whose `cnf_kid` equals the entry's claimed `approver_kid`, rebuilds the per-approver challenge, and verifies
/// the sig under THAT key — so the claimed kid only *selects* a candidate; acceptance still requires a real
/// signature by that exact pinned key over a challenge bound to that exact kid. Distinct approver kids are
/// deduped (one approver signing twice counts once — no threshold inflation); an entry whose kid matches no
/// pinned key, whose sig is malformed, or whose sig fails verification is ignored (never counted).
fn count_cosig_approvals(
    rec: &CanonValue,
    grant_id: &str,
    credential_binding: &str,
    threshold_m: i64,
    exp: i64,
    approver_keys: &[VerifyingKey],
) -> usize {
    let cosignatures = match cosignatures_of(rec) {
        Some(a) => a,
        None => return 0,
    };
    // kid -> pinned approver key (raw-bytes identity; cnf_kid is a deterministic function of the key, so a
    // distinct kid is a distinct key modulo a negligible 64-bit collision in an operator's own pin set).
    let pinned: BTreeMap<String, &VerifyingKey> =
        approver_keys.iter().map(|vk| (cnf_kid(vk), vk)).collect();
    let mut credited: BTreeSet<String> = BTreeSet::new();
    for cs in cosignatures {
        let kid = match cs.get("approver_kid").and_then(|v| v.as_str()) {
            Some(k) => k,
            None => continue,
        };
        if credited.contains(kid) {
            continue; // this approver is already credited (dedup — no double counting)
        }
        let vk = match pinned.get(kid) {
            Some(vk) => *vk,
            None => continue, // not a pinned approver -> never counts
        };
        let sig_str = match cs.get("sig").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let sig_bytes = match crate::b64::decode_fixed::<64>(sig_str) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let signature = Signature::from_bytes(&sig_bytes);
        let challenge = cosig_approval_challenge(grant_id, kid, credential_binding, threshold_m, exp);
        if vk.verify_strict(&challenge, &signature).is_ok() {
            credited.insert(kid.to_string());
        }
    }
    credited.len()
}

/// Re-derive the per-hop delegation challenge a delegator signs (ADR 0005 M2), byte-identically to the Go
/// producer: `sha256( LP4(tag) ‖ LP4(grant_id) ‖ BE8(hop_index) ‖ LP4(delegator_kid) ‖ LP4(delegate_kid) ‖
/// LP4(scope) ‖ LP4(action) ‖ LP4(resource_id) ‖ BE8(exp) )`, tag = "feir.broker.delegation.hop.v1". Binding
/// the kids + hop_index makes a hop assertion non-transferable to a different delegator/delegate/position;
/// binding scope/action/resource/exp makes it non-replayable onto a different authority or window. Returns the
/// 32-byte digest the delegator signs (raw, like `use_pop_challenge`). Kept in sync with Go via the shared
/// golden vector `spec/golden-vectors/broker-preimages.json`.
#[allow(clippy::too_many_arguments)]
pub fn delegation_hop_challenge(
    grant_id: &str,
    hop_index: i64,
    delegator_kid: &str,
    delegate_kid: &str,
    scope: &str,
    action: &str,
    resource_id: &str,
    exp: i64,
) -> [u8; 32] {
    let mut pre = Vec::new();
    let lp4 = |pre: &mut Vec<u8>, b: &[u8]| {
        pre.extend_from_slice(&(b.len() as u32).to_be_bytes());
        pre.extend_from_slice(b);
    };
    lp4(&mut pre, b"feir.broker.delegation.hop.v1");
    lp4(&mut pre, grant_id.as_bytes());
    pre.extend_from_slice(&(hop_index as u64).to_be_bytes());
    lp4(&mut pre, delegator_kid.as_bytes());
    lp4(&mut pre, delegate_kid.as_bytes());
    lp4(&mut pre, scope.as_bytes());
    lp4(&mut pre, action.as_bytes());
    lp4(&mut pre, resource_id.as_bytes());
    pre.extend_from_slice(&(exp as u64).to_be_bytes());
    crate::hashx::sha256(&pre)
}

/// Outcome of re-walking a grant's `delegation_assertions[]` chain (ADR 0005 M2).
enum ChainResult {
    /// No (or empty) delegation_assertions — an ordinary, undelegated grant.
    Absent,
    /// Fully verified: every hop signed by its delegator, linked from the root, and monotone. The use binds
    /// to `eff_cnf_kid` (the leaf delegate) and the narrowed window `eff_exp = min(grant exp, hop exps)`.
    Verified { eff_cnf_kid: String, eff_exp: i64 },
    /// Sigs + links re-walked, but a hop widened scope/action/resource beyond the grant (demonstrator
    /// monotonicity = equality). Counted separately so the capstone can require `== 0`.
    Monotonicity,
    /// A malformed hop, an undecodable key/sig, a broken link (delegator ≠ prior delegate / ≠ root cnf_kid),
    /// or a forged hop signature. The grant is not Tier-B-eligible.
    Invalid,
}

/// M2 (ADR 0005): re-walk a grant's signed `delegation_assertions[]` from the broker-signed root cnf_kid,
/// proving each hop and computing the effective (leaf) cnf_kid + narrowed window — never trusting the
/// broker's flattened `delegation_chain[]` claim. Each assertion is `{delegator_cnf, delegate_cnf, scope,
/// action, resource_id, exp, sig}` where the `*_cnf` are base64url ed25519 PUBLIC keys (the verifier derives
/// the kids) and `sig` is the base64url-64 signature over `delegation_hop_challenge`. Hop 0's delegator must
/// be the root; hop i's delegator must equal hop i-1's delegate; the effective cnf is the final delegate.
fn verify_delegation_chain(
    rec: &CanonValue,
    grant_id: &str,
    root_cnf_kid: &str,
    grant_scope: &str,
    grant_action: &str,
    grant_resource_id: &str,
    grant_exp: i64,
) -> ChainResult {
    let assertions = match rec
        .get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get("grant_evidence"))
        .and_then(|g| g.get("delegation_assertions"))
        .and_then(|v| v.as_array())
    {
        Some(a) if !a.is_empty() => a,
        _ => return ChainResult::Absent,
    };
    let mut expected_delegator_kid = root_cnf_kid.to_string(); // hop 0's delegator must be the grant's cnf
    let mut eff_exp = grant_exp;
    let mut monotone = true;
    for (i, hop) in assertions.iter().enumerate() {
        let (delegator_b64, delegate_b64, scope, action, resource_id, sig_b64) = match (
            hop.get("delegator_cnf").and_then(|v| v.as_str()),
            hop.get("delegate_cnf").and_then(|v| v.as_str()),
            hop.get("scope").and_then(|v| v.as_str()),
            hop.get("action").and_then(|v| v.as_str()),
            hop.get("resource_id").and_then(|v| v.as_str()),
            hop.get("sig").and_then(|v| v.as_str()),
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => (a, b, c, d, e, f),
            _ => return ChainResult::Invalid,
        };
        let hop_exp = match hop.get("exp").and_then(|v| v.as_int()) {
            Some(e) => e,
            None => return ChainResult::Invalid,
        };
        let delegator_vk = match crate::b64::decode_fixed::<32>(delegator_b64)
            .ok()
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        {
            Some(vk) => vk,
            None => return ChainResult::Invalid,
        };
        let delegate_vk = match crate::b64::decode_fixed::<32>(delegate_b64)
            .ok()
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        {
            Some(vk) => vk,
            None => return ChainResult::Invalid,
        };
        let delegator_kid = cnf_kid(&delegator_vk);
        let delegate_kid = cnf_kid(&delegate_vk);
        // Link: hop 0's delegator must be the root cnf_kid; hop i's must be the previous hop's delegate.
        if delegator_kid != expected_delegator_kid {
            return ChainResult::Invalid;
        }
        // Signature: the delegator authorized THIS hop (binds the next delegate + scope/action/resource/exp).
        let challenge = delegation_hop_challenge(
            grant_id,
            i as i64,
            &delegator_kid,
            &delegate_kid,
            scope,
            action,
            resource_id,
            hop_exp,
        );
        let sig_bytes = match crate::b64::decode_fixed::<64>(sig_b64) {
            Ok(b) => b,
            Err(_) => return ChainResult::Invalid,
        };
        if delegator_vk
            .verify_strict(&challenge, &Signature::from_bytes(&sig_bytes))
            .is_err()
        {
            return ChainResult::Invalid;
        }
        // Monotonicity (demonstrator = equality, fail-closed): a hop may not change scope/action/resource. A
        // true narrowing lattice over the scope vocabulary is the documented future extension (ADR 0005 M2).
        if scope != grant_scope || action != grant_action || resource_id != grant_resource_id {
            monotone = false;
        }
        eff_exp = eff_exp.min(hop_exp); // a delegation can only NARROW the window, never extend it
        expected_delegator_kid = delegate_kid;
    }
    if !monotone {
        return ChainResult::Monotonicity;
    }
    // expected_delegator_kid now holds the LAST hop's delegate kid = the leaf the use must present.
    ChainResult::Verified { eff_cnf_kid: expected_delegator_kid, eff_exp }
}

/// Re-derive the cnf key id (Go `broker.KeyID`): `"ed25519-" + base64url-nopad(sha256(pubkey)[..8])`.
/// Used to confirm a carried cnf public key matches the receipt's `cnf_kid` (ADR 0004 D2).
pub fn cnf_kid(cnf_pub: &VerifyingKey) -> String {
    let sum = crate::hashx::sha256(cnf_pub.as_bytes());
    format!("ed25519-{}", crate::b64::encode(&sum[..8]))
}

/// Offline PoP re-verification (ADR 0004 D2). Returns `Ok(true)` if the receipt carried the agent
/// cnf pubkey + use_sig and the Ed25519 PoP RE-RAN successfully (the verifier independently proved
/// PoP — off the shim TCB); `Ok(false)` if it carries neither (legacy ADR-0003 `shim_asserted` path,
/// not re-run); `Err(reason)` if it CLAIMS re-verification but the re-check fails (a violation). The
/// challenge is reconstructed from the proven use_evidence fields + the matched grant's
/// credential_binding + the record's input_commit.commitment.
fn pop_reverify(rec: &CanonValue, credential_binding: &str) -> Result<bool, String> {
    let (cnf_b64, sig_b64) = match (
        ev_str(rec, "use_evidence", "cnf_pub"),
        ev_str(rec, "use_evidence", "use_sig"),
    ) {
        (Some(a), Some(b)) => (a, b),
        _ => return Ok(false), // shim_asserted: nothing to re-run
    };
    let cnf_bytes = crate::b64::decode_fixed::<32>(&cnf_b64)
        .map_err(|_| "use_evidence.cnf_pub is not a base64url ed25519 public key".to_string())?;
    let cnf_pub = VerifyingKey::from_bytes(&cnf_bytes)
        .map_err(|_| "use_evidence.cnf_pub is not a valid ed25519 public key".to_string())?;
    if ev_str(rec, "use_evidence", "cnf_kid").as_deref() != Some(&cnf_kid(&cnf_pub)) {
        return Err("carried cnf_pub does not match use_evidence.cnf_kid".into());
    }
    let challenge = use_pop_challenge(
        &ev_str(rec, "use_evidence", "grant_id").unwrap_or_default(),
        &ev_str(rec, "use_evidence", "resource_id").unwrap_or_default(),
        &ev_str(rec, "use_evidence", "action").unwrap_or_default(),
        rec.get("input_commit")
            .and_then(|c| c.get("commitment"))
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        credential_binding,
        &ev_str(rec, "use_evidence", "nonce").unwrap_or_default(),
    );
    let expected = format!("sha256:{}", crate::hashx::hex_lower(&challenge));
    if ev_str(rec, "use_evidence", "pop_challenge_hash").as_deref() != Some(&expected) {
        return Err("reconstructed PoP challenge != use_evidence.pop_challenge_hash".into());
    }
    let sig_bytes = crate::b64::decode_fixed::<64>(&sig_b64)
        .map_err(|_| "use_evidence.use_sig is not a base64url 64-byte signature".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);
    cnf_pub
        .verify_strict(&challenge, &sig)
        .map_err(|_| "use_sig does not verify under cnf_pub (offline PoP re-check failed)".to_string())?;
    Ok(true)
}

/// Read an integer field from a record's canonical evidence payload (used for issued_at/exp/used_at).
fn ev_int(rec: &CanonValue, payload_key: &str, field: &str) -> Option<i64> {
    rec.get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get(payload_key))
        .and_then(|p| p.get(field))
        .and_then(|v| v.as_int())
}

/// A checkpoint's `broker_grant_head` (ADR 0004 D6 / MF2), parsed fail-closed.
#[derive(PartialEq)]
struct GrantHead {
    max_seq: i64,
    prior_head_hash: String,
    cumulative_root: String,
}

fn parse_grant_head(cp: &CanonValue) -> Option<GrantHead> {
    let h = cp.get("broker_grant_head")?;
    Some(GrantHead {
        max_seq: h.get("max_seq").and_then(|v| v.as_int())?,
        prior_head_hash: h.get("prior_head_hash").and_then(|v| v.as_str())?.to_string(),
        cumulative_root: h.get("cumulative_root").and_then(|v| v.as_str())?.to_string(),
    })
}

struct TaxonomyInfo {
    /// (resource_id, action) pairs the issuer asserts ARE single-operation. RESOURCE-BOUND (an entry
    /// vetted for one resource must not validate the same action name on another — Codex AREA 2).
    actions: BTreeSet<(String, String)>,
    /// (resource_id, action) pairs the issuer affirmatively marks as escalating / NOT single-operation:
    /// a grant claiming `single_operation` scope for one of these is mis-scoped and is rejected (D4).
    escalating: BTreeSet<(String, String)>,
    effective_from: i64,
    effective_until: i64,
}

/// Parse a taxonomy list of `{resource_id, action}` objects into a `(resource_id, action)` set. `absent`
/// chooses the value for a missing field (`Some(empty)` for an optional list, `None` to require it); any
/// PRESENT-but-malformed entry (not an array, or an object missing a string `resource_id`/`action`)
/// returns `None` so the WHOLE taxonomy fails closed to `untrusted` rather than silently dropping a row.
fn tax_pairs(tax: &CanonValue, key: &str, absent: Option<BTreeSet<(String, String)>>) -> Option<BTreeSet<(String, String)>> {
    let arr = match tax.get(key) {
        None | Some(CanonValue::Null) => return absent,
        Some(v) => v.as_array()?,
    };
    let mut set = BTreeSet::new();
    for e in arr {
        let r = e.get("resource_id").and_then(|x| x.as_str())?;
        let a = e.get("action").and_then(|x| x.as_str())?;
        set.insert((r.to_string(), a.to_string()));
    }
    Some(set)
}

/// Parse `coverage_manifest.side_effect_closure` (T6) into the set of `(resource_id, action)` pairs it
/// DECLARES — for every entry, the primary `(resource_id, action)` PLUS `(may_touch_resource, action)` for
/// each resource in that entry's `may_touch` list (the may_touch resources are declared touchable UNDER THE
/// ENTRY'S ACTION). Closure is action-bound (per `(resource_id, action)`, like the ADR specifies): a resource
/// declared only under a DIFFERENT action does not close that resource for the action actually acting on it.
/// Fail-closed like `tax_pairs`: a present-but-malformed list (an entry that is not an object, is missing a
/// string `resource_id`/`action`, or whose `may_touch` is not an array of strings) returns `None`. The caller
/// checks field PRESENCE separately, so an absent field is `not_declared` while a malformed one fails closed.
fn side_effect_closure_resources(manifest: &CanonValue) -> Option<BTreeSet<(String, String)>> {
    let arr = manifest.get("side_effect_closure")?.as_array()?;
    let mut declared = BTreeSet::new();
    for e in arr {
        // Reject EMPTY resource_id/action (fail-closed): an `action:""` entry would otherwise declare a
        // ("",..)/(.., "") pair that could "close" a malformed action-less grant whose own action parsed
        // empty — so an empty action can never appear in the declared set (Codex hardening).
        let r = e.get("resource_id").and_then(|x| x.as_str()).filter(|s| !s.is_empty())?;
        let a = e.get("action").and_then(|x| x.as_str()).filter(|s| !s.is_empty())?; // action-bound: per (resource_id, action)
        let may_touch = e.get("may_touch").and_then(|x| x.as_array())?;
        declared.insert((r.to_string(), a.to_string()));
        for t in may_touch {
            let tr = t.as_str().filter(|s| !s.is_empty())?;
            declared.insert((tr.to_string(), a.to_string()));
        }
    }
    Some(declared)
}

/// Validate a pinned signed operation taxonomy (ADR 0004 D4 / MF5): returns its info iff ALL of —
/// (1) the verifier pinned BOTH an expected content digest and version (`pinned_digest`/`pinned_version`
/// present); (2) the taxonomy's RCP-canonical digest (minus `sig`) equals the pinned digest; (3) `sig`
/// verifies under a pinned `taxonomy_keys` issuer over that digest; (4) the carried `version` field
/// equals the pinned version; and (5) the required fields are present + well-formed. `None`
/// (→ `untrusted`) otherwise.
///
/// The pin (digest+version) is what makes a `validated` taxonomy mean "the operator vetted THIS artifact
/// at THIS version" — a signature alone proves only issuer authority, not that the structurally-minimal
/// blob the bundle carries is the taxonomy the operator reviewed (an unpinned signed taxonomy stays
/// `untrusted`, fail-closed). The effective window is enforced PER-USE (a validly-signed but stale
/// taxonomy validates nothing outside its interval — so it cannot back-date an action). The version pin
/// is checked by EQUALITY against the operator's pin (the pin is the rollback anchor — the offline
/// verifier cannot know a "last seen" version, so it does not enforce ordering itself).
fn validate_taxonomy(
    tax: &CanonValue,
    keys: &[VerifyingKey],
    pinned_digest: Option<&str>,
    pinned_version: Option<i64>,
) -> Option<TaxonomyInfo> {
    // MF5: no pin ⇒ unprovable provenance ⇒ never `validated`. Require BOTH the digest and version pins
    // up front so an operator who forgets one cannot silently get a weaker check than they intended.
    let pinned_digest = pinned_digest?;
    let pinned_version = pinned_version?;
    let sig = tax.get("sig").and_then(|v| v.as_str())?;
    let mut obj = tax.as_object()?.clone();
    obj.retain(|(k, _)| k != "sig");
    let digest = crate::hashx::sha256_prefixed(CanonValue::Object(obj).serialize().as_bytes());
    // The pin must match the EXACT bytes signed (digests are public, so a plain compare is fine).
    if digest != pinned_digest {
        return None;
    }
    if !keys
        .iter()
        .any(|vk| crate::sign::verify("feir.taxonomy.v1", &digest, sig, vk).is_ok())
    {
        return None;
    }
    // The carried version must equal the pin (rollback anchor). `version` is part of the digest preimage,
    // so a digest match already pins it byte-for-byte — but an explicit version field + pin gives a
    // distinct, human-meaningful mismatch signal and forces the taxonomy to actually carry one (a minimal
    // blob with no `version` cannot reach `validated`).
    if tax.get("version").and_then(|v| v.as_int())? != pinned_version {
        return None;
    }
    Some(TaxonomyInfo {
        actions: tax_pairs(tax, "single_operation_actions", None)?,
        escalating: tax_pairs(tax, "escalating_actions", Some(BTreeSet::new()))?,
        effective_from: tax.get("effective_from").and_then(|v| v.as_int())?,
        effective_until: tax.get("effective_until").and_then(|v| v.as_int())?,
    })
}

/// D6 (ADR 0004 / MF2): compute `broker_trust` by re-deriving the grant-transparency cumulative_root over
/// the recorded grant log and checking it against the bundle's `broker_grant_head`s. Membership is the
/// role TUPLE (`BrokerRole::Broker`) with a `broker_seq >= 1` — NOT sig-gated (a broker must not be able
/// to drop a grant from the log by under-signing it; that IS the suppression D6 detects), matching the
/// producer's grantLog. A gap / tail-omission / root-mismatch / broken prior-head chain is a hard
/// violation pushed to `issues`.
#[allow(clippy::too_many_arguments)]
fn compute_broker_trust(
    cp_heads: &[(i64, bool, GrantHead, Vec<String>)],
    verified_headless: &[Vec<String>],
    malformed_head: bool,
    record_trust: &[RecordTrust],
    records: &[CanonValue],
    by_hash: &BTreeMap<String, usize>,
    dag_heads: &[String],
    latest_cp_seq: i64,
    issues: &mut Vec<String>,
) -> String {
    // re-derive the tuple-classified grant log (broker_seq >= 1, NOT sig-gated — under-signing is
    // suppression) committed by an arbitrary checkpoint frontier, sorted by broker_seq.
    let log_for = |frontier: &[String]| -> Vec<(i64, String)> {
        let committed = committed_set(records, by_hash, frontier);
        let mut log: Vec<(i64, String)> = record_trust
            .iter()
            .filter(|rt| {
                rt.broker_role == BrokerRole::Broker.as_str() && committed.contains(&rt.content_hash)
            })
            .filter_map(|rt| {
                ev_int(&records[rt.index], "grant_evidence", "broker_seq")
                    .filter(|seq| *seq >= 1)
                    .map(|seq| (seq, rt.content_hash.clone()))
            })
            .collect();
        log.sort_by_key(|(seq, _)| *seq);
        log
    };

    // D6 is active once there is ANY well-formed head, ANY broker_seq grant, or a PRESENT-but-malformed head
    // (a tampered D6 head is still a D6 signal — pre-D6 checkpoints never carry the field). With NO D6 signal
    // at all the bundle is byte-INDISTINGUISHABLE from a legitimate pre-D6 / grant-only export (committed
    // seq-less grants, no head field anywhere), so `broker_trust` stays `assumed`. That TOTAL grant-
    // suppression case is an inherent OFFLINE residual (ADR 0004 D6: equivalence to pre-D6) — closing it
    // would false-positive every genuine pre-D6 bundle, so it is pushed to the out-of-band transparency
    // monitor (which has seen the project's adoption history), NOT decidable from the bundle alone.
    let full_log = log_for(dag_heads);
    if cp_heads.is_empty() && full_log.is_empty() && !malformed_head {
        return "assumed".to_string();
    }
    let mut ok = true;

    // A verified checkpoint carrying a present-but-malformed broker_grant_head is a tampered/garbled D6 head:
    // a hard violation (and the activation signal above), never silently demoted to a benign headless cp.
    if malformed_head {
        issues.push("a verified checkpoint carries a present-but-malformed broker_grant_head — tampered/garbled D6 head (suppression, D6)".into());
        ok = false;
    }

    // Once D6 is active, EVERY committed Broker-role grant MUST carry a broker_seq >= 1 — the producer always
    // assigns one. A committed broker grant with NO broker_seq is one SMUGGLED OUT of the transparency log
    // (it would be silently excluded from every head's max_seq + cumulative_root), so it is a suppression
    // violation in its own right. Run this BEFORE the latest-head early-return so a seq-less grant under a
    // malformed-or-missing latest head is still flagged, not skipped by the early bail.
    let full_committed = committed_set(records, by_hash, dag_heads);
    for rt in record_trust {
        if rt.broker_role == BrokerRole::Broker.as_str()
            && full_committed.contains(&rt.content_hash)
            && ev_int(&records[rt.index], "grant_evidence", "broker_seq")
                .filter(|seq| *seq >= 1)
                .is_none()
        {
            issues.push(format!(
                "committed broker grant {} carries no broker_seq while D6 is active — smuggled out of the transparency log (suppression, D6)",
                rt.content_hash
            ));
            ok = false;
        }
    }

    // D6 grant_id INJECTIVITY: a grant_id is one credential identity, so the producer assigns it exactly
    // ONE broker_seq and emits record_id == grant_id (store dedups broker_seq per grant_id). The head/log
    // fold binds only (broker_seq, content_hash) — grant_id is NOT in the preimage — so two committed
    // Broker-role grants that SHARE a grant_id but are bound to DISTINCT (broker_seq, content_hash) pairs
    // re-derive a perfectly gapless cumulative_root and would otherwise pass as `sequence_verified` while
    // the credential identity is equivocated (one grant_id double-bound to two different credentials,
    // e.g. distinct cnf/scope at seq 1 and seq 2). Both twins are co-committed in this one anchored log,
    // so the equivocation is LOCALLY decidable here — it is NOT the irreducible globally-consistent
    // equivocation floor (divergent histories never co-committed in one bundle, ADR 0004 D6). Identical
    // re-exports of the SAME grant record (same content_hash at the same seq) are benign and collapse.
    let mut pairs_by_grant: BTreeMap<String, BTreeSet<(i64, String)>> = BTreeMap::new();
    for rt in record_trust {
        if rt.broker_role != BrokerRole::Broker.as_str() || !full_committed.contains(&rt.content_hash) {
            continue;
        }
        if let Some(gid) = ev_str(&records[rt.index], "grant_evidence", "grant_id") {
            let seq = ev_int(&records[rt.index], "grant_evidence", "broker_seq").unwrap_or(0);
            pairs_by_grant
                .entry(gid)
                .or_default()
                .insert((seq, rt.content_hash.clone()));
        }
    }
    for (gid, pairs) in &pairs_by_grant {
        if pairs.len() > 1 {
            issues.push(format!(
                "grant_id {gid} is bound to {} distinct (broker_seq, content_hash) pairs in one committed transparency log — equivocated credential identity (D6)",
                pairs.len()
            ));
            ok = false;
        }
    }

    // A VERIFIED checkpoint with NO well-formed head whose frontier commits D6 grants binds those grants
    // into the anchored chain WITHOUT a head — they'd be omitted from every head's log. Require a head on
    // every grant-committing checkpoint (the producer emits one on every checkpoint). Dedup identical
    // frontiers first so a benign byte-identical duplicate checkpoint does not double-report.
    let mut headless: Vec<&Vec<String>> = verified_headless.iter().collect();
    headless.sort();
    headless.dedup();
    for frontier in headless {
        if !log_for(frontier).is_empty() {
            issues.push("a verified checkpoint commits D6 grants but carries no (well-formed) broker_grant_head — grants bound without a transparency head (suppression, D6)".into());
            ok = false;
        }
    }

    // The head MUST be on the LATEST checkpoint (the one whose frontier covers the full DAG). A head only
    // on an EARLIER checkpoint — with the latest checkpoint dropping its head — is exactly how an attacker
    // hides grants the later checkpoint commits, so that is a suppression violation, never an inherited pass.
    let latest = cp_heads.iter().find(|(seq, _, _, _)| *seq == latest_cp_seq);
    let latest_anchored = match latest {
        Some((_, anchored, _, _)) => *anchored,
        None => {
            issues.push("D6 grant transparency is active but the LATEST checkpoint carries no broker_grant_head — a dropped head hides later grants (suppression, D6)".into());
            return "assumed".to_string();
        }
    };

    // Re-derive EVERY verified head against ITS OWN committed frontier, ascending by seq: each head must
    // (a) cover a gapless [1..n_i] prefix of grants its frontier commits, (b) carry max_seq == n_i, (c)
    // re-derive cumulative_root over that exact log, and (d) chain (prior_head_hash == the previous head's
    // cumulative_root; the first == the empty-log root). Validating each head against its OWN frontier —
    // not only the latest against the full log — catches a fraudulent HISTORICAL head that omitted a grant
    // its own frontier committed, even when a later checkpoint carries a correct full head.
    let empty_root = grant_head_root(&[]);
    let mut heads: Vec<&(i64, bool, GrantHead, Vec<String>)> = cp_heads.iter().collect();
    heads.sort_by_key(|(seq, _, _, _)| *seq);
    // validate_chain treats a byte-identical DUPLICATE checkpoint as benign (idempotent re-export); D6 must
    // match — chaining the same head twice would make the 2nd copy's prior_head_hash mismatch the 1st copy's
    // cumulative_root and fabricate a fork. Collapse exact-duplicate heads (same seq + head + frontier); a
    // genuine same-seq divergence is a real fork already flagged by validate_chain.
    heads.dedup_by(|a, b| a.0 == b.0 && a.2 == b.2 && a.3 == b.3);

    let mut prev_root = empty_root;
    for (cseq, _, head, frontier) in heads {
        let log_i = log_for(frontier);
        let n_i = log_i.len() as i64;
        if !log_i.iter().enumerate().all(|(i, (seq, _))| *seq == i as i64 + 1) {
            issues.push(format!("checkpoint seq {cseq}: committed grant broker_seq set is not a gapless [1..N] prefix — suppression/renumber (D6)"));
            ok = false;
        }
        if head.max_seq != n_i {
            issues.push(format!("checkpoint seq {cseq}: broker_grant_head.max_seq {} != its committed grant count {n_i} — omission/inflation (D6)", head.max_seq));
            ok = false;
        }
        if grant_head_root(&log_i) != head.cumulative_root {
            issues.push(format!("checkpoint seq {cseq}: broker_grant_head.cumulative_root does not re-derive from its committed grant log — suppression (D6)"));
            ok = false;
        }
        if head.prior_head_hash != prev_root {
            issues.push(format!("checkpoint seq {cseq}: broker_grant_head prior_head_hash does not chain to the previous head — grant-log fork/restart (D6)"));
            ok = false;
        }
        prev_root = head.cumulative_root.clone();
    }
    if !ok {
        return "assumed".to_string(); // a detected mismatch fails the bundle; the sequence is not trusted
    }
    // every head checks out (incl. the latest, whose frontier == the full DAG head set). The latest head is
    // bound into a verified+anchored checkpoint ⇒ externally pinned; else self-asserted (internal only).
    if latest_anchored {
        "sequence_verified".to_string()
    } else {
        "sequence_consistent_export".to_string()
    }
}

/// The surfaced outcome of D7 deployment-attestation evaluation.
struct AttestationEval {
    status: String,
    issuer_kid: Option<String>,
    issued_at: Option<String>,
    not_after: Option<String>,
    claim_types: Vec<String>,
    subject_digest: Option<String>,
}

/// D7 (ADR 0004): evaluate a `deployment_attestation`. It does NOT verify the runtime properties; it proves
/// a fresh, PINNED-issuer attestation whose signed `subject` binds THIS exact bundle EXISTS. Returns
/// `attested_claims` only when the `sig` verifies under a pinned `attestation_keys` issuer, the claimed
/// `issuer_kid` matches that signer, the latest anchored checkpoint timestamp falls within
/// `[issued_at, not_after]`, AND every `subject` field (project / coverage_manifest digest / latest
/// anchored checkpoint_hash + broker_grant_head root / authority key-id set / resource_id set) matches the
/// bundle. A present-but-bad attestation is `failed` (never silently `unevaluated`); absent attestation or
/// no pinned issuer is `unevaluated`.
#[allow(clippy::too_many_arguments)]
fn evaluate_attestation(
    bundle: &CanonValue,
    opts: &VerifyOptions,
    project_id: Option<&str>,
    anchored_cp_ids: &[(i64, String, String, Option<String>)],
    latest_cp_seq: i64,
    resource_ids: &BTreeSet<String>,
    issues: &mut Vec<String>,
) -> AttestationEval {
    let unevaluated = || AttestationEval {
        status: "unevaluated".to_string(),
        issuer_kid: None,
        issued_at: None,
        not_after: None,
        claim_types: Vec::new(),
        subject_digest: None,
    };
    let att = match bundle.get("deployment_attestation") {
        Some(a) if !a.is_null() => a,
        _ => return unevaluated(), // no attestation -> runtime claims simply not evaluated
    };
    if opts.attestation_keys.is_empty() {
        return unevaluated(); // present, but the verifier pinned no issuer -> cannot evaluate
    }
    let s_str = |o: &CanonValue, k: &str| o.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    // surfaced fields (parsed up front so a `failed` verdict still reports what/by-whom/for-when).
    let claim_types: Vec<String> = att
        .get("claim_types")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let subject_digest = att.get("subject").map(|s| crate::hashx::sha256_prefixed(s.serialize().as_bytes()));
    let (issued_at, not_after) = (s_str(att, "issued_at"), s_str(att, "not_after"));
    let mut eval = AttestationEval {
        status: "failed".to_string(), // default to failed once an attestation is present + evaluable
        issuer_kid: att.get("issuer_kid").and_then(|v| v.as_str()).map(String::from),
        issued_at: Some(issued_at.clone()),
        not_after: Some(not_after.clone()),
        claim_types,
        subject_digest,
    };

    // 1. signature over the canonical attestation minus `sig`, under a pinned issuer (mirrors taxonomy).
    let sig = match att.get("sig").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            issues.push("deployment_attestation: missing sig (D7)".into());
            return eval;
        }
    };
    let mut obj = match att.as_object() {
        Some(o) => o.clone(),
        None => {
            issues.push("deployment_attestation: not an object (D7)".into());
            return eval;
        }
    };
    obj.retain(|(k, _)| k != "sig");
    let digest = crate::hashx::sha256_prefixed(CanonValue::Object(obj).serialize().as_bytes());
    let signer = match opts
        .attestation_keys
        .iter()
        .find(|vk| crate::sign::verify("feir.attestation.v1", &digest, sig, vk).is_ok())
    {
        Some(vk) => vk,
        None => {
            issues.push("deployment_attestation: sig does not verify under any pinned attestation key (D7)".into());
            return eval;
        }
    };
    // the CLAIMED issuer_kid must be the ACTUAL signer (else a reader's surfaced issuer is a lie).
    let signer_kid = cnf_kid(signer);
    if eval.issuer_kid.as_deref() != Some(signer_kid.as_str()) {
        issues.push("deployment_attestation: issuer_kid does not match the signing key (D7)".into());
        eval.issuer_kid = Some(signer_kid); // surface the truth, not the claim
        return eval;
    }

    // 2. freshness / window coverage: the LATEST anchored checkpoint's TSA timestamp must fall within
    // [issued_at, not_after] (offline has no wall clock; the anchored time is the trusted reference).
    let latest = match anchored_cp_ids.iter().max_by_key(|(seq, _, _, _)| *seq) {
        Some(a) => a,
        None => {
            issues.push("deployment_attestation present but no verified+anchored checkpoint to bind/date it (D7)".into());
            return eval;
        }
    };
    // the attestation must cover the bundle's TRUE frontier (Codex): if a checkpoint exists BEYOND the latest
    // anchored one the subject binds, the bundle has moved on (records/head the attestation never covered) —
    // an old anchored attestation replayed onto a later, unanchored-tail bundle. attested_claims requires the
    // latest anchored checkpoint to BE the latest checkpoint overall.
    if latest.0 != latest_cp_seq {
        issues.push("deployment_attestation: a checkpoint exists beyond the latest anchored one the subject binds — does not cover the bundle frontier (D7)".into());
        return eval;
    }
    let ts = &latest.2;
    // a MISSING/empty bound is not "no bound" — an empty issued_at would make `"" <= ts` always true and
    // silently drop the LOWER freshness bound (open-ended backdating). Require both bounds present...
    if issued_at.is_empty() || not_after.is_empty() {
        issues.push("deployment_attestation: missing/empty issued_at or not_after — no bounded freshness window (D7)".into());
        return eval;
    }
    // ...and CANONICAL (Codex): a malformed non-empty bound like "0".."z" sorts around a real timestamp and
    // would pass the lexicographic window check, so require the exact YYYY-MM-DDTHH:MM:SS.mmmZ shape and a
    // non-inverted window before comparing.
    if !is_canonical_ts(&issued_at) || !is_canonical_ts(&not_after) || issued_at.as_str() > not_after.as_str() {
        issues.push("deployment_attestation: issued_at/not_after are not canonical timestamps, or issued_at > not_after — malformed window (D7)".into());
        return eval;
    }
    if !(issued_at.as_str() <= ts.as_str() && ts.as_str() <= not_after.as_str()) {
        issues.push("deployment_attestation: anchored checkpoint time is outside the attestation window — stale/not-covering (D7)".into());
        return eval;
    }

    // 3. subject match: every bound field must equal the bundle under review (substitution/replay guard).
    let sub = match att.get("subject").and_then(|s| s.as_object()) {
        Some(_) => att.get("subject").unwrap(),
        None => {
            issues.push("deployment_attestation: missing/!object subject (D7)".into());
            return eval;
        }
    };
    let arr = |o: &CanonValue, k: &str| -> BTreeSet<String> {
        o.get(k)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    let manifest_digest = bundle
        .get("coverage_manifest")
        .filter(|m| !m.is_null())
        .map(|m| crate::hashx::sha256_prefixed(m.serialize().as_bytes()))
        .unwrap_or_default();
    let head_root = latest.3.clone().unwrap_or_else(|| grant_head_root(&[]));
    // `authority_kids` binds the deployment's GRANT/USE authorities — the broker and resource roles ONLY.
    // taxonomy_keys is deliberately NOT folded in: the operation taxonomy is a separate verifier-pinned
    // artifact (validated independently via `taxonomy_status`), not a runtime authority over this
    // deployment's grants/uses, and the attestation producer (broker/server) holds no taxonomy key — it
    // cannot bind a kid it never sees. Folding it would force every auditor who pins a taxonomy issuer
    // (the normal D4/D8 posture) into a spurious authority_kids mismatch -> attestation_status:"failed".
    let mut kids: BTreeSet<String> = BTreeSet::new();
    for vk in opts.broker_authority_keys.iter().chain(opts.resource_authority_keys.iter()) {
        kids.insert(cnf_kid(vk));
    }
    let mut mism: Vec<&str> = Vec::new();
    // project_id MUST be a non-empty binding: an empty bundle project_id matching an empty subject field
    // would turn this substitution guard into a no-op, so an absent/empty project_id is always a mismatch.
    let bundle_project = project_id.unwrap_or_default();
    if bundle_project.is_empty() || s_str(sub, "project_id") != bundle_project { mism.push("project_id"); }
    if s_str(sub, "coverage_manifest_digest") != manifest_digest { mism.push("coverage_manifest_digest"); }
    if s_str(sub, "checkpoint_hash") != latest.1 { mism.push("checkpoint_hash"); }
    if s_str(sub, "broker_grant_head_root") != head_root { mism.push("broker_grant_head_root"); }
    if arr(sub, "authority_kids") != kids { mism.push("authority_kids"); }
    if &arr(sub, "resource_ids") != resource_ids { mism.push("resource_ids"); }
    if !mism.is_empty() {
        issues.push(format!("deployment_attestation: subject does not match the bundle under review — substitution/replay (D7): {}", mism.join(", ")));
        return eval;
    }

    eval.status = "attested_claims".to_string();
    eval
}

pub fn verify_bundle_with(bundle: &CanonValue, opts: &VerifyOptions) -> VerifyReport {
    let mut issues: Vec<String> = Vec::new();
    let project_id = s(bundle, "project_id");

    // R2 (ADR 0003) + D4 (ADR 0004): the broker, resource, and operation-taxonomy authority key sets
    // MUST be PAIRWISE disjoint. A key shared across two roles could sign across the role boundary —
    // e.g. a broker/resource key in `taxonomy_keys` could self-validate a D4 taxonomy to fabricate
    // `taxonomy_status:"validated"`, or a key in both broker+resource could sign either a grant or a
    // use. This is a FATAL configuration error — abort before evaluating any record (VerifyingKey
    // equality is raw-bytes, which also settles the derived key id). Never proceed on an ambiguous
    // key universe.
    let role_sets: [(&str, &[VerifyingKey]); 6] = [
        ("broker_authority_keys", &opts.broker_authority_keys),
        ("resource_authority_keys", &opts.resource_authority_keys),
        ("taxonomy_keys", &opts.taxonomy_keys),
        // D7: the attestation authority must be role-separated too — else a broker/resource could sign a
        // deployment_attestation that vouches for its own runtime (self-attestation).
        ("attestation_keys", &opts.attestation_keys),
        // The TSA mints the freshness timestamp D7 anchors the attestation window to; a key that is BOTH
        // the TSA and an authority (broker/resource/taxonomy/attestation) could self-mint a timestamp inside
        // its own window, so the time authority must be disjoint from every signing role too.
        ("trusted_tsa_keys", &opts.trusted_tsa_keys),
        // M6 (ADR 0005): a cosignature approver must be disjoint from the broker it governs and from every
        // other role — else an approver who is also the broker/resource/taxonomy/attestation/TSA signer
        // could self-approve a grant (dual control collapses to single control).
        ("cosig_approver_keys", &opts.cosig_approver_keys),
    ];
    for i in 0..role_sets.len() {
        for j in (i + 1)..role_sets.len() {
            if role_sets[i].1.iter().any(|k| role_sets[j].1.contains(k)) {
                return fatal_config_report(
                    project_id,
                    &format!(
                        "{} and {} must be disjoint (a key in both breaks role separation) — fatal configuration error",
                        role_sets[i].0, role_sets[j].0
                    ),
                );
            }
        }
    }
    // T7 (Codex): `authority_keys` (the keys that elevate a GENERIC BrokerRole::None record's
    // policy_engine_signed/human_signed/gateway_enforced authority to `verified`) MAY equal
    // `broker_authority_keys` — the self-host model where the broker IS the policy authority for its own
    // gateway_enforced records (Go pins authority_keys=broker_keys). But it MUST be disjoint from the
    // RESOURCE/taxonomy/attestation/TSA roles: a key in any of those that also elevates generic authority is
    // role confusion (e.g. a resource key signing a generic record's evidence_sig would read as `verified`).
    for (name, set) in [
        ("resource_authority_keys", &opts.resource_authority_keys),
        ("taxonomy_keys", &opts.taxonomy_keys),
        ("attestation_keys", &opts.attestation_keys),
        ("trusted_tsa_keys", &opts.trusted_tsa_keys),
        // M6: an approver key must not also elevate a generic record's authority to `verified`.
        ("cosig_approver_keys", &opts.cosig_approver_keys),
    ] {
        if opts.trusted_authority_keys.iter().any(|k| set.contains(k)) {
            return fatal_config_report(
                project_id,
                &format!("authority_keys and {name} must be disjoint (a non-broker role key must not also elevate generic authority) — fatal configuration error"),
            );
        }
    }

    let keys_externally_pinned = opts.trusted_keys.is_some();

    // D4 (ADR 0004 / MF5): a pinned signed operation taxonomy. `taxonomy_info` is `Some` iff the
    // signature verifies under a pinned key AND the pinned digest/version match; the effective window is
    // enforced PER-USE below (a stale taxonomy can't back-date an action). The `stale` vs `validated`
    // distinction is finalized after the use loop (a window rejection of a listed action → stale).
    let taxonomy_info = opts.taxonomy.as_ref().and_then(|t| {
        validate_taxonomy(
            t,
            &opts.taxonomy_keys,
            opts.taxonomy_digest.as_deref(),
            opts.taxonomy_version,
        )
    });
    let mut taxonomy_window_failed = false;

    let empty: Vec<CanonValue> = Vec::new();
    let key_entries = arr(bundle, "keys", &empty, &mut issues);
    let records = arr(bundle, "records", &empty, &mut issues);
    let checkpoints = arr(bundle, "checkpoints", &empty, &mut issues);
    if bundle.as_object().is_none() {
        issues.push("bundle is not a JSON object".into());
    }
    if bundle.get("records").is_none() {
        issues.push("bundle has no records".into());
    }

    // ---- 1. key store ----
    let mut keys: BTreeMap<(String, i64), KeyEntry> = BTreeMap::new();
    for e in key_entries {
        match (
            s(e, "signing_key_id"),
            e.get("key_epoch").and_then(|v| v.as_int()),
            s(e, "public_key"),
        ) {
            (Some(id), Some(epoch), Some(pk)) => match decode_pubkey(&pk) {
                Ok(vk) => {
                    keys.insert(
                        (id, epoch),
                        KeyEntry {
                            vk,
                            status: s(e, "key_status").unwrap_or_else(|| "active".into()),
                            status_changed_at: s(e, "status_changed_at"),
                        },
                    );
                }
                Err(err) => issues.push(format!("key {id}/{epoch} bad public_key: {err}")),
            },
            _ => issues.push("key entry missing signing_key_id/key_epoch/public_key".into()),
        }
    }
    let pinned_for = |vk: &VerifyingKey| -> Option<&TrustedKey> {
        opts.trusted_keys
            .as_ref()
            .and_then(|set| set.iter().find(|t| &t.vk == vk))
    };
    let is_trusted = |vk: &VerifyingKey| match &opts.trusted_keys {
        Some(_) => pinned_for(vk).is_some(),
        None => true,
    };

    // ---- 2. per-record pass 1 (provisional) ----
    let mut pending: Vec<Pending> = Vec::with_capacity(records.len());
    for (i, rec) in records.iter().enumerate() {
        let mut notes = Vec::new();
        let project_ok = match &project_id {
            Some(pid) => {
                let m = s(rec, "project_id").as_deref() == Some(pid.as_str());
                if !m {
                    notes.push("project_id does not match bundle".into());
                }
                m
            }
            None => true,
        };
        let rec_key_status = rec
            .get("key")
            .and_then(|k| s(k, "key_status"))
            .unwrap_or_else(|| "unknown".into());
        let key_id = rec.get("key").and_then(|k| s(k, "signing_key_id"));
        let key_epoch = rec
            .get("key")
            .and_then(|k| k.get("key_epoch"))
            .and_then(|v| v.as_int());
        let resolved = match (key_id, key_epoch) {
            (Some(id), Some(ep)) => keys.get(&(id, ep)),
            _ => {
                notes.push("record key block missing signing_key_id/key_epoch".into());
                None
            }
        };

        let integrity_ok = validate_record_shape(rec)
            .and_then(|()| verify_content_hash(rec))
            .is_ok();

        let (signature_ok, eff_status, pinned, status_changed_at) = match resolved {
            Some(entry) => {
                let sig_ok = integrity_ok && verify_sealed(rec, &entry.vk).is_ok();
                if !sig_ok {
                    if let Err(e) = verify_sealed(rec, &entry.vk) {
                        notes.push(format!("verify failed: {e}"));
                    }
                }
                let pin = pinned_for(&entry.vk);
                // worst of record-asserted, bundle-asserted, and (if pinned) the authoritative
                // pinned status — fail-safe in all directions.
                let mut eff = worst_status(&rec_key_status, &entry.status);
                if let Some(ps) = pin.and_then(|t| t.status.as_deref()) {
                    eff = worst_status(&eff, ps);
                }
                // Compromise time used for the anchored-before upgrade: under pinning ONLY the
                // auditor-supplied (authoritative) time is trusted; the bundle's self-asserted
                // time is ignored so an attacker cannot future-date a compromise to upgrade. Without
                // pinning (evidence-for-yourself), the bundle's self-asserted time is best-effort.
                let changed_at = if keys_externally_pinned {
                    pin.and_then(|t| t.status_changed_at.clone())
                } else {
                    entry.status_changed_at.clone()
                };
                (sig_ok, eff, is_trusted(&entry.vk), changed_at)
            }
            None => {
                notes.push("no public key available — signature unverifiable".into());
                (false, worst_status(&rec_key_status, "unknown"), false, None)
            }
        };
        if keys_externally_pinned && !pinned && signature_ok {
            notes.push("signed by a key that is NOT externally pinned".into());
        }

        // R2 (ADR 0003): verify the authority evidence under the record's ROLE-specific key set — a
        // broker-role record (grant) only elevates under broker keys, a resource-role record (use)
        // only under resource keys, and any other record under the generic authority keys. This makes
        // role confusion (a resource key signing a grant, or vice versa) fail to elevate.
        let (broker_role, claims_role) = classify_role(rec);
        let auth_keys: &[VerifyingKey] = match broker_role {
            BrokerRole::Broker => &opts.broker_authority_keys,
            BrokerRole::Resource => &opts.resource_authority_keys,
            BrokerRole::None => &opts.trusted_authority_keys,
        };
        let authority = verify_authority(rec, auth_keys);
        if authority == AuthorityTrust::Failed {
            notes.push(format!(
                "authority claims a verified source but its evidence_sig did not verify under a trusted {} authority key",
                broker_role.as_str()
            ));
        }
        // R2 rule 4: a record that CLAIMS a Tier-B role (carries extensions.broker.kind) but does not
        // classify to a recognized (kind, enforcement_point) role is a fail-closed verification
        // failure — surfaced as an issue, never a silent drop that could let a mislabeled use escape.
        if claims_role && broker_role == BrokerRole::None {
            let msg = format!(
                "record {i}: extensions.broker.kind set but (kind, enforcement_point) is not a recognized broker/resource role (R2 fail-closed)"
            );
            notes.push(msg.clone());
            issues.push(msg);
        }

        pending.push(Pending {
            index: i,
            record_id: s(rec, "record_id").unwrap_or_default(),
            content_hash: s(rec, "content_hash").unwrap_or_default(),
            observed_via: s(rec, "observed_via").unwrap_or_else(|| "unknown".into()),
            integrity_ok,
            signature_ok,
            pinned,
            project_ok,
            eff_status,
            status_changed_at,
            authority,
            broker_role,
            notes,
        });
    }

    // record_ids must be unique (two distinct records may not share a record_id). This keeps
    // `record_id` a sound binding handle for authority evidence (a verified evidence triple bound to
    // a record_id cannot be copied onto a different record without colliding here).
    {
        let mut by_id: BTreeMap<String, String> = BTreeMap::new();
        for rec in records.iter() {
            if let (Some(id), Some(ch)) = (s(rec, "record_id"), s(rec, "content_hash")) {
                if let Some(prev) = by_id.insert(id.clone(), ch.clone()) {
                    if prev != ch {
                        issues.push(format!("duplicate record_id '{id}' on distinct records"));
                    }
                }
            }
        }
    }

    // selective-disclosure entries (optional): bind revealed (value, nonce) to record commitments.
    let (disclosures_total, disclosures_verified, cred_descriptors) =
        verify_disclosures(bundle, records, &mut issues);

    // ---- 3. DAG ----
    let (dag_ok, dag_heads, collapsed_duplicates, dag_opt) = match dag::build(records) {
        Ok(d) => (true, d.heads.len(), d.collapsed_duplicates, Some(d)),
        Err(e) => {
            issues.push(format!("DAG invalid: {e}"));
            (false, 0, 0, None)
        }
    };

    // ---- 4. checkpoints + anchors ----
    let mut checkpoints_verified = 0usize;
    let mut checkpoints_anchored = 0usize;
    // (seq, anchored_ts, frontier) for each checkpoint with a verified anchor
    let mut anchored: Vec<(i64, String, Vec<String>)> = Vec::new();
    // D7: (seq, checkpoint_hash, anchored_ts, head cumulative_root) of each verified+anchored checkpoint,
    // so the deployment-attestation subject can bind the LATEST anchored checkpoint identity + its head.
    let mut anchored_cp_ids: Vec<(i64, String, String, Option<String>)> = Vec::new();
    // D6: (seq, anchored_and_verified, head, frontier) for each VERIFIED checkpoint carrying a head;
    // `verified_headless` holds the frontiers of verified checkpoints that carry NO well-formed head.
    let mut cp_heads: Vec<(i64, bool, GrantHead, Vec<String>)> = Vec::new();
    let mut verified_headless: Vec<Vec<String>> = Vec::new();
    // A broker_grant_head FIELD present on a VERIFIED checkpoint but unparseable is a tampered/garbled D6
    // head — pre-D6 checkpoints never carry the field, so it is a D6 activation signal (and a violation),
    // distinct from a checkpoint with no head field at all. Tracked so D6 cannot be dodged by garbling it.
    let mut verified_malformed_head = false;
    for (i, cp) in checkpoints.iter().enumerate() {
        if let Some(pid) = &project_id {
            if s(cp, "project_id").as_deref() != Some(pid.as_str()) {
                issues.push(format!("checkpoint {i} project_id does not match bundle"));
            }
        }
        let cp_seq = cp
            .get("checkpoint_seq")
            .and_then(|v| v.as_int())
            .unwrap_or(0);
        let cp_frontier: Vec<String> = cp
            .get("frontier")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|h| h.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let head_field_present = cp.get("broker_grant_head").is_some();
        let cp_head = parse_grant_head(cp);
        let mut this_anchored = false;
        let vk = cp
            .get("key")
            .and_then(|k| s(k, "signing_key_id"))
            .zip(
                cp.get("key")
                    .and_then(|k| k.get("key_epoch"))
                    .and_then(|v| v.as_int()),
            )
            .and_then(|(id, ep)| keys.get(&(id, ep)))
            .filter(|e| !keys_externally_pinned || is_trusted(&e.vk))
            .map(|e| e.vk);
        let cp_verified = match vk {
            Some(vk) => match verify_checkpoint_sealed(cp, &vk) {
                Ok(()) => {
                    checkpoints_verified += 1;
                    true
                }
                Err(e) => {
                    issues.push(format!("checkpoint {i} invalid: {e}"));
                    false
                }
            },
            None => {
                issues.push(format!("checkpoint {i}: no trusted public key to verify"));
                false
            }
        };
        if let Some(anchor) = cp.get("anchor") {
            checkpoints_anchored += 1;
            let any_tsa_trust =
                !opts.trusted_tsa_keys.is_empty() || !opts.trusted_tsa_spki.is_empty();
            // Only an anchor on a *verified* checkpoint can contribute to trust — otherwise an
            // attacker pairs an unsigned checkpoint (arbitrary frontier) with a valid TSA token.
            if cp_verified && any_tsa_trust {
                let anchor_trust = crate::anchor::AnchorTrust {
                    test_anchor_keys: opts.trusted_tsa_keys.clone(),
                    rfc3161_tsa_spki: opts.trusted_tsa_spki.clone(),
                };
                let cph = s(cp, "checkpoint_hash").unwrap_or_default();
                match verify_anchor(&cph, anchor, &anchor_trust) {
                    Ok(ts) => {
                        this_anchored = true;
                        anchored_cp_ids.push((cp_seq, cph.clone(), ts.clone(), cp_head.as_ref().map(|h| h.cumulative_root.clone())));
                        anchored.push((cp_seq, ts, cp_frontier.clone()));
                    }
                    Err(e) => issues.push(format!("checkpoint {i} anchor invalid: {e}")),
                }
            }
        }
        // Only a VERIFIED checkpoint's head + frontier are cryptographically bound — never seed D6 trust
        // from an unsigned checkpoint whose head/frontier an attacker could choose. A verified checkpoint
        // that carries NO (or a malformed → None) head is tracked separately so D6 can flag it if its
        // frontier commits grants (a checkpoint that binds grants without a head omits them from the log).
        if cp_verified {
            match cp_head {
                Some(head) => cp_heads.push((cp_seq, this_anchored, head, cp_frontier)),
                None => {
                    // present-but-malformed head ⇒ tampered D6 head: a D6 signal + violation (handled in
                    // compute_broker_trust); absent field ⇒ genuinely headless (pre-D6 / no D6 head).
                    if head_field_present {
                        verified_malformed_head = true;
                    }
                    verified_headless.push(cp_frontier);
                }
            }
        }
    }
    // The latest checkpoint by seq (authoritative — validate_chain pins its frontier to the full DAG head
    // set, so D6 trust MUST be bound to its head, never inherited from an earlier subset-frontier head).
    let latest_cp_seq = checkpoints
        .iter()
        .filter_map(|cp| cp.get("checkpoint_seq").and_then(|v| v.as_int()))
        .max()
        .unwrap_or(-1);
    if !records.is_empty() && checkpoints.is_empty() {
        issues.push("no checkpoints: a non-empty run must be checkpoint-committed".into());
    }

    // anchored times must be non-decreasing with seq (RCP §10.1 step 5 — backdating #3).
    // NOTE: this compares only checkpoints that carry a *verified* anchor. Partial anchoring does
    // not enable a meaningful backdate: the latest anchored checkpoint cryptographically bounds the
    // existence time of all its causal ancestors, and `agent_ts` is untrusted regardless. Anchoring
    // every checkpoint is the exporter's responsibility, not a verifier PASS invariant.
    let mut sorted_anchored = anchored.clone();
    sorted_anchored.sort_by_key(|(seq, _, _)| *seq);
    // A non-canonical anchored_ts breaks the assumption that lexical order == chronological order (RFC3339
    // fixed-ms UTC sorts lexically iff canonical), so reject it rather than silently mis-ordering — matching
    // how the rest of the file gates string-time comparisons on is_canonical_ts (e.g. the attestation window).
    for (seq, ts, _) in &sorted_anchored {
        if !is_canonical_ts(ts) {
            issues.push(format!(
                "checkpoint {seq}: anchor time {ts:?} is not a canonical RCP timestamp — the backdating ordering check requires canonical times (threat #3)"
            ));
        }
    }
    for w in sorted_anchored.windows(2) {
        if is_canonical_ts(&w[0].1) && is_canonical_ts(&w[1].1) && w[1].1 < w[0].1 {
            issues.push(format!(
                "anchor time decreased across checkpoints {} -> {} (backdating, threat #3)",
                w[0].0, w[1].0
            ));
        }
    }

    let mut chain_ok = true;
    match &dag_opt {
        Some(d) if !checkpoints.is_empty() => {
            if let Err(e) = validate_chain(checkpoints, d) {
                chain_ok = false;
                issues.push(format!("checkpoint chain: {e}"));
            }
        }
        None if !checkpoints.is_empty() => chain_ok = false,
        _ => {}
    }

    // ---- 5. finalize per-record trust (pass 2) ----
    // Precompute the committed set ONCE per anchored checkpoint (not per record×checkpoint) to
    // avoid quadratic blowup on large bundles.
    let anchored_committed: Vec<(String, BTreeSet<String>)> = match dag_opt.as_ref() {
        Some(d) => anchored
            .iter()
            .map(|(_, ts, frontier)| (ts.clone(), committed_set(records, &d.by_hash, frontier)))
            .collect(),
        None => Vec::new(),
    };
    let anchored_before = |content_hash: &str, changed_at: &str| -> bool {
        // Lexical `<=` is only valid between two canonical fixed-precision UTC timestamps; a
        // malformed `changed_at` (or anchor time) must NOT silently skew the ordering — fail closed.
        if !is_canonical_ts(changed_at) {
            return false;
        }
        anchored_committed.iter().any(|(ts, committed)| {
            is_canonical_ts(ts) && ts.as_str() <= changed_at && committed.contains(content_hash)
        })
    };

    let mut record_trust = Vec::with_capacity(pending.len());
    let mut records_proven = 0usize;
    for mut p in pending {
        let base_ok = p.integrity_ok && p.signature_ok && p.project_ok && p.pinned;
        let trust = if !base_ok {
            TrustLevel::Untrusted
        } else if matches!(p.eff_status.as_str(), "active" | "retired") {
            TrustLevel::IntegrityProven
        } else if matches!(p.eff_status.as_str(), "revoked" | "compromised") {
            match &p.status_changed_at {
                Some(changed) if anchored_before(&p.content_hash, changed) => {
                    p.notes.push(format!(
                        "key {}: record anchored before status change — trustworthy",
                        p.eff_status
                    ));
                    TrustLevel::IntegrityProven
                }
                _ => {
                    p.notes.push(format!(
                        "key {}: NOT anchored before status change — untrusted (threat #9)",
                        p.eff_status
                    ));
                    TrustLevel::Untrusted
                }
            }
        } else {
            TrustLevel::Untrusted
        };

        if trust == TrustLevel::IntegrityProven {
            records_proven += 1;
        } else {
            issues.push(format!(
                "record {} ({}) untrusted: {}",
                p.index,
                p.record_id,
                p.notes.last().cloned().unwrap_or_default()
            ));
        }

        record_trust.push(RecordTrust {
            index: p.index,
            record_id: p.record_id,
            content_hash: p.content_hash,
            integrity_ok: p.integrity_ok,
            signature_ok: p.signature_ok,
            key_status: p.eff_status,
            observed_via: p.observed_via,
            trust,
            authority: p.authority,
            broker_role: p.broker_role.as_str().to_string(),
            notes: p.notes,
        });
    }

    // Level 3 Tier-A: count credential-broker grants and how many are fully accountable. A grant only
    // counts as VERIFIED when ALL of: the record is integrity-proven (its own seal is valid —
    // event_type and action are part of the signed body); it classifies to the BROKER role and its
    // authority verified under a pinned BROKER key (ADR 0003 R2 — a resource key, or the generic
    // authority set, can NOT elevate a grant); AND its signed authority.evidence_hash re-derives from
    // the embedded extensions.broker.grant_evidence (R1) — so the hash actually commits to the
    // canonical match fields, not an opaque value. A credential_grant that does NOT classify as broker
    // is a fail-closed verification failure (surfaced, never silently uncounted). Grants are deduped by
    // content_hash so a verbatim-replayed grant isn't double-counted.
    let mut grant_total = 0usize;
    let mut grant_verified = 0usize;
    let mut denied_grants = 0usize;
    let mut seen_grants: BTreeSet<&str> = BTreeSet::new();
    let mut seen_denials: BTreeSet<&str> = BTreeSet::new();
    // F8 (always-on, anchoring-independent): grant_id -> content_hash over the VERIFIED broker grants, so a
    // second distinct content_hash under one grant_id (broker equivocation) is flagged whether or not the
    // grant is anchored/closed. Tracked in THIS (un-gated) counting pass, not the closed-gated accounting
    // loop below — an earlier version gated it on `closed`, so a verified-but-UNANCHORED equivocation slipped
    // through as ok:true / grant_verified=2.
    let mut grant_content_seen: BTreeMap<String, String> = BTreeMap::new();
    let mut grant_equivocations: BTreeSet<String> = BTreeSet::new();
    for rt in &record_trust {
        let rec = &records[rt.index];
        if s(rec, "event_type").as_deref() == Some("credential_grant")
            && seen_grants.insert(rt.content_hash.as_str())
        {
            grant_total += 1;
            // R2: a credential_grant MUST carry the broker role discriminator (kind=grant +
            // enforcement_point=credential_broker). A grant that doesn't is mislabeled/misrouted — its
            // authority was checked under the wrong (or no) role key set; fail closed.
            if rt.broker_role != BrokerRole::Broker.as_str() {
                issues.push(format!(
                    "grant {} ({}): credential_grant does not classify to the broker role (kind/enforcement_point) — R2 fail-closed",
                    rt.index, rt.record_id
                ));
                continue;
            }
            // MUST-FIX 1 divergence guard: `kind` is duplicated at extensions.broker.kind (the role
            // discriminator that made this a broker record) and inside the canonical grant_evidence. If
            // the embedded payload's kind disagrees, fail closed — the signed evidence and the role
            // label disagree on what this record is. (An absent grant_evidence is caught by the
            // re-derivation check below; this only fires on a present-but-divergent kind.)
            let ge_kind = rec
                .get("extensions")
                .and_then(|e| e.get("broker"))
                .and_then(|b| b.get("grant_evidence"))
                .and_then(|g| g.get("kind"))
                .and_then(|v| v.as_str());
            if matches!(ge_kind, Some(k) if k != "grant") {
                issues.push(format!(
                    "grant {} ({}): grant_evidence.kind diverges from the extensions.broker.kind role discriminator (MUST-FIX 1 fail-closed)",
                    rt.index, rt.record_id
                ));
                continue;
            }
            if rt.trust == TrustLevel::IntegrityProven && rt.authority == AuthorityTrust::Verified {
                if evidence_rederivable(rec, "grant_evidence") {
                    grant_verified += 1;
                    // F8: a second DISTINCT content_hash under one grant_id is equivocation (flag once per
                    // grant_id). `seen_grants` above already collapsed byte-identical duplicates, so this
                    // fires only on a true distinct-content collision; honest producers emit unique grant_ids.
                    if let Some(gid) = ev_str(rec, "grant_evidence", "grant_id") {
                        match grant_content_seen.get(&gid) {
                            Some(prev) if prev != &rt.content_hash => {
                                if grant_equivocations.insert(gid.clone()) {
                                    issues.push(format!(
                                        "grant_id {gid}: two distinct grant records ({prev}, {}) share one grant_id — equivocated credential identity",
                                        rt.content_hash
                                    ));
                                }
                            }
                            None => {
                                grant_content_seen.insert(gid, rt.content_hash.clone());
                            }
                            _ => {}
                        }
                    }
                } else {
                    issues.push(format!(
                        "grant {} ({}): authority.evidence_hash is not re-derivable from extensions.broker.grant_evidence (payload absent or divergent — R1, threat #4)",
                        rt.index, rt.record_id
                    ));
                }
            }
        }
        // B11 denied-grant log: count sealed grant_denied records (deduped by content_hash). A denial is a
        // generic BrokerRole::None record (no broker role discriminator, no broker_seq, no grant_evidence),
        // so it is never grant-counted nor a D6 sequence member — surfaced here purely as evidence that a
        // forbidden/invalid request was refused and RECORDED rather than silently dropped (threat B11).
        if s(rec, "event_type").as_deref() == Some("credential_grant_denied")
            && seen_denials.insert(rt.content_hash.as_str())
        {
            denied_grants += 1;
        }
    }

    // ---- Tier-B (ADR 0003 step 5): use↔grant join over the CLOSED set (R3) ----
    // CLOSED = a record's content_hash is transitively committed by a verified, ANCHORED checkpoint
    // (the union of the anchored committed sets). Tier-B outcomes are computed over closed records
    // only; a use not yet closed is `unmatched_pending` (in-flight), never a violation. Replacing an
    // exporter watermark with this cryptographic boundary closes the watermark-specific suppression
    // path (MUST-FIX 2); never-anchored use suppression remains an accepted residual.
    let closed: BTreeSet<&str> = anchored_committed
        .iter()
        .flat_map(|(_, set)| set.iter().map(String::as_str))
        .collect();

    // Index closed, fully-verified grants by grant_id, reading match fields ONLY from the proven
    // grant_evidence (R1). `used` tracks matched uses (single-use ≤1 per grant_id, and grants_unused).
    struct GrantInfo {
        action: String,
        resource_id: String,
        scope_class: String,
        credential_binding: String,
        issued_at: i64,
        used: usize,
        /// M1 (bounded_reuse): the declared cap N (0 for other scope classes). `used <= use_limit`.
        use_limit: i64,
        /// M1 (bounded_reuse): the `use_sequence_number`s already CONSUMED by accepted uses, for
        /// `(grant_id, usn)` replay dedup. A usn is inserted only when a use is fully accepted (mirrors
        /// `used`), so a use that fails PoP/outcome does not burn its sequence number.
        used_seqs: BTreeSet<i64>,
        /// M2 (delegation): the cnf_kid a USE must present, and the temporal window the use must fall in —
        /// the LEAF of a verified delegation chain (narrowed window `min(grant exp, hop exps)`), or the root
        /// cnf_kid / grant exp for an undelegated grant. The use predicate keys on these so a sub-agent's PoP
        /// matches a re-delegated grant. (For an undelegated grant these equal the root cnf_kid / grant exp.)
        effective_cnf_kid: String,
        effective_exp: i64,
    }
    let mut grants_by_id: BTreeMap<String, GrantInfo> = BTreeMap::new();
    // D4 (ADR 0004): grant_ids flagged mis-scoped at issuance (a single_operation grant for an action a
    // signed+pinned taxonomy marks ESCALATING). Rejected here, NOT only when exercised, so a dangerous
    // capability is visible even with no use receipt; a use against one is then skipped (single violation).
    let mut misscoped: BTreeSet<String> = BTreeSet::new();
    // M6 (ADR 0005): cosig (M-of-N grant approval) accounting. A grant declaring grant_evidence.cosig_threshold
    // >= 1 must carry >= M distinct valid approver cosignatures or it is NOT indexed (gated below). Counts are
    // deduped per grant_id via `cosig_seen` so an equivocating/duplicate record cannot inflate them.
    let mut cosigned_grants_total = 0usize;
    let mut cosigned_grants_satisfied = 0usize;
    let mut cosig_threshold_failures = 0usize;
    let mut cosig_seen: BTreeSet<String> = BTreeSet::new();
    // M2 (ADR 0005): delegation accounting. A grant whose grant_evidence.delegation_assertions[] is non-empty
    // must re-walk to a verified, monotone chain or it is NOT indexed (gated below). Deduped per grant_id.
    let mut delegation_chains_total = 0usize;
    let mut delegation_chains_verified = 0usize;
    let mut delegation_monotonicity_violations = 0usize;
    let mut delegation_seen: BTreeSet<String> = BTreeSet::new();
    for rt in &record_trust {
        let rec = &records[rt.index];
        let qualifies = rt.broker_role == BrokerRole::Broker.as_str()
            && rt.trust == TrustLevel::IntegrityProven
            && rt.authority == AuthorityTrust::Verified
            && evidence_rederivable(rec, "grant_evidence")
            && closed.contains(rt.content_hash.as_str());
        if !qualifies {
            continue;
        }
        match (
            ev_str(rec, "grant_evidence", "grant_id"),
            ev_str(rec, "grant_evidence", "action"),
            ev_str(rec, "grant_evidence", "resource_id"),
            ev_str(rec, "grant_evidence", "scope_class"),
            ev_str(rec, "grant_evidence", "cnf_kid"),
            ev_str(rec, "grant_evidence", "credential_binding"),
            ev_int(rec, "grant_evidence", "issued_at"),
            ev_int(rec, "grant_evidence", "exp"),
        ) {
            (Some(gid), Some(action), Some(resource_id), Some(scope_class), Some(cnf_kid), Some(credential_binding), Some(issued_at), Some(exp)) => {
                // M1 (bounded_reuse): the cap rides inside the signed grant_evidence (0/absent for other
                // classes). A bounded_reuse grant MUST declare a positive use_limit; an "unbounded bounded"
                // grant is fail-closed (NOT indexed), so a use against it reads as action-without-credential
                // rather than silently honoring an uncapped reuse.
                let use_limit = ev_int(rec, "grant_evidence", "use_limit").unwrap_or(0);
                if scope_class == "bounded_reuse" && use_limit < 1 {
                    issues.push(format!(
                        "grant {} ({}): bounded_reuse grant_evidence.use_limit must be >= 1 — fail-closed",
                        rt.index, rt.record_id
                    ));
                    continue;
                }
                // Mis-scope at issuance: a single_operation OR bounded_reuse grant (both fix one
                // (action, resource_id)) for a (resource, action) the taxonomy affirmatively marks
                // escalating is rejected here regardless of whether it is exercised. `misscoped.insert`
                // is the LAST condition so the issue is pushed exactly once per grant_id (a second closed
                // record reusing the same grant_id does not double-count).
                if (scope_class == "single_operation" || scope_class == "bounded_reuse")
                    && taxonomy_info
                        .as_ref()
                        .is_some_and(|ti| ti.escalating.contains(&(resource_id.clone(), action.clone())))
                    && misscoped.insert(gid.clone())
                {
                    issues.push(format!(
                        "grant {} ({}): claims {scope_class} for action '{action}' on '{resource_id}' which the taxonomy marks escalating — mis-scoped (D4)",
                        rt.index, rt.record_id
                    ));
                }
                // (F8 grant_id-injectivity equivocation detection now runs in the un-gated grant-counting
                // pass above, so it covers anchored AND unanchored grants — see the grant_content_seen block.)
                // M6 (ADR 0005): cosig gate. A grant declaring grant_evidence.cosig_threshold >= 1 must carry
                // >= M DISTINCT approver cosignatures verifying under the pinned cosig_approver_keys; otherwise
                // it is NOT Tier-B-eligible (not indexed → a use against it reads as unmatched_violation). The
                // counts are deduped per grant_id (cosig_seen), but the `continue` gate ALWAYS applies — so a
                // duplicate of an already-counted, cosig-failed grant is never silently indexed.
                let cosig_threshold = ev_int(rec, "grant_evidence", "cosig_threshold").unwrap_or(0);
                // A grant carrying cosignatures but NO positive cosig_threshold is a malformed/ambiguous cosig
                // declaration — fail-closed (NOT indexed) rather than silently demoted to an ordinary grant, so
                // a producer that emits approvals but forgets the threshold cannot quietly lose dual control.
                // Both fields live inside the SIGNED grant_evidence, so this fires on a producer mistake, never
                // on a stripped field (stripping breaks evidence_rederivable). Threshold absent AND no
                // cosignatures => an ordinary grant, unaffected (additive).
                if cosig_threshold < 1 && cosignatures_of(rec).is_some_and(|a| !a.is_empty()) {
                    issues.push(format!(
                        "grant {} ({}): carries cosignatures but no positive cosig_threshold — malformed cosig declaration (M6 fail-closed)",
                        rt.index, rt.record_id
                    ));
                    continue;
                }
                if cosig_threshold >= 1 {
                    let approvals = count_cosig_approvals(
                        rec,
                        &gid,
                        &credential_binding,
                        cosig_threshold,
                        exp,
                        &opts.cosig_approver_keys,
                    );
                    // Compare in i64, NOT `cosig_threshold as usize`: on the wasm32 verifier `usize == u32`,
                    // so a broker-signed `cosig_threshold` above 2^32 would truncate to a small value and let a
                    // SUB-threshold grant read as satisfied (a fail-open on the browser verifier; the 64-bit
                    // CLI/cgo build was unaffected). `approvals` is bounded by the cosignature count, so the
                    // widen is lossless on every target. (`cosig_threshold >= 1` is already guaranteed above.)
                    let satisfied = approvals as i64 >= cosig_threshold;
                    if cosig_seen.insert(gid.clone()) {
                        cosigned_grants_total += 1;
                        if satisfied {
                            cosigned_grants_satisfied += 1;
                        } else {
                            cosig_threshold_failures += 1;
                            issues.push(format!(
                                "grant {} ({}): cosig threshold not met — {approvals} of {cosig_threshold} required approver signatures verified under pinned cosig_approver_keys — not Tier-B-eligible (M6)",
                                rt.index, rt.record_id
                            ));
                        }
                    }
                    if !satisfied {
                        continue; // fail-closed: do not index a grant that did not meet its approval threshold
                    }
                }
                // M2 (ADR 0005): delegation. If the grant re-delegates (delegation_assertions[] present),
                // re-walk the signed chain from the root cnf_kid and bind the use to the LEAF cnf/narrowed
                // window; an invalid or non-monotone chain is fail-closed (not indexed → its use reads as
                // unmatched_violation). An undelegated grant keeps the root cnf_kid + exp (additive). Counts
                // are deduped per grant_id (delegation_seen); the `continue` gate always applies.
                let grant_scope = ev_str(rec, "grant_evidence", "scope").unwrap_or_default();
                let (effective_cnf_kid, effective_exp) = match verify_delegation_chain(
                    rec, &gid, &cnf_kid, &grant_scope, &action, &resource_id, exp,
                ) {
                    ChainResult::Absent => (cnf_kid.clone(), exp),
                    ChainResult::Verified { eff_cnf_kid, eff_exp } => {
                        if delegation_seen.insert(gid.clone()) {
                            delegation_chains_total += 1;
                            delegation_chains_verified += 1;
                        }
                        (eff_cnf_kid, eff_exp)
                    }
                    ChainResult::Monotonicity => {
                        if delegation_seen.insert(gid.clone()) {
                            delegation_chains_total += 1;
                            delegation_monotonicity_violations += 1;
                            issues.push(format!(
                                "grant {} ({}): delegation chain widens scope/action/resource beyond the grant — monotonicity violation (M2)",
                                rt.index, rt.record_id
                            ));
                        }
                        continue; // fail-closed: not Tier-B-eligible
                    }
                    ChainResult::Invalid => {
                        if delegation_seen.insert(gid.clone()) {
                            delegation_chains_total += 1;
                            issues.push(format!(
                                "grant {} ({}): delegation chain failed signature/link/root re-verification — not Tier-B-eligible (M2)",
                                rt.index, rt.record_id
                            ));
                        }
                        continue; // fail-closed: not Tier-B-eligible
                    }
                };
                grants_by_id.entry(gid).or_insert(GrantInfo {
                    action,
                    resource_id,
                    scope_class,
                    credential_binding,
                    issued_at,
                    used: 0,
                    use_limit,
                    used_seqs: BTreeSet::new(),
                    effective_cnf_kid,
                    effective_exp,
                });
            }
            // A verified, closed broker grant whose grant_evidence is missing a required match field is
            // a fail-closed failure surfaced as an issue — NOT a silent skip (which would let a use
            // against it read as "action without a credential" and mask the real cause).
            _ => issues.push(format!(
                "grant {} ({}): closed broker grant has incomplete grant_evidence (missing a required match field) — fail-closed",
                rt.index, rt.record_id
            )),
        }
    }

    // D6.4 (ADR 0004 D6) — credential-descriptor cross-check, the SECOND broker_trust lever. D4's
    // action_verified trusts the broker's grant LABELS; when the credential descriptor is DISCLOSED (its
    // credential_commit opened + verified in verify_disclosures), cross-check it against the record's SIGNED
    // grant_evidence: sha256(descriptor) must equal credential_binding, and the descriptor's
    // act/aud/jti/cnf/exp/single_use must match action/resource_id/grant_id/cnf_kid/exp/
    // (scope_class=="single_operation"). A mismatch proves the broker MISLABELED the minted credential (a
    // broad capability dressed as a benign single-op) — a broker-equivocation violation. The labels AND the
    // credential_commit live in the SAME record, bound by its content signature (integrity_ok), so the
    // contradiction is detectable WITHOUT a pinned broker authority key (authority/grant_verified is a
    // separate trust axis); we gate only on an integrity-proven broker-role grant. An undisclosed descriptor
    // leaves the label↔credential gap a residual.
    let mut grant_labels: BTreeMap<&str, &CanonValue> = BTreeMap::new();
    for rt in &record_trust {
        if rt.broker_role == BrokerRole::Broker.as_str() && rt.trust == TrustLevel::IntegrityProven {
            grant_labels.entry(rt.record_id.as_str()).or_insert(&records[rt.index]);
        }
    }
    let mut cred_label_checks = 0usize;
    let mut cred_label_matched = 0usize;
    for (rid, descriptor_bytes) in &cred_descriptors {
        let rec = match grant_labels.get(rid.as_str()) {
            Some(r) => *r,
            None => continue, // disclosed for a record that is not an integrity-proven broker grant
        };
        cred_label_checks += 1;
        // (a) the disclosed descriptor must be THE credential the signed grant_evidence bound.
        if crate::hashx::sha256_prefixed(descriptor_bytes) != ev_str(rec, "grant_evidence", "credential_binding").unwrap_or_default() {
            issues.push(format!("grant {rid}: disclosed credential descriptor sha256 != grant_evidence.credential_binding — wrong or forged descriptor (D6.4)"));
            continue;
        }
        // (b) descriptor fields must agree with the signed grant labels.
        let descriptor = match core::str::from_utf8(descriptor_bytes).ok().and_then(|s| CanonValue::parse(s).ok()) {
            Some(d) => d,
            None => {
                issues.push(format!("grant {rid}: disclosed credential descriptor is not valid canonical JSON (D6.4)"));
                continue;
            }
        };
        let ds = |k: &str| descriptor.get(k).and_then(|v| v.as_str()).unwrap_or_default();
        let label = |f: &str| ev_str(rec, "grant_evidence", f).unwrap_or_default();
        let (act, aud, jti) = (ds("act"), ds("aud"), ds("jti"));
        let (action, resource, gid, kidl) = (label("action"), label("resource_id"), label("grant_id"), label("cnf_kid"));
        let single = label("scope_class") == "single_operation";
        let single_use = match descriptor.get("single_use") {
            Some(CanonValue::Bool(b)) => Some(*b),
            _ => None,
        };
        let cnf_kid_ok = crate::b64::decode_fixed::<32>(ds("cnf"))
            .ok()
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            .map(|vk| cnf_kid(&vk) == kidl)
            .unwrap_or(false);
        let mut mism: Vec<String> = Vec::new();
        if act != action.as_str() { mism.push(format!("act '{act}' != action '{action}'")); }
        if aud != resource.as_str() { mism.push(format!("aud '{aud}' != resource_id '{resource}'")); }
        if jti != gid.as_str() { mism.push(format!("jti '{jti}' != grant_id '{gid}'")); }
        if descriptor.get("exp").and_then(|v| v.as_int()) != ev_int(rec, "grant_evidence", "exp") { mism.push("exp != grant_evidence.exp".to_string()); }
        if single_use != Some(single) { mism.push(format!("single_use != (scope_class=='single_operation' => {single})")); }
        if !cnf_kid_ok { mism.push(format!("cnf does not derive cnf_kid '{kidl}'")); }
        // EVERY capability-shaping claim the producer mirrors into BOTH the descriptor and grant_evidence must
        // agree (Codex): scope (a broad scope minted but a narrow scope LABELED is exactly the mislabel D6.4
        // exists to catch), sub↔agent_id (a credential for a different subject), and iat/nbf↔issued_at (a
        // back/post-dated validity). Checking only act/aud/jti/cnf/exp/single_use left scope+subject+timing
        // unbound — a real false-clean.
        if ds("scope") != label("scope").as_str() { mism.push(format!("scope '{}' != grant_evidence.scope '{}'", ds("scope"), label("scope"))); }
        if ds("sub") != label("agent_id").as_str() { mism.push(format!("sub '{}' != grant_evidence.agent_id '{}'", ds("sub"), label("agent_id"))); }
        let iss_at = ev_int(rec, "grant_evidence", "issued_at");
        if descriptor.get("iat").and_then(|v| v.as_int()) != iss_at { mism.push("iat != grant_evidence.issued_at".to_string()); }
        if descriptor.get("nbf").and_then(|v| v.as_int()) != iss_at { mism.push("nbf != grant_evidence.issued_at".to_string()); }
        // M1 (ADR 0005): for a bounded_reuse grant the cap is mirrored into BOTH the descriptor (which the
        // resource shim enforces at runtime) and grant_evidence (which THIS verifier caps from). They must
        // agree — a credential minted for more uses than the grant labels is the same mislabel/equivocation
        // D6.4 catches for the other claims. RESIDUAL (broker TCB, like every D6.4 label↔credential check):
        // this descriptor↔evidence equality is only reachable when the descriptor is DISCLOSED. It is NOT a
        // fail-open, though: the evidence-plane cap is `grant_evidence.use_limit`, enforced fail-CLOSED
        // (a use beyond it is `bounded_reuse_overspent` → !ok), so the verifier never certifies CLEAN over
        // more uses than the signed grant_evidence authorizes — a descriptor minted with a larger cap can
        // only surface as overspend receipts, never as silent over-acceptance.
        if label("scope_class") == "bounded_reuse"
            && descriptor.get("use_limit").and_then(|v| v.as_int()) != ev_int(rec, "grant_evidence", "use_limit")
        {
            mism.push("use_limit (descriptor) != grant_evidence.use_limit".to_string());
        }
        if mism.is_empty() {
            cred_label_matched += 1;
        } else {
            issues.push(format!("grant {rid}: disclosed credential descriptor contradicts signed grant labels — broker mislabel/equivocation (D6.4): {}", mism.join("; ")));
        }
    }

    let mut uses_total = 0usize;
    let mut uses_matched = 0usize;
    let mut uses_action_unverified = 0usize;
    let mut uses_pop_reverified = 0usize;
    let mut unmatched_violation = 0usize;
    // M1 (bounded_reuse): per-class anomaly counters (also folded into unmatched_violation).
    let mut bounded_reuse_overspent = 0usize;
    let mut bounded_reuse_seq_replays = 0usize;
    let mut unmatched_pending = 0usize;
    let mut seen_uses: BTreeSet<&str> = BTreeSet::new();
    // D3 (ADR 0004): a (resource_id, PoP nonce) pair seen on two CLOSED receipts is a replay/duplicate
    // submission over the visible set — independent of the per-grant_id single-use rule.
    let mut seen_nonces: BTreeSet<(String, String)> = BTreeSet::new();
    let mut intent_without_outcome = 0usize;
    let mut one_phase_use_present = false; // D8/MF3: any matched one-phase `use` blocks the capstone
    let broker_kind = |rec: &CanonValue| -> Option<String> {
        rec.get("extensions").and_then(|e| e.get("broker")).and_then(|b| b.get("kind")).and_then(|v| v.as_str()).map(String::from)
    };
    // D5 pre-pass: a `use_outcome` (kind=use_outcome) COMPLETES a `use_intent`. The join key (intent_ref)
    // AND the grant_id are read from the SIGNED `use_outcome` PAYLOAD — bound by `authority.evidence_hash`
    // (re-derived here) + the resource `evidence_sig` — NOT the unsigned sibling `extensions.broker.intent_ref`
    // (which the resource's signature never covers). Without this, the record-signing key (a relay/exporter,
    // a DIFFERENT trust domain than the resource) could redirect a resource-signed outcome to complete a
    // different intent. A CLOSED outcome MUST be fully validatable (integrity + resource authority +
    // re-derivable payload) — else it is a Tier-B violation (parity with a one-phase use; a use_outcome must
    // not be a laundering path for an unauthorized resource record). An intent completes only when an outcome
    // references it AND attests THE SAME grant. The signed payload must ALSO assert kind="use_outcome" (the role discriminator that routed it
    // here is the UNSIGNED sibling, outside the resource signature — without this a relabeled signed payload
    // could complete an intent). Every validated outcome MUST be consumed by a matching intent; an
    // un-consumed (orphan) outcome is a completion with NO recorded pre-action intent — flagged below. Each
    // validated outcome is tracked as a DISTINCT record (intent_ref, grant_id, record_id, index) — NOT a
    // map keyed by intent_ref, which would let a second outcome for the same intent_ref overwrite the first
    // (hiding an extra unauthorized outcome, or dropping the legitimate one — order-dependent).
    let mut outcomes: Vec<(String, String, String, usize, String)> = Vec::new();
    for rt in &record_trust {
        let rec = &records[rt.index];
        if rt.broker_role != BrokerRole::Resource.as_str() || broker_kind(rec).as_deref() != Some("use_outcome") {
            continue;
        }
        if !closed.contains(rt.content_hash.as_str()) {
            continue; // in-flight outcome: not yet anchored, completes nothing
        }
        if rt.trust != TrustLevel::IntegrityProven
            || rt.authority != AuthorityTrust::Verified
            || !evidence_rederivable(rec, "use_outcome")
        {
            unmatched_violation += 1;
            issues.push(format!("use_outcome {} ({}): closed but not validatable (integrity / resource authority / re-derivable payload) — Tier-B violation", rt.index, rt.record_id));
            continue;
        }
        // The SIGNED payload also carries `intent_hash` (the intent's content_hash) — the RESOURCE attesting
        // it observed THAT specific intent before signing this outcome. This binds the before-act ordering to
        // the resource signature, NOT to the relay-controlled top-level causal_prev_hashes (which the
        // record-signing key, a different trust domain, could backfill).
        match (
            ev_str(rec, "use_outcome", "kind"),
            ev_str(rec, "use_outcome", "intent_ref"),
            ev_str(rec, "use_outcome", "grant_id"),
            ev_str(rec, "use_outcome", "intent_hash"),
        ) {
            (Some(k), Some(iref), Some(ogid), Some(ihash)) if k == "use_outcome" => {
                outcomes.push((iref, ogid, rt.record_id.clone(), rt.index, ihash));
            }
            _ => {
                unmatched_violation += 1;
                issues.push(format!("use_outcome {} ({}): signed payload missing kind=use_outcome / intent_ref / grant_id / intent_hash — violation", rt.index, rt.record_id));
            }
        }
    }
    // index outcomes by (intent_ref, grant_id) -> positions, so each intent pops at most one candidate
    // instead of scanning every outcome (O(intents·outcomes) — a verifier DoS on adversarial bundles).
    let mut outcomes_by: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (i, (iref, ogid, _, _, _)) in outcomes.iter().enumerate() {
        outcomes_by.entry((iref.clone(), ogid.clone())).or_default().push(i);
    }
    let mut consumed_outcomes: BTreeSet<String> = BTreeSet::new();
    for rt in &record_trust {
        let rec = &records[rt.index];
        if rt.broker_role != BrokerRole::Resource.as_str() {
            continue;
        }
        let bkind = broker_kind(rec).unwrap_or_default();
        if bkind == "use_outcome" {
            continue; // outcomes are joined to their intent in the pre-pass, not counted as standalone uses
        }
        if !seen_uses.insert(rt.content_hash.as_str()) {
            continue; // verbatim-duplicate use deduped (not double-counted)
        }
        uses_total += 1;
        if !closed.contains(rt.content_hash.as_str()) {
            unmatched_pending += 1; // in-flight: not yet committed by a verified anchored checkpoint
            continue;
        }
        // A CLOSED use must be cryptographically validatable (integrity + resource-role authority +
        // re-derivable use_evidence) before its match fields can be trusted — otherwise fail closed.
        let violation = |issues: &mut Vec<String>, msg: String| {
            issues.push(format!("use {} ({}): {msg}", rt.index, rt.record_id));
        };
        if rt.trust != TrustLevel::IntegrityProven
            || rt.authority != AuthorityTrust::Verified
            || !evidence_rederivable(rec, "use_evidence")
        {
            unmatched_violation += 1;
            violation(&mut issues, "closed but not validatable (integrity / resource authority / re-derivable evidence) — Tier-B violation".into());
            continue;
        }
        // MUST-FIX 1: read match inputs ONLY from use_evidence; a divergent top-level `action` echo is a
        // hard failure, not a silent non-match.
        let u_action = ev_str(rec, "use_evidence", "action");
        if let (Some(top), Some(ua)) = (s(rec, "action"), &u_action) {
            if &top != ua {
                unmatched_violation += 1;
                violation(&mut issues, "top-level action diverges from use_evidence.action (MUST-FIX 1)".into());
                continue;
            }
        }
        // MUST-FIX 1 (mirror of the grant-side kind guard): `kind` is duplicated at extensions.broker.kind
        // (the role discriminator that made this a resource record) and inside use_evidence. The payload
        // MUST say the SAME kind as the discriminator ("use" one-phase, or "use_intent" two-phase); absence
        // or divergence is a hard failure. (D5: a `use_intent` carries the same PoP-validated use_evidence as
        // a one-phase use, with kind="use_intent".)
        if ev_str(rec, "use_evidence", "kind").as_deref() != Some(bkind.as_str()) {
            unmatched_violation += 1;
            violation(&mut issues, "use_evidence.kind is absent or diverges from the extensions.broker.kind discriminator (MUST-FIX 1)".into());
            continue;
        }
        // MUST-FIX 4: the receipt must CARRY well-formed audit fields the verifier surfaces for offline
        // inspection — pop_challenge_hash + ledger_commitment as sha256:<hex>, and a non-empty nonce.
        // (The verifier does NOT re-run PoP or prove ledger ordering — that is the resource-shim TCB —
        // but a use that simply omits or mangles these fields must not read as a clean match.)
        let well_formed_sha = |key: &str| {
            ev_str(rec, "use_evidence", key)
                .as_deref()
                .and_then(crate::hashx::parse_sha256)
                .is_some()
        };
        if !well_formed_sha("pop_challenge_hash") || !well_formed_sha("ledger_commitment") {
            unmatched_violation += 1;
            violation(&mut issues, "use_evidence is missing or malformed pop_challenge_hash / ledger_commitment (must be sha256:<hex>) — MUST-FIX 4".into());
            continue;
        }
        if ev_str(rec, "use_evidence", "nonce").is_none_or(|n| n.is_empty()) {
            unmatched_violation += 1;
            violation(&mut issues, "use_evidence is missing the PoP nonce (R4) — violation".into());
            continue;
        }
        let (gid, action, resource_id, jti, cnf_kid, used_at) = match (
            ev_str(rec, "use_evidence", "grant_id"),
            u_action,
            ev_str(rec, "use_evidence", "resource_id"),
            ev_str(rec, "use_evidence", "jti"),
            ev_str(rec, "use_evidence", "cnf_kid"),
            ev_int(rec, "use_evidence", "used_at"),
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => (a, b, c, d, e, f),
            _ => {
                unmatched_violation += 1;
                violation(&mut issues, "use_evidence is missing a required match field — violation".into());
                continue;
            }
        };
        // D3 (ADR 0004): the carried ledger_commitment must re-derive from (jti, nonce, used_at) the
        // same way the resource shim computed it, and a (resource_id, nonce) must not repeat across
        // closed receipts. nonce is already present + non-empty and ledger_commitment is well-formed
        // sha256 (checked above).
        let nonce = ev_str(rec, "use_evidence", "nonce").unwrap_or_default();
        let carried_lc = ev_str(rec, "use_evidence", "ledger_commitment").unwrap_or_default();
        if ledger_commitment(&jti, &nonce, used_at) != carried_lc {
            unmatched_violation += 1;
            violation(&mut issues, "use_evidence.ledger_commitment does not re-derive from (jti, nonce, used_at) — R5/D3 violation".into());
            continue;
        }
        if !seen_nonces.insert((resource_id.clone(), nonce.clone())) {
            unmatched_violation += 1;
            violation(&mut issues, format!("PoP nonce '{nonce}' replayed across closed receipts for resource '{resource_id}' (duplicate submission) — D3"));
            continue;
        }
        // D4 mis-scope (ADR 0004): the grant was already flagged + rejected at issuance (see grant
        // indexing). Skip its use BEFORE any matching/counting so the violation is recorded exactly once
        // (at the grant, even if unused) and the use never touches uses_matched / uses_pop_reverified /
        // action_verified. Checked before the grant lookup so a mis-scoped grant left out of (or kept in)
        // the index behaves identically.
        if misscoped.contains(&gid) {
            continue;
        }
        let g = match grants_by_id.get_mut(&gid) {
            Some(g) => g,
            None => {
                unmatched_violation += 1;
                violation(&mut issues, format!("no matching closed grant '{gid}' — action without a credential (Tier-B violation)"));
                continue;
            }
        };
        // Full predicate: action / resource / temporal-window / cnf_kid equality, read from the proven
        // payloads on both sides.
        // The temporal window is [issued_at, exp) — used_at >= exp is expired, matching the resource
        // shim's `now >= exp` rejection (so the verifier is not more lenient than the gateway).
        // M2 (delegation): match the use's cnf_kid against the EFFECTIVE (leaf) cnf and the NARROWED window,
        // not the root — so a sub-agent's PoP matches a re-delegated grant, and a use by the original root
        // (root cnf != leaf cnf) correctly fails to match a delegated-away credential. For an undelegated
        // grant effective_cnf_kid==cnf_kid and effective_exp==exp, so this is unchanged (additive).
        if action != g.action
            || resource_id != g.resource_id
            || cnf_kid != g.effective_cnf_kid
            || used_at < g.issued_at
            || used_at >= g.effective_exp
        {
            unmatched_violation += 1;
            violation(&mut issues, format!("action/resource/cnf/window does not match grant '{gid}' — violation"));
            continue;
        }
        // Single-use (R5 rev 4): per-grant_id at most once, regardless of jti; jti must equal grant_id.
        // M1 (bounded_reuse, ADR 0005): a 4th scope class allowing N uses of the IDENTICAL
        // (action, resource_id); replay is bounded by a per-grant `use_sequence_number in [1, use_limit]`,
        // deduped per (grant_id, usn). jti still equals grant_id for both classes (the resource sources
        // use_evidence.jti from the descriptor jti, so the D6.4 descriptor cross-check is UNCHANGED); the
        // per-exercise identity is the SEPARATE use_sequence_number.
        let single = g.scope_class == "single_operation";
        let bounded = g.scope_class == "bounded_reuse";
        if (single || bounded) && jti != gid {
            unmatched_violation += 1;
            violation(&mut issues, format!("{} grant '{gid}' requires use_evidence.jti == grant_id (R5) — violation", g.scope_class));
            continue;
        }
        if single && g.used >= 1 {
            unmatched_violation += 1;
            violation(&mut issues, format!("single-use grant '{gid}' exercised more than once — double-spend (R5)"));
            continue;
        }
        // M1: validate the bounded_reuse sequence number BEFORE counting; the usn is CONSUMED only when the
        // use is fully accepted (alongside g.used), so a use that later fails PoP/outcome does not burn it.
        let use_seq: Option<i64> = if bounded {
            let usn = ev_int(rec, "use_evidence", "use_sequence_number").unwrap_or(0);
            if usn < 1 || usn > g.use_limit {
                bounded_reuse_overspent += 1;
                unmatched_violation += 1;
                violation(&mut issues, format!("bounded_reuse grant '{gid}' use_sequence_number {usn} outside [1, {}] — overspend (M1)", g.use_limit));
                continue;
            }
            if g.used_seqs.contains(&usn) {
                bounded_reuse_seq_replays += 1;
                unmatched_violation += 1;
                violation(&mut issues, format!("bounded_reuse grant '{gid}' use_sequence_number {usn} replayed across receipts — seq-replay (M1)"));
                continue;
            }
            // Compare in i64, NOT `use_limit as usize` (same wasm32 `usize==u32` truncation concern as the
            // cosig gate above). Here truncation would shrink the cap (fail-CLOSED, over-restrictive) rather
            // than open, but the verdict must still be platform-independent; `g.used` is a small count.
            if g.used as i64 >= g.use_limit {
                bounded_reuse_overspent += 1;
                unmatched_violation += 1;
                violation(&mut issues, format!("bounded_reuse grant '{gid}' exercised more than use_limit {} times — overspend (M1)", g.use_limit));
                continue;
            }
            Some(usn)
        } else {
            None
        };
        // D5 (ADR 0004 F4): a `use_intent` is a COMPLETE two-phase use only if a valid `use_outcome` whose
        // SIGNED payload references THIS intent's record_id AND attests THIS grant_id completes it. An intent
        // that passed every predicate above but has no such outcome is an `intent_without_outcome` anomaly —
        // recorded-but-incomplete (the crash-after-act case). Surface it and stop BEFORE it counts as matched
        // / PoP-reverified or consumes a single-use grant.
        // D5 (ADR 0004 F4): pick a SPECIFIC un-consumed validated outcome that references THIS intent's
        // record_id, attests THIS grant, and proves the BEFORE-ACT ordering: the outcome's RESOURCE-SIGNED
        // `intent_hash` must equal this intent's content_hash (the resource attests it observed THIS intent
        // before signing the outcome — unforgeable by the relay), AND the top-level `causal_prev_hashes`
        // include it (a DAG consistency check; the signed binding is the security boundary, since the
        // record-signing key could backfill the top-level edge). An unordered/backfilled pair does NOT
        // complete. The pick is held and only CONSUMED after every acceptance check (incl. PoP) passes — a
        // later-rejected intent must not consume (and thereby mask from orphan accounting) its outcome.
        let mut pending_consume: Option<usize> = None;
        if bkind == "use_intent" {
            let key = (rt.record_id.clone(), gid.clone());
            pending_consume = outcomes_by.get(&key).and_then(|idxs| {
                idxs.iter().copied().find(|&i| {
                    let (_, _, orec, oidx, ihash) = &outcomes[i];
                    !consumed_outcomes.contains(orec)
                        && ihash.as_str() == rt.content_hash.as_str()
                        && records[*oidx]
                            .get("causal_prev_hashes")
                            .and_then(|v| v.as_array())
                            .is_some_and(|p| p.iter().any(|h| h.as_str() == Some(rt.content_hash.as_str())))
                })
            });
            if pending_consume.is_none() {
                intent_without_outcome += 1;
                continue;
            }
        }
        // D2 (ADR 0004): re-run the Ed25519 PoP offline if the receipt carries the cnf pubkey + use_sig —
        // reconstructing the challenge from the proven fields + this grant's credential_binding + the
        // record's input_commit. A claimed re-verification that FAILS is a violation; a receipt that
        // carries neither stays `shim_asserted` (legacy ADR-0003 path).
        match pop_reverify(rec, &g.credential_binding) {
            Ok(true) => uses_pop_reverified += 1,
            Ok(false) => {}
            Err(msg) => {
                unmatched_violation += 1;
                violation(&mut issues, format!("offline PoP re-verification: {msg}"));
                continue;
            }
        }
        if let Some(i) = pending_consume {
            consumed_outcomes.insert(outcomes[i].2.clone()); // accepted intent → consume its outcome now
        }
        if bkind == "use" {
            one_phase_use_present = true; // D8/MF3: a matched one-phase receipt blocks the capstone
        }
        g.used += 1;
        if let Some(usn) = use_seq {
            g.used_seqs.insert(usn); // M1: consume the sequence number only now (use fully accepted)
        }
        uses_matched += 1;
        // R6/D4: a matched use is action-VERIFIED only when a pinned, in-window taxonomy lists the
        // grant's action FOR THIS RESOURCE — otherwise it stays a demonstrator artifact
        // (uses_action_unverified) that can never reach the attested_complete upgrade. The listing is
        // resource-BOUND so a taxonomy vetted for one resource cannot validate a colliding action name on
        // another (Codex AREA 2). M1: bounded_reuse is action-verifiable too — it fixes one
        // (action, resource_id) exactly like single_operation (action↔grant tightness preserved).
        let action_verified = (single || bounded)
            && taxonomy_info.as_ref().is_some_and(|ti| {
                if !ti.actions.contains(&(resource_id.clone(), action.clone())) {
                    return false;
                }
                let in_window = g.issued_at >= ti.effective_from
                    && g.issued_at <= ti.effective_until
                    && used_at >= ti.effective_from
                    && used_at <= ti.effective_until;
                if !in_window {
                    // a listed action rejected ONLY by the effective window → the taxonomy is stale (MF5)
                    taxonomy_window_failed = true;
                }
                in_window
            });
        if !action_verified {
            uses_action_unverified += 1;
        }
    }
    // D5: a validated `use_outcome` that NO closed matching `use_intent` consumed is an ORPHAN — a recorded
    // completion with no anchored pre-action intent (the resource skipped the before-act recording that two-
    // phase exists to require). Flag it; otherwise an outcome-only bundle would read clean (false-clean).
    for (iref, ogid, orec, _, _) in &outcomes {
        if !consumed_outcomes.contains(orec) {
            unmatched_violation += 1;
            issues.push(format!("use_outcome {orec}: references intent '{iref}' (grant {ogid}) but no closed matching use_intent consumed it — completion without a recorded intent (D5)"));
        }
    }
    // D4: a mis-scoped grant is rejected, not "unused" — exclude it so an exercised-but-mis-scoped grant
    // (whose use was skipped, leaving used==0) is not mis-reported as a clean unused grant.
    let grants_unused = grants_by_id
        .iter()
        .filter(|(gid, g)| g.used == 0 && !misscoped.contains(*gid))
        .count();
    // M1: closed grants bounded to N uses of one (action, resource_id).
    let bounded_reuse_grants = grants_by_id
        .values()
        .filter(|g| g.scope_class == "bounded_reuse")
        .count();

    // M6 (ADR 0005): cosig artifact status. `absent` (no grant declared a cosig requirement) | `satisfied`
    // (every cosigned grant met its threshold) | `unsatisfied` (≥1 fell short — each is also a hard violation).
    let cosig_status = if cosigned_grants_total == 0 {
        "absent"
    } else if cosig_threshold_failures == 0 && cosigned_grants_satisfied == cosigned_grants_total {
        "satisfied"
    } else {
        "unsatisfied"
    }
    .to_string();

    // M2 (ADR 0005): delegation artifact status. `absent` (no grant re-delegated) | `verified` (every chain
    // fully re-walked + monotone) | `unverified` (≥1 chain failed sig/link/root or widened).
    let delegation_status = if delegation_chains_total == 0 {
        "absent"
    } else if delegation_chains_verified == delegation_chains_total && delegation_monotonicity_violations == 0 {
        "verified"
    } else {
        "unverified"
    }
    .to_string();

    // D4/MF5 taxonomy_status: absent (none pinned) | untrusted (bad sig/issuer/pin) | stale (signed +
    // pinned but a listed action was out of its effective window) | validated (signed, pinned, in-window).
    let taxonomy_status = match (&opts.taxonomy, &taxonomy_info) {
        (None, _) => "absent",
        (Some(_), None) => "untrusted",
        (Some(_), Some(_)) if taxonomy_window_failed => "stale",
        (Some(_), Some(_)) => "validated",
    };

    // D6/MF2 broker_trust: re-derive the grant-transparency head over the recorded grant log. Needs the
    // DAG (committed_set); without it (DAG invalid) the sequence cannot be re-derived → stays `assumed`.
    let broker_trust = match dag_opt.as_ref() {
        Some(d) => compute_broker_trust(
            &cp_heads,
            &verified_headless,
            verified_malformed_head,
            &record_trust,
            records,
            &d.by_hash,
            &d.heads,
            latest_cp_seq,
            &mut issues,
        ),
        None => "assumed".to_string(),
    };

    // D7: the resource_id set the deployment-attestation subject must bind — every resource named by a
    // grant_evidence or use_evidence in the bundle (so a substituted attestation for a different surface
    // is rejected).
    let mut resource_ids: BTreeSet<String> = BTreeSet::new();
    // T6: the (resource_id, action) PAIRS the brokered surface actually touches — closure is checked
    // action-bound (per the ADR), so a resource touched under action A must be declared under A, not merely
    // named somewhere under an unrelated action. A grant/use missing its action contributes ("", resource)
    // so it can never match a declared (resource, real-action) pair — it fails closed.
    let mut touched_pairs: BTreeSet<(String, String)> = BTreeSet::new();
    // F10: harvest ONLY from INTEGRITY-PROVEN records, so a non-proven (e.g. relay-appended) record cannot
    // inject a bogus resource_id/(resource,action) — which would force the D7 attestation (must bind every
    // resource_id) or the T6 side_effect_closure (must declare every touched pair) to fail, a
    // denial-of-attestation. Gating on integrity (not role) is the safe level: every genuine grant/use is
    // integrity-proven, so no actually-touched resource is dropped (which would be the opposite, fail-open).
    for rt in &record_trust {
        if rt.trust != TrustLevel::IntegrityProven {
            continue;
        }
        let rec = &records[rt.index];
        if let Some(r) = ev_str(rec, "grant_evidence", "resource_id") {
            touched_pairs.insert((r.clone(), ev_str(rec, "grant_evidence", "action").unwrap_or_default()));
            resource_ids.insert(r);
        }
        if let Some(r) = ev_str(rec, "use_evidence", "resource_id") {
            touched_pairs.insert((r.clone(), ev_str(rec, "use_evidence", "action").unwrap_or_default()));
            resource_ids.insert(r);
        }
    }
    let attest = evaluate_attestation(bundle, opts, project_id.as_deref(), &anchored_cp_ids, latest_cp_seq, &resource_ids, &mut issues);

    let coverage_manifest = bundle.get("coverage_manifest").cloned();

    // T6 (ADR 0002 open Q1, ACTIONABLE half): side_effect_closure COMPLETENESS over the observed brokered
    // surface. The operator declares, in the D7-digest-bound coverage_manifest, per `(resource_id, action)`,
    // which resources each acted action may transitively touch; every `(resource_id, action)` the bundle's
    // grants/uses actually exercise (`touched_pairs`) must fall within that ACTION-BOUND declared closure —
    // a resource declared only under a DIFFERENT action does NOT close it for the action acting on it (Codex).
    // Note touched_pairs is built from EVERY grant_evidence AND use_evidence pair above — so a grant that was
    // ISSUED BUT NEVER USED still contributes its `(resource_id, action)`, and the operator must declare
    // closure for it too. This is intentional: a grant's mere existence widened the authorized surface (the
    // broker could have honored a use), so completeness is claimed over what was AUTHORIZED, not only what was
    // exercised. A touched-but-undeclared `(resource_id, action)` is an unclosed-side-effect violation (hard
    // `issues` → !ok). This proves the manifest DECLARES a complete closure over what happened — NOT that the
    // runtime obeyed it nor that the closure is semantically complete (resource TCB, resource_trust:assumed_truthful, D9 floor 2).
    let mut unclosed_side_effects = 0usize;
    let side_effect_closure_status = match coverage_manifest.as_ref().filter(|m| !m.is_null()) {
        Some(m) if m.get("side_effect_closure").is_some() => match side_effect_closure_resources(m) {
            Some(declared) => {
                for pair in &touched_pairs {
                    if !declared.contains(pair) {
                        unclosed_side_effects += 1;
                        let (r, a) = pair;
                        issues.push(format!("resource '{r}' under action '{a}' is touched by the brokered surface but is within no declared side_effect_closure (T6)"));
                    }
                }
                if unclosed_side_effects == 0 { "closed" } else { "unclosed" }
            }
            None => {
                issues.push("coverage_manifest.side_effect_closure is present but malformed (T6 fail-closed)".into());
                "unclosed"
            }
        },
        _ => "not_declared",
    }
    .to_string();

    let first_broken_link = issues.first().cloned();
    let ok = issues.is_empty()
        && records_proven == records.len()
        && !records.is_empty()
        && dag_ok
        && checkpoints_verified == checkpoints.len()
        && !checkpoints.is_empty()
        && chain_ok;

    // The trust label must never outrank the verdict: if the bundle is not `ok` (e.g. a broken checkpoint
    // chain, an unverified checkpoint, or any other failure), `broker_trust` cannot claim a reduction.
    let broker_trust = if ok { broker_trust } else { "assumed".to_string() };

    VerifyReport {
        ok,
        project_id,
        keys_externally_pinned,
        records_total: records.len(),
        records_proven,
        record_trust,
        dag_ok,
        dag_heads,
        collapsed_duplicates,
        checkpoints_total: checkpoints.len(),
        checkpoints_verified,
        checkpoints_anchored,
        chain_ok,
        disclosures_total,
        disclosures_verified,
        grant_total,
        denied_grants,
        grant_verified,
        uses_total,
        uses_matched,
        uses_action_unverified,
        uses_pop_reverified,
        unmatched_violation,
        unmatched_pending,
        intent_without_outcome,
        one_phase_use_present,
        grants_unused,
        bounded_reuse_grants,
        bounded_reuse_overspent,
        bounded_reuse_seq_replays,
        cosigned_grants_total,
        cosigned_grants_satisfied,
        cosig_threshold_failures,
        cosig_status,
        delegation_chains_total,
        delegation_chains_verified,
        delegation_monotonicity_violations,
        delegation_status,
        taxonomy_status: taxonomy_status.to_string(),
        broker_trust,
        cred_label_checks,
        cred_label_matched,
        attestation_status: attest.status,
        attestation_issuer_kid: attest.issuer_kid,
        attestation_issued_at: attest.issued_at,
        attestation_not_after: attest.not_after,
        attestation_claim_types: attest.claim_types,
        attestation_subject_digest: attest.subject_digest,
        resource_trust: "assumed_truthful".to_string(),
        coverage_manifest,
        unclosed_side_effects,
        side_effect_closure_status,
        issues,
        first_broken_link,
    }
}
