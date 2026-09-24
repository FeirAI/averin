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
//! `≤ status_changed_at` transitively commits it (RCP §10.2, threat #9). The same rule applies to a
//! CHECKPOINT's signing key: a checkpoint signed by a revoked/compromised key is trusted only when a
//! verified anchor at or before the status change commits it (itself, or a later checkpoint chaining to it).

use crate::anchor::verify_anchor_keyed;
use crate::authority::{verify_authority_with_key, AuthorityTrust};
use crate::canon::CanonValue;
use crate::checkpoint::{validate_chain, verify_checkpoint_sealed};
use crate::dag;
use crate::record::{validate_record_shape, verify_content_hash, verify_sealed};
use crate::sign::decode_pubkey;
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};

mod verdict;
use verdict::{AnchoredCheckpoint, CapstoneFacts, PinnedRecordSeal, ValidatedFacts};
pub use verdict::{
    ClaimDecision, ClaimPolicy, ClaimResults, RequestedClaim, RevocationRequirement,
};

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
    /// Authority gradient: `verified` binds the complete semantic body under v3;
    /// `legacy_unbound` is a valid historical v2 signature over evidence identity
    /// only and cannot satisfy an authorized-action claim.
    pub authority: AuthorityTrust,
    /// Broker/resource role (ADR 0003 R2): broker|resource|none. Surfaces which role's key set the
    /// authority was checked under, so an auditor sees broker-signed vs resource-signed provenance.
    pub broker_role: String,
    pub notes: Vec<String>,
}

/// The D8 capstone verdict (ADR 0004 / ADR 0005), promoted from an inline serialization string to a typed,
/// exhaustively-matched field. It is DERIVED from the rest of the report — `ActionCompleteness::of(&report)`
/// runs as the final step over the fully-built report, so it can never go stale. ALWAYS read alongside
/// `resource_trust` (MF1): even the strongest label means "complete over the surface IF the resource labeled
/// it truthfully" (the irreducible resource TCB, D9) — never "everything the agent did".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionCompleteness {
    /// No (non-null) coverage manifest, or some capstone conjunct failed — the baseline.
    NotClaimed,
    /// A non-null coverage manifest is present, but the full `attested_complete` conjunction did not hold.
    ClaimedOverManifest,
    /// The STANDARD capstone: every reduction held over a non-empty, PURELY-BROKERED (PoP) surface.
    AttestedCompleteOverBrokeredSurface,
    /// The PARALLEL, strictly-weaker M3 capstone: every reduction held over a PURELY-INTROSPECTED native surface.
    AttestedCompleteOverIntrospectedSurface,
}

impl ActionCompleteness {
    /// The canonical report string for this verdict — byte-identical to the prior inline serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            ActionCompleteness::NotClaimed => "not_claimed",
            ActionCompleteness::ClaimedOverManifest => "claimed_over_manifest",
            ActionCompleteness::AttestedCompleteOverBrokeredSurface => {
                "attested_complete_over_brokered_surface"
            }
            ActionCompleteness::AttestedCompleteOverIntrospectedSurface => {
                "attested_complete_over_introspected_surface"
            }
        }
    }

    /// D8 (ADR 0004) — the `attested_complete` capstone: the CONJUNCTION of every reduction, derived from a
    /// fully-built report. The label `attested_complete_over_brokered_surface` is reached ONLY when ALL hold:
    /// the bundle verified (`ok` — all in-scope records L2-proven, DAG + chain valid, no issues); there is a
    /// brokered surface (`uses_matched > 0`); EVERY matched use is a closed two-phase pair (MF3 —
    /// `!one_phase_use_present`, `intent_without_outcome == 0`); every matched use is taxonomy-`validated` AND
    /// action-verified (D4); every matched use was PoP-RE-verified offline (D2 —
    /// `uses_pop_reverified == uses_matched`); the grant log is anchored + gapless (D6 —
    /// `broker_trust=="sequence_verified"`); a fresh pinned-issuer deployment attestation binds this bundle
    /// (D7 — `attestation_status=="attested_claims"`); and there is no unmatched violation or unexplained
    /// in-flight use. The capstone is asserted over a `coverage_manifest`; absent one it is at most
    /// `claimed_over_manifest`. It is ALWAYS qualified by `resource_trust:"assumed_truthful"` (MF1).
    /// M3 (ADR 0005): native/STS credentials add the PARALLEL, strictly-weaker
    /// `attested_complete_over_introspected_surface` over a PURELY-INTROSPECTED native surface; a MIXED
    /// native+PoP bundle reaches NEITHER label (it is `claimed_over_manifest`), keeping each label's MF1
    /// meaning crisp.
    pub fn of(r: &VerifyReport) -> Self {
        Self::of_with_integrity(r, r.ok, r.broker_trust == "sequence_verified")
    }

    // The new claims use structural integrity plus typed committed contradictions. Legacy `ok`
    // also includes diagnostics for malformed optional attachments; deleting such an attachment
    // may change `ok` but cannot create proof of a stronger claim.
    fn of_with_integrity(
        r: &VerifyReport,
        integrity: bool,
        broker_sequence_verified: bool,
    ) -> Self {
        // a JSON `"coverage_manifest": null` deserializes to `Some(Null)`, which is NOT a real manifest
        // (D7 already treats null as the empty digest) — the capstone must be asserted OVER a real scope
        // claim, so require a NON-NULL manifest.
        let has_manifest = r.coverage_manifest.as_ref().is_some_and(|m| !m.is_null());
        // `base` is the conjunction SHARED by both capstone labels — every reduction EXCEPT the surface-shape
        // conjuncts (`uses_matched`, native-vs-brokered) that distinguish the two labels.
        let base = integrity
            && r.keys_externally_pinned
            && r.body_bound_role_evidence
            && has_manifest
            && !r.one_phase_use_present
            && r.intent_without_outcome == 0
            && r.taxonomy_status == "validated"
            && r.uses_action_unverified == 0
            && r.uses_pop_reverified == r.uses_matched
            && broker_sequence_verified
            && r.attestation_status == "attested_claims"
            && r.unmatched_violation == 0
            && r.unmatched_pending == 0
            // M1 (ADR 0005): no bounded_reuse grant overspent or had a replayed sequence number.
            && r.bounded_reuse_overspent == 0
            && r.bounded_reuse_seq_replays == 0
            // M6 (ADR 0005): every cosigned grant met its M-of-N approval threshold.
            && r.cosig_threshold_failures == 0
            && (r.cosigned_grants_total == 0 || r.cosigned_grants_satisfied == r.cosigned_grants_total)
            // M2 (ADR 0005): every present delegation chain fully re-walked (sigs + links + monotonic).
            && (r.delegation_chains_total == 0
                || r.delegation_chains_verified == r.delegation_chains_total)
            && r.delegation_monotonicity_violations == 0
            // M5 (ADR 0005): no fresh revocation list flagged a revoked use, and the list is not stale.
            && r.revocation_status != "stale"
            && r.revocation_status != "revoked_present"
            // M5: revocation keys were pinned but the bundle carries no revocation artifact at all (stripped).
            && r.revocation_status != "missing"
            && r.revoked_uses_blocked == 0
            // M5 Merkle-non-disclosure: a present-but-stale signed root is too old to certify currency.
            && r.revocation_merkle_status != "stale"
            // M4 (ADR 0005): when federation is active, every per-broker_id head chain verified, none suppressed.
            && r.cross_broker_suppression == 0
            && r.brokers_seq_verified == r.brokers_total
            // T6: the brokered surface stayed within the operator's AFFIRMATIVELY-declared side-effect closure
            // (load-bearing beyond `r.ok` — a `not_declared` manifest does not force `!ok`).
            && r.side_effect_closure_status == "closed";
        // The STANDARD capstone: a non-empty BROKERED surface, every matched use PoP-reverified (in `base`),
        // and NO native credential (M3 — `!native_credential_present` makes "purely brokered surface" load-bearing).
        let brokered = base && r.uses_matched > 0 && !r.native_credential_present;
        // M3: the parallel native-surface capstone — ZERO brokered PoP uses (purity), a native credential, and
        // every closed introspection transcript verified + every native grant covered (`introspection_status`).
        let introspected = base
            && r.uses_matched == 0
            && r.native_credential_present
            && r.introspection_status == "attested";
        if brokered {
            ActionCompleteness::AttestedCompleteOverBrokeredSurface
        } else if introspected {
            ActionCompleteness::AttestedCompleteOverIntrospectedSurface
        } else if has_manifest {
            ActionCompleteness::ClaimedOverManifest
        } else {
            ActionCompleteness::NotClaimed
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub ok: bool,
    /// Versioned, typed claim decisions under the caller's fixed verification policy.
    claims: ClaimResults,
    pub project_id: Option<String>,
    pub keys_externally_pinned: bool,
    /// Every committed broker/resource/void contributor used by the strong claim has a
    /// body-bound v3 authority signature. Historical v2 evidence remains a legacy join only.
    pub body_bound_role_evidence: bool,
    pub records_total: usize,
    pub records_proven: usize,
    pub record_trust: Vec<RecordTrust>,
    pub dag_ok: bool,
    pub dag_heads: usize,
    pub collapsed_duplicates: usize,
    pub checkpoints_total: usize,
    pub checkpoints_verified: usize,
    /// Checkpoints whose external anchor VERIFIED under a pinned TSA (on a verified checkpoint, TSA key honored)
    /// — the anchors that actually contribute trust. `checkpoints_anchors_attached` counts mere PRESENCE of an
    /// `anchor` field (unverified: anyone can attach garbage), so the two are never conflated.
    pub checkpoints_anchored: usize,
    pub checkpoints_anchors_attached: usize,
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
    /// Tier-B use↔grant join (ADR 0003 step 5, R3). Violations are evaluated over the COMMITTED set (records
    /// committed by ANY verified checkpoint), positive claims over the CLOSED set (committed by a verified,
    /// ANCHORED checkpoint) — so deleting the unsigned `anchor` can only weaken the verdict. `uses_total` =
    /// resource-role use receipts; `uses_matched` = closed uses bound to a closed grant under the full
    /// predicate; `uses_action_unverified` = matched
    /// uses NOT action-verified — i.e. a non-`single_operation` grant, or no `validated`, in-window
    /// taxonomy listing the grant's `(resource_id, action)` (ADR 0004 D4; `0` ⇔ every matched use is
    /// action-verified); `unmatched_violation` = a committed use with no/again a matching grant, or one
    /// honoring a mis-scoped grant (hard fail); `unmatched_pending` = a use that passed every check but is not
    /// yet closed (in-flight); `grants_unused` = closed grants with no matching use.
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
    /// `cosig_approver_keys` produced a valid `averin.broker.cosig.approval.v1` cosignature; `cosig_threshold_failures`
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
    /// alone (adversarial review AREA 1).
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
    /// M5 / ADR 0005 (Revocation — tiered). `revocation_status` ∈ {`absent` (no `revocation_keys` pinned — not
    /// evaluated, the legitimate baseline — or a Merkle-mode bundle carrying only a `revocation_merkle_root`),
    /// `missing` (`revocation_keys` ARE pinned but the bundle carries neither a `revocation_list` nor a
    /// `revocation_merkle_root` — e.g. stripped; blocks the capstone), `fresh` (a list signed
    /// under a pinned role-separated `revocation_keys` issuer whose disclosed `revoked_grant_ids` re-derive its
    /// signed `merkle_root`, with the latest anchored checkpoint timestamp inside `[issued_at, not_after]`),
    /// `stale` (validly signed but the anchored time is outside the window — too old to trust for currency, OR
    /// a malformed/forged list, surfaced honestly), `revoked_present` (a FRESH list AND ≥1 matched use is
    /// against a revoked grant_id — a use of a revoked credential)}. `revoked_grants_matched` = closed grants in
    /// this bundle whose grant_id is in the (valid) list; `revoked_uses_blocked` = matched-candidate uses
    /// rejected because their grant was revoked inside the window (each also a hard violation → `!ok`). `absent`
    /// and `fresh` do NOT block the capstone; `stale`, `revoked_present` and `missing` do.
    pub revocation_status: String,
    pub revoked_grants_matched: usize,
    pub revoked_uses_blocked: usize,
    /// M5 Merkle-non-disclosure (ADR 0005): `revocation_merkle_status` ∈ {`absent`, `fresh`, `stale`} for a
    /// top-level signed `revocation_merkle_root` (a commitment to the revoked set that does NOT disclose it).
    /// When `fresh`, EVERY Tier-B use must carry a per-grant proof in `revocation_proofs`: a non-membership proof
    /// to proceed (counted in `revocation_nonmembership_verified`), else it is blocked (a membership proof) or
    /// FAIL-CLOSED (missing/forged) — both counted in `revoked_uses_blocked` + a hard violation (`!ok`). `stale`
    /// blocks the capstone (like the disclosed list); `absent`/`fresh`-with-all-proofs do not.
    pub revocation_merkle_status: String,
    pub revocation_nonmembership_verified: usize,
    /// M3 / ADR 0005 (Native/STS — post-mint resource-signed introspection transcript, resolves ADR 0002 Q3).
    /// `native_credential_present` = a closed, verified broker grant declared `grant_evidence.mode ==
    /// "token_exchange"` (a credential minted by an external IdP/STS whose effective scope the verifier cannot
    /// recompute). Such a grant has NO broker `credential_binding` and NO cnf-key PoP, so it is accounted on a
    /// SEPARATE channel: it is NEVER folded into the brokered `grants_by_id`/`uses_matched`, and its surface is
    /// attested by resource-signed `introspection_transcript` records, NOT brokered use receipts (so the two
    /// surfaces stay DISJOINT — a brokered use naming a native grant_id reads as `unmatched_violation`, and a
    /// transcript naming a brokered/absent grant_id is a violation). `introspection_transcripts_total` = closed
    /// `introspection_transcript` records; `introspection_transcripts_verified` = those whose structured
    /// `averin.resource.introspection.v1` signature verifies under a pinned `resource_authority_keys` issuer, bind to
    /// a present native grant, and whose `effective_scope ⊆ grant.scope` (space-delimited OAuth token subset) with
    /// no time-broadening (`effective_exp <= grant.exp`) and `issued_at <= introspected_at`. A failing transcript
    /// (bad sig / dangling / scope- or time-broadening) is a hard `unmatched_violation` (→ `!ok`).
    /// `introspection_scope_narrowed` = verified transcripts whose effective scope is a PROPER subset of the grant
    /// scope (the resource attested a narrowing — informational). `introspection_status` ∈ {`absent` (no native
    /// credential), `attested` (a native credential is present, every closed transcript verified, every native
    /// grant is covered by ≥1 verified transcript, and total > 0), `unattested` (a native credential is present
    /// but a transcript failed or a native grant is uncovered)}. The native surface reaches the strictly-weaker
    /// parallel capstone `attested_complete_over_introspected_surface`, NEVER the brokered one (PoP is broken);
    /// a MIXED native+PoP bundle reaches NEITHER. Residual: the transcript is resource-signed, so it RELOCATES —
    /// does not remove — the resource TCB (`resource_trust: assumed_truthful`, ADR 0004 D9 floor 2 / ADR 0002 Q3).
    pub native_credential_present: bool,
    pub introspection_transcripts_total: usize,
    pub introspection_transcripts_verified: usize,
    pub introspection_scope_narrowed: usize,
    pub introspection_status: String,
    /// M4 / ADR 0005 (Federation — tiered multi-broker). Activated ONLY when a committed, integrity-proven
    /// broker grant carries a non-empty signed `grant_evidence.broker_id` (a single-broker bundle is BYTE-FOR-BYTE
    /// unchanged — D6 `broker_trust` runs exactly as before and these fields stay at the `absent` defaults). When
    /// active, the grant-transparency log is PARTITIONED per `broker_id`: each broker's grants must form their own
    /// gapless `[1..n_b]` `broker_seq` prefix with their own `cumulative_root` chain re-derived against that
    /// broker's entry in the checkpoint's `broker_grant_heads` map — so a gap in broker A's sequence is detected
    /// in A's partition and can never be masked by broker B's interleaved grants (the cross-broker suppression the
    /// flat D6 log could not see). `brokers_total` = distinct `broker_id`s with a committed grant;
    /// `brokers_seq_verified` = those whose per-broker head chain fully re-derived AND is bound into a
    /// verified+anchored checkpoint; `cross_broker_suppression` = brokers whose partition failed (a gap, a tail
    /// omission, a missing/inflated head, or a non-chaining prior-head — each also a hard `issues` violation).
    /// `federation_status` ∈ {`absent` (single-broker / not activated), `sequence_verified` (every broker's head
    /// chain verified + anchored), `sequence_consistent_export` (verified but the latest head is not anchored),
    /// `suppression` (≥1 broker partition failed)}. `per_broker_trust` lists each `broker_id` with its own trust.
    /// Capstone-gated by `cross_broker_suppression==0 && brokers_seq_verified==brokers_total`. Those two conjuncts
    /// surface PER-BROKER suppression; the whole-log global failures (a grant smuggled out of every partition, a
    /// phantom-broker head, a grant_id equivocation, a malformed head) additionally force `broker_trust=="assumed"`
    /// (failing the existing `broker_trust=="sequence_verified"` capstone conjunct) AND a hard `issues` violation
    /// (`!ok`), so the capstone is blocked on multiple independent grounds, not the two federation conjuncts alone.
    /// Residual: a
    /// globally-consistent cross-broker equivocation (divergent histories never co-committed in one bundle) stays
    /// the offline floor (ADR 0004 D9 floor 1) — only an out-of-band monitor catches a coordinated multi-broker
    /// rewrite. (The baseline pins one shared broker root; per-`broker_id` key pinning + cross-broker certs layer on.)
    pub federation_status: String,
    pub brokers_total: usize,
    pub brokers_seq_verified: usize,
    pub cross_broker_suppression: usize,
    pub per_broker_trust: Vec<(String, String)>,
    /// M4 (ADR 0005, OPTIONAL transitive tier): how many verified broker grants elevated ONLY because a PINNED
    /// issuer broker's cross_broker_cert vouched for the (otherwise-unpinned) subject broker's key. `0` for a
    /// directly-pinned federation (the common case). Observability only — a transitive grant is otherwise
    /// counted/matched exactly like a directly-verified grant; the cert's soundness is enforced at elevation.
    pub transitive_grants: usize,
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

impl VerifyReport {
    /// The D8 capstone verdict (typed) — DERIVED from the report's own fields, so it always reflects the
    /// CURRENT state and can never go stale (a stored field would, if a caller mutates a conjunct field). The
    /// `action_completeness` JSON key serializes this; see [`ActionCompleteness::of`] for the conjunction.
    pub fn action_completeness(&self) -> ActionCompleteness {
        ActionCompleteness::of(self)
    }

    pub fn claims(&self) -> ClaimResults {
        self.claims
    }
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

/// The lifecycle of a pinned ROLE key (the keys that ELEVATE grants/uses — broker/resource/federated/generic
/// authority), generalizing [`TrustedKey`]'s status to those keys (ADR 0006 §1). Absent ⇒ `active`. A
/// non-active status WITHDRAWS authority elevation for any grant/use NOT transitively committed by a verified
/// anchor at or before `status_changed_at` — so a grant signed by a compromised broker key after the
/// compromise no longer reaches `gateway_enforced` (a use of it then fails to match → violation). Like
/// `TrustedKey`, these values are AUTHORITATIVE (auditor-supplied, out of band) and override any bundle
/// self-assertion. Statuses other than `active` that trigger the withdrawal: `rotated`, `compromised`,
/// `revoked`.
#[derive(Debug, Clone, Default)]
pub struct RoleKeyStatus {
    pub status: String,
    pub status_changed_at: Option<String>,
}

/// ADR 0006 §1 — is a signature by role key `vk` HONORED under its pinned rotation lifecycle? `active` (absent
/// from `role_status`) ⇒ always. A non-active status delegates to `honored`, which encodes the ROLE's dating
/// rule over the full [`RoleKeyStatus`]. Two families:
///   * ANCHOR-COMMITTED artifacts (grant/use authority — done in item 1; cosig approvals — committed inside the
///     grant) ⇒ honored when the record was anchored before `status_changed_at`, the SAME for every non-active
///     status (the anchor is the cryptographic proof of predating). See [`honored_anchored_before`].
///   * NON-anchor-committed artifacts with a SELF-asserted time (attestation / revocation list / TSA token)
///     ⇒ a STOLEN key (`compromised`/`revoked`) can forge any timestamp, so it is NEVER honored; only a cleanly
///     `rotated` key's artifact is honored, and only if its own time is at/before the rotation. See
///     [`honored_clean_rotation`].
fn role_key_honored(
    vk: &VerifyingKey,
    role_status: &BTreeMap<[u8; 32], RoleKeyStatus>,
    honored: impl FnOnce(&RoleKeyStatus) -> bool,
) -> bool {
    match role_status.get(&vk.to_bytes()) {
        None => true,
        Some(rks) => honored(rks),
    }
}

/// ANCHOR-COMMITTED dating rule: honored when the record (`content_hash`) was transitively committed by a
/// verified anchor at/before the key's `status_changed_at` — valid for every non-active status (the anchor
/// proves the artifact predates the compromise). Fail-closed if `status_changed_at` is absent.
fn honored_anchored_before(
    rks: &RoleKeyStatus,
    content_hash: &str,
    anchored_before: &impl Fn(&str, &str) -> bool,
) -> bool {
    rks.status_changed_at
        .as_deref()
        .is_some_and(|t| anchored_before(content_hash, t))
}

/// NON-anchor-committed dating rule (self-asserted `artifact_time`): a STOLEN key (`compromised`/`revoked`)
/// can forge any timestamp, so it is NEVER honored; a cleanly `rotated` key's artifact is genuine and honored
/// iff its own time is canonical and at/before the (canonical) rotation time. Fail-closed otherwise.
fn honored_clean_rotation(rks: &RoleKeyStatus, artifact_time: &str) -> bool {
    rks.status == "rotated"
        && rks.status_changed_at.as_deref().is_some_and(|t| {
            is_canonical_ts(t) && is_canonical_ts(artifact_time) && artifact_time <= t
        })
}

#[derive(Default)]
pub struct VerifyOptions {
    /// Requested claim and evidence requirements fixed by the caller, never read from the bundle.
    pub claim_policy: ClaimPolicy,
    /// ADR 0006 §1 — out-of-band lifecycle for the authority-elevation ROLE keys, keyed by raw 32-byte public
    /// key. A key absent from this map is `active`. Consulted ONLY for the keys that elevate authority via
    /// `verify_authority` (broker/resource/federated/generic `authority_keys`); the freshness-dated roles
    /// (tsa/attestation/cosig/revocation/taxonomy) are not yet rotation-gated, so the JSON parser REJECTS a
    /// rotation directive on them rather than silently ignoring it.
    pub role_key_status: BTreeMap<[u8; 32], RoleKeyStatus>,
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
    /// DISTINCT keys in this set produced a valid `averin.broker.cosig.approval.v1` cosignature over it;
    /// otherwise the grant is NOT indexed (its use reads as `unmatched_violation`). Role-separated — a
    /// FATAL config error on overlap with ANY other role (broker/resource/taxonomy/attestation/tsa) and
    /// with the generic `authority_keys`, so an approver cannot self-approve via another hat. Absent ⇒ a
    /// cosigned grant has zero countable approvers and is fail-closed (the governance keys must be pinned
    /// to trust the governance).
    pub cosig_approver_keys: Vec<VerifyingKey>,
    /// Trusted REVOCATION-LIST issuer keys (ADR 0005 M5). A bundle's top-level `revocation_list` is evaluated
    /// ONLY when its `sig` verifies under one of these. Role-separated — a FATAL config error on overlap with
    /// ANY other role (broker/resource/taxonomy/attestation/tsa/cosig) and with the generic `authority_keys`,
    /// so a broker cannot sign its own revocation list. Absent ⇒ `revocation_status` stays `absent` (a present
    /// list is not evaluated — the operator must pin the revocation authority to honor revocations).
    pub revocation_keys: Vec<VerifyingKey>,
    /// M4 / ADR 0005 (Federation — per-`broker_id` authority pinning). OPTIONAL: when non-empty, the operator has
    /// pinned a SEPARATE broker authority key set PER `broker_id`. A federated grant (one carrying a non-empty
    /// signed `grant_evidence.broker_id`) then elevates its `evidence_sig` to `verified` ONLY under ITS OWN
    /// broker_id's key set here — a `broker_id` with no entry does NOT elevate (fail-closed; never under another
    /// broker's keys or the union), so broker B cannot issue grants in broker A's name. A grant with NO `broker_id`
    /// (non-federated) still elevates under `broker_authority_keys`. When this map is EMPTY (the default), ALL
    /// broker grants elevate under `broker_authority_keys` — the "brokers share one pinned root" baseline the ADR
    /// permits. The R2 disjointness is enforced against the UNION of `broker_authority_keys` and every per-broker
    /// set: every OTHER role (resource/taxonomy/attestation/tsa/cosig/revocation/generic-authority) must be
    /// disjoint from that union (a FATAL config error otherwise); distinct brokers MAY share a key.
    pub federated_broker_keys: BTreeMap<String, Vec<VerifyingKey>>,
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
    /// ADR 0006 §1: the NON-ACTIVE rotation lifecycles of every pinned key this record's authority elevation
    /// depends on — the verifying authority/subject key AND (transitive) the cross_broker_cert issuer key.
    /// Resolved in pass-1 (the keys are known there); the anchored-before withdrawal is GATED in pass-2 where
    /// the anchored set is known. Empty ⇒ every involved key is active (or authority not Verified).
    authority_role_statuses: Vec<RoleKeyStatus>,
    broker_role: BrokerRole,
    /// M4 (ADR 0005): this grant's authority verified ONLY via a cross_broker_cert (the subject broker was not
    /// directly pinned). Counted for observability; the grant is otherwise treated as any verified broker grant.
    transitive_authority: bool,
    notes: Vec<String>,
}

/// Per-checkpoint pre-pass result (see the checkpoint loop in `verify_bundle_with`): the seal check under the
/// resolved (and, under pinning, trusted) key (`None` = no usable key), the RCP §10.2 gate for a non-active
/// signing key (`(effective status, authoritative status_changed_at)`, `None` = active/retired), and — only on a
/// sealed checkpoint with TSA trust pinned — the anchor check (`(genTime, test-anchor TSA key)`).
struct CpPre {
    seal: Option<Result<(), crate::checkpoint::CheckpointError>>,
    gate: Option<(String, Option<String>)>,
    anchor: Option<Result<(String, Option<VerifyingKey>), String>>,
}

/// A record's broker/resource role (ADR 0003 R2), classified fail-closed from the
/// `(extensions.broker.kind, authority.enforcement_point)` discriminator. `None` means the record
/// does not claim a recognized Tier-B role (a plain record, or a fail-closed misclassification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerRole {
    Broker,
    Resource,
    /// An operator-voided broker_seq (a signed `grant_void` tombstone, `(grant_void, credential_broker)`): it fills
    /// its seq in the D6/M4 transparency log so a reserved-but-never-recorded seq stops wedging the gapless prefix,
    /// but it is NEVER a grant — not counted, not joinable by a use, never Tier-B eligible (see `check_grant_voids`).
    Void,
    None,
}

impl BrokerRole {
    fn as_str(self) -> &'static str {
        match self {
            BrokerRole::Broker => "broker",
            BrokerRole::Resource => "resource",
            BrokerRole::Void => "grant_void",
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
        (Some("grant_void"), Some("credential_broker")) => BrokerRole::Void,
        // D5 (ADR 0004): a two-phase use is a `use_intent` (recorded BEFORE the side effect) + a
        // `use_outcome` (AFTER); both are resource-signed records under the tool gateway, alongside the
        // one-phase `use` (ADR 0003, still accepted for back-compat).
        (Some("use"), Some("tool_gateway"))
        | (Some("use_intent"), Some("tool_gateway"))
        | (Some("use_outcome"), Some("tool_gateway")) => BrokerRole::Resource,
        // M3 (ADR 0005): a resource-signed introspection transcript (its statement of an externally-minted
        // credential's effective scope) is a RESOURCE-role record — so its `evidence_sig` elevates under
        // `resource_authority_keys` (R2). It is NOT a use receipt: the use-loop SKIPS it and the M3 pre-pass
        // handles it (binding it to a native grant + checking `effective_scope ⊆ grant.scope`).
        (Some("introspection_transcript"), Some("tool_gateway")) => BrokerRole::Resource,
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
/// validation (adversarial review D7) also stops a signed-but-malformed attestation window like `2026-99-99T99:99:99.999Z`
/// from passing the freshness check. (Day is 01-31, not month-length/leap-aware — impossible values are
/// rejected; a harmless 02-30 is not, which does not affect ordering.)
fn is_canonical_ts(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 24 {
        return false;
    }
    let digit = |i: usize| b[i].is_ascii_digit();
    let shape = (0..4).all(digit)
        && b[4] == b'-'
        && digit(5)
        && digit(6)
        && b[7] == b'-'
        && digit(8)
        && digit(9)
        && b[10] == b'T'
        && digit(11)
        && digit(12)
        && b[13] == b':'
        && digit(14)
        && digit(15)
        && b[16] == b':'
        && digit(17)
        && digit(18)
        && b[19] == b'.'
        && digit(20)
        && digit(21)
        && digit(22)
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
        ("claims_version".into(), CanonValue::string("1")),
        ("claims".into(), r.claims.to_canon()),
        ("project_id".into(), opt_str(&r.project_id)),
        (
            "keys_externally_pinned".into(),
            CanonValue::Bool(r.keys_externally_pinned),
        ),
        (
            "body_bound_role_evidence".into(),
            CanonValue::Bool(r.body_bound_role_evidence),
        ),
        ("records_total".into(), count(r.records_total)),
        ("records_proven".into(), count(r.records_proven)),
        ("dag_ok".into(), CanonValue::Bool(r.dag_ok)),
        ("dag_heads".into(), count(r.dag_heads)),
        ("collapsed_duplicates".into(), count(r.collapsed_duplicates)),
        ("checkpoints_total".into(), count(r.checkpoints_total)),
        ("checkpoints_verified".into(), count(r.checkpoints_verified)),
        ("checkpoints_anchored".into(), count(r.checkpoints_anchored)),
        (
            "checkpoints_anchors_attached".into(),
            count(r.checkpoints_anchors_attached),
        ),
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
        ("uses_pop_reverified".into(), count(r.uses_pop_reverified)),
        ("unmatched_violation".into(), count(r.unmatched_violation)),
        ("unmatched_pending".into(), count(r.unmatched_pending)),
        (
            "intent_without_outcome".into(),
            count(r.intent_without_outcome),
        ),
        ("grants_unused".into(), count(r.grants_unused)),
        ("bounded_reuse_grants".into(), count(r.bounded_reuse_grants)),
        (
            "bounded_reuse_overspent".into(),
            count(r.bounded_reuse_overspent),
        ),
        (
            "bounded_reuse_seq_replays".into(),
            count(r.bounded_reuse_seq_replays),
        ),
        // M6 (ADR 0005): cosig (M-of-N grant approval) accounting + the artifact-level status.
        (
            "cosigned_grants_total".into(),
            count(r.cosigned_grants_total),
        ),
        (
            "cosigned_grants_satisfied".into(),
            count(r.cosigned_grants_satisfied),
        ),
        (
            "cosig_threshold_failures".into(),
            count(r.cosig_threshold_failures),
        ),
        (
            "cosig_status".into(),
            CanonValue::string(r.cosig_status.clone()),
        ),
        // M2 (ADR 0005): delegation (per-hop signed re-delegation) accounting + artifact status.
        (
            "delegation_chains_total".into(),
            count(r.delegation_chains_total),
        ),
        (
            "delegation_chains_verified".into(),
            count(r.delegation_chains_verified),
        ),
        (
            "delegation_monotonicity_violations".into(),
            count(r.delegation_monotonicity_violations),
        ),
        (
            "delegation_status".into(),
            CanonValue::string(r.delegation_status.clone()),
        ),
        // M5 (ADR 0005): revocation (tiered signed-list) status + counts.
        (
            "revocation_status".into(),
            CanonValue::string(r.revocation_status.clone()),
        ),
        (
            "revoked_grants_matched".into(),
            count(r.revoked_grants_matched),
        ),
        ("revoked_uses_blocked".into(), count(r.revoked_uses_blocked)),
        (
            "revocation_merkle_status".into(),
            CanonValue::string(r.revocation_merkle_status.clone()),
        ),
        (
            "revocation_nonmembership_verified".into(),
            count(r.revocation_nonmembership_verified),
        ),
        // M3 (ADR 0005): native/STS introspection-transcript accounting + the artifact-level status.
        (
            "native_credential_present".into(),
            CanonValue::Bool(r.native_credential_present),
        ),
        (
            "introspection_transcripts_total".into(),
            count(r.introspection_transcripts_total),
        ),
        (
            "introspection_transcripts_verified".into(),
            count(r.introspection_transcripts_verified),
        ),
        (
            "introspection_scope_narrowed".into(),
            count(r.introspection_scope_narrowed),
        ),
        (
            "introspection_status".into(),
            CanonValue::string(r.introspection_status.clone()),
        ),
        // M4 (ADR 0005): federation (per-broker_id grant-transparency partition) status + counts.
        (
            "federation_status".into(),
            CanonValue::string(r.federation_status.clone()),
        ),
        ("brokers_total".into(), count(r.brokers_total)),
        ("brokers_seq_verified".into(), count(r.brokers_seq_verified)),
        (
            "cross_broker_suppression".into(),
            count(r.cross_broker_suppression),
        ),
        ("transitive_grants".into(), count(r.transitive_grants)),
        (
            "per_broker_trust".into(),
            CanonValue::Array(
                r.per_broker_trust
                    .iter()
                    .map(|(bid, trust)| {
                        CanonValue::object(vec![
                            ("broker_id".into(), CanonValue::string(bid.clone())),
                            ("trust".into(), CanonValue::string(trust.clone())),
                        ])
                        .unwrap()
                    })
                    .collect(),
            ),
        ),
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
        (
            "attestation_issuer_kid".into(),
            opt_str(&r.attestation_issuer_kid),
        ),
        (
            "attestation_issued_at".into(),
            opt_str(&r.attestation_issued_at),
        ),
        (
            "attestation_not_after".into(),
            opt_str(&r.attestation_not_after),
        ),
        (
            "attestation_claim_types".into(),
            str_array(&r.attestation_claim_types),
        ),
        (
            "attestation_subject_digest".into(),
            opt_str(&r.attestation_subject_digest),
        ),
        // D8 (ADR 0004) — the `attested_complete` capstone, now derived by the typed
        // [`VerifyReport::action_completeness`] / [`ActionCompleteness::of`] (see its doc for the full
        // conjunction + the M1–M6 conjuncts). Recomputed here from the report, byte-identical to the prior
        // inline block — deriving at serialization (not caching a field) keeps it from ever going stale.
        (
            "action_completeness".into(),
            CanonValue::string(r.action_completeness().as_str()),
        ),
        // MF1: the resource-truthful-labeling conditional, ALWAYS present so the capstone can never be read
        // as "everything the agent did" — only "everything over the brokered surface, IF the resource
        // labeled it truthfully" (the irreducible resource TCB, D9).
        (
            "resource_trust".into(),
            CanonValue::string(r.resource_trust.clone()),
        ),
        (
            "coverage_manifest".into(),
            r.coverage_manifest.clone().unwrap_or(CanonValue::Null),
        ),
        (
            "unclosed_side_effects".into(),
            count(r.unclosed_side_effects),
        ),
        (
            "side_effect_closure_status".into(),
            CanonValue::string(r.side_effect_closure_status.clone()),
        ),
        ("issues".into(), str_array(&r.issues)),
        ("first_broken_link".into(), opt_str(&r.first_broken_link)),
        ("record_trust".into(), CanonValue::Array(records)),
    ])
    .unwrap()
}

pub fn report_to_json(r: &VerifyReport) -> String {
    report_to_canon(r).serialize()
}

/// Serialize the report with a `bundle_digest` = sha256 of the EXACT input bytes verified, bound in at the JSON
/// boundary (the only place the raw input exists). This makes an `ok:true` report un-detachable from its artifact:
/// a verdict pasted next to a DIFFERENT bundle is detectable (the bundle's own digest won't match). It is the raw
/// input, not the canonical form, so it binds the literal bytes an auditor supplied.
fn report_json_with_digest(r: &VerifyReport, input_bytes: &[u8]) -> String {
    let mut canon = report_to_canon(r);
    if let CanonValue::Object(ref mut fields) = canon {
        fields.push((
            "bundle_digest".into(),
            CanonValue::string(crate::hashx::sha256_prefixed(input_bytes)),
        ));
    }
    canon.serialize()
}

/// DoS backstop: the maximum input bundle the FFI/WASM/CLI verify entrypoints will process. The verifier runs on
/// an UNTRUSTED, attacker-supplied artifact, and its work is ~O(input bytes) (parse + per-record verify + per-hop
/// signature checks), so an uncapped multi-GB bundle is a memory/CPU amplification on the relying party. 256 MiB
/// is far above any realistic export yet bounds a hostile one; an over-cap input fails closed before parse.
pub const MAX_BUNDLE_BYTES: usize = 256 << 20;

fn over_cap_report(len: usize) -> String {
    CanonValue::object(vec![
        ("ok".into(), CanonValue::Bool(false)),
        ("error".into(), CanonValue::string(format!("bundle is {len} bytes, exceeding the {MAX_BUNDLE_BYTES}-byte verify cap (DoS backstop) — fail-closed"))),
    ])
    .unwrap()
    .serialize()
}

/// Verify a bundle JSON string and return the report as a JSON string (the shape WASM/FFI return).
pub fn verify_bundle_to_json(text: &str) -> String {
    if text.len() > MAX_BUNDLE_BYTES {
        return over_cap_report(text.len());
    }
    match verify_bundle_json(text) {
        Ok(r) => report_json_with_digest(&r, text.as_bytes()),
        Err(e) => CanonValue::object(vec![
            ("ok".into(), CanonValue::Bool(false)),
            ("error".into(), CanonValue::string(e.to_string())),
            (
                "bundle_digest".into(),
                CanonValue::string(crate::hashx::sha256_prefixed(text.as_bytes())),
            ),
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
/// optional arrays: `authority_keys`/`tsa_keys` are `ed25519pub:` strings (or rotation objects, ADR 0006);
/// `signing_keys` are `ed25519pub:` strings or `{key,status,status_changed_at}` objects (see
/// `parse_signing_keys`); `tsa_spki_b64` are base64url-no-pad DER SubjectPublicKeyInfos.
pub fn verify_bundle_with_json(bundle_text: &str, opts_text: &str) -> String {
    if bundle_text.len() > MAX_BUNDLE_BYTES {
        return over_cap_report(bundle_text.len());
    }
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
    // ADR 0006 §1: the authority-elevation roles accept a string-OR-object rotation form; their lifecycle is
    // collected here (keyed by raw key bytes) and consulted at the pass-2 elevation gate. The record-signing
    // keys take their own RCP §10.2 object form (`parse_signing_keys` — key_status vocabulary, not `rotated`).
    let mut role_key_status: BTreeMap<[u8; 32], RoleKeyStatus> = BTreeMap::new();
    let authority = match parse_role_pubkeys(&opts_val, "authority_keys", &mut role_key_status) {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let broker_authority =
        match parse_role_pubkeys(&opts_val, "broker_authority_keys", &mut role_key_status) {
            Ok(k) => k,
            Err(e) => return error_report(&e),
        };
    let resource_authority =
        match parse_role_pubkeys(&opts_val, "resource_authority_keys", &mut role_key_status) {
            Ok(k) => k,
            Err(e) => return error_report(&e),
        };
    // ADR 0006 §1: taxonomy issuers accept the rotation object form (compromised/revoked → untrusted; rotated
    // keeps the digest-pinned taxonomy valid — defense-in-depth atop the dominant digest pin).
    let taxonomy_keys = match parse_role_pubkeys(&opts_val, "taxonomy_keys", &mut role_key_status) {
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
    // ADR 0006 §1: test-anchor TSA keys accept the rotation object form (a compromised TSA mints any genTime →
    // its anchors are never honored). RFC 3161 SPKIs (tsa_spki_b64) are not ed25519 role keys — out of scope.
    let tsa_keys = match parse_role_pubkeys(&opts_val, "tsa_keys", &mut role_key_status) {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let tsa_spki = match parse_spki(&opts_val, "tsa_spki_b64") {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    let signing = match parse_signing_keys(&opts_val) {
        Ok(k) => k,
        Err(e) => return error_report(&e),
    };
    // D7.2: pinned deployment-attestation issuer keys (so the JSON/FFI path — used by the Go server and any
    // external auditor — can elevate `attestation_status` to `attested_claims`, not just the direct Rust API).
    // ADR 0006 §1: attestation issuers accept the rotation object form (compromised/revoked → never honored;
    // cleanly rotated → honored only for an attestation issued at/before the rotation).
    let attestation_keys =
        match parse_role_pubkeys(&opts_val, "attestation_keys", &mut role_key_status) {
            Ok(k) => k,
            Err(e) => return error_report(&e),
        };
    // M6 (ADR 0005): pinned cosignature-approver keys, so the JSON/FFI path (the Go server + any external
    // auditor) can enforce M-of-N grant approval, not just the direct Rust API.
    // ADR 0006 §1: revocation issuers accept the rotation object form (a non-active issuer can't certify
    // currency → stale; the disclosed revocations still block).
    let revocation_keys =
        match parse_role_pubkeys(&opts_val, "revocation_keys", &mut role_key_status) {
            Ok(k) => k,
            Err(e) => return error_report(&e),
        };
    // ADR 0006 §1: cosig approvers accept the rotation object form (a compromised approver's approvals stop
    // counting for grants anchored after the compromise).
    let cosig_approver_keys =
        match parse_role_pubkeys(&opts_val, "cosig_approver_keys", &mut role_key_status) {
            Ok(k) => k,
            Err(e) => return error_report(&e),
        };
    // M4 (ADR 0005): optional per-`broker_id` authority key map, so the JSON/FFI path (the Go server + any
    // external auditor) can pin per-broker federation authority, not just the direct Rust API.
    let federated_broker_keys =
        match parse_pubkey_map(&opts_val, "federated_broker_keys", &mut role_key_status) {
            Ok(m) => m,
            Err(e) => return error_report(&e),
        };
    let opts = VerifyOptions {
        claim_policy: match ClaimPolicy::parse(&opts_val) {
            Ok(p) => p,
            Err(e) => return error_report(&e),
        },
        trusted_authority_keys: authority,
        broker_authority_keys: broker_authority,
        resource_authority_keys: resource_authority,
        federated_broker_keys,
        role_key_status,
        taxonomy: opts_val.get("taxonomy").cloned(),
        taxonomy_keys,
        taxonomy_digest,
        taxonomy_version,
        trusted_tsa_keys: tsa_keys,
        trusted_tsa_spki: tsa_spki,
        attestation_keys,
        cosig_approver_keys,
        revocation_keys,
        trusted_keys: signing,
    };
    report_json_with_digest(&verify_bundle_with(&bundle, &opts), bundle_text.as_bytes())
}

/// Parse the pinned RECORD-SIGNING keys (`signing_keys`) into [`TrustedKey`]s. Each element is an `ed25519pub:`
/// string (no out-of-band status) OR an object `{"key":"ed25519pub:…","status":"active"|"retired"|"revoked"|
/// "compromised","status_changed_at":"…"}` carrying the AUTHORITATIVE RCP §10.2 key status + compromise time
/// (the same override the Rust [`TrustedKey`] API has — previously unreachable from JSON/CLI/FFI). Absent/null ⇒
/// `None` (unpinned: internal consistency only). Fail-closed: an EMPTY array is a config error (it used to fall
/// back silently to UNPINNED verification — the opposite of what a caller who supplied the field asked for), as
/// is a malformed key, an unknown field or status (never silently active), or a non-string field.
fn parse_signing_keys(opts: &CanonValue) -> Result<Option<Vec<TrustedKey>>, String> {
    const KEY: &str = "signing_keys";
    let arr = match opts.get(KEY) {
        None | Some(CanonValue::Null) => return Ok(None),
        Some(v) => v.as_array().ok_or_else(|| {
            format!("{KEY} must be an array of ed25519pub: strings or {{key,status,status_changed_at}} objects")
        })?,
    };
    if arr.is_empty() {
        return Err(format!(
            "{KEY} is present but empty — pinning no signing key would silently verify UNPINNED; omit the field for internal-consistency-only verification"
        ));
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let ctx = format!("{KEY}[{i}]");
        if let Some(s) = v.as_str() {
            let vk = decode_pubkey(s)
                .map_err(|e| format!("{ctx} is not a valid ed25519pub key: {e}"))?;
            out.push(TrustedKey::from(vk));
            continue;
        }
        let obj = v.as_object().ok_or_else(|| {
            format!(
                "{ctx} must be an ed25519pub: string or a {{key,status,status_changed_at}} object"
            )
        })?;
        for (k, _) in obj {
            if !matches!(k.as_str(), "key" | "status" | "status_changed_at") {
                return Err(format!(
                    "{ctx} has unknown field {k:?} (allowed: key, status, status_changed_at)"
                ));
            }
        }
        let ks = v
            .get("key")
            .and_then(|k| k.as_str())
            .ok_or_else(|| format!("{ctx}.key must be an ed25519pub: string"))?;
        let vk = decode_pubkey(ks)
            .map_err(|e| format!("{ctx}.key is not a valid ed25519pub key: {e}"))?;
        let status = match v.get("status") {
            None | Some(CanonValue::Null) => None,
            Some(sv) => {
                let st = sv
                    .as_str()
                    .ok_or_else(|| format!("{ctx}.status must be a string"))?;
                // The RCP §10.2 key_status vocabulary (NOT the role-key `rotated`).
                if !matches!(st, "active" | "retired" | "revoked" | "compromised") {
                    return Err(format!(
                        "{ctx}.status {st:?} is not one of active|retired|revoked|compromised"
                    ));
                }
                Some(st.to_string())
            }
        };
        let status_changed_at = match v.get("status_changed_at") {
            None | Some(CanonValue::Null) => None,
            Some(cv) => Some(
                cv.as_str()
                    .map(String::from)
                    .ok_or_else(|| format!("{ctx}.status_changed_at must be a string"))?,
            ),
        };
        out.push(TrustedKey {
            vk,
            status,
            status_changed_at,
        });
    }
    Ok(Some(out))
}

/// Parse ONE authority-elevation role-key element (ADR 0006 §1 rotation): an `ed25519pub:` string (status
/// `active`) OR an object `{"key":"ed25519pub:…","status":"compromised"|"rotated"|"revoked"|"active",
/// "status_changed_at":"…"}`. `ctx` is the error-location prefix. A non-active status is recorded in `status`
/// keyed by the raw 32-byte key. Fail-closed: a malformed key, an UNKNOWN status (NEVER silently read as
/// active), or a non-string field is an Err.
fn parse_one_role_key(
    v: &CanonValue,
    ctx: &str,
    status: &mut BTreeMap<[u8; 32], RoleKeyStatus>,
) -> Result<VerifyingKey, String> {
    if let Some(s) = v.as_str() {
        return decode_pubkey(s).map_err(|e| format!("{ctx} is not a valid ed25519pub key: {e}"));
    }
    let obj = match v.as_object() {
        Some(o) => o,
        None => {
            return Err(format!(
                "{ctx} must be an ed25519pub: string or a {{key,status,status_changed_at}} object"
            ))
        }
    };
    // Fail-closed on an UNKNOWN/misspelled field (e.g. "statuss"): silently dropping it would lose the
    // auditor's compromise pin (the key would read as active). Only these three keys are allowed.
    for (k, _) in obj {
        if !matches!(k.as_str(), "key" | "status" | "status_changed_at") {
            return Err(format!(
                "{ctx} has unknown field {k:?} (allowed: key, status, status_changed_at)"
            ));
        }
    }
    let ks = v
        .get("key")
        .and_then(|k| k.as_str())
        .ok_or_else(|| format!("{ctx}.key must be an ed25519pub: string"))?;
    let vk =
        decode_pubkey(ks).map_err(|e| format!("{ctx}.key is not a valid ed25519pub key: {e}"))?;
    let st = match v.get("status") {
        None | Some(CanonValue::Null) => "active".to_string(),
        Some(sv) => sv
            .as_str()
            .map(String::from)
            .ok_or_else(|| format!("{ctx}.status must be a string"))?,
    };
    if !matches!(
        st.as_str(),
        "active" | "rotated" | "compromised" | "revoked"
    ) {
        return Err(format!(
            "{ctx}.status {st:?} is not one of active|rotated|compromised|revoked"
        ));
    }
    let changed = match v.get("status_changed_at") {
        None | Some(CanonValue::Null) => None,
        Some(cv) => Some(
            cv.as_str()
                .map(String::from)
                .ok_or_else(|| format!("{ctx}.status_changed_at must be a string"))?,
        ),
    };
    // Only a NON-active status needs recording; an explicit "active" entry is the same as a bare key.
    if st != "active" {
        status.insert(
            vk.to_bytes(),
            RoleKeyStatus {
                status: st,
                status_changed_at: changed,
            },
        );
    }
    Ok(vk)
}

/// Parse an AUTHORITY-ELEVATION role-key array (broker/resource/generic authority), each element via
/// [`parse_one_role_key`]. Returns the bare key vector (so the existing membership-based elevation is
/// unchanged) and populates the rotation lifecycle in `status` out of band.
fn parse_role_pubkeys(
    opts: &CanonValue,
    key: &str,
    status: &mut BTreeMap<[u8; 32], RoleKeyStatus>,
) -> Result<Vec<VerifyingKey>, String> {
    let arr = match opts.get(key) {
        None | Some(CanonValue::Null) => return Ok(Vec::new()),
        Some(v) => v.as_array().ok_or_else(|| {
            format!("{key} must be an array of ed25519pub: strings or {{key,status,status_changed_at}} objects")
        })?,
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        out.push(parse_one_role_key(v, &format!("{key}[{i}]"), status)?);
    }
    Ok(out)
}

/// M4 (ADR 0005): parse an optional MAP `{<broker_id>: [ed25519pub: …]}` (per-broker authority key sets).
/// Absent ⇒ empty; present-but-malformed (not an object, or any value not an array of valid keys) ⇒ Err
/// (fail-closed). An empty `broker_id` key is rejected (it would collide with the non-federated default).
fn parse_pubkey_map(
    opts: &CanonValue,
    key: &str,
    status: &mut BTreeMap<[u8; 32], RoleKeyStatus>,
) -> Result<BTreeMap<String, Vec<VerifyingKey>>, String> {
    let obj = match opts.get(key) {
        None | Some(CanonValue::Null) => return Ok(BTreeMap::new()),
        Some(v) => v
            .as_object()
            .ok_or_else(|| format!("{key} must be an object {{broker_id: [ed25519pub: …]}}"))?,
    };
    let mut out = BTreeMap::new();
    for (bid, v) in obj.iter() {
        if bid.is_empty() {
            return Err(format!("{key} has an empty broker_id key (not allowed)"));
        }
        let arr = v
            .as_array()
            .ok_or_else(|| format!("{key}[{bid}] must be an array of ed25519pub: strings"))?;
        let mut keys = Vec::with_capacity(arr.len());
        for (i, e) in arr.iter().enumerate() {
            // ADR 0006 §1: per-broker federated authority keys carry the same string-or-object rotation form.
            keys.push(parse_one_role_key(
                e,
                &format!("{key}[{bid}][{i}]"),
                status,
            )?);
        }
        out.insert(bid.clone(), keys);
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
        claims: ClaimResults::fatal(),
        project_id,
        keys_externally_pinned: false,
        body_bound_role_evidence: false,
        records_total: 0,
        records_proven: 0,
        record_trust: Vec::new(),
        dag_ok: false,
        dag_heads: 0,
        collapsed_duplicates: 0,
        checkpoints_total: 0,
        checkpoints_verified: 0,
        checkpoints_anchored: 0,
        checkpoints_anchors_attached: 0,
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
        revocation_status: "absent".to_string(),
        revocation_merkle_status: "absent".to_string(),
        revocation_nonmembership_verified: 0,
        revoked_grants_matched: 0,
        revoked_uses_blocked: 0,
        native_credential_present: false,
        introspection_transcripts_total: 0,
        introspection_transcripts_verified: 0,
        introspection_scope_narrowed: 0,
        introspection_status: "absent".to_string(),
        federation_status: "absent".to_string(),
        brokers_total: 0,
        transitive_grants: 0,
        brokers_seq_verified: 0,
        cross_broker_suppression: 0,
        per_broker_trust: Vec::new(),
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

/// Re-derive a GOVDER record's `evidence_hash` and confirm it equals the signed
/// `authority.evidence_hash` (ADR 0003 R1, threat #4 — the govder analogue of
/// `evidence_rederivable` above). Without this, `authority.evidence_hash` for every govder
/// record was signed but never checked against anything: a record could carry any payload in
/// `extensions.govder.body` while the signed hash committed to different, never-shown evidence,
/// the signature would still verify, and the record would still read `verified`.
///
/// UNLIKE a broker record, govder never emits one self-contained sub-object holding exactly
/// what it hashed — `evidenceForRow` (govder/internal/averin/adapter.go) builds the evidence
/// from fields SCATTERED across the record, under DIFFERENT names than the evidence's own keys.
/// This reconstructs the identical shape from those fields, verified against a real signed
/// record (govder internal/averin's golden vector; the reconstruction below matches it exactly):
///
///   evidence key    | read from
///   ----------------|------------------------------------------------------------------
///   event_type      | extensions.govder.type   (govder's fine-grained event type string —
///                    | NOT the record's own top-level event_type, which is averin's own
///                    | coarser mapped classification and a DIFFERENT string)
///   event_id        | extensions.govder.event_id
///   agent_id        | record.agent_id           (top-level; MAY BE ABSENT from the wire —
///                    | omitempty — for an approval/sign-off record with no requester/principal;
///                    | treated as "" in that case, matching evidenceForRow, never a hard failure)
///   tenant_id       | record.project_id         (top-level — govder's tenant IS the averin
///                    | project axis)
///   outcome         | extensions.govder.outcome
///   occurred_at     | extensions.govder.occurred_at
///   previous_parent_id / attempted_new_parent_id / reverted_to_parent_id
///                    | extensions.govder.body.<key>, each OPTIONAL and included only when
///                    | present and non-empty (mirrors govder's stringFieldFromPayload; most
///                    | event types carry none of the three)
///
/// Returns false if `extensions.govder` is absent, any REQUIRED field above is missing, the
/// signed hash is absent, or the two hashes differ.
fn govder_evidence_rederivable(rec: &CanonValue) -> bool {
    let signed = match rec
        .get("authority")
        .and_then(|a| a.get("evidence_hash"))
        .and_then(|v| v.as_str())
    {
        Some(h) => h,
        None => return false,
    };
    let gov = match rec.get("extensions").and_then(|e| e.get("govder")) {
        Some(g) => g,
        None => return false,
    };
    // agent_id, unlike the fields below, may be LEGITIMATELY ABSENT from the wire: govder's
    // Record.AgentID carries `json:",omitempty"`, and an approval/sign-off record with neither
    // a Requester nor a Principal set (runtime/seals.go firstNonEmpty) seals with an empty
    // agent_id — which evidenceForRow (adapter.go) includes verbatim either way (pair("agent_id",
    // row.AgentID), never conditionally omitted). Treating an absent key here as a hard failure
    // would reject every such record even though govder signed it correctly (measured: this
    // broke govder's own approval sign-off test suite before the fix — see the golden vector
    // test below, which does NOT cover this case on its own since its fixture happens to carry
    // a non-empty agent_id).
    let agent_id = s(rec, "agent_id").unwrap_or_default();
    let tenant_id = match s(rec, "project_id") {
        Some(v) => v,
        None => return false,
    };
    let event_type = match s(gov, "type") {
        Some(v) => v,
        None => return false,
    };
    let event_id = match s(gov, "event_id") {
        Some(v) => v,
        None => return false,
    };
    let outcome = match s(gov, "outcome") {
        Some(v) => v,
        None => return false,
    };
    let occurred_at = match s(gov, "occurred_at") {
        Some(v) => v,
        None => return false,
    };
    let mut pairs = vec![
        ("event_type".to_string(), CanonValue::string(event_type)),
        ("event_id".to_string(), CanonValue::string(event_id)),
        ("agent_id".to_string(), CanonValue::string(agent_id)),
        ("tenant_id".to_string(), CanonValue::string(tenant_id)),
        ("outcome".to_string(), CanonValue::string(outcome)),
        ("occurred_at".to_string(), CanonValue::string(occurred_at)),
    ];
    let body = gov.get("body");
    for key in [
        "previous_parent_id",
        "attempted_new_parent_id",
        "reverted_to_parent_id",
    ] {
        if let Some(v) = body.and_then(|b| s(b, key)).filter(|v| !v.is_empty()) {
            pairs.push((key.to_string(), CanonValue::string(v)));
        }
    }
    let evidence = match CanonValue::object(pairs) {
        Ok(v) => v,
        Err(_) => return false,
    };
    crate::hashx::sha256_prefixed(evidence.serialize().as_bytes()) == signed
}

/// Length-prefixed framing (LP4) shared by EVERY broker/resource challenge + Merkle-leaf preimage below: a
/// 4-byte big-endian length prefix then the bytes. Defined ONCE (was re-inlined as a per-function closure or
/// loop ~8×) so the framing rule lives in a single place — a divergent copy would silently break the
/// producer↔verifier byte-identity the shared golden vectors enforce.
#[inline]
fn lp4(pre: &mut Vec<u8>, b: &[u8]) {
    pre.extend_from_slice(&(b.len() as u32).to_be_bytes());
    pre.extend_from_slice(b);
}

/// 8-byte big-endian integer (BE8) — the companion numeric framing for those same challenges.
#[inline]
fn be8(pre: &mut Vec<u8>, n: u64) {
    pre.extend_from_slice(&n.to_be_bytes());
}

/// Re-derive the resource ledger_commitment (ADR 0003 R5 / ADR 0004 D3) the SAME way the resource
/// shim does: `sha256( LP4("averin.broker.use.ledger.v1") ‖ LP4(jti) ‖ LP4(nonce) ‖ BE8(used_at) )`,
/// where LP4 is a 4-byte big-endian length prefix and BE8 an 8-byte big-endian integer. Returns
/// `sha256:<lowercase hex>`. Kept byte-identical to Go `resourceshim.ledgerCommitment` via the SHARED
/// golden vector `spec/golden-vectors/broker-preimages.json` — loaded by BOTH Go
/// `TestLedgerCommitmentGoldenVector` and Rust `ledger_commitment_golden_vector`, so a drift in either
/// implementation breaks both suites against the one file (not two independently-hardcoded copies).
pub fn ledger_commitment(jti: &str, nonce: &str, used_at: i64) -> String {
    crate::hashx::sha256_prefixed(&ledger_commitment_preimage(jti, nonce, used_at))
}

/// Exact bytes hashed by the production ledger commitment builder.
#[doc(hidden)]
pub fn ledger_commitment_preimage(jti: &str, nonce: &str, used_at: i64) -> Vec<u8> {
    let mut pre = Vec::new();
    for part in ["averin.broker.use.ledger.v1", jti, nonce] {
        lp4(&mut pre, part.as_bytes());
    }
    be8(&mut pre, used_at as u64);
    pre
}

/// Cumulative grant-transparency root (ADR 0004 D6 / MF2): a hash-CHAIN over a broker's grant log,
/// folding `(broker_seq, grant content_hash)` pairs **in ascending `broker_seq` order**. Byte-identical
/// to Go `broker.GrantHeadRoot`, so the offline verifier re-derives the `cumulative_root` an anchored
/// checkpoint's `broker_grant_head` carries and a dropped/renumbered/forked grant fails the match.
///
/// `acc_0 = sha256( LP4(tag) )`; `acc_i = sha256( LP4(tag) ‖ acc_{i-1}(32 raw bytes) ‖ BE8(seq_i) ‖
/// LP4(content_hash_i) )`, tag = "averin.broker.grant_head.v1". The caller MUST pass the pairs already
/// sorted by `broker_seq` (the verifier sorts the closed grant set; the producer folds in issue order).
/// Returns `sha256:<hex>` of the final accumulator. The empty log has a well-defined non-zero root.
pub fn grant_head_root(grants: &[(i64, String)]) -> String {
    let mut acc = crate::hashx::sha256(&grant_head_seed_preimage());
    for (seq, content_hash) in grants {
        acc = crate::hashx::sha256(&grant_head_step_preimage(&acc, *seq, content_hash));
    }
    format!("sha256:{}", crate::hashx::hex_lower(&acc))
}

/// Exact seed bytes hashed by the production grant-head chain.
#[doc(hidden)]
pub fn grant_head_seed_preimage() -> Vec<u8> {
    let mut seed = Vec::new();
    lp4(&mut seed, b"averin.broker.grant_head.v1");
    seed
}

/// Exact per-step bytes hashed by the production grant-head chain.
#[doc(hidden)]
pub fn grant_head_step_preimage(acc: &[u8; 32], seq: i64, content_hash: &str) -> Vec<u8> {
    let mut pre = grant_head_seed_preimage();
    pre.extend_from_slice(acc); // raw 32-byte accumulator, NOT length-prefixed
    be8(&mut pre, seq as u64);
    lp4(&mut pre, content_hash.as_bytes());
    pre
}

/// M5 Merkle-non-disclosure revocation (ADR 0005): the domain-separated leaf VALUE for a (possibly) revoked
/// grant_id: `sha256( LP4("averin.broker.revocation.leaf.v1") ‖ LP4(grant_id) )`. The revocation tree's leaves are
/// the SORTED set of these 32-byte values, bracketed by the MIN (0x00*32) / MAX (0xff*32) sentinels so EVERY
/// queried id has a strictly-bracketing CONSECUTIVE pair (eliminating the first/last edge case). A
/// non-membership proof reveals only the two adjacent leaf VALUES (hashes), never the full revoked list — the
/// non-disclosure win. Kept in sync with the Go producer via the shared golden vector.
pub fn revocation_leaf(grant_id: &str) -> [u8; 32] {
    crate::hashx::sha256(&revocation_leaf_preimage(grant_id))
}

/// Exact bytes hashed by the production revocation-leaf builder.
#[doc(hidden)]
pub fn revocation_leaf_preimage(grant_id: &str) -> Vec<u8> {
    let mut pre = Vec::new();
    lp4(&mut pre, b"averin.broker.revocation.leaf.v1");
    lp4(&mut pre, grant_id.as_bytes());
    pre
}

/// M5 Merkle-non-disclosure (ADR 0005): the canonical Merkle ROOT (`sha256:<hex>`) the revocation authority
/// signs, over the SORTED, sentinel-bracketed set of `revocation_leaf(grant_id)` values. A PRODUCER reference
/// (the verifier checks proofs against the SIGNED root, never recomputing the whole tree) — kept in sync with
/// the Go producer via the shared golden vector. Leaves = `[MIN(0x00*32)] ++ sorted(leaf hashes) ++ [MAX(0xff*32)]`;
/// the tree folds RFC6962-style (`merkle_leaf_hash` for the 0x00 leaves, `merkle_node_hash` for 0x01 nodes, an
/// odd level promotes its last node).
pub fn revocation_merkle_root(revoked: &[&str]) -> String {
    let mut hs: Vec<[u8; 32]> = revoked.iter().map(|g| revocation_leaf(g)).collect();
    hs.sort();
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(hs.len() + 2);
    leaves.push([0u8; 32]);
    leaves.extend(hs);
    leaves.push([0xffu8; 32]);
    let mut level: Vec<[u8; 32]> = leaves.iter().map(merkle_leaf_hash).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(merkle_node_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(level[i]); // promote the last (odd) node
                i += 1;
            }
        }
        level = next;
    }
    format!("sha256:{}", crate::hashx::hex_lower(&level[0]))
}

/// RFC6962-style domain-separated Merkle LEAF hash: `sha256( 0x00 ‖ leaf_value )`. The 0x00 prefix separates
/// leaves from internal nodes so a leaf hash can never be reinterpreted as an interior node (a second-preimage
/// guard standard to transparency logs).
fn merkle_leaf_hash(v: &[u8; 32]) -> [u8; 32] {
    crate::hashx::sha256(&merkle_leaf_preimage(v))
}

/// Exact bytes hashed for an RFC6962 revocation-tree leaf.
#[doc(hidden)]
pub fn merkle_leaf_preimage(v: &[u8; 32]) -> Vec<u8> {
    let mut pre = Vec::with_capacity(33);
    pre.push(0x00);
    pre.extend_from_slice(v);
    pre
}

/// RFC6962-style internal Merkle NODE: `sha256( 0x01 ‖ left ‖ right )`.
fn merkle_node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    crate::hashx::sha256(&merkle_node_preimage(l, r))
}

/// Exact bytes hashed for an RFC6962 revocation-tree node.
#[doc(hidden)]
pub fn merkle_node_preimage(l: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    let mut pre = Vec::with_capacity(65);
    pre.push(0x01);
    pre.extend_from_slice(l);
    pre.extend_from_slice(r);
    pre
}

/// Recompute the Merkle root from an inclusion proof (RFC6962 audit path; an odd level PROMOTES its last node,
/// consuming NO path entry). `leaf_value` is the 32-byte leaf VALUE at `index` in a tree of `size` leaves;
/// `path` is the audit path (bottom-up siblings). Returns `None` on ANY inconsistency — index out of range, a
/// path entry missing, or an UNCONSUMED path entry (a too-long path) — so a malformed proof is fail-closed, not
/// a recomputed-but-wrong root. The caller compares the result to the signed root.
fn merkle_root_from_proof(
    leaf_value: &[u8; 32],
    index: usize,
    size: usize,
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if size == 0 || index >= size {
        return None;
    }
    let mut hash = merkle_leaf_hash(leaf_value);
    let mut idx = index;
    let mut last = size - 1;
    let mut it = path.iter();
    while last > 0 {
        if idx % 2 == 1 {
            // right child: the sibling is on the LEFT.
            hash = merkle_node_hash(it.next()?, &hash);
        } else if idx < last {
            // left child WITH a right sibling.
            hash = merkle_node_hash(&hash, it.next()?);
        }
        // else: a left child that is the last node at this level (odd count) — promoted, no path entry.
        idx /= 2;
        last /= 2;
    }
    if it.next().is_some() {
        return None; // extra (unconsumed) path entries -> malformed -> fail-closed
    }
    Some(hash)
}

/// Re-derive the use-time PoP challenge digest the resource shim signs over (ADR 0003 R4 / ADR 0004
/// D2), byte-identically to Go `resourceshim.usePoPChallenge`: `sha256( LP4(tag) ‖ LP4(grant_id) ‖
/// LP4(resource_id) ‖ LP4(action) ‖ LP4(params_commitment) ‖ LP4(credential_binding) ‖ LP4(nonce) )`,
/// tag = "averin.broker.use.pop.v1". Returns the 32-byte digest the agent signs. Kept in sync with Go via
/// a shared golden vector.
pub fn use_pop_challenge(
    grant_id: &str,
    resource_id: &str,
    action: &str,
    params_commitment: &str,
    credential_binding: &str,
    nonce: &str,
) -> [u8; 32] {
    crate::hashx::sha256(&use_pop_preimage(
        grant_id,
        resource_id,
        action,
        params_commitment,
        credential_binding,
        nonce,
    ))
}

/// Exact bytes hashed by the production use-time PoP challenge builder.
#[doc(hidden)]
pub fn use_pop_preimage(
    grant_id: &str,
    resource_id: &str,
    action: &str,
    params_commitment: &str,
    credential_binding: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut pre = Vec::new();
    for part in [
        "averin.broker.use.pop.v1",
        grant_id,
        resource_id,
        action,
        params_commitment,
        credential_binding,
        nonce,
    ] {
        lp4(&mut pre, part.as_bytes());
    }
    pre
}

/// Re-derive the cosignature-approval challenge an approver signs (ADR 0005 M6), byte-identically to the
/// Go producer: `sha256( LP4(tag) ‖ LP4(grant_id) ‖ LP4(approver_kid) ‖ LP4(credential_binding) ‖
/// BE8(threshold_m) ‖ BE8(exp) )`, tag = "averin.broker.cosig.approval.v1". Binding `approver_kid` makes an
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
    crate::hashx::sha256(&cosig_approval_preimage(
        grant_id,
        approver_kid,
        credential_binding,
        threshold_m,
        exp,
    ))
}

/// Exact bytes hashed by the production cosignature challenge builder.
#[doc(hidden)]
pub fn cosig_approval_preimage(
    grant_id: &str,
    approver_kid: &str,
    credential_binding: &str,
    threshold_m: i64,
    exp: i64,
) -> Vec<u8> {
    let mut pre = Vec::new();
    for part in [
        "averin.broker.cosig.approval.v1",
        grant_id,
        approver_kid,
        credential_binding,
    ] {
        lp4(&mut pre, part.as_bytes());
    }
    be8(&mut pre, threshold_m as u64);
    be8(&mut pre, exp as u64);
    pre
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

/// True iff a broker record's signed `grant_evidence` carries a non-empty `delegation_assertions[]` (ADR 0005
/// M2). Used by the M3 native branch to fail-closed on the deferred native × delegation composition.
fn delegation_assertions_present(rec: &CanonValue) -> bool {
    rec.get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get("grant_evidence"))
        .and_then(|g| g.get("delegation_assertions"))
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty())
}

/// M6 (ADR 0005): count the DISTINCT pinned approver keys that produced a valid cosignature over this grant.
/// Each entry in the signed `grant_evidence.cosignatures[]` is `{approver_kid, sig}` (`sig` a base64url-no-pad
/// 64-byte Ed25519 signature, like `use_sig`). For each entry the verifier selects the pinned approver key
/// whose `cnf_kid` equals the entry's claimed `approver_kid`, rebuilds the per-approver challenge, and verifies
/// the sig under THAT key — so the claimed kid only *selects* a candidate; acceptance still requires a real
/// signature by that exact pinned key over a challenge bound to that exact kid. Distinct approver kids are
/// deduped (one approver signing twice counts once — no threshold inflation); an entry whose kid matches no
/// pinned key, whose sig is malformed, or whose sig fails verification is ignored (never counted).
#[allow(clippy::too_many_arguments)]
fn count_cosig_approvals(
    rec: &CanonValue,
    grant_id: &str,
    credential_binding: &str,
    threshold_m: i64,
    exp: i64,
    approver_keys: &[VerifyingKey],
    // ADR 0006 §1 cosig-approver rotation: an approval by a compromised/rotated approver counts ONLY if THIS
    // grant (which embeds the approval in its signed evidence) was anchored before the approver's status change.
    role_status: &BTreeMap<[u8; 32], RoleKeyStatus>,
    grant_content_hash: &str,
    anchored_before: &impl Fn(&str, &str) -> bool,
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
        let challenge =
            cosig_approval_challenge(grant_id, kid, credential_binding, threshold_m, exp);
        if vk.verify_strict(&challenge, &signature).is_ok()
            && role_key_honored(vk, role_status, |rks| {
                honored_anchored_before(rks, grant_content_hash, anchored_before)
            })
        {
            credited.insert(kid.to_string());
        }
    }
    credited.len()
}

/// Re-derive the per-hop delegation challenge a delegator signs (ADR 0005 M2), byte-identically to the Go
/// producer: `sha256( LP4(tag) ‖ LP4(grant_id) ‖ BE8(hop_index) ‖ LP4(delegator_kid) ‖ LP4(delegate_kid) ‖
/// LP4(scope) ‖ LP4(action) ‖ LP4(resource_id) ‖ BE8(exp) )`, tag = "averin.broker.delegation.hop.v1". Binding
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
    crate::hashx::sha256(&delegation_hop_preimage(
        grant_id,
        hop_index,
        delegator_kid,
        delegate_kid,
        scope,
        action,
        resource_id,
        exp,
    ))
}

/// Exact bytes hashed by the production delegation-hop challenge builder.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn delegation_hop_preimage(
    grant_id: &str,
    hop_index: i64,
    delegator_kid: &str,
    delegate_kid: &str,
    scope: &str,
    action: &str,
    resource_id: &str,
    exp: i64,
) -> Vec<u8> {
    let mut pre = Vec::new();
    lp4(&mut pre, b"averin.broker.delegation.hop.v1");
    lp4(&mut pre, grant_id.as_bytes());
    be8(&mut pre, hop_index as u64);
    lp4(&mut pre, delegator_kid.as_bytes());
    lp4(&mut pre, delegate_kid.as_bytes());
    lp4(&mut pre, scope.as_bytes());
    lp4(&mut pre, action.as_bytes());
    lp4(&mut pre, resource_id.as_bytes());
    be8(&mut pre, exp as u64);
    pre
}

/// Re-derive the resource's introspection-transcript challenge (ADR 0005 M3), byte-identically to the Go
/// producer: `sha256( LP4(tag) ‖ LP4(grant_id) ‖ LP4(credential_ref) ‖ LP4(effective_scope) ‖ LP4(resource_id)
/// ‖ BE8(introspected_at) ‖ BE8(effective_exp) )`, tag = "averin.resource.introspection.v1". A native/STS
/// credential is minted by an external IdP/STS the broker never sees, so the verifier cannot recompute its
/// effective scope; the RESOURCE signs this statement of the scope it observed (the `credential_ref` is the
/// `lease_id`). Binding `grant_id` ties the transcript to the broker grant authorizing the exchange; binding
/// `effective_scope`/`resource_id`/`effective_exp` makes the attested scope/window non-malleable. Returns the
/// 32-byte digest the resource signs (raw, like `use_pop_challenge`). Kept in sync with Go via the shared golden
/// vector `spec/golden-vectors/broker-preimages.json`.
#[allow(clippy::too_many_arguments)]
pub fn introspection_transcript_challenge(
    grant_id: &str,
    credential_ref: &str,
    effective_scope: &str,
    resource_id: &str,
    introspected_at: i64,
    effective_exp: i64,
) -> [u8; 32] {
    crate::hashx::sha256(&introspection_transcript_preimage(
        grant_id,
        credential_ref,
        effective_scope,
        resource_id,
        introspected_at,
        effective_exp,
    ))
}

/// Exact bytes hashed by the production introspection transcript builder.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn introspection_transcript_preimage(
    grant_id: &str,
    credential_ref: &str,
    effective_scope: &str,
    resource_id: &str,
    introspected_at: i64,
    effective_exp: i64,
) -> Vec<u8> {
    let mut pre = Vec::new();
    lp4(&mut pre, b"averin.resource.introspection.v1");
    lp4(&mut pre, grant_id.as_bytes());
    lp4(&mut pre, credential_ref.as_bytes());
    lp4(&mut pre, effective_scope.as_bytes());
    lp4(&mut pre, resource_id.as_bytes());
    be8(&mut pre, introspected_at as u64);
    be8(&mut pre, effective_exp as u64);
    pre
}

/// Re-derive the cross-broker certificate challenge (ADR 0005 M4, OPTIONAL transitive-trust tier),
/// byte-identically to the Go producer: `sha256( LP4(tag) ‖ LP4(issuer_broker_id) ‖ LP4(subject_broker_id)
/// ‖ LP4(subject_kid) ‖ LP4(scope) ‖ LP4(resource_id) ‖ BE8(not_after) )`, tag = "averin.broker.federation.cert.v1".
/// Issuer broker A — whose key the auditor PINS in `federated_broker_keys` — vouches that subject broker B is
/// authorized for `scope` over `resource_id` until `not_after`. B is identified BY KEY via
/// `subject_kid = cnf_kid(subject_pubkey)`, NOT by id alone: binding the subject's key is what makes the cert
/// un-substitutable — without it, A's (public) cert could be replayed over a grant signed by ANY key claiming
/// B's id (a key-substitution fail-open). Kept in sync with Go via the shared golden vector.
pub fn federation_cert_challenge(
    issuer_broker_id: &str,
    subject_broker_id: &str,
    subject_kid: &str,
    scope: &str,
    resource_id: &str,
    not_after: i64,
) -> [u8; 32] {
    crate::hashx::sha256(&federation_cert_preimage(
        issuer_broker_id,
        subject_broker_id,
        subject_kid,
        scope,
        resource_id,
        not_after,
    ))
}

/// Exact bytes hashed by the production federation certificate builder.
#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn federation_cert_preimage(
    issuer_broker_id: &str,
    subject_broker_id: &str,
    subject_kid: &str,
    scope: &str,
    resource_id: &str,
    not_after: i64,
) -> Vec<u8> {
    let mut pre = Vec::new();
    lp4(&mut pre, b"averin.broker.federation.cert.v1");
    lp4(&mut pre, issuer_broker_id.as_bytes());
    lp4(&mut pre, subject_broker_id.as_bytes());
    lp4(&mut pre, subject_kid.as_bytes());
    lp4(&mut pre, scope.as_bytes());
    lp4(&mut pre, resource_id.as_bytes());
    be8(&mut pre, not_after as u64);
    pre
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
    ChainResult::Verified {
        eff_cnf_kid: expected_delegator_kid,
        eff_exp,
    }
}

/// Re-derive the cnf key id (Go `broker.KeyID`): `"ed25519-" + base64url-nopad(sha256(pubkey)[..8])`.
/// Used to confirm a carried cnf public key matches the receipt's `cnf_kid` (ADR 0004 D2).
pub fn cnf_kid(cnf_pub: &VerifyingKey) -> String {
    let sum = crate::hashx::sha256(cnf_pub.as_bytes());
    format!("ed25519-{}", crate::b64::encode(&sum[..8]))
}

/// M4 (ADR 0005, OPTIONAL transitive trust): validate a grant's `grant_evidence.cross_broker_cert` and, if it
/// holds, return the SUBJECT broker's authority key — the key the grant's own `evidence_sig` must then verify
/// under (via the normal `verify_authority`). This elevates an otherwise-UNPINNED subject broker B to
/// `transitive` trust BECAUSE a PINNED issuer broker A (`federated_broker_keys[issuer]`) signed a certificate
/// vouching for B's key over a specific resource/scope. Fail-closed at EVERY step (returns `None`): the issuer
/// is not pinned, issuer == subject (a broker may not vouch for itself), a malformed key/sig, a forged cert sig,
/// the grant's `broker_id`/`scope`/`resource_id` ≠ the cert's (demonstrator monotonicity = equality, consistent
/// with delegation — a true subset lattice is the documented future extension), or the cert expired relative to
/// the grant's own `issued_at`. Returning the subject key does NOT by itself trust the grant: the caller still
/// runs `verify_authority` under it, so a valid cert + a grant NOT signed by the vouched key still fails to
/// elevate (the cert binds `subject_kid = cnf_kid(subject_pubkey)`, closing key substitution).
/// Returns `(subject_vk, issuer_vk)` when a valid cross_broker_cert vouches for the grant's subject: the
/// SUBJECT key elevates the grant, and the ISSUER key is the PINNED federated key that signed the cert — the
/// caller must gate the transitive elevation on the ISSUER's rotation lifecycle (a cert signed after the
/// issuer's own compromise is forged; ADR 0006 §1).
fn cross_broker_cert_key(
    rec: &CanonValue,
    opts: &VerifyOptions,
) -> Option<(VerifyingKey, VerifyingKey)> {
    let cert = rec
        .get("extensions")?
        .get("broker")?
        .get("grant_evidence")?
        .get("cross_broker_cert")?;
    let issuer = cert.get("issuer_broker_id")?.as_str()?;
    let subject = cert.get("subject_broker_id")?.as_str()?;
    let subject_pub_b64 = cert.get("subject_pubkey")?.as_str()?;
    let cert_scope = cert.get("scope")?.as_str()?;
    let cert_resource = cert.get("resource_id")?.as_str()?;
    let not_after = cert.get("not_after").and_then(|v| v.as_int())?;
    let sig_b64 = cert.get("sig")?.as_str()?;
    // Both ids required; a broker may not vouch for itself (issuer ≠ subject — the disjointness boundary).
    if issuer.is_empty() || subject.is_empty() || issuer == subject {
        return None;
    }
    // The grant's claimed broker_id MUST be the cert's subject, and the grant's scope/resource MUST equal the
    // cert's — otherwise A's cert for (B, scopeX, resX) could launder a (B, scopeY) grant.
    if ev_str(rec, "grant_evidence", "broker_id").as_deref() != Some(subject)
        || ev_str(rec, "grant_evidence", "scope").as_deref() != Some(cert_scope)
        || ev_str(rec, "grant_evidence", "resource_id").as_deref() != Some(cert_resource)
    {
        return None;
    }
    // Temporal: the grant must have been issued while the cert was still valid (cert.not_after ≥ grant.issued_at).
    // `issued_at` rides the SUBJECT-signed grant evidence; the cert (issuer-signed) bounds the validity window.
    let issued_at = ev_int(rec, "grant_evidence", "issued_at")?;
    if not_after < issued_at {
        return None;
    }
    let subject_vk = crate::b64::decode_fixed::<32>(subject_pub_b64)
        .ok()
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())?;
    // R2 (STRUCTURAL): the cert-derived subject key becomes a de-facto BROKER authority key, so it MUST be
    // disjoint from every NON-broker role — else a pinned issuer (or a COMPROMISED one) could vouch for a
    // resource/tsa/taxonomy/attestation/cosig/revocation key and turn it into broker authority, a RUNTIME
    // backdoor around the unconditional startup disjointness fatal (which only covers PINNED broker keys). The
    // generic `trusted_authority_keys` set is intentionally NOT here: a broker key MAY equal it (the self-host
    // model where the broker IS its own generic policy authority), exactly as the startup check permits.
    let non_broker_roles: [&[VerifyingKey]; 6] = [
        &opts.resource_authority_keys,
        &opts.taxonomy_keys,
        &opts.attestation_keys,
        &opts.trusted_tsa_keys,
        &opts.cosig_approver_keys,
        &opts.revocation_keys,
    ];
    if non_broker_roles.iter().any(|set| set.contains(&subject_vk)) {
        return None; // fail-closed: the cert may not launder a non-broker key into broker authority
    }
    let subject_kid = cnf_kid(&subject_vk);
    let challenge = federation_cert_challenge(
        issuer,
        subject,
        &subject_kid,
        cert_scope,
        cert_resource,
        not_after,
    );
    let sig_bytes = crate::b64::decode_fixed::<64>(sig_b64).ok()?;
    let sig = Signature::from_bytes(&sig_bytes);
    // The cert must be signed by ONE of the issuer's PINNED keys; an unpinned issuer yields no candidates → None.
    // Capture WHICH issuer key verified it, so the caller can gate the transitive elevation on that pinned
    // issuer key's rotation lifecycle (ADR 0006 §1 — a cert the issuer signed after its own compromise).
    let issuer_keys = opts.federated_broker_keys.get(issuer)?;
    let issuer_vk = issuer_keys
        .iter()
        .find(|vk| vk.verify_strict(&challenge, &sig).is_ok())?;
    Some((subject_vk, *issuer_vk))
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
    cnf_pub.verify_strict(&challenge, &sig).map_err(|_| {
        "use_sig does not verify under cnf_pub (offline PoP re-check failed)".to_string()
    })?;
    Ok(true)
}

/// Read a field from a record's canonical evidence payload. Callers that
/// negotiate a protocol version must distinguish absent from present-but-bad.
fn ev_value<'a>(rec: &'a CanonValue, payload_key: &str, field: &str) -> Option<&'a CanonValue> {
    rec.get("extensions")
        .and_then(|e| e.get("broker"))
        .and_then(|b| b.get(payload_key))
        .and_then(|p| p.get(field))
}

/// Read an integer field from a record's canonical evidence payload (used for issued_at/exp/used_at).
fn ev_int(rec: &CanonValue, payload_key: &str, field: &str) -> Option<i64> {
    ev_value(rec, payload_key, field).and_then(CanonValue::as_int)
}

/// A checkpoint's `broker_grant_head` (ADR 0004 D6 / MF2), parsed fail-closed.
#[derive(PartialEq)]
struct GrantHead {
    max_seq: i64,
    prior_head_hash: String,
    cumulative_root: String,
}

/// M4 (ADR 0005): one verified checkpoint's federated head context — `(checkpoint_seq, anchored, per-`broker_id`
/// head map, frontier)`. The per-broker generalization of `compute_broker_trust`'s `(seq, anchored, GrantHead, frontier)`.
type FedHeadCp = (i64, bool, BTreeMap<String, GrantHead>, Vec<String>);

fn parse_grant_head(cp: &CanonValue) -> Option<GrantHead> {
    let h = cp.get("broker_grant_head")?;
    Some(GrantHead {
        max_seq: h.get("max_seq").and_then(|v| v.as_int())?,
        prior_head_hash: h
            .get("prior_head_hash")
            .and_then(|v| v.as_str())?
            .to_string(),
        cumulative_root: h
            .get("cumulative_root")
            .and_then(|v| v.as_str())?
            .to_string(),
    })
}

struct TaxonomyInfo {
    /// (resource_id, action) pairs the issuer asserts ARE single-operation. RESOURCE-BOUND (an entry
    /// vetted for one resource must not validate the same action name on another — adversarial review AREA 2).
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
fn tax_pairs(
    tax: &CanonValue,
    key: &str,
    absent: Option<BTreeSet<(String, String)>>,
) -> Option<BTreeSet<(String, String)>> {
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
        // empty — so an empty action can never appear in the declared set (adversarial review hardening).
        let r = e
            .get("resource_id")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())?;
        let a = e
            .get("action")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())?; // action-bound: per (resource_id, action)
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
    role_status: &BTreeMap<[u8; 32], RoleKeyStatus>,
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
    let signer = keys
        .iter()
        .find(|vk| crate::sign::verify("averin.taxonomy.v1", &digest, sig, vk).is_ok())?;
    // ADR 0006 §1 — taxonomy-key rotation (defense-in-depth). The auditor's `pinned_digest` already binds the
    // EXACT vetted artifact, so a compromised key cannot SUBSTITUTE a different taxonomy (the dominant check).
    // Still, an issuer the auditor flagged `compromised`/`revoked` is no longer a trusted source, so its
    // taxonomy is not `validated` (untrusted → blocks D4 `action_verified` + the capstone, fail-closed). A
    // cleanly `rotated` issuer keeps its digest-pinned taxonomy valid (the vetted artifact is unchanged). There
    // is no clean self-asserted issue time on a taxonomy, so this gates on status alone, not a window.
    if !role_key_honored(signer, role_status, |rks| rks.status == "rotated") {
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
/// The committed broker-grant log a `frontier` commits: Broker-role grants with `broker_seq >= 1` committed
/// by that frontier, sorted ascending by broker_seq. Membership is the role TUPLE (NOT sig-gated — a broker
/// under-signing a grant IS the suppression D6/M4 detect). `broker_id = None` takes ALL brokers (the D6
/// single-broker transparency log); `Some(bid)` restricts to one broker's partition (the M4 federation
/// per-broker log) — federation is the per-broker generalization of D6, so both derive the log identically
/// here (one place to keep byte-aligned with the producer's grantLog) and diverge only in their head folding.
/// A `grant_void` tombstone (`BrokerRole::Void`) is a log entry too: it fills its seq exactly as a grant would
/// (the producer folds it identically), so an operator-voided reservation keeps the prefix gapless.
fn committed_broker_log(
    record_trust: &[RecordTrust],
    records: &[CanonValue],
    by_hash: &BTreeMap<String, usize>,
    frontier: &[String],
    broker_id: Option<&str>,
) -> Vec<(i64, String)> {
    let committed = committed_set(records, by_hash, frontier);
    let mut log: Vec<(i64, String)> = record_trust
        .iter()
        .filter_map(|rt| log_payload_key(&rt.broker_role).map(|key| (rt, key)))
        .filter(|(rt, key)| {
            committed.contains(&rt.content_hash)
                && match broker_id {
                    None => true,
                    // empty broker_id never matches a (non-empty) partition id — it is a smuggling signal the
                    // caller flags separately, exactly as the prior broker_id_of(rt) filter did.
                    Some(bid) => {
                        ev_str(&records[rt.index], key, "broker_id")
                            .filter(|b| !b.is_empty())
                            .as_deref()
                            == Some(bid)
                    }
                }
        })
        .filter_map(|(rt, key)| {
            ev_int(&records[rt.index], key, "broker_seq")
                .filter(|seq| *seq >= 1)
                .map(|seq| (seq, rt.content_hash.clone()))
        })
        .collect();
    log.sort_by_key(|(seq, _)| *seq);
    log
}

/// The evidence payload carrying a transparency-log entry's `broker_seq`/`broker_id`: `grant_evidence` for a grant,
/// `void_evidence` for a `grant_void` tombstone, `None` for every other role (not a log entry).
fn log_payload_key(role: &str) -> Option<&'static str> {
    if role == BrokerRole::Broker.as_str() {
        Some("grant_evidence")
    } else if role == BrokerRole::Void.as_str() {
        Some("void_evidence")
    } else {
        None
    }
}

/// Report every `broker_seq` held by more than one DISTINCT committed log entry — a grant and a `grant_void`
/// tombstone (a real grant claiming a voided seq), or two of either. `log` is seq-sorted. Returns true when clean.
fn check_duplicate_seqs(log: &[(i64, String)], scope: &str, issues: &mut Vec<String>) -> bool {
    let mut ok = true;
    for w in log.windows(2) {
        if w[0].0 == w[1].0 && w[0].1 != w[1].1 {
            issues.push(format!(
                "{scope}broker_seq {} is claimed by more than one committed record (a grant and a grant_void tombstone, or two of either) — duplicate seq (D6)",
                w[0].0
            ));
            ok = false;
        }
    }
    ok
}

/// The domain tag every `grant_void` tombstone's `void_evidence` carries, so its canonical bytes (and therefore its
/// signed `evidence_hash`) can never coincide with a `grant_evidence` payload's.
const GRANT_VOID_DOMAIN: &str = "averin.broker.grant_void.v1";

/// Validate every `grant_void` tombstone (ADR 0004 D6 operator remediation). A tombstone fills its `broker_seq` in the
/// gapless log, so a malformed or unsigned one must never be accepted as doing so: its `void_evidence` must carry the
/// domain tag, a `broker_seq >= 1`, and bind the record's own `project_id` and `record_id` (== the voided grant_id);
/// its signed `evidence_hash` must re-derive from that payload; under a pinned broker key set it must verify; and no
/// Broker grant anywhere in the bundle may carry the voided grant_id (a voided reservation that was nonetheless
/// issued). Each failure is a hard issue. Returns the number of valid tombstones.
fn check_grant_voids(
    record_trust: &[RecordTrust],
    records: &[CanonValue],
    opts: &VerifyOptions,
    issues: &mut Vec<String>,
) -> usize {
    let granted: BTreeSet<String> = record_trust
        .iter()
        .filter(|rt| rt.broker_role == BrokerRole::Broker.as_str())
        .filter_map(|rt| ev_str(&records[rt.index], "grant_evidence", "grant_id"))
        .collect();
    let broker_keys_pinned =
        !opts.broker_authority_keys.is_empty() || !opts.federated_broker_keys.is_empty();
    let mut valid = 0usize;
    for rt in record_trust
        .iter()
        .filter(|rt| rt.broker_role == BrokerRole::Void.as_str())
    {
        let rec = &records[rt.index];
        let mut bad: Vec<&str> = Vec::new();
        if ev_str(rec, "void_evidence", "domain").as_deref() != Some(GRANT_VOID_DOMAIN) {
            bad.push("void_evidence.domain is not averin.broker.grant_void.v1");
        }
        if ev_int(rec, "void_evidence", "broker_seq").is_none_or(|seq| seq < 1) {
            bad.push("void_evidence carries no broker_seq >= 1");
        }
        let gid = ev_str(rec, "void_evidence", "grant_id");
        if gid.is_none() || gid.as_deref() != s(rec, "record_id").as_deref() {
            bad.push("void_evidence.grant_id does not equal the tombstone's record_id");
        }
        if ev_str(rec, "void_evidence", "project_id") != s(rec, "project_id") {
            bad.push("void_evidence.project_id does not equal the tombstone's project_id");
        }
        if !evidence_rederivable(rec, "void_evidence") {
            bad.push(
                "authority.evidence_hash is not re-derivable from extensions.broker.void_evidence",
            );
        }
        if broker_keys_pinned
            && !matches!(
                rt.authority,
                AuthorityTrust::Verified | AuthorityTrust::LegacyUnbound
            )
        {
            bad.push("its authority does not verify under a pinned broker key");
        }
        if gid.as_ref().is_some_and(|g| granted.contains(g)) {
            bad.push(
                "a grant with the voided grant_id is also present (a voided reservation was issued)",
            );
        }
        if bad.is_empty() {
            valid += 1;
        } else {
            issues.push(format!(
                "grant_void tombstone {} ({}): {} — it cannot fill its broker_seq (D6)",
                rt.index,
                rt.record_id,
                bad.join("; ")
            ));
        }
    }
    valid
}

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
    // the tuple-classified single-broker (D6) grant log committed by an arbitrary checkpoint frontier.
    let log_for =
        |frontier: &[String]| committed_broker_log(record_trust, records, by_hash, frontier, None);

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
    // a grant claiming a voided seq (or any two distinct entries sharing one seq) is a hard violation of its own,
    // named as such rather than only as the gap it also causes.
    let mut ok = check_duplicate_seqs(&full_log, "", issues);

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
        if rt.broker_role != BrokerRole::Broker.as_str()
            || !full_committed.contains(&rt.content_hash)
        {
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
        if !log_i
            .iter()
            .enumerate()
            .all(|(i, (seq, _))| *seq == i as i64 + 1)
        {
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

/// M4 (ADR 0005): a checkpoint's federated `broker_grant_heads` — a MAP `{<broker_id>: {max_seq, prior_head_hash,
/// cumulative_root}}` (the per-`broker_id` generalization of the single D6 `broker_grant_head`). Parsed fail-closed:
/// a present-but-non-object map, or ANY entry missing a field, returns `None` (a malformed/tampered federation head).
fn parse_grant_heads_map(cp: &CanonValue) -> Option<BTreeMap<String, GrantHead>> {
    let obj = cp.get("broker_grant_heads")?.as_object()?;
    let mut map = BTreeMap::new();
    for (bid, v) in obj.iter() {
        map.insert(
            bid.clone(),
            GrantHead {
                max_seq: v.get("max_seq").and_then(|x| x.as_int())?,
                prior_head_hash: v
                    .get("prior_head_hash")
                    .and_then(|x| x.as_str())?
                    .to_string(),
                cumulative_root: v
                    .get("cumulative_root")
                    .and_then(|x| x.as_str())?
                    .to_string(),
            },
        );
    }
    Some(map)
}

/// M4 (ADR 0005): the surfaced outcome of federated (per-`broker_id`) grant-transparency evaluation.
struct FederationEval {
    /// Aggregate broker_trust: the WORST per-broker trust, or `assumed` on any global failure (the caller also
    /// forces `assumed` when the bundle is not `ok`).
    broker_trust: String,
    /// `sequence_verified` (every broker's head chain verified + anchored) | `sequence_consistent_export`
    /// (verified but the latest head is not anchored) | `suppression` (≥1 broker partition failed) | `absent`.
    status: String,
    brokers_total: usize,
    brokers_seq_verified: usize,
    cross_broker_suppression: usize,
    per_broker: Vec<(String, String)>,
}

/// M4 (ADR 0005): compute federated grant-transparency trust over a PARTITION of the recorded grant log by
/// `broker_id`. Each broker's grants must form their OWN gapless `[1..n_b]` `broker_seq` prefix with their OWN
/// `cumulative_root` chain re-derived against that broker's entry in each checkpoint's `broker_grant_heads` map —
/// so a gap in broker A's sequence is detected in A's partition and can NEVER be masked by broker B's interleaved
/// grants (the cross-broker suppression a single flat D6 log cannot see). Structurally a per-`broker_id` replica of
/// `compute_broker_trust`'s head-chain re-derivation; kept SEPARATE (not a refactor of the legacy function) so the
/// single-broker path stays byte-for-byte unchanged. Every detected failure is a hard `issues` violation (→ `!ok`).
#[allow(clippy::too_many_arguments)]
fn compute_federation_trust(
    cp_fed_heads: &[FedHeadCp],
    verified_fed_headless: &[Vec<String>],
    malformed_fed_head: bool,
    record_trust: &[RecordTrust],
    records: &[CanonValue],
    by_hash: &BTreeMap<String, usize>,
    dag_heads: &[String],
    latest_cp_seq: i64,
    issues: &mut Vec<String>,
) -> FederationEval {
    let broker_id_of = |rt: &RecordTrust| -> Option<String> {
        ev_str(&records[rt.index], "grant_evidence", "broker_id").filter(|b| !b.is_empty())
    };
    // The per-broker (M4) grant log committed by a frontier: the SAME derivation as the D6 single-broker log,
    // restricted to THIS broker_id's partition (membership is the role tuple + broker_id).
    let log_for = |frontier: &[String], bid: &str| {
        committed_broker_log(record_trust, records, by_hash, frontier, Some(bid))
    };

    let full_committed = committed_set(records, by_hash, dag_heads);
    let mut suppressed: BTreeSet<String> = BTreeSet::new();

    if malformed_fed_head {
        issues.push("a verified checkpoint carries a present-but-malformed broker_grant_heads map — tampered/garbled federation head (suppression, M4)".into());
    }

    // distinct broker_ids over committed Broker grants; fail-closed on a committed broker grant MISSING broker_id
    // (smuggled out of every partition — omitted from all per-broker heads) or broker_seq (smuggled out of its log).
    let mut brokers: BTreeSet<String> = BTreeSet::new();
    let mut smuggled = false;
    for rt in record_trust {
        if rt.broker_role != BrokerRole::Broker.as_str()
            || !full_committed.contains(&rt.content_hash)
        {
            continue;
        }
        match broker_id_of(rt) {
            Some(b) => {
                brokers.insert(b);
            }
            None => {
                issues.push(format!(
                    "committed broker grant {} carries no broker_id while federation is active — smuggled out of the per-broker partition (suppression, M4)",
                    rt.content_hash
                ));
                smuggled = true;
            }
        }
        if ev_int(&records[rt.index], "grant_evidence", "broker_seq")
            .filter(|seq| *seq >= 1)
            .is_none()
        {
            issues.push(format!(
                "committed broker grant {} carries no broker_seq while federation is active — smuggled out of the transparency log (suppression, M4)",
                rt.content_hash
            ));
            smuggled = true;
        }
    }

    // A committed grant_void tombstone fills a seq in ITS broker's partition (its signed void_evidence.broker_id).
    // One without a broker_id fills no partition while federation is active — fail closed, like a grant.
    for rt in record_trust {
        if rt.broker_role != BrokerRole::Void.as_str() || !full_committed.contains(&rt.content_hash)
        {
            continue;
        }
        match ev_str(&records[rt.index], "void_evidence", "broker_id").filter(|b| !b.is_empty()) {
            Some(b) => {
                brokers.insert(b);
            }
            None => {
                issues.push(format!(
                    "committed grant_void tombstone {} carries no broker_id while federation is active — it fills no per-broker partition (M4)",
                    rt.content_hash
                ));
                smuggled = true;
            }
        }
    }

    // grant_id INJECTIVITY across the whole committed log: broker_id is part of the credential identity, so a
    // grant_id bound to >1 distinct (broker_id, broker_seq, content_hash) tuple is equivocated (one credential
    // identity double-bound, incl. the same grant_id reused under two brokers). Locally decidable (co-committed).
    let mut by_grant: BTreeMap<String, BTreeSet<(String, i64, String)>> = BTreeMap::new();
    for rt in record_trust {
        if rt.broker_role != BrokerRole::Broker.as_str()
            || !full_committed.contains(&rt.content_hash)
        {
            continue;
        }
        if let Some(gid) = ev_str(&records[rt.index], "grant_evidence", "grant_id") {
            let bid = broker_id_of(rt).unwrap_or_default();
            let seq = ev_int(&records[rt.index], "grant_evidence", "broker_seq").unwrap_or(0);
            by_grant
                .entry(gid)
                .or_default()
                .insert((bid, seq, rt.content_hash.clone()));
        }
    }
    let mut equivocated = false;
    for (gid, tuples) in &by_grant {
        if tuples.len() > 1 {
            issues.push(format!(
                "grant_id {gid} is bound to {} distinct (broker_id, broker_seq, content_hash) tuples in one committed log — equivocated credential identity (M4/D6)",
                tuples.len()
            ));
            equivocated = true;
        }
    }

    // A verified checkpoint carrying NO (well-formed) broker_grant_heads map whose frontier commits a broker's
    // grants binds them without a head — suppression for that broker. Dedup identical frontiers first.
    let mut headless: Vec<&Vec<String>> = verified_fed_headless.iter().collect();
    headless.sort();
    headless.dedup();
    for frontier in headless {
        for b in &brokers {
            if !log_for(frontier, b).is_empty() {
                issues.push(format!(
                    "broker '{b}': a verified checkpoint commits its grants but carries no broker_grant_heads map — bound without a transparency head (suppression, M4)"
                ));
                suppressed.insert(b.clone());
            }
        }
    }

    // The head MUST be on the LATEST checkpoint (whose frontier covers the full DAG); a head only on an EARLIER
    // checkpoint hides grants the latest commits. The latest checkpoint's map must carry a head for EVERY broker
    // with committed grants.
    let latest_fed = cp_fed_heads
        .iter()
        .find(|(seq, _, _, _)| *seq == latest_cp_seq);
    let latest_anchored = latest_fed.map(|(_, a, _, _)| *a).unwrap_or(false);
    match latest_fed {
        None => {
            issues.push("federation is active but the LATEST checkpoint carries no broker_grant_heads map — a dropped federation head hides later grants (suppression, M4)".into());
            for b in &brokers {
                suppressed.insert(b.clone());
            }
        }
        Some((_, _, m, _)) => {
            for b in &brokers {
                if !m.contains_key(b) {
                    issues.push(format!("broker '{b}' has committed grants but the LATEST checkpoint's broker_grant_heads has no head for it — dropped head (suppression, M4)"));
                    suppressed.insert(b.clone());
                }
            }
        }
    }

    // A head entry for a broker_id with NO committed grants anywhere is a phantom-broker head (inflation): a head
    // claiming a partition that does not exist. Surfaced once per phantom broker_id.
    let mut phantom: BTreeSet<String> = BTreeSet::new();
    for (cseq, _, map, _) in cp_fed_heads {
        for bid in map.keys() {
            if !brokers.contains(bid) && phantom.insert(bid.clone()) {
                issues.push(format!(
                    "broker_grant_heads (checkpoint seq {cseq}) carries a head for broker '{bid}' with no committed grants — phantom-broker head (inflation, M4)"
                ));
            }
        }
    }

    // Per-broker head-chain re-derivation: for EACH broker, re-walk its own head entries ascending by checkpoint
    // seq — gapless [1..n], max_seq == n, cumulative_root re-derive over the broker's committed log, prior_head
    // chaining the broker's OWN previous head (per-broker chain). A checkpoint that commits the broker's grants but
    // whose map lacks its head binds them without a head (suppression).
    let empty_root = grant_head_root(&[]);
    for b in &brokers {
        if !check_duplicate_seqs(&log_for(dag_heads, b), &format!("broker '{b}': "), issues) {
            suppressed.insert(b.clone());
        }
        let mut entries: Vec<(i64, &GrantHead, &Vec<String>)> = Vec::new();
        for (cseq, _, map, frontier) in cp_fed_heads {
            match map.get(b) {
                Some(h) => entries.push((*cseq, h, frontier)),
                None => {
                    if !log_for(frontier, b).is_empty() {
                        issues.push(format!("broker '{b}' checkpoint seq {cseq}: commits its grants but its broker_grant_heads has no head for it — bound without a head (suppression, M4)"));
                        suppressed.insert(b.clone());
                    }
                }
            }
        }
        entries.sort_by_key(|(seq, _, _)| *seq);
        entries.dedup_by(|a, c| a.0 == c.0 && a.1 == c.1 && a.2 == c.2);
        let mut prev_root = empty_root.clone();
        for (cseq, head, frontier) in entries {
            let log_i = log_for(frontier, b);
            let n_i = log_i.len() as i64;
            if !log_i
                .iter()
                .enumerate()
                .all(|(i, (seq, _))| *seq == i as i64 + 1)
            {
                issues.push(format!("broker '{b}' checkpoint seq {cseq}: committed grant broker_seq set is not a gapless [1..N] prefix — suppression/renumber (M4)"));
                suppressed.insert(b.clone());
            }
            if head.max_seq != n_i {
                issues.push(format!("broker '{b}' checkpoint seq {cseq}: head max_seq {} != its committed grant count {n_i} — omission/inflation (M4)", head.max_seq));
                suppressed.insert(b.clone());
            }
            if grant_head_root(&log_i) != head.cumulative_root {
                issues.push(format!("broker '{b}' checkpoint seq {cseq}: head cumulative_root does not re-derive from its committed grant log — suppression (M4)"));
                suppressed.insert(b.clone());
            }
            if head.prior_head_hash != prev_root {
                issues.push(format!("broker '{b}' checkpoint seq {cseq}: head prior_head_hash does not chain the broker's previous head — grant-log fork/restart (M4)"));
                suppressed.insert(b.clone());
            }
            prev_root = head.cumulative_root.clone();
        }
    }

    let global_fail = smuggled || equivocated || malformed_fed_head || !phantom.is_empty();

    let brokers_total = brokers.len();
    let mut per_broker: Vec<(String, String)> = Vec::new();
    let mut brokers_seq_verified = 0usize;
    let mut worst = "sequence_verified";
    for b in &brokers {
        // A non-suppressed broker's head chain validated AND (we required) its head is on the latest checkpoint —
        // so its trust is bound to the latest checkpoint's anchored status (the same single anchor for all brokers).
        let trust = if suppressed.contains(b) {
            "suppression"
        } else if latest_anchored {
            "sequence_verified"
        } else {
            "sequence_consistent_export"
        };
        match trust {
            "sequence_verified" => brokers_seq_verified += 1,
            "sequence_consistent_export" if worst == "sequence_verified" => {
                worst = "sequence_consistent_export"
            }
            _ => {}
        }
        per_broker.push((b.clone(), trust.to_string()));
    }
    let cross_broker_suppression = per_broker
        .iter()
        .filter(|(_, t)| t == "suppression")
        .count();

    let failed = global_fail || cross_broker_suppression > 0;
    let status = if failed {
        "suppression".to_string()
    } else if brokers_total == 0 {
        "absent".to_string() // federation activated but no committed federated grant (degenerate); caller→assumed
    } else {
        worst.to_string()
    };
    let broker_trust = if failed || brokers_total == 0 {
        "assumed".to_string()
    } else {
        worst.to_string()
    };

    FederationEval {
        broker_trust,
        status,
        brokers_total,
        brokers_seq_verified,
        cross_broker_suppression,
        per_broker,
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

struct RevocationEval {
    status: String, // absent | fresh | stale (revoked_present is set by the use loop)
    revoked: BTreeSet<String>, // disclosed revoked grant_ids (covered by the sig); empty unless validly signed
}

/// M5 (ADR 0005): evaluate a bundle's top-level `revocation_list` — a signed, time-bounded list of revoked
/// grant_ids under a pinned, role-separated `revocation_keys` issuer. Reuses the deployment_attestation
/// pattern wholesale: the `sig` (domain `averin.revocation.v1`) covers the canonical list minus `sig` (so the
/// disclosed `revoked_grant_ids` are authenticated directly — a Merkle-root NON-disclosure mode is the future
/// extension), and freshness is the latest anchored checkpoint TSA timestamp falling within
/// `[issued_at, not_after]` (canonical ISO, the same temporal anchor D7 uses). `fresh` iff signed + the
/// issuer_kid matches the signer + in-window; `stale` iff validly signed but out of window (or malformed →
/// issue pushed → !ok); `absent` iff no list or no pinned issuer. The returned `revoked` set is enforced
/// (blocks in-window uses) by the caller ONLY when `status == "fresh"`.
fn evaluate_revocation(
    bundle: &CanonValue,
    opts: &VerifyOptions,
    anchored_latest_ts: Option<&str>,
    anchored_is_latest: bool,
    issues: &mut Vec<String>,
) -> RevocationEval {
    let absent = RevocationEval {
        status: "absent".to_string(),
        revoked: BTreeSet::new(),
    };
    if opts.revocation_keys.is_empty() {
        return absent; // no pinned issuer -> not evaluated (a present list's revocations are not honored)
    }
    let rl = match bundle.get("revocation_list") {
        Some(a) if !a.is_null() => a,
        // The operator PINNED a revocation authority, so revocation evidence is EXPECTED: a bundle carrying
        // neither a `revocation_list` nor a `revocation_merkle_root` is `missing`, not the benign `absent` —
        // otherwise deleting the (unsigned-at-bundle-level) revocation artifacts would be a free downgrade that
        // un-blocks every revoked use while the capstone stays reachable. `missing` blocks the capstone. (A
        // Merkle-mode bundle carries only the root, so the disclosed list is legitimately absent there.)
        _ => {
            let has_merkle_root = bundle
                .get("revocation_merkle_root")
                .is_some_and(|r| !r.is_null());
            return RevocationEval {
                status: if has_merkle_root { "absent" } else { "missing" }.to_string(),
                revoked: BTreeSet::new(),
            };
        }
    };
    let stale_empty = || RevocationEval {
        status: "stale".to_string(),
        revoked: BTreeSet::new(),
    };

    // 1. signature over the canonical list minus `sig`, under a pinned issuer (mirrors evaluate_attestation).
    let sig = match rl.get("sig").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            issues.push("revocation_list: missing sig (M5)".into());
            return stale_empty();
        }
    };
    let mut obj = match rl.as_object() {
        Some(o) => o.clone(),
        None => {
            issues.push("revocation_list: not an object (M5)".into());
            return stale_empty();
        }
    };
    obj.retain(|(k, _)| k != "sig");
    let digest = crate::hashx::sha256_prefixed(CanonValue::Object(obj).serialize().as_bytes());
    let signer = match opts
        .revocation_keys
        .iter()
        .find(|vk| crate::sign::verify("averin.revocation.v1", &digest, sig, vk).is_ok())
    {
        Some(vk) => vk,
        None => {
            issues.push(
                "revocation_list: sig does not verify under any pinned revocation_keys issuer (M5)"
                    .into(),
            );
            return stale_empty();
        }
    };
    // the CLAIMED issuer_kid must be the ACTUAL signer (else a reader's surfaced issuer is a lie).
    if rl.get("issuer_kid").and_then(|v| v.as_str()) != Some(cnf_kid(signer).as_str()) {
        issues.push("revocation_list: issuer_kid does not match the signing key (M5)".into());
        return stale_empty();
    }

    // 2. the disclosed revoked grant_ids — covered by the verified sig above.
    let revoked: BTreeSet<String> = rl
        .get("revoked_grant_ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // 3. freshness window (canonical ISO, compared lexicographically against the anchored TSA time).
    let issued_at = rl
        .get("issued_at")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let not_after = rl
        .get("not_after")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let stale_with_list = || RevocationEval {
        status: "stale".to_string(),
        revoked: revoked.clone(),
    };
    if issued_at.is_empty()
        || not_after.is_empty()
        || !is_canonical_ts(issued_at)
        || !is_canonical_ts(not_after)
        || issued_at > not_after
    {
        issues.push("revocation_list: issued_at/not_after missing, non-canonical, or inverted — malformed window (M5)".into());
        return stale_with_list();
    }
    // ADR 0006 §1 — revocation-key rotation. The list is NOT anchor-committed (self-asserted issued_at), so a
    // non-active issuer cannot CERTIFY currency → freshness drops to `stale` (blocking the capstone). The
    // disclosed revocations are KEPT, NOT dropped: a signed revocation is monotone, and un-honoring it would
    // UN-BLOCK a revoked grant — the only fail-OPEN direction here (a forged over-revocation merely DoS-blocks a
    // good grant, which is the fail-CLOSED direction an evidence verifier prefers). compromised/revoked never
    // certifies fresh; a cleanly rotated issuer certifies only a list issued at/before the rotation.
    if !role_key_honored(signer, &opts.role_key_status, |rks| {
        honored_clean_rotation(rks, issued_at)
    }) {
        issues.push("revocation_list: issuer key is rotated/compromised and the list is not provably before that status change — currency not certified (stale); listed revocations still block (ADR 0006 role-key rotation)".into());
        return stale_with_list();
    }
    let ts = match anchored_latest_ts {
        Some(t) => t,
        None => {
            issues.push(
                "revocation_list present but no verified+anchored checkpoint to date it (M5)"
                    .into(),
            );
            return stale_with_list();
        }
    };
    // Currency is dated against the LATEST ANCHORED checkpoint's TSA time. If an UNANCHORED checkpoint exists
    // beyond it (anchored_is_latest == false), a producer has rolled "now" backward — a list that is actually
    // stale relative to the bundle's true frontier would otherwise read `fresh`, hiding revocations made after
    // the anchored point. Mirror the deployment_attestation guard (`latest != latest_cp_seq`): the revocation
    // currency cannot be established, so it is `stale` (blocks the capstone; named grants still block via the
    // membership gate). Not a hard violation — an unanchored tail is a normal pending-anchoring state.
    let fresh = issued_at <= ts && ts <= not_after && anchored_is_latest;
    RevocationEval {
        status: if fresh { "fresh" } else { "stale" }.to_string(),
        revoked,
    }
}

/// Parse a 64-char lowercase-hex string into 32 raw bytes (the Merkle leaf VALUES / audit-path nodes are raw
/// hashes, not the `sha256:` content-hash form). Fail-closed (`None`) on wrong length or a non-hex digit.
/// Decodes BYTE-wise over ASCII lowercase hex only: these strings ride the UNSIGNED `revocation_proofs` map, and
/// the former `from_str_radix(&s[2i..2i+2])` both PANICKED on a multibyte char straddling a slice boundary (a
/// 64-byte "€aaa…") and accepted non-canonical pairs like "+a" / uppercase.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    crate::hashx::hex32(s)
}

/// Outcome of evaluating a top-level `revocation_merkle_root` (M5 Merkle-non-disclosure mode).
struct MerkleRevEval {
    status: String,         // absent | fresh | stale
    root: Option<[u8; 32]>, // the signed Merkle root (raw 32 bytes); Some iff validly signed
    leaf_count: usize,      // the tree's leaf count (incl. the 2 sentinels), covered by the sig
}

/// M5 Merkle-non-disclosure revocation (ADR 0005): evaluate a bundle's top-level `revocation_merkle_root` — a
/// signed, time-bounded commitment to the SORTED revoked-grant set that does NOT disclose it. Mirrors
/// `evaluate_revocation` exactly: the `sig` (domain `averin.broker.revocation.merkleroot.v1`) covers the canonical
/// object minus `sig`, verified under a pinned role-separated `revocation_keys` issuer; the claimed `issuer_kid`
/// must be the signer; freshness is the latest anchored TSA time within `[issued_at, not_after]`. Unlike the
/// disclosed list, the revoked set is NOT in the bundle — each USE proves its grant's (non-)membership against
/// `root` via a per-grant proof (`check_revocation_proof`). `fresh` iff signed + in-window; `stale` iff signed
/// but out-of-window (or malformed → issue → !ok); `absent` iff no root or no pinned issuer.
fn evaluate_merkle_revocation(
    bundle: &CanonValue,
    opts: &VerifyOptions,
    anchored_latest_ts: Option<&str>,
    anchored_is_latest: bool,
    issues: &mut Vec<String>,
) -> MerkleRevEval {
    let absent = || MerkleRevEval {
        status: "absent".to_string(),
        root: None,
        leaf_count: 0,
    };
    let rr = match bundle.get("revocation_merkle_root") {
        Some(a) if !a.is_null() => a,
        _ => return absent(),
    };
    if opts.revocation_keys.is_empty() {
        return absent(); // present but no pinned issuer -> not evaluated
    }
    let stale = || MerkleRevEval {
        status: "stale".to_string(),
        root: None,
        leaf_count: 0,
    };

    let sig = match rr.get("sig").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            issues.push("revocation_merkle_root: missing sig (M5)".into());
            return stale();
        }
    };
    let mut obj = match rr.as_object() {
        Some(o) => o.clone(),
        None => {
            issues.push("revocation_merkle_root: not an object (M5)".into());
            return stale();
        }
    };
    obj.retain(|(k, _)| k != "sig");
    let digest = crate::hashx::sha256_prefixed(CanonValue::Object(obj).serialize().as_bytes());
    let signer = match opts.revocation_keys.iter().find(|vk| {
        crate::sign::verify("averin.broker.revocation.merkleroot.v1", &digest, sig, vk).is_ok()
    }) {
        Some(vk) => vk,
        None => {
            issues.push("revocation_merkle_root: sig does not verify under any pinned revocation_keys issuer (M5)".into());
            return stale();
        }
    };
    if rr.get("issuer_kid").and_then(|v| v.as_str()) != Some(cnf_kid(signer).as_str()) {
        issues
            .push("revocation_merkle_root: issuer_kid does not match the signing key (M5)".into());
        return stale();
    }

    // the committed root (sha256:<hex>) + leaf_count, both covered by the verified sig.
    let root = match rr
        .get("root")
        .and_then(|v| v.as_str())
        .and_then(|s| s.strip_prefix("sha256:"))
        .and_then(parse_hex32)
    {
        Some(r) => r,
        None => {
            issues.push(
                "revocation_merkle_root: malformed root (expect sha256:<64-hex>) (M5)".into(),
            );
            return stale();
        }
    };
    let leaf_count = match rr.get("leaf_count").and_then(|v| v.as_int()) {
        // a sound tree always carries the 2 sentinels, so leaf_count >= 2.
        Some(n) if n >= 2 => n as usize,
        _ => {
            issues.push("revocation_merkle_root: leaf_count missing or < 2 (the sentinels are mandatory) (M5)".into());
            return stale();
        }
    };

    let issued_at = rr
        .get("issued_at")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let not_after = rr
        .get("not_after")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let signed = MerkleRevEval {
        status: "stale".to_string(),
        root: Some(root),
        leaf_count,
    };
    if issued_at.is_empty()
        || not_after.is_empty()
        || !is_canonical_ts(issued_at)
        || !is_canonical_ts(not_after)
        || issued_at > not_after
    {
        issues.push(
            "revocation_merkle_root: issued_at/not_after missing, non-canonical, or inverted (M5)"
                .into(),
        );
        return signed;
    }
    // ADR 0006 §1 — revocation-key rotation (Merkle variant): identical rule to the disclosed list. A non-active
    // issuer cannot certify currency → `stale` (the per-use non-membership proof is still demanded since the
    // root is kept). compromised/revoked never certifies fresh; rotated only for a root issued at/before the
    // rotation.
    if !role_key_honored(signer, &opts.role_key_status, |rks| {
        honored_clean_rotation(rks, issued_at)
    }) {
        issues.push("revocation_merkle_root: issuer key is rotated/compromised and the root is not provably before that status change — currency not certified (stale) (ADR 0006 role-key rotation)".into());
        return signed;
    }
    let ts = match anchored_latest_ts {
        Some(t) => t,
        None => {
            issues.push("revocation_merkle_root present but no verified+anchored checkpoint to date it (M5)".into());
            return signed;
        }
    };
    // See evaluate_revocation: an UNANCHORED checkpoint beyond the latest anchored one rolls "now" backward, so
    // currency cannot be established → `stale` (the per-use non-membership proof is still demanded since the root
    // is present). Mirrors the deployment_attestation latest-checkpoint guard.
    let fresh = issued_at <= ts && ts <= not_after && anchored_is_latest;
    MerkleRevEval {
        status: if fresh { "fresh" } else { "stale" }.to_string(),
        root: Some(root),
        leaf_count,
    }
}

/// The per-grant verdict of a Merkle revocation proof (M5 non-disclosure).
#[derive(PartialEq)]
enum ProofVerdict {
    NotRevoked, // a valid NON-membership proof: the grant is provably absent from the revoked set
    Revoked,    // a valid MEMBERSHIP proof: the grant is in the revoked set
    Unproven,   // missing/malformed/forged — fail-closed (cannot prove non-revocation)
}

/// Parse an audit path: an array of 64-char-hex node hashes. Fail-closed on any malformed entry.
fn parse_hex32_path(v: Option<&CanonValue>) -> Option<Vec<[u8; 32]>> {
    let arr = v?.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for e in arr {
        out.push(parse_hex32(e.as_str()?)?);
    }
    Some(out)
}

/// M5 Merkle-non-disclosure: verify a single per-grant revocation proof against the signed `root`. A
/// `nonmembership` proof reveals the two CONSECUTIVE sorted leaves `lo < q < hi` (q = `revocation_leaf(grant_id)`)
/// that strictly bracket the grant — proving no leaf equals q (the tree is issuer-sorted + sentinel-bracketed,
/// so adjacency + strict bracketing ⇒ absence). A `membership` proof authenticates q itself as a leaf. EVERYTHING
/// must re-derive the signed root, both bracketing leaves must authenticate at CONSECUTIVE indices, and the
/// bracket must be STRICT — any deviation is `Unproven` (fail-closed). Soundness rests on the issuer (a pinned,
/// role-separated revocation authority) building a sorted tree; the bundle assembler cannot forge a false
/// non-membership for a leaf that is actually present.
fn check_revocation_proof(
    proof: &CanonValue,
    grant_id: &str,
    root: &[u8; 32],
    leaf_count: usize,
) -> ProofVerdict {
    let q = revocation_leaf(grant_id);
    match proof.get("type").and_then(|v| v.as_str()).unwrap_or("") {
        "membership" => {
            let index = proof.get("index").and_then(|v| v.as_int());
            let path = parse_hex32_path(proof.get("path"));
            match (index, path) {
                (Some(i), Some(p)) if i >= 0 => {
                    if merkle_root_from_proof(&q, i as usize, leaf_count, &p) == Some(*root) {
                        ProofVerdict::Revoked
                    } else {
                        ProofVerdict::Unproven
                    }
                }
                _ => ProofVerdict::Unproven,
            }
        }
        "nonmembership" => {
            let lo = proof
                .get("lo")
                .and_then(|v| v.as_str())
                .and_then(parse_hex32);
            let hi = proof
                .get("hi")
                .and_then(|v| v.as_str())
                .and_then(parse_hex32);
            let lo_index = proof.get("lo_index").and_then(|v| v.as_int());
            let hi_index = proof.get("hi_index").and_then(|v| v.as_int());
            let lo_path = parse_hex32_path(proof.get("lo_path"));
            let hi_path = parse_hex32_path(proof.get("hi_path"));
            match (lo, hi, lo_index, hi_index, lo_path, hi_path) {
                (Some(lo), Some(hi), Some(li), Some(hi_i), Some(lp), Some(hp))
                    if li >= 0 && hi_i >= 0 =>
                {
                    // adjacency: the two leaves must be CONSECUTIVE in the sorted tree. `li`/`hi_i` are
                    // attacker-controlled i64 from the unsigned proof, so use checked_add — `li == i64::MAX`
                    // would overflow `li + 1` and PANIC under the debug overflow-checks the shipped staticlib
                    // uses (a DoS + UB across cgo). An overflow is simply an invalid proof.
                    if li.checked_add(1) != Some(hi_i) {
                        return ProofVerdict::Unproven;
                    }
                    // STRICT bracket: lo < q < hi, so q is not equal to either leaf and nothing lies between them.
                    if !(lo < q && q < hi) {
                        return ProofVerdict::Unproven;
                    }
                    // both adjacent leaves must authenticate to the SAME signed root at their claimed indices.
                    if merkle_root_from_proof(&lo, li as usize, leaf_count, &lp) != Some(*root)
                        || merkle_root_from_proof(&hi, hi_i as usize, leaf_count, &hp)
                            != Some(*root)
                    {
                        return ProofVerdict::Unproven;
                    }
                    ProofVerdict::NotRevoked
                }
                _ => ProofVerdict::Unproven,
            }
        }
        _ => ProofVerdict::Unproven,
    }
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
    let s_str = |o: &CanonValue, k: &str| {
        o.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    // surfaced fields (parsed up front so a `failed` verdict still reports what/by-whom/for-when).
    let claim_types: Vec<String> = att
        .get("claim_types")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let subject_digest = att
        .get("subject")
        .map(|s| crate::hashx::sha256_prefixed(s.serialize().as_bytes()));
    let (issued_at, not_after) = (s_str(att, "issued_at"), s_str(att, "not_after"));
    let mut eval = AttestationEval {
        status: "failed".to_string(), // default to failed once an attestation is present + evaluable
        issuer_kid: att
            .get("issuer_kid")
            .and_then(|v| v.as_str())
            .map(String::from),
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
        .find(|vk| crate::sign::verify("averin.attestation.v1", &digest, sig, vk).is_ok())
    {
        Some(vk) => vk,
        None => {
            issues.push(
                "deployment_attestation: sig does not verify under any pinned attestation key (D7)"
                    .into(),
            );
            return eval;
        }
    };
    // the CLAIMED issuer_kid must be the ACTUAL signer (else a reader's surfaced issuer is a lie).
    let signer_kid = cnf_kid(signer);
    if eval.issuer_kid.as_deref() != Some(signer_kid.as_str()) {
        issues
            .push("deployment_attestation: issuer_kid does not match the signing key (D7)".into());
        eval.issuer_kid = Some(signer_kid); // surface the truth, not the claim
        return eval;
    }

    // ADR 0006 §1 — attestation-key rotation. The attestation is NOT anchor-committed: it is a top-level
    // bundle artifact with a SELF-asserted `issued_at`, so a STOLEN issuer key could forge an attestation with
    // any time. A `compromised`/`revoked` issuer is therefore NEVER honored; a cleanly `rotated` issuer is
    // honored only when the attestation's own `issued_at` is at/before the rotation. A withdrawn attestation
    // stays `failed` (no `attested_claims`) — fail-closed (it weakens the capstone, never strengthens it).
    if !role_key_honored(signer, &opts.role_key_status, |rks| {
        honored_clean_rotation(rks, &issued_at)
    }) {
        issues.push("deployment_attestation: issuer key is rotated/compromised and the attestation is not provably before that status change — not honored (ADR 0006 role-key rotation)".into());
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
    // the attestation must cover the bundle's TRUE frontier (adversarial review): if a checkpoint exists BEYOND the latest
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
    // ...and CANONICAL (adversarial review): a malformed non-empty bound like "0".."z" sorts around a real timestamp and
    // would pass the lexicographic window check, so require the exact YYYY-MM-DDTHH:MM:SS.mmmZ shape and a
    // non-inverted window before comparing.
    if !is_canonical_ts(&issued_at)
        || !is_canonical_ts(&not_after)
        || issued_at.as_str() > not_after.as_str()
    {
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
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let manifest_digest = bundle
        .get("coverage_manifest")
        .filter(|m| !m.is_null())
        .map(|m| crate::hashx::sha256_prefixed(m.serialize().as_bytes()))
        .unwrap_or_default();
    // #3 (deep review): the digest of the bundle's `revocation_list`, "" when absent. Binding it into the signed
    // attestation subject closes the STRIP-revocation downgrade: revocation is a "soft" tier whose ABSENCE reads
    // as the safe baseline, so an attacker who can edit the bundle (a relay/MITM/malicious customer) can delete
    // `revocation_list` → `revocation_status: absent` → revoked uses no longer blocked while `ok` stays true. A
    // fresh attestation that committed a revocation_list will mismatch once the list is stripped (digest "" != the
    // signed digest) → subject mismatch → !ok. The attestation sig protects the subject field itself from removal.
    let revocation_digest = bundle
        .get("revocation_list")
        .filter(|m| !m.is_null())
        .map(|m| crate::hashx::sha256_prefixed(m.serialize().as_bytes()))
        .unwrap_or_default();
    // M5 Merkle mode: the same strip-downgrade defense for the signed `revocation_merkle_root` ("" when absent).
    let revocation_merkle_digest = bundle
        .get("revocation_merkle_root")
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
    // M4 (ADR 0005): the broker authorities include every per-`broker_id` `federated_broker_keys` set (a
    // federation deployment may pin per-broker authority and leave `broker_authority_keys` empty), so the
    // attestation must bind those kids too. Folding them is strictly stricter (a larger expected kid set →
    // a federated attestation that omits a per-broker kid mismatches → `failed`, fail-closed); for a
    // single-broker deployment (empty map) the set is byte-for-byte unchanged.
    for vk in opts
        .broker_authority_keys
        .iter()
        .chain(opts.federated_broker_keys.values().flatten())
        .chain(opts.resource_authority_keys.iter())
    {
        kids.insert(cnf_kid(vk));
    }
    let mut mism: Vec<&str> = Vec::new();
    // project_id MUST be a non-empty binding: an empty bundle project_id matching an empty subject field
    // would turn this substitution guard into a no-op, so an absent/empty project_id is always a mismatch.
    let bundle_project = project_id.unwrap_or_default();
    if bundle_project.is_empty() || s_str(sub, "project_id") != bundle_project {
        mism.push("project_id");
    }
    if s_str(sub, "coverage_manifest_digest") != manifest_digest {
        mism.push("coverage_manifest_digest");
    }
    if s_str(sub, "checkpoint_hash") != latest.1 {
        mism.push("checkpoint_hash");
    }
    if s_str(sub, "broker_grant_head_root") != head_root {
        mism.push("broker_grant_head_root");
    }
    if arr(sub, "authority_kids") != kids {
        mism.push("authority_kids");
    }
    if &arr(sub, "resource_ids") != resource_ids {
        mism.push("resource_ids");
    }
    // #3: enforce the bound revocation_list digest ONLY when the (signed) subject carries the field — so a
    // pre-this-change attestation (no field) stays compatible, while a new attestation that committed a list
    // mismatches if the list is later stripped. The attacker cannot drop the subject field (it is sig-covered).
    // When the auditor PINS revocation keys, the field is REQUIRED (an attestation that never committed to the
    // revocation evidence cannot vouch that none was stripped).
    if (sub.get("revocation_digest").is_some() || !opts.revocation_keys.is_empty())
        && s_str(sub, "revocation_digest") != revocation_digest
    {
        mism.push("revocation_digest");
    }
    // The Merkle-mode root is bound the same way when the (signed) subject carries `revocation_merkle_digest`.
    // It stays optional even under pinned revocation keys, since existing producers do not emit it; the
    // `missing` revocation status covers stripping BOTH artifacts regardless.
    if sub.get("revocation_merkle_digest").is_some()
        && s_str(sub, "revocation_merkle_digest") != revocation_merkle_digest
    {
        mism.push("revocation_merkle_digest");
    }
    if !mism.is_empty() {
        issues.push(format!("deployment_attestation: subject does not match the bundle under review — substitution/replay (D7): {}", mism.join(", ")));
        return eval;
    }

    eval.status = "attested_claims".to_string();
    eval
}

/// R2 (ADR 0003) + D4 (ADR 0004) + D7 + M5/M6 role separation. The broker (∪ every per-`broker_id`
/// `federated_broker_keys` set, M4), resource, operation-taxonomy, attestation, TSA, cosig-approver, and
/// revocation key sets MUST be PAIRWISE disjoint — a key shared across two roles could sign ACROSS the role
/// boundary (a broker/resource key in `taxonomy_keys` self-validating a D4 taxonomy; a TSA that is also an
/// authority self-minting a freshness timestamp inside its own window; an approver that is also the broker
/// self-approving a grant; a broker signing its own revocation list). Separately, `authority_keys` MAY equal
/// `broker_authority_keys` (the self-host model — Go pins them equal) but MUST be disjoint from every
/// NON-broker role (T7); the pinned record-signing keys (`trusted_keys`) follow the same rule (broker overlap
/// allowed, every non-broker role disjoint). Any overlap is a FATAL configuration error: abort before evaluating any record over an
/// ambiguous key universe. Returns `Some(report)` — the fatal report to abort with — on any overlap, or `None`
/// to proceed. (VerifyingKey equality is raw-bytes, which also settles the derived key id.)
fn check_role_disjointness(
    opts: &VerifyOptions,
    project_id: Option<String>,
) -> Option<VerifyReport> {
    // M4: the "broker" role for disjointness is the UNION of `broker_authority_keys` and every per-broker set;
    // when `federated_broker_keys` is empty the union == `broker_authority_keys` (single-broker unchanged).
    let mut broker_union: Vec<VerifyingKey> = opts.broker_authority_keys.clone();
    for keys in opts.federated_broker_keys.values() {
        for k in keys.iter().cloned() {
            if !broker_union.contains(&k) {
                broker_union.push(k);
            }
        }
    }
    let role_sets: [(&str, &[VerifyingKey]); 7] = [
        ("broker_authority_keys", &broker_union),
        ("resource_authority_keys", &opts.resource_authority_keys),
        ("taxonomy_keys", &opts.taxonomy_keys),
        ("attestation_keys", &opts.attestation_keys),
        ("trusted_tsa_keys", &opts.trusted_tsa_keys),
        ("cosig_approver_keys", &opts.cosig_approver_keys),
        ("revocation_keys", &opts.revocation_keys),
    ];
    for i in 0..role_sets.len() {
        for j in (i + 1)..role_sets.len() {
            if role_sets[i].1.iter().any(|k| role_sets[j].1.contains(k)) {
                return Some(fatal_config_report(
                    project_id,
                    &format!(
                        "{} and {} must be disjoint (a key in both breaks role separation) — fatal configuration error",
                        role_sets[i].0, role_sets[j].0
                    ),
                ));
            }
        }
    }
    // T7 (adversarial review): `authority_keys` MAY equal `broker_authority_keys`, but a key in any NON-broker role that
    // ALSO elevates a generic record's authority to `verified` is role confusion.
    for (name, set) in [
        ("resource_authority_keys", &opts.resource_authority_keys),
        ("taxonomy_keys", &opts.taxonomy_keys),
        ("attestation_keys", &opts.attestation_keys),
        ("trusted_tsa_keys", &opts.trusted_tsa_keys),
        ("cosig_approver_keys", &opts.cosig_approver_keys),
        ("revocation_keys", &opts.revocation_keys),
    ] {
        if opts.trusted_authority_keys.iter().any(|k| set.contains(k)) {
            return Some(fatal_config_report(
                project_id,
                &format!("authority_keys and {name} must be disjoint (a non-broker role key must not also elevate generic authority) — fatal configuration error"),
            ));
        }
    }
    // The pinned RECORD-SIGNING keys (`trusted_keys` / opts `signing_keys`) must be disjoint from every
    // NON-broker role too (docs/dev/SECURITY.md "Role separation"). The sharpest case is TSA: a thief holding a
    // compromised signing key that is ALSO a pinned TSA key self-anchors every checkpoint "before" the
    // compromise, salvaging all its forgeries (RCP §10.2). As with `authority_keys`, the broker overlap stays
    // allowed — the broker recording key IS the record-signing key by design (ADR 0002), and self-host pins the
    // generic `authority_keys` equal to it.
    if let Some(signing) = &opts.trusted_keys {
        for (name, set) in [
            ("resource_authority_keys", &opts.resource_authority_keys),
            ("taxonomy_keys", &opts.taxonomy_keys),
            ("attestation_keys", &opts.attestation_keys),
            ("trusted_tsa_keys", &opts.trusted_tsa_keys),
            ("cosig_approver_keys", &opts.cosig_approver_keys),
            ("revocation_keys", &opts.revocation_keys),
        ] {
            if signing.iter().any(|t| set.contains(&t.vk)) {
                return Some(fatal_config_report(
                    project_id,
                    &format!("signing_keys and {name} must be disjoint (a record-signing key must not also act in a non-broker role) — fatal configuration error"),
                ));
            }
        }
    }
    None
}

/// Build the bundle's signing-key store: (signing_key_id, key_epoch) -> KeyEntry, decoding each declared
/// public_key. A malformed entry (undecodable key, or missing id/epoch/public_key) is recorded as an issue and
/// skipped — that simply leaves any record referencing it signature-unverifiable downstream (fail-closed).
fn build_key_store(
    key_entries: &[CanonValue],
    issues: &mut Vec<String>,
) -> BTreeMap<(String, i64), KeyEntry> {
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
    keys
}

/// Backdating gate (RCP §10.1 step 5 / threat #3): anchored times must be NON-DECREASING with checkpoint seq.
/// `anchored` is `(seq, anchored_ts, frontier)` for each checkpoint carrying a VERIFIED anchor — only verified
/// anchors are compared (partial anchoring cannot backdate: the latest anchored checkpoint cryptographically
/// bounds the existence time of all its causal ancestors, and `agent_ts` is untrusted regardless). A
/// non-canonical `anchored_ts` breaks the lexical==chronological assumption (RFC3339 fixed-ms UTC sorts
/// lexically iff canonical), so it is rejected rather than silently mis-ordered.
fn check_anchor_backdating(
    anchored: &[(i64, String, Vec<String>)],
    issues: &mut Vec<String>,
) -> bool {
    let mut sorted_anchored = anchored.to_vec();
    sorted_anchored.sort_by_key(|(seq, _, _)| *seq);
    let mut valid = true;
    for (seq, ts, _) in &sorted_anchored {
        if !is_canonical_ts(ts) {
            valid = false;
            issues.push(format!(
                "checkpoint {seq}: anchor time {ts:?} is not a canonical RCP timestamp — the backdating ordering check requires canonical times (threat #3)"
            ));
        }
    }
    for w in sorted_anchored.windows(2) {
        if is_canonical_ts(&w[0].1) && is_canonical_ts(&w[1].1) && w[1].1 < w[0].1 {
            valid = false;
            issues.push(format!(
                "anchor time decreased across checkpoints {} -> {} (backdating, threat #3)",
                w[0].0, w[1].0
            ));
        }
    }
    valid
}

pub fn verify_bundle_with(bundle: &CanonValue, opts: &VerifyOptions) -> VerifyReport {
    let mut issues: Vec<String> = Vec::new();
    let mut semantic_record_conflict = false;
    let mut checkpoint_project_conflict = false;
    let project_id = s(bundle, "project_id");

    // Seam 1 — role-key disjointness (R2/D4/D7/M5/M6). A FATAL config error aborts here before any record is
    // evaluated; see check_role_disjointness for the full role matrix + rationale.
    if let Some(report) = check_role_disjointness(opts, project_id.clone()) {
        return report;
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
            &opts.role_key_status,
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
    // The project every record and checkpoint must be bound to. A bundle that OMITS the top-level `project_id`
    // must not skip the binding (records/checkpoints from different projects could then be spliced into one
    // bundle and verify clean): derive it from the first record (else checkpoint) carrying one, so the per-record
    // and per-checkpoint checks below still require ONE shared project. The report and the D7 attestation
    // subject keep using the bundle's STATED `project_id` (an absent one never satisfies the attestation).
    let binding_project_id: Option<String> = project_id.clone().or_else(|| {
        records
            .iter()
            .chain(checkpoints.iter())
            .find_map(|v| s(v, "project_id"))
    });

    // Seam 2 — the bundle's signing-key store ((signing_key_id, key_epoch) -> KeyEntry).
    let keys = build_key_store(key_entries, &mut issues);
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
        let project_ok = match &binding_project_id {
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
        // M4 (ADR 0005, OPTIONAL transitive trust): a Broker grant whose `broker_id` is NOT directly pinned may
        // still elevate IF it carries a valid cross_broker_cert from a PINNED issuer broker vouching for the
        // subject's key. Computed here (owned) so the borrow below can fall back to it. Only attempted for an
        // unpinned subject under a non-empty `federated_broker_keys`; a directly-pinned broker never reaches it.
        // `(subject_vk, issuer_vk)`: the subject elevates the grant; the issuer is the pinned federated key that
        // signed the vouching cert (gated for rotation below).
        let cross_cert_pair: Option<(VerifyingKey, VerifyingKey)> =
            if broker_role == BrokerRole::Broker && !opts.federated_broker_keys.is_empty() {
                match ev_str(rec, "grant_evidence", "broker_id").filter(|b| !b.is_empty()) {
                    Some(bid) if !opts.federated_broker_keys.contains_key(&bid) => {
                        cross_broker_cert_key(rec, opts)
                    }
                    _ => None,
                }
            } else {
                None
            };
        let cross_cert_slice: &[VerifyingKey] = match &cross_cert_pair {
            Some((subject, _issuer)) => std::slice::from_ref(subject),
            None => &[],
        };
        let auth_keys: &[VerifyingKey] = match broker_role {
            // M4 (ADR 0005): per-broker authority. When `federated_broker_keys` is pinned, a grant carrying a
            // `broker_id` elevates ONLY under THAT broker's key set — a broker_id with no pinned set does NOT
            // elevate (fail-closed, never under another broker's keys or the union), so broker B cannot issue a
            // grant in broker A's name — UNLESS a valid cross_broker_cert vouches for it (`cross_cert_slice`,
            // the OPTIONAL transitive tier; empty when no cert holds → still fail-closed). A grant with NO
            // broker_id (non-federated) uses `broker_authority_keys`. When the map is empty (default), every
            // broker grant uses `broker_authority_keys` (shared-root baseline) — single-broker is unchanged.
            BrokerRole::Broker if !opts.federated_broker_keys.is_empty() => {
                match ev_str(rec, "grant_evidence", "broker_id").filter(|b| !b.is_empty()) {
                    Some(bid) => opts
                        .federated_broker_keys
                        .get(&bid)
                        .map(|v| v.as_slice())
                        .unwrap_or(cross_cert_slice),
                    None => &opts.broker_authority_keys,
                }
            }
            BrokerRole::Broker => &opts.broker_authority_keys,
            // A grant_void tombstone is the broker's statement, so it elevates only under the broker key set of
            // its partition (never a cross_broker_cert: voiding is not delegable).
            BrokerRole::Void if !opts.federated_broker_keys.is_empty() => {
                match ev_str(rec, "void_evidence", "broker_id").filter(|b| !b.is_empty()) {
                    Some(bid) => opts
                        .federated_broker_keys
                        .get(&bid)
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]),
                    None => &opts.broker_authority_keys,
                }
            }
            BrokerRole::Void => &opts.broker_authority_keys,
            BrokerRole::Resource => &opts.resource_authority_keys,
            BrokerRole::None => &opts.trusted_authority_keys,
        };
        let (authority, authority_vk) = verify_authority_with_key(rec, auth_keys);
        // ADR 0006 §1: the rotation lifecycle of EVERY pinned key this elevation depends on (the non-active
        // ones), looked up here (the verifying key is known) and gated by anchored-before in pass-2. Two keys:
        //   1. the verifying AUTHORITY key (the direct elevating key, or — transitive — the cert SUBJECT key,
        //      which an auditor MAY also pin), and
        //   2. for a transitive (cross_broker_cert) elevation, the cert ISSUER key — a cert the issuer signed
        //      AFTER its own compromise is forged, so the issuer's lifecycle must gate the transitive grant too
        //      (else a stolen issuer key launders a forged grant to gateway_enforced — the fail-open this closes).
        let authority_role_statuses: Vec<RoleKeyStatus> = authority_vk
            .into_iter()
            .chain(cross_cert_pair.map(|(_subject, issuer)| issuer))
            .filter_map(|vk| opts.role_key_status.get(&vk.to_bytes()).cloned())
            .collect();
        // A grant verified ONLY because a cross_broker_cert vouched for its (unpinned) subject key is `transitive`.
        let transitive_authority = cross_cert_pair.is_some()
            && matches!(
                authority,
                AuthorityTrust::Verified | AuthorityTrust::LegacyUnbound
            );
        if authority == AuthorityTrust::Failed {
            notes.push(format!(
                "authority claims a verified source but its evidence_sig did not verify under a trusted {} authority key",
                broker_role.as_str()
            ));
        }
        if authority == AuthorityTrust::LegacyUnbound {
            notes.push("historical v2 authority signature verifies, but does not bind the semantic record body".into());
        }
        // R2 rule 4: a record that CLAIMS a Tier-B role (carries extensions.broker.kind) but does not
        // classify to a recognized (kind, enforcement_point) role is a fail-closed verification
        // failure — surfaced as an issue, never a silent drop that could let a mislabeled use escape.
        if claims_role && broker_role == BrokerRole::None {
            semantic_record_conflict = true;
            let msg = format!(
                "record {i}: extensions.broker.kind set but (kind, enforcement_point) is not a recognized broker/resource role (R2 fail-closed)"
            );
            notes.push(msg.clone());
            issues.push(msg);
        }
        // GOVDER EVIDENCE BINDING (ADR 0003 R1, threat #4 — the govder analogue of the broker
        // grant/use checks' evidence_rederivable calls elsewhere in this function). A govder
        // record (extensions.govder present) whose signature verified must ALSO have its signed
        // evidence_hash re-derivable from the record's own fields, or the visible governance
        // decision is cryptographically unbound from the signed one — see
        // govder_evidence_rederivable's doc comment. Gated on Verified (not just claims_role,
        // which has no govder equivalent) so an already-Failed/Declared/Unverifiable record does
        // not double-report; gated on extensions.govder present so no non-govder record is
        // affected.
        if matches!(
            authority,
            AuthorityTrust::Verified | AuthorityTrust::LegacyUnbound
        ) && rec
            .get("extensions")
            .and_then(|e| e.get("govder"))
            .is_some()
            && !govder_evidence_rederivable(rec)
        {
            semantic_record_conflict = true;
            let msg = format!(
                "record {i}: authority.evidence_hash is not re-derivable from the govder record's own fields (payload absent or divergent — R1, threat #4)"
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
            authority_role_statuses,
            broker_role,
            transitive_authority,
            notes,
        });
    }

    // record_ids must be unique (two distinct records may not share a record_id). This keeps
    // `record_id` a sound binding handle for authority evidence (a verified evidence triple bound to
    // a record_id cannot be copied onto a different record without colliding here).
    let mut duplicate_record_id = false;
    {
        let mut by_id: BTreeMap<String, String> = BTreeMap::new();
        for rec in records.iter() {
            if let (Some(id), Some(ch)) = (s(rec, "record_id"), s(rec, "content_hash")) {
                if let Some(prev) = by_id.insert(id.clone(), ch.clone()) {
                    if prev != ch {
                        duplicate_record_id = true;
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
    let mut checkpoints_anchors_attached = 0usize;
    // (seq, anchored_ts, frontier) for each checkpoint with a verified anchor
    let mut anchored: Vec<(i64, String, Vec<String>)> = Vec::new();
    // D7: (seq, checkpoint_hash, anchored_ts, head cumulative_root) of each verified+anchored checkpoint,
    // so the deployment-attestation subject can bind the LATEST anchored checkpoint identity + its head.
    let mut anchored_cp_ids: Vec<(i64, String, String, Option<String>)> = Vec::new();
    // D6: (seq, anchored_and_verified, head, frontier) for each VERIFIED checkpoint carrying a head;
    // `verified_headless` holds the frontiers of verified checkpoints that carry NO well-formed head.
    let mut cp_heads: Vec<(i64, bool, GrantHead, Vec<String>)> = Vec::new();
    let mut verified_headless: Vec<Vec<String>> = Vec::new();
    // M4 (ADR 0005): the per-`broker_id` federated head maps of verified checkpoints (the generalization of the
    // single D6 head), the frontiers of verified checkpoints carrying NO such map, and a present-but-malformed
    // map flag — used by `compute_federation_trust` ONLY when federation is active (else they are ignored and the
    // single-broker D6 path runs verbatim).
    let mut cp_fed_heads: Vec<FedHeadCp> = Vec::new();
    let mut verified_fed_headless: Vec<Vec<String>> = Vec::new();
    let mut verified_malformed_fed_head = false;
    // A broker_grant_head FIELD present on a VERIFIED checkpoint but unparseable is a tampered/garbled D6
    // head — pre-D6 checkpoints never carry the field, so it is a D6 activation signal (and a violation),
    // distinct from a checkpoint with no head field at all. Tracked so D6 cannot be dodged by garbling it.
    let mut verified_malformed_head = false;
    // The frontiers of EVERY verified (signature-checked, key-honored) checkpoint, anchored or not — the
    // `committed` set the Tier-B join evaluates its NEGATIVE findings over (see the R3 note at the join).
    let mut verified_frontiers: Vec<String> = Vec::new();
    // Pre-pass: each checkpoint's seal check and (on a sealed checkpoint) anchor check, done ONCE up front so the
    // RCP §10.2 key-status gate below can see anchors on LATER checkpoints before any checkpoint is accepted.
    let any_tsa_trust = !opts.trusted_tsa_keys.is_empty() || !opts.trusted_tsa_spki.is_empty();
    let anchor_trust = crate::anchor::AnchorTrust {
        test_anchor_keys: opts.trusted_tsa_keys.clone(),
        rfc3161_tsa_spki: opts.trusted_tsa_spki.clone(),
    };
    let cp_pre: Vec<CpPre> = checkpoints
        .iter()
        .map(|cp| {
            let entry = cp
                .get("key")
                .and_then(|k| s(k, "signing_key_id"))
                .zip(
                    cp.get("key")
                        .and_then(|k| k.get("key_epoch"))
                        .and_then(|v| v.as_int()),
                )
                .and_then(|(id, ep)| keys.get(&(id, ep)))
                .filter(|e| !keys_externally_pinned || is_trusted(&e.vk));
            let seal = entry.map(|e| verify_checkpoint_sealed(cp, &e.vk));
            let sealed = matches!(seal, Some(Ok(())));
            // RCP §10.2 applied to the CHECKPOINT key exactly as to a record key: the worst of the checkpoint's
            // own asserted key_status (when present), the bundle key entry's, and the authoritative pinned status;
            // under pinning ONLY the pinned compromise time counts (a bundle cannot future-date it).
            let gate = entry.and_then(|e| {
                let pin = pinned_for(&e.vk);
                let mut eff = e.status.clone();
                if let Some(cs) = cp.get("key").and_then(|k| s(k, "key_status")) {
                    eff = worst_status(&eff, &cs);
                }
                if let Some(ps) = pin.and_then(|t| t.status.as_deref()) {
                    eff = worst_status(&eff, ps);
                }
                if matches!(eff.as_str(), "active" | "retired") {
                    return None;
                }
                let changed_at = if keys_externally_pinned {
                    pin.and_then(|t| t.status_changed_at.clone())
                } else {
                    e.status_changed_at.clone()
                };
                Some((eff, changed_at))
            });
            // Only an anchor on a SEALED checkpoint can contribute (else an attacker pairs an unsigned
            // checkpoint — arbitrary frontier — with a valid TSA token).
            let anchor = match cp.get("anchor") {
                Some(a) if sealed && any_tsa_trust => Some(
                    verify_anchor_keyed(
                        &s(cp, "checkpoint_hash").unwrap_or_default(),
                        a,
                        &anchor_trust,
                    )
                    .map_err(|e| e.to_string()),
                ),
                _ => None,
            };
            CpPre { seal, gate, anchor }
        })
        .collect();
    // An anchor honored under the TSA-key rotation rule (ADR 0006 §1 — see the main loop) — its genTime.
    let honored_anchor_ts = |pre: &CpPre| -> Option<String> {
        match &pre.anchor {
            Some(Ok((ts, tsa_vk))) => tsa_vk
                .is_none_or(|vk| {
                    role_key_honored(&vk, &opts.role_key_status, |rks| {
                        honored_clean_rotation(rks, ts)
                    })
                })
                .then(|| ts.clone()),
            _ => None,
        }
    };
    // Earliest honored anchor time that COMMITS each checkpoint: its own anchor, or one on a LATER sealed
    // checkpoint whose `prev_checkpoint_hash` chain reaches it (an anchor over a checkpoint hash commits every
    // earlier checkpoint hash it chains to — the anchor proves those bytes existed at genTime, whoever signed the
    // later checkpoint). Anchors are visited in ascending time and each walk stops at a checkpoint already dated,
    // so every checkpoint is dated at most once (linear, cycle-safe).
    let mut cp_committed_at: Vec<Option<String>> = vec![None; checkpoints.len()];
    {
        let mut by_hash: BTreeMap<String, usize> = BTreeMap::new();
        for (i, cp) in checkpoints.iter().enumerate() {
            if matches!(cp_pre[i].seal, Some(Ok(()))) {
                if let Some(h) = s(cp, "checkpoint_hash") {
                    by_hash.entry(h).or_insert(i);
                }
            }
        }
        let mut dated: Vec<(String, usize)> = cp_pre
            .iter()
            .enumerate()
            .filter_map(|(i, pre)| honored_anchor_ts(pre).map(|ts| (ts, i)))
            .filter(|(ts, _)| is_canonical_ts(ts))
            .collect();
        dated.sort();
        for (ts, j) in dated {
            let mut k = j;
            while cp_committed_at[k].is_none() {
                cp_committed_at[k] = Some(ts.clone());
                match s(&checkpoints[k], "prev_checkpoint_hash").and_then(|h| by_hash.get(&h)) {
                    Some(&prev) => k = prev,
                    None => break,
                }
            }
        }
    }
    for (i, cp) in checkpoints.iter().enumerate() {
        if let Some(pid) = &binding_project_id {
            if s(cp, "project_id").as_deref() != Some(pid.as_str()) {
                checkpoint_project_conflict = true;
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
            .map(|a| {
                a.iter()
                    .filter_map(|h| h.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let head_field_present = cp.get("broker_grant_head").is_some();
        let cp_head = parse_grant_head(cp);
        // M4: the federated head MAP (mutually exclusive with the single head in a well-formed bundle).
        let fed_head_field_present = cp.get("broker_grant_heads").is_some();
        let cp_fed_head = parse_grant_heads_map(cp);
        let mut this_anchored = false;
        let pre = &cp_pre[i];
        let cp_verified = match (&pre.seal, &pre.gate) {
            (Some(Ok(())), None) => true,
            // RCP §10.2 for CHECKPOINTS (threat #9 omission): a checkpoint signed by a revoked/compromised key is
            // trusted ONLY if a verified anchor at/before the key's status change commits it. Otherwise a thief
            // holding the key could drop a session and re-sign a fresh, internally-consistent chain — the record
            // rule alone never saw it, since the surviving records may be signed by a different, active key.
            (Some(Ok(())), Some((status, changed_at))) => {
                let predates = changed_at.as_deref().is_some_and(|c| {
                    is_canonical_ts(c) && cp_committed_at[i].as_deref().is_some_and(|t| t <= c)
                });
                if !predates {
                    issues.push(format!(
                        "checkpoint {i}: signed by a {status} key and NOT anchored before its status change — untrusted (RCP §10.2, threat #9)"
                    ));
                }
                predates
            }
            (Some(Err(e)), _) => {
                issues.push(format!("checkpoint {i} invalid: {e}"));
                false
            }
            (None, _) => {
                issues.push(format!("checkpoint {i}: no trusted public key to verify"));
                false
            }
        };
        if cp_verified {
            checkpoints_verified += 1;
            verified_frontiers.extend(cp_frontier.iter().cloned());
        }
        if cp.get("anchor").is_some() {
            // PRESENCE only — `checkpoints_anchored` is incremented below solely for an anchor that verified.
            checkpoints_anchors_attached += 1;
            // Only an anchor on a *verified* checkpoint can contribute to trust — otherwise an
            // attacker pairs an unsigned checkpoint (arbitrary frontier) with a valid TSA token.
            if cp_verified {
                let cph = s(cp, "checkpoint_hash").unwrap_or_default();
                match &pre.anchor {
                    Some(Ok((ts, _))) => {
                        // ADR 0006 §1 — TSA-key rotation (the foundational case). The TSA MINTS the genTime, so a
                        // STOLEN key can forge a token with ANY genTime (backdating) — "genTime <= T" cannot be
                        // trusted. So a `compromised`/`revoked` TSA key's anchors are NEVER honored (the
                        // checkpoint becomes effectively UN-anchored, which correctly cascades: records committed
                        // only by it are no longer `anchored_before` anything, defeating the very backdating that
                        // would otherwise bypass every other rotation gate). A cleanly `rotated` TSA key's
                        // anchors are honored only for genTime at/before the rotation. (RFC 3161 SPKIs are not
                        // ed25519 role keys — tsa_vk is None there — so they pass; their rotation is out of scope.)
                        if honored_anchor_ts(pre).is_none() {
                            issues.push(format!(
                                "checkpoint {i} anchor: TSA key is rotated/compromised and the anchor genTime {ts} is not provably before that status change — anchor NOT trusted (ADR 0006 role-key rotation)"
                            ));
                        } else {
                            this_anchored = true;
                            checkpoints_anchored += 1;
                            anchored_cp_ids.push((
                                cp_seq,
                                cph.clone(),
                                ts.clone(),
                                cp_head.as_ref().map(|h| h.cumulative_root.clone()),
                            ));
                            anchored.push((cp_seq, ts.clone(), cp_frontier.clone()));
                        }
                    }
                    Some(Err(e)) => issues.push(format!("checkpoint {i} anchor invalid: {e}")),
                    None => {}
                }
            }
        }
        // Only a VERIFIED checkpoint's head + frontier are cryptographically bound — never seed D6 trust
        // from an unsigned checkpoint whose head/frontier an attacker could choose. A verified checkpoint
        // that carries NO (or a malformed → None) head is tracked separately so D6 can flag it if its
        // frontier commits grants (a checkpoint that binds grants without a head omits them from the log).
        if cp_verified {
            // M4: the per-broker federated head map (used only when federation is active). A verified checkpoint
            // with NO well-formed map is tracked as fed-headless (so a federated grant it commits without a head is
            // flagged); a present-but-malformed map is a tampered federation head.
            match cp_fed_head {
                Some(map) => cp_fed_heads.push((cp_seq, this_anchored, map, cp_frontier.clone())),
                None => {
                    if fed_head_field_present {
                        verified_malformed_fed_head = true;
                    }
                    verified_fed_headless.push(cp_frontier.clone());
                }
            }
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

    // Seam 3 — anchored times must be non-decreasing with seq (backdating, threat #3).
    let anchor_order_valid = check_anchor_backdating(&anchored, &mut issues);

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
    // M4 (ADR 0005, OPTIONAL): count integrity-proven broker grants whose authority verified ONLY via a
    // cross_broker_cert (observability — a transitive grant is otherwise counted/matched as any verified grant).
    let mut transitive_grants = 0usize;
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

        // ADR 0006 §1 — role-key rotation. A grant/use whose authority evidence verified under a COMPROMISED /
        // ROTATED / REVOKED role key keeps its `gateway_enforced` elevation ONLY if the record was transitively
        // committed by a verified anchor AT OR BEFORE the role key's status_changed_at — i.e. it predates the
        // compromise. Otherwise the elevation is WITHDRAWN (authority -> Failed): the grant no longer reaches
        // Tier-A, so any USE of it fails to match (a violation, -> !ok) while an unused grant simply drops to
        // unaccountable. The status is AUTHORITATIVE (auditor-pinned, out of band) — the bundle cannot
        // self-assert it. A non-active status whose `status_changed_at` is absent or non-canonical withdraws
        // UNCONDITIONALLY (fail-closed: an undatable compromise cannot be proven to predate any record). The
        // record's own integrity/signature trust (above) is independent — a real record signed by a good
        // signing key stays integrity-proven; only its authority ELEVATION is withdrawn.
        if matches!(
            p.authority,
            AuthorityTrust::Verified | AuthorityTrust::LegacyUnbound
        ) {
            // Withdraw if ANY involved pinned key (direct authority/subject OR transitive cert issuer) is
            // non-active and this record does NOT predate that key's status change. The list holds only
            // non-active statuses, so each entry is a real gate.
            for rks in &p.authority_role_statuses {
                let predates = rks
                    .status_changed_at
                    .as_deref()
                    .is_some_and(|c| anchored_before(&p.content_hash, c));
                if !predates {
                    p.authority = AuthorityTrust::Failed;
                    p.transitive_authority = false;
                    p.notes.push(format!(
                        "an authority role key it depends on is {}: this grant/use is NOT anchored before that role-key status change — elevation withdrawn (ADR 0006 role-key rotation)",
                        rks.status
                    ));
                    break;
                }
            }
        }

        if trust == TrustLevel::IntegrityProven {
            records_proven += 1;
            if p.transitive_authority && p.broker_role == BrokerRole::Broker {
                transitive_grants += 1;
            }
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

    // D6 operator remediation: every grant_void tombstone must be well-formed, bound and (under pinned broker keys)
    // broker-signed before it may fill its seq; a bad one is a hard issue (it never counts as a grant either way).
    let void_issues_before = issues.len();
    check_grant_voids(&record_trust, records, opts, &mut issues);
    let void_contradiction = issues.len() > void_issues_before;

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
    let grant_issues_before = issues.len();
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
            if rt.trust == TrustLevel::IntegrityProven
                && matches!(
                    rt.authority,
                    AuthorityTrust::Verified | AuthorityTrust::LegacyUnbound
                )
            {
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

    let grant_contradiction = issues.len() > grant_issues_before;
    // ---- Tier-B (ADR 0003 step 5): use↔grant join (R3) ----
    // CLOSED = a record's content_hash is transitively committed by a verified, ANCHORED checkpoint (the union of
    // the anchored committed sets). COMMITTED = transitively committed by ANY verified (signed, key-honored)
    // checkpoint, anchored or not; CLOSED ⊆ COMMITTED.
    //
    // MONOTONICITY (the reason for the split): `anchor` is outside the checkpoint hash (checkpoint.rs STRIP), so
    // it is UNSIGNED, optional data — anyone can delete it and the checkpoints still verify. When the join ran
    // over CLOSED alone, deleting every anchor turned every closed use into `unmatched_pending` (never a
    // violation), so an action-without-credential, a double-spend, a revoked use, a cosig/delegation failure or a
    // mis-scoped grant all read `ok:true` with no key at all. Removing unsigned data must never IMPROVE the
    // verdict. So:
    //   * NEGATIVE findings (violations, blocked uses, grant-issuance rejections) are evaluated over COMMITTED
    //     records — this is ADR 0003 R3's own wording ("a use NOT yet committed by a verified checkpoint ⇒
    //     pending"). The checkpoint signer can only ADD evidence against itself this way: every grant/use it
    //     commits is independently broker-/resource-signed, and dropping the anchor no longer hides it.
    //   * POSITIVE claims (`uses_matched`, PoP re-verification, action verification, `grants_unused`, native
    //     coverage) still require CLOSURE: a committed use that passes every check but whose use/grant/outcome
    //     is not anchored-closed is `unmatched_pending` (in-flight), exactly as before. It still CONSUMES its
    //     single-use/bounded grant and its outcome, so a second committed spend is a violation, never pending.
    //   * A CLOSED use whose grant is committed but NOT closed stays a violation ("no matching closed grant"),
    //     unchanged — closure is never inherited from an unanchored peer.
    // Replacing an exporter watermark with this cryptographic boundary closes the watermark-specific
    // suppression path (MUST-FIX 2); never-committed use suppression remains an accepted residual.
    let closed: BTreeSet<&str> = anchored_committed
        .iter()
        .flat_map(|(_, set)| set.iter().map(String::as_str))
        .collect();
    // The COMMITTED extension applies once the auditor pins a Tier-B authority (broker, per-broker, or resource
    // keys) — i.e. asks for Tier-B evaluation at all. With NONE pinned no grant/use can ever validate, so every
    // committed receipt would read "not validatable" and fail the default, pin-nothing integrity flow (the web
    // verifier's) on every broker bundle; there the join stays over CLOSED exactly as before. This gate reads
    // only the auditor's opts, never attacker-removable bundle data, so monotonicity is preserved.
    let tier_b_pinned = !opts.broker_authority_keys.is_empty()
        || !opts.resource_authority_keys.is_empty()
        || !opts.federated_broker_keys.is_empty();
    let committed: BTreeSet<String> = match dag_opt.as_ref() {
        Some(d) if tier_b_pinned => committed_set(records, &d.by_hash, &verified_frontiers),
        _ => closed.iter().map(|h| h.to_string()).collect(),
    };

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
        /// R3: the grant record is anchored-CLOSED (not merely committed) — required for a positive match.
        closed: bool,
    }
    let mut grants_by_id: BTreeMap<String, GrantInfo> = BTreeMap::new();
    // A required credential disclosure applies to every accepted committed broker grant,
    // including an unused grant. Counting only disclosures the exporter chose to provide would
    // let one opened grant mask a second grant's missing descriptor.
    let mut required_descriptor_record_ids: BTreeSet<String> = BTreeSet::new();
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
    // M3 (ADR 0005): native/STS grants. A grant whose SIGNED grant_evidence declares `mode == "token_exchange"`
    // is an externally-minted (IdP/STS) credential the broker never saw the secret of — it has no broker
    // credential_binding and no cnf-key PoP. It is indexed into a SEPARATE map, NEVER the brokered `grants_by_id`,
    // so the brokered and native surfaces stay disjoint: a brokered use receipt naming a native grant_id finds no
    // entry in `grants_by_id` → `unmatched_violation`, and a use of the native credential is accountable ONLY via
    // a resource-signed introspection transcript (the M3 pre-pass below), never a PoP receipt.
    struct NativeGrant {
        scope: String,
        resource_id: String,
        /// The external (IdP/STS) credential reference. A transcript's `credential_ref` MUST equal this — the M3
        /// signature binds `credential_ref`, so the verifier cross-checks it against the grant's own lease so a
        /// resource-signed statement about a DIFFERENT leased credential cannot cover this grant.
        lease_id: String,
        issued_at: i64,
        exp: i64,
        /// R3: anchored-CLOSED (required for the positive `covered_native` claim).
        closed: bool,
    }
    let mut native_grants_by_id: BTreeMap<String, NativeGrant> = BTreeMap::new();
    let mut native_credential_present = false;
    // A rejected, already committed grant is a fixed semantic contradiction even when no
    // receipt exercises that grant. Keep it separate from optional attachment diagnostics.
    let mut committed_grant_rejected = false;
    for rt in &record_trust {
        let rec = &records[rt.index];
        let qualifies = rt.broker_role == BrokerRole::Broker.as_str()
            && rt.trust == TrustLevel::IntegrityProven
            && matches!(
                rt.authority,
                AuthorityTrust::Verified | AuthorityTrust::LegacyUnbound
            )
            && evidence_rederivable(rec, "grant_evidence")
            && committed.contains(&rt.content_hash);
        if !qualifies {
            continue;
        }
        let grant_closed = closed.contains(rt.content_hash.as_str());
        // M3 (ADR 0005): native/STS early branch. Detected from the SIGNED grant_evidence (riding the evidence
        // hash, so it cannot be stripped without breaking `evidence_rederivable` above). A native grant is
        // accounted on the separate `native_grants_by_id` channel and NEVER falls through to the brokered 8-tuple
        // match below — so the brokered path is byte-for-byte unchanged for every non-native grant (additive).
        if ev_str(rec, "grant_evidence", "mode").as_deref() == Some("token_exchange") {
            native_credential_present = true; // set even if malformed → excludes the brokered capstone
                                              // Cross-mode compositions (native × cosig / native × delegation) are deferred (ADR 0005 §5 open
                                              // question) — a native grant that ALSO carries cosignatures or delegation_assertions is fail-closed
                                              // (NOT indexed as native), so its transcript dangles and the introspected capstone is unreachable,
                                              // rather than silently skipping the cosig/delegation gates the brokered path would have enforced.
            if cosignatures_of(rec).is_some_and(|a| !a.is_empty())
                || delegation_assertions_present(rec)
            {
                committed_grant_rejected = true;
                issues.push(format!(
                    "grant {} ({}): native (token_exchange) grant also carries cosignatures/delegation_assertions — unsupported composition in M3 (fail-closed)",
                    rt.index, rt.record_id
                ));
                continue;
            }
            // D4 × M3: a native grant for a (resource_id, action) a signed+pinned taxonomy marks ESCALATING is
            // mis-scoped at issuance, mirroring the brokered single_operation discipline — fail-closed (NOT indexed
            // as native; its transcript then dangles), so an escalating native exchange can never reach the
            // introspected capstone. Only fires when a pinned taxonomy affirmatively lists the pair (else additive).
            if let (Some(n_resource), Some(n_action)) = (
                ev_str(rec, "grant_evidence", "resource_id"),
                ev_str(rec, "grant_evidence", "action"),
            ) {
                if taxonomy_info.as_ref().is_some_and(|ti| {
                    ti.escalating
                        .contains(&(n_resource.clone(), n_action.clone()))
                }) {
                    committed_grant_rejected = true;
                    issues.push(format!(
                        "grant {} ({}): native (token_exchange) grant for action '{n_action}' on '{n_resource}' which the taxonomy marks escalating — mis-scoped (D4)",
                        rt.index, rt.record_id
                    ));
                    continue;
                }
            }
            match (
                ev_str(rec, "grant_evidence", "grant_id"),
                ev_str(rec, "grant_evidence", "scope"),
                ev_str(rec, "grant_evidence", "resource_id"),
                ev_str(rec, "grant_evidence", "lease_id"),
                ev_int(rec, "grant_evidence", "issued_at"),
                ev_int(rec, "grant_evidence", "exp"),
            ) {
                (
                    Some(gid),
                    Some(scope),
                    Some(resource_id),
                    Some(lease_id),
                    Some(issued_at),
                    Some(exp),
                ) => {
                    native_grants_by_id.entry(gid).or_insert(NativeGrant {
                        scope,
                        resource_id,
                        lease_id,
                        issued_at,
                        exp,
                        closed: grant_closed,
                    });
                }
                _ => {
                    committed_grant_rejected = true;
                    issues.push(format!(
                        "grant {} ({}): native (token_exchange) grant_evidence is missing a required field (grant_id/scope/resource_id/lease_id/issued_at/exp) — fail-closed",
                        rt.index, rt.record_id
                    ));
                }
            }
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
            (
                Some(gid),
                Some(action),
                Some(resource_id),
                Some(scope_class),
                Some(cnf_kid),
                Some(credential_binding),
                Some(issued_at),
                Some(exp),
            ) => {
                // v2 brokered grants carry the authorized project inside the
                // broker-signed evidence as well as the sealed record. This gate
                // applies even when the credential descriptor is not disclosed.
                let pop_version = ev_value(rec, "grant_evidence", "pop_version");
                let v2_fields_present = pop_version.is_some()
                    || ev_value(rec, "grant_evidence", "project_id").is_some()
                    || ev_value(rec, "grant_evidence", "request_hash").is_some();
                if v2_fields_present
                    && (pop_version.and_then(CanonValue::as_int) != Some(2)
                        || ev_str(rec, "grant_evidence", "project_id") != s(rec, "project_id")
                        || ev_str(rec, "grant_evidence", "request_hash").is_none_or(|h| {
                            !h.starts_with("sha256:")
                                || h.len() != 71
                                || !h[7..]
                                    .bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        }))
                {
                    committed_grant_rejected = true;
                    issues.push(format!("grant {} ({}): v2 signed project/request identity does not match sealed grant", rt.index, rt.record_id));
                    continue;
                }
                // M1 (bounded_reuse): the cap rides inside the signed grant_evidence (0/absent for other
                // classes). A bounded_reuse grant MUST declare a positive use_limit; an "unbounded bounded"
                // grant is fail-closed (NOT indexed), so a use against it reads as action-without-credential
                // rather than silently honoring an uncapped reuse.
                let use_limit = ev_int(rec, "grant_evidence", "use_limit").unwrap_or(0);
                if scope_class == "bounded_reuse" && use_limit < 1 {
                    committed_grant_rejected = true;
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
                    && taxonomy_info.as_ref().is_some_and(|ti| {
                        ti.escalating
                            .contains(&(resource_id.clone(), action.clone()))
                    })
                    && misscoped.insert(gid.clone())
                {
                    committed_grant_rejected = true;
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
                    committed_grant_rejected = true;
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
                        &opts.role_key_status,
                        &rt.content_hash,
                        &anchored_before,
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
                        committed_grant_rejected = true;
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
                    rec,
                    &gid,
                    &cnf_kid,
                    &grant_scope,
                    &action,
                    &resource_id,
                    exp,
                ) {
                    ChainResult::Absent => (cnf_kid.clone(), exp),
                    ChainResult::Verified {
                        eff_cnf_kid,
                        eff_exp,
                    } => {
                        if delegation_seen.insert(gid.clone()) {
                            delegation_chains_total += 1;
                            delegation_chains_verified += 1;
                        }
                        (eff_cnf_kid, eff_exp)
                    }
                    ChainResult::Monotonicity => {
                        committed_grant_rejected = true;
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
                        committed_grant_rejected = true;
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
                required_descriptor_record_ids.insert(rt.record_id.clone());
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
                    closed: grant_closed,
                });
            }
            // A verified, closed broker grant whose grant_evidence is missing a required match field is
            // a fail-closed failure surfaced as an issue — NOT a silent skip (which would let a use
            // against it read as "action without a credential" and mask the real cause).
            _ => {
                committed_grant_rejected = true;
                issues.push(format!(
                    "grant {} ({}): closed broker grant has incomplete grant_evidence (missing a required match field) — fail-closed",
                    rt.index, rt.record_id
                ));
            }
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
        if rt.broker_role == BrokerRole::Broker.as_str() && rt.trust == TrustLevel::IntegrityProven
        {
            grant_labels
                .entry(rt.record_id.as_str())
                .or_insert(&records[rt.index]);
        }
    }
    let mut cred_label_checks = 0usize;
    let mut cred_label_matched = 0usize;
    let mut matched_descriptor_record_ids: BTreeSet<String> = BTreeSet::new();
    for (rid, descriptor_bytes) in &cred_descriptors {
        let rec = match grant_labels.get(rid.as_str()) {
            Some(r) => *r,
            None => continue, // disclosed for a record that is not an integrity-proven broker grant
        };
        cred_label_checks += 1;
        // (a) the disclosed descriptor must be THE credential the signed grant_evidence bound.
        if crate::hashx::sha256_prefixed(descriptor_bytes)
            != ev_str(rec, "grant_evidence", "credential_binding").unwrap_or_default()
        {
            issues.push(format!("grant {rid}: disclosed credential descriptor sha256 != grant_evidence.credential_binding — wrong or forged descriptor (D6.4)"));
            continue;
        }
        // (b) descriptor fields must agree with the signed grant labels.
        let descriptor = match core::str::from_utf8(descriptor_bytes)
            .ok()
            .and_then(|s| CanonValue::parse(s).ok())
        {
            Some(d) => d,
            None => {
                issues.push(format!("grant {rid}: disclosed credential descriptor is not valid canonical JSON (D6.4)"));
                continue;
            }
        };
        let ds = |k: &str| {
            descriptor
                .get(k)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
        };
        let label = |f: &str| ev_str(rec, "grant_evidence", f).unwrap_or_default();
        let (act, aud, jti) = (ds("act"), ds("aud"), ds("jti"));
        let (action, resource, gid, kidl) = (
            label("action"),
            label("resource_id"),
            label("grant_id"),
            label("cnf_kid"),
        );
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
        if act != action.as_str() {
            mism.push(format!("act '{act}' != action '{action}'"));
        }
        if aud != resource.as_str() {
            mism.push(format!("aud '{aud}' != resource_id '{resource}'"));
        }
        if jti != gid.as_str() {
            mism.push(format!("jti '{jti}' != grant_id '{gid}'"));
        }
        if ev_value(rec, "grant_evidence", "pop_version").is_some()
            || ev_value(rec, "grant_evidence", "project_id").is_some()
            || ev_value(rec, "grant_evidence", "request_hash").is_some()
            || descriptor.get("version").is_some()
            || descriptor.get("project_id").is_some()
        {
            if descriptor.get("version").and_then(|v| v.as_int()) != Some(2) {
                mism.push("v2 descriptor.version is missing or wrong".to_string());
            }
            if ev_int(rec, "grant_evidence", "pop_version") != Some(2) {
                mism.push("v2 grant_evidence.pop_version is missing or wrong".to_string());
            }
            if ds("project_id") != s(rec, "project_id").unwrap_or_default() {
                mism.push("v2 descriptor.project_id != sealed record.project_id".to_string());
            }
            if ds("project_id") != label("project_id") {
                mism.push(
                    "v2 descriptor.project_id != signed grant_evidence.project_id".to_string(),
                );
            }
        }
        if descriptor.get("exp").and_then(|v| v.as_int()) != ev_int(rec, "grant_evidence", "exp") {
            mism.push("exp != grant_evidence.exp".to_string());
        }
        if single_use != Some(single) {
            mism.push(format!(
                "single_use != (scope_class=='single_operation' => {single})"
            ));
        }
        if !cnf_kid_ok {
            mism.push(format!("cnf does not derive cnf_kid '{kidl}'"));
        }
        // EVERY capability-shaping claim the producer mirrors into BOTH the descriptor and grant_evidence must
        // agree (adversarial review): scope (a broad scope minted but a narrow scope LABELED is exactly the mislabel D6.4
        // exists to catch), sub↔agent_id (a credential for a different subject), and iat/nbf↔issued_at (a
        // back/post-dated validity). Checking only act/aud/jti/cnf/exp/single_use left scope+subject+timing
        // unbound — a real false-clean.
        if ds("scope") != label("scope").as_str() {
            mism.push(format!(
                "scope '{}' != grant_evidence.scope '{}'",
                ds("scope"),
                label("scope")
            ));
        }
        if ds("sub") != label("agent_id").as_str() {
            mism.push(format!(
                "sub '{}' != grant_evidence.agent_id '{}'",
                ds("sub"),
                label("agent_id")
            ));
        }
        let iss_at = ev_int(rec, "grant_evidence", "issued_at");
        if descriptor.get("iat").and_then(|v| v.as_int()) != iss_at {
            mism.push("iat != grant_evidence.issued_at".to_string());
        }
        if descriptor.get("nbf").and_then(|v| v.as_int()) != iss_at {
            mism.push("nbf != grant_evidence.issued_at".to_string());
        }
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
            && descriptor.get("use_limit").and_then(|v| v.as_int())
                != ev_int(rec, "grant_evidence", "use_limit")
        {
            mism.push("use_limit (descriptor) != grant_evidence.use_limit".to_string());
        }
        if mism.is_empty() {
            cred_label_matched += 1;
            matched_descriptor_record_ids.insert(rid.clone());
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
    // M5 (ADR 0005): revocation. Evaluate the bundle's signed revocation_list against the latest anchored TSA
    // time; a FRESH list blocks any matched use of a revoked grant_id.
    let anchored_latest = anchored_cp_ids.iter().max_by_key(|(seq, _, _, _)| *seq);
    let anchored_latest_ts = anchored_latest.map(|(_, _, ts, _)| ts.as_str());
    // #2 (deep review): the revocation freshness "now" is the latest ANCHORED checkpoint's time. If a newer
    // UNANCHORED checkpoint exists, "now" has been rolled back; treat revocation currency as un-establishable
    // (stale) so an attacker cannot keep a stale list reading `fresh` by withholding an anchor. Mirrors the
    // deployment_attestation `latest != latest_cp_seq` guard. (No anchored checkpoint → handled inside the
    // evaluators as a distinct hard issue.)
    let anchored_is_latest = anchored_latest.map(|(seq, _, _, _)| *seq) == Some(latest_cp_seq);
    let revocation = evaluate_revocation(
        bundle,
        opts,
        anchored_latest_ts,
        anchored_is_latest,
        &mut issues,
    );
    // M5 Merkle-non-disclosure (ADR 0005): the signed root + the top-level per-grant proof map. When the root is
    // FRESH, every Tier-B use MUST carry a valid proof — a non-membership proof to proceed, else (membership or
    // missing/malformed) the use is blocked/fail-closed (the revoked set is not disclosed, so silence ≠ safe).
    let merkle_rev = evaluate_merkle_revocation(
        bundle,
        opts,
        anchored_latest_ts,
        anchored_is_latest,
        &mut issues,
    );
    let revocation_proofs = bundle.get("revocation_proofs");
    let mut revoked_uses_blocked = 0usize;
    let mut revoked_membership_found = false;
    let mut revocation_nonmembership_verified = 0usize;
    let mut seen_uses: BTreeSet<&str> = BTreeSet::new();
    // D3 (ADR 0004): a (resource_id, PoP nonce) pair seen on two CLOSED receipts is a replay/duplicate
    // submission over the visible set — independent of the per-grant_id single-use rule.
    let mut seen_nonces: BTreeSet<(String, String)> = BTreeSet::new();
    let mut intent_without_outcome = 0usize;
    let mut one_phase_use_present = false; // D8/MF3: any matched one-phase `use` blocks the capstone
    let broker_kind = |rec: &CanonValue| -> Option<String> {
        rec.get("extensions")
            .and_then(|e| e.get("broker"))
            .and_then(|b| b.get("kind"))
            .and_then(|v| v.as_str())
            .map(String::from)
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
    // (intent_ref, grant_id, record_id, index, signed intent_hash, anchored-CLOSED)
    #[allow(clippy::type_complexity)]
    let mut outcomes: Vec<(String, String, String, usize, String, bool)> = Vec::new();
    for rt in &record_trust {
        let rec = &records[rt.index];
        if rt.broker_role != BrokerRole::Resource.as_str()
            || broker_kind(rec).as_deref() != Some("use_outcome")
        {
            continue;
        }
        if !committed.contains(&rt.content_hash) {
            continue; // in-flight outcome: not yet committed by a verified checkpoint, completes nothing
        }
        if rt.trust != TrustLevel::IntegrityProven
            || !matches!(
                rt.authority,
                AuthorityTrust::Verified | AuthorityTrust::LegacyUnbound
            )
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
                let oclosed = closed.contains(rt.content_hash.as_str());
                outcomes.push((iref, ogid, rt.record_id.clone(), rt.index, ihash, oclosed));
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
    for (i, (iref, ogid, _, _, _, _)) in outcomes.iter().enumerate() {
        outcomes_by
            .entry((iref.clone(), ogid.clone()))
            .or_default()
            .push(i);
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
        // M3 (ADR 0005): an introspection_transcript is a RESOURCE record but NOT a use receipt — it carries no
        // use_evidence/PoP. It is handled by the M3 pre-pass below (bound to a native grant + scope-subset
        // checked); skip it here so it is never mis-counted as a use (which would read as `unmatched_violation`).
        if bkind == "introspection_transcript" {
            continue;
        }
        if !seen_uses.insert(rt.content_hash.as_str()) {
            continue; // verbatim-duplicate use deduped (not double-counted)
        }
        uses_total += 1;
        if !committed.contains(&rt.content_hash) {
            unmatched_pending += 1; // in-flight: not yet committed by any verified checkpoint
            continue;
        }
        // R3 split (see the CLOSED/COMMITTED note above): every check below runs for a COMMITTED use, but it can
        // only count as MATCHED when it (and its grant/outcome) is anchored-CLOSED; otherwise it ends as pending.
        let use_closed = closed.contains(rt.content_hash.as_str());
        // A COMMITTED use must be cryptographically validatable (integrity + resource-role authority +
        // re-derivable use_evidence) before its match fields can be trusted — otherwise fail closed.
        let violation = |issues: &mut Vec<String>, msg: String| {
            issues.push(format!("use {} ({}): {msg}", rt.index, rt.record_id));
        };
        if rt.trust != TrustLevel::IntegrityProven
            || !matches!(
                rt.authority,
                AuthorityTrust::Verified | AuthorityTrust::LegacyUnbound
            )
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
                violation(
                    &mut issues,
                    "top-level action diverges from use_evidence.action (MUST-FIX 1)".into(),
                );
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
            violation(
                &mut issues,
                "use_evidence is missing the PoP nonce (R4) — violation".into(),
            );
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
                violation(
                    &mut issues,
                    "use_evidence is missing a required match field — violation".into(),
                );
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
            // a CLOSED use needs a CLOSED grant (unchanged R3 semantics); a committed-only use may pair with a
            // committed-only grant, but can then only end as pending.
            Some(g) if g.closed || !use_closed => g,
            _ => {
                unmatched_violation += 1;
                violation(&mut issues, format!("no matching {} grant '{gid}' — action without a credential (Tier-B violation)", if use_closed { "closed" } else { "committed" }));
                continue;
            }
        };
        // M5 (ADR 0005): a use of a grant the revocation_list EXPLICITLY marks revoked is blocked — whether the
        // list is `fresh` OR `stale`. `revoked` is populated ONLY for a validly-signed list (a forged/malformed
        // list yields an empty set + an issue), and a signed "this grant is revoked" is a MONOTONE fact: staleness
        // (the window no longer brackets the anchored time) means the list may not be the LATEST snapshot, NOT
        // that a named grant became valid again. Blocking only on `fresh` was a fail-open (a relying party gating
        // on `ok` accepted a provably-revoked credential). A hard violation (→ !ok); the grant is NOT consumed.
        // `absent` (no list / unpinned issuer) leaves `revoked` empty, so this is a no-op there.
        if revocation.revoked.contains(&gid) {
            revoked_uses_blocked += 1;
            revoked_membership_found = true;
            violation(&mut issues, format!("use of grant '{gid}' which a signed revocation_list ({}) marks REVOKED — blocked (M5)", revocation.status));
            continue;
        }
        // M5 Merkle-non-disclosure (ADR 0005): when a signed root is present (fresh OR stale), this use's grant
        // must PROVE its non-revocation against the (undisclosed) revoked set. A valid non-membership proof lets
        // it proceed; a valid membership proof blocks it (revoked); a missing/malformed/forged proof is
        // FAIL-CLOSED (the set is hidden, so an unproven use cannot be assumed safe — and a STALE root must still
        // demand a proof, else an attacker presents an old root + omits the proof for a revoked grant). The stale
        // status separately blocks the capstone; here we only enforce per-use non-revocation. `absent` (no
        // root / unpinned issuer) leaves `root: None`, so this gate is skipped.
        if merkle_rev.root.is_some() {
            let proof = revocation_proofs.and_then(|m| m.get(gid.as_str()));
            let verdict = merkle_rev
                .root
                .as_ref()
                .map(|root| {
                    proof.map_or(ProofVerdict::Unproven, |p| {
                        check_revocation_proof(p, &gid, root, merkle_rev.leaf_count)
                    })
                })
                .unwrap_or(ProofVerdict::Unproven);
            match verdict {
                ProofVerdict::NotRevoked => {
                    revocation_nonmembership_verified += 1; // proven not-revoked; fall through to matching
                }
                ProofVerdict::Revoked => {
                    revoked_uses_blocked += 1;
                    revoked_membership_found = true;
                    violation(&mut issues, format!("use of grant '{gid}' which a signed revocation_merkle_root ({}) proves REVOKED — blocked (M5)", merkle_rev.status));
                    continue;
                }
                ProofVerdict::Unproven => {
                    revoked_uses_blocked += 1;
                    violation(&mut issues, format!("use of grant '{gid}': a signed revocation_merkle_root ({}) is present but no valid non-membership proof — cannot prove the credential was not revoked (M5 fail-closed)", merkle_rev.status));
                    continue;
                }
            }
        }
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
            violation(
                &mut issues,
                format!("action/resource/cnf/window does not match grant '{gid}' — violation"),
            );
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
            violation(
                &mut issues,
                format!(
                    "{} grant '{gid}' requires use_evidence.jti == grant_id (R5) — violation",
                    g.scope_class
                ),
            );
            continue;
        }
        if single && g.used >= 1 {
            unmatched_violation += 1;
            violation(
                &mut issues,
                format!("single-use grant '{gid}' exercised more than once — double-spend (R5)"),
            );
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
                    let (_, _, orec, oidx, ihash, _) = &outcomes[i];
                    !consumed_outcomes.contains(orec)
                        && ihash.as_str() == rt.content_hash.as_str()
                        && records[*oidx]
                            .get("causal_prev_hashes")
                            .and_then(|v| v.as_array())
                            .is_some_and(|p| {
                                p.iter()
                                    .any(|h| h.as_str() == Some(rt.content_hash.as_str()))
                            })
                })
            });
        }
        // D2 (ADR 0004): re-run the Ed25519 PoP offline if the receipt carries the cnf pubkey + use_sig —
        // reconstructing the challenge from the proven fields + this grant's credential_binding + the
        // record's input_commit. A claimed re-verification that FAILS is a violation; a receipt that
        // carries neither stays `shim_asserted` (legacy ADR-0003 path). This NEGATIVE check runs on every
        // committed use/intent BEFORE any completion (closure) branch below: a two-phase intent whose
        // outcome is missing or only committed must still fail on a bad PoP, or deleting one checkpoint's
        // unsigned `anchor` would turn a violation into a pass (monotonicity). A failed intent never
        // consumes its outcome, so the outcome is still reported as an orphan.
        let pop_reverified = match pop_reverify(rec, &g.credential_binding) {
            Ok(r) => r,
            Err(msg) => {
                unmatched_violation += 1;
                violation(&mut issues, format!("offline PoP re-verification: {msg}"));
                continue;
            }
        };
        if bkind == "use_intent" {
            match pending_consume {
                // no outcome at all: a CLOSED intent is the D5 anomaly; a committed-only one is still in flight.
                None => {
                    if use_closed {
                        intent_without_outcome += 1;
                    } else {
                        unmatched_pending += 1;
                    }
                    continue;
                }
                // a CLOSED intent whose outcome is only committed (not anchored): completion is not yet
                // established over the closed set — the D5 anomaly, as before (when the outcome was invisible).
                // The (validated) intent consumes the outcome so it is not ALSO reported as an orphan.
                Some(i) if use_closed && !outcomes[i].5 => {
                    consumed_outcomes.insert(outcomes[i].2.clone());
                    intent_without_outcome += 1;
                    continue;
                }
                Some(_) => {}
            }
        }
        if let Some(i) = pending_consume {
            consumed_outcomes.insert(outcomes[i].2.clone()); // accepted intent → consume its outcome now
        }
        // R3: a use that passed every check but is not anchored-CLOSED (nor, for a two-phase pair, its outcome —
        // handled above, nor its grant — `!g.closed` implies `!use_closed` here) is in-flight: pending, not
        // matched. It still CONSUMES the grant (and its sequence number / outcome), so a second committed spend
        // of a single-use grant is a double-spend violation rather than a second pending use.
        if !use_closed || !g.closed {
            g.used += 1;
            if let Some(usn) = use_seq {
                g.used_seqs.insert(usn);
            }
            unmatched_pending += 1;
            continue;
        }
        if pop_reverified {
            uses_pop_reverified += 1;
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
        // another (adversarial review AREA 2). M1: bounded_reuse is action-verifiable too — it fixes one
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
    for (iref, ogid, orec, _, _, _) in &outcomes {
        if !consumed_outcomes.contains(orec) {
            unmatched_violation += 1;
            issues.push(format!("use_outcome {orec}: references intent '{iref}' (grant {ogid}) but no closed matching use_intent consumed it — completion without a recorded intent (D5)"));
        }
    }
    // D4: a mis-scoped grant is rejected, not "unused" — exclude it so an exercised-but-mis-scoped grant
    // (whose use was skipped, leaving used==0) is not mis-reported as a clean unused grant.
    let grants_unused = grants_by_id
        .iter()
        .filter(|(gid, g)| g.closed && g.used == 0 && !misscoped.contains(*gid))
        .count();
    // M1: closed grants bounded to N uses of one (action, resource_id).
    let bounded_reuse_grants = grants_by_id
        .values()
        .filter(|g| g.closed && g.scope_class == "bounded_reuse")
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
    } else if delegation_chains_verified == delegation_chains_total
        && delegation_monotonicity_violations == 0
    {
        "verified"
    } else {
        "unverified"
    }
    .to_string();

    // M5 (ADR 0005): a NATIVE (token_exchange) credential can be revoked too. The use-loop revocation gates only
    // cover the BROKERED surface; native accountability is the separate introspection pre-pass, so a revoked
    // native grant would otherwise keep introspection_status:"attested" (a revoked credential certified — a
    // fail-open). Apply the SAME gates to each native grant_id HERE (before finalizing revocation_status so it
    // recolors), collecting the revoked set so the pre-pass can force those grants out of `covered_native` (never
    // `attested` over a revoked credential). Each is also a hard violation (→ !ok) + counted in revoked_uses_blocked.
    // Mirrors the brokered use-loop gates: block on an EXPLICIT disclosed revocation (fresh OR stale — a signed
    // "revoked" is monotone), and demand a non-membership proof whenever a Merkle root is present (fresh OR stale).
    let mut revoked_native: BTreeSet<String> = BTreeSet::new();
    for gid in native_grants_by_id.keys() {
        if revocation.revoked.contains(gid.as_str()) {
            revoked_uses_blocked += 1;
            revoked_membership_found = true;
            revoked_native.insert(gid.clone());
            issues.push(format!("native credential for grant '{gid}': a signed revocation_list ({}) marks it REVOKED — its introspected surface is blocked (M5)", revocation.status));
        } else if merkle_rev.root.is_some() {
            let proof = revocation_proofs.and_then(|m| m.get(gid.as_str()));
            let verdict = merkle_rev
                .root
                .as_ref()
                .map(|root| {
                    proof.map_or(ProofVerdict::Unproven, |p| {
                        check_revocation_proof(p, gid, root, merkle_rev.leaf_count)
                    })
                })
                .unwrap_or(ProofVerdict::Unproven);
            match verdict {
                ProofVerdict::NotRevoked => revocation_nonmembership_verified += 1,
                ProofVerdict::Revoked => {
                    revoked_uses_blocked += 1;
                    revoked_membership_found = true;
                    revoked_native.insert(gid.clone());
                    issues.push(format!("native credential for grant '{gid}': a signed revocation_merkle_root ({}) proves it REVOKED — blocked (M5)", merkle_rev.status));
                }
                ProofVerdict::Unproven => {
                    revoked_uses_blocked += 1;
                    revoked_native.insert(gid.clone());
                    issues.push(format!("native credential for grant '{gid}': a signed revocation_merkle_root ({}) is present but no valid non-membership proof — cannot prove the credential was not revoked (M5 fail-closed)", merkle_rev.status));
                }
            }
        }
    }

    // M5 (ADR 0005): finalize revocation. revoked_grants_matched = closed grants whose grant_id is on the
    // (validly-signed) list; if a fresh list blocked any use OR native credential, the status becomes
    // `revoked_present`.
    let revoked_grants_matched = grants_by_id
        .iter()
        .filter(|(gid, g)| g.closed && revocation.revoked.contains(*gid))
        .count();
    let revocation_status = if revoked_uses_blocked > 0 {
        "revoked_present".to_string()
    } else {
        revocation.status.clone()
    };
    // The Merkle-mode status is reported as evaluated (absent|fresh|stale); blocked/unproven uses already raise a
    // hard violation (→ !ok) and are counted in revoked_uses_blocked, so no separate "revoked_present" recolor.
    let revocation_merkle_status = merkle_rev.status.clone();

    // M3 (ADR 0005): native/STS introspection-transcript pre-pass. A native (token_exchange) credential's use is
    // accountable ONLY via a resource-signed introspection transcript, never a brokered PoP receipt. Each CLOSED
    // `introspection_transcript` record must: be a validatable resource record (integrity + resource authority +
    // re-derivable `introspection_evidence`); bind to a present NATIVE grant by grant_id (a brokered/absent
    // grant_id is dangling — the surfaces stay disjoint); carry a structured `averin.resource.introspection.v1`
    // signature verifying under a pinned `resource_authority_keys` issuer over its EXACT
    // (grant_id, credential_ref, effective_scope, resource_id, introspected_at, effective_exp) tuple; name the
    // grant's own resource_id; and prove `effective_scope ⊆ grant.scope` (space-delimited OAuth token subset — no
    // scope-broadening) with no time-broadening (`effective_exp <= grant.exp`) and `grant.issued_at <=
    // introspected_at`. ANY failure is a hard `unmatched_violation` (→ !ok): a resource broadening past the grant
    // it was handed is an escalation, not a quiet non-match. Every native grant must be covered by ≥1 verified
    // transcript for the introspected surface to be COMPLETE.
    let mut introspection_transcripts_total = 0usize;
    let mut introspection_transcripts_verified = 0usize;
    let mut introspection_scope_narrowed = 0usize;
    let mut introspected_seen: BTreeSet<&str> = BTreeSet::new();
    let mut covered_native: BTreeSet<String> = BTreeSet::new();
    // OAuth-style scope subset over SPACE-delimited tokens: `sub` ⊆ `sup` iff every token of sub is a token of sup
    // (a real narrowing lattice — empty effective_scope is the maximal narrowing, trivially ⊆ anything).
    let scope_tokens = |sc: &str| -> BTreeSet<String> {
        sc.split(' ')
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect()
    };
    for rt in &record_trust {
        let rec = &records[rt.index];
        if rt.broker_role != BrokerRole::Resource.as_str()
            || broker_kind(rec).as_deref() != Some("introspection_transcript")
        {
            continue;
        }
        if !committed.contains(&rt.content_hash) {
            continue; // in-flight transcript: not committed by a verified checkpoint, attests nothing
        }
        if !introspected_seen.insert(rt.content_hash.as_str()) {
            continue; // verbatim-duplicate transcript deduped (not double-counted)
        }
        introspection_transcripts_total += 1;
        let violation = |issues: &mut Vec<String>, msg: String| {
            issues.push(format!(
                "introspection_transcript {} ({}): {msg}",
                rt.index, rt.record_id
            ));
        };
        if rt.trust != TrustLevel::IntegrityProven
            || !matches!(
                rt.authority,
                AuthorityTrust::Verified | AuthorityTrust::LegacyUnbound
            )
            || !evidence_rederivable(rec, "introspection_evidence")
        {
            unmatched_violation += 1;
            violation(&mut issues, "closed but not validatable (integrity / resource authority / re-derivable introspection_evidence) — Tier-B violation".into());
            continue;
        }
        let (gid, cred_ref, eff_scope, t_resource, introspected_at, eff_exp, sig) = match (
            ev_str(rec, "introspection_evidence", "grant_id"),
            ev_str(rec, "introspection_evidence", "credential_ref"),
            ev_str(rec, "introspection_evidence", "effective_scope"),
            ev_str(rec, "introspection_evidence", "resource_id"),
            ev_int(rec, "introspection_evidence", "introspected_at"),
            ev_int(rec, "introspection_evidence", "effective_exp"),
            ev_str(rec, "introspection_evidence", "sig"),
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f), Some(g)) => {
                (a, b, c, d, e, f, g)
            }
            _ => {
                unmatched_violation += 1;
                violation(&mut issues, "introspection_evidence is missing a required field (grant_id/credential_ref/effective_scope/resource_id/introspected_at/effective_exp/sig) — violation".into());
                continue;
            }
        };
        // Bind to a present NATIVE grant — a transcript can ONLY introspect a native credential. A grant_id that
        // is brokered or absent finds no native grant, keeping the surfaces disjoint (fail-closed).
        let g = match native_grants_by_id.get(&gid) {
            Some(g) => g,
            None => {
                unmatched_violation += 1;
                violation(&mut issues, format!("references grant '{gid}' which is not a present native (token_exchange) grant — dangling/cross-surface transcript (violation)"));
                continue;
            }
        };
        // The structured M3 signature over the EXACT tuple, verified under a pinned resource issuer (the record's
        // evidence_sig already proved it is a genuine resource record; THIS proves the resource committed to this
        // exact effective-scope statement, the M3 signature domain pinned byte-for-byte by the golden vector).
        let sig_bytes = match crate::b64::decode_fixed::<64>(&sig) {
            Ok(b) => b,
            Err(_) => {
                unmatched_violation += 1;
                violation(
                    &mut issues,
                    "introspection_evidence.sig is not a base64url 64-byte signature — violation"
                        .into(),
                );
                continue;
            }
        };
        let signature = Signature::from_bytes(&sig_bytes);
        let challenge = introspection_transcript_challenge(
            &gid,
            &cred_ref,
            &eff_scope,
            &t_resource,
            introspected_at,
            eff_exp,
        );
        if !opts
            .resource_authority_keys
            .iter()
            .any(|vk| vk.verify_strict(&challenge, &signature).is_ok())
        {
            unmatched_violation += 1;
            violation(&mut issues, "introspection sig does not verify under any pinned resource_authority_keys issuer over its (grant_id, credential_ref, effective_scope, resource_id, introspected_at, effective_exp) tuple — violation".into());
            continue;
        }
        // The transcript must attest the grant's OWN resource (no redirect to a different resource_id).
        if t_resource != g.resource_id {
            unmatched_violation += 1;
            violation(&mut issues, format!("attests resource '{t_resource}' but native grant '{gid}' is for resource '{}' — resource mismatch (violation)", g.resource_id));
            continue;
        }
        // The transcript must attest the grant's OWN leased credential. `credential_ref` is bound into the M3
        // signature, so without this cross-check a resource-signed statement about a DIFFERENT leased credential
        // could cover this grant (grant_id binds the broker's authorization; lease_id binds the actual credential).
        if cred_ref != g.lease_id {
            unmatched_violation += 1;
            violation(&mut issues, format!("attests credential_ref '{cred_ref}' but native grant '{gid}' leased '{}' — credential_ref mismatch (violation)", g.lease_id));
            continue;
        }
        // Scope subset (no broadening) + no time-broadening + causal ordering — a resource may NARROW the grant's
        // authority but never widen it (in scope or in time).
        let sub = scope_tokens(&eff_scope);
        let sup = scope_tokens(&g.scope);
        if !sub.is_subset(&sup) {
            unmatched_violation += 1;
            violation(&mut issues, format!("attested effective_scope '{eff_scope}' is not within native grant scope '{}' — resource broadened past the grant (violation)", g.scope));
            continue;
        }
        if eff_exp > g.exp {
            unmatched_violation += 1;
            violation(&mut issues, format!("attested effective_exp {eff_exp} outlives native grant exp {} — time-broadening (violation)", g.exp));
            continue;
        }
        if introspected_at < g.issued_at {
            unmatched_violation += 1;
            violation(&mut issues, format!("introspected_at {introspected_at} precedes native grant issued_at {} — non-causal (violation)", g.issued_at));
            continue;
        }
        introspection_transcripts_verified += 1;
        if sub != sup {
            introspection_scope_narrowed += 1; // a proper subset: the resource attested a real narrowing
        }
        // R3: COVERAGE is a positive claim — only an anchored-CLOSED transcript of a CLOSED grant covers it (a
        // committed-only one was still fully checked above, so its violations are never hidden).
        if g.closed && closed.contains(rt.content_hash.as_str()) {
            covered_native.insert(gid);
        }
    }
    // M5 (ADR 0005): a REVOKED native grant (computed above) is forced OUT of coverage — so even a fully-verified
    // transcript cannot make a revoked credential's surface `attested` (it counts as uncovered → `unattested`).
    for gid in &revoked_native {
        covered_native.remove(gid);
    }
    // Every native grant must be covered by ≥1 verified transcript for the introspected surface to be COMPLETE.
    let native_grants_uncovered = native_grants_by_id
        .keys()
        .filter(|gid| !covered_native.contains(*gid))
        .count();
    // M3 artifact status: `absent` (no native credential) | `attested` (native present, every closed transcript
    // verified, every native grant covered, ≥1 transcript) | `unattested` (native present but a transcript failed
    // or a native grant is uncovered). The strictly-weaker introspected capstone keys on `attested`.
    let introspection_status = if !native_credential_present {
        "absent"
    } else if introspection_transcripts_total > 0
        && introspection_transcripts_verified == introspection_transcripts_total
        && native_grants_uncovered == 0
    {
        "attested"
    } else {
        "unattested"
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
    // M4 (ADR 0005): the federation ACTIVATION BOUNDARY. Federation is active iff a committed, integrity-proven
    // Broker grant carries a non-empty signed `grant_evidence.broker_id`. When NOT active the single-broker D6
    // path runs VERBATIM (byte-for-byte unchanged) and the federation fields stay at their `absent` defaults; when
    // active the per-`broker_id` partition runs instead and these fields are populated.
    let mut federation_status = "absent".to_string();
    let mut brokers_total = 0usize;
    let mut brokers_seq_verified = 0usize;
    let mut cross_broker_suppression = 0usize;
    let mut per_broker_trust: Vec<(String, String)> = Vec::new();
    let broker_issues_before = issues.len();
    let broker_trust = match dag_opt.as_ref() {
        Some(d) => {
            let full_committed = committed_set(records, &d.by_hash, &d.heads);
            // ACTIVATION (spec §M4): a committed, INTEGRITY-PROVEN Broker grant carrying a non-empty signed
            // `broker_id`. The integrity-proven qualifier matches the spec exactly; it is also strictly
            // fail-closed either way (an unproven `broker_id`-bearing record already forces `records_proven <
            // len` → `!ok`, and `broker_id` rides inside the sealed grant_evidence so a relay cannot strip it
            // from a genuine grant without breaking the seal).
            let federation_active = record_trust.iter().any(|rt| {
                rt.broker_role == BrokerRole::Broker.as_str()
                    && rt.trust == TrustLevel::IntegrityProven
                    && full_committed.contains(&rt.content_hash)
                    && ev_str(&records[rt.index], "grant_evidence", "broker_id")
                        .is_some_and(|b| !b.is_empty())
            });
            if federation_active {
                let fe = compute_federation_trust(
                    &cp_fed_heads,
                    &verified_fed_headless,
                    verified_malformed_fed_head,
                    &record_trust,
                    records,
                    &d.by_hash,
                    &d.heads,
                    latest_cp_seq,
                    &mut issues,
                );
                federation_status = fe.status;
                brokers_total = fe.brokers_total;
                brokers_seq_verified = fe.brokers_seq_verified;
                cross_broker_suppression = fe.cross_broker_suppression;
                per_broker_trust = fe.per_broker;
                fe.broker_trust
            } else {
                compute_broker_trust(
                    &cp_heads,
                    &verified_headless,
                    verified_malformed_head,
                    &record_trust,
                    records,
                    &d.by_hash,
                    &d.heads,
                    latest_cp_seq,
                    &mut issues,
                )
            }
        }
        None => "assumed".to_string(),
    };
    let broker_log_contradiction = issues.len() > broker_issues_before;

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
            touched_pairs.insert((
                r.clone(),
                ev_str(rec, "grant_evidence", "action").unwrap_or_default(),
            ));
            resource_ids.insert(r);
        }
        if let Some(r) = ev_str(rec, "use_evidence", "resource_id") {
            touched_pairs.insert((
                r.clone(),
                ev_str(rec, "use_evidence", "action").unwrap_or_default(),
            ));
            resource_ids.insert(r);
        }
    }
    let attest = evaluate_attestation(
        bundle,
        opts,
        project_id.as_deref(),
        &anchored_cp_ids,
        latest_cp_seq,
        &resource_ids,
        &mut issues,
    );

    let coverage_manifest = bundle.get("coverage_manifest").cloned();

    // T6 (ADR 0002 open Q1, ACTIONABLE half): side_effect_closure COMPLETENESS over the observed brokered
    // surface. The operator declares, in the D7-digest-bound coverage_manifest, per `(resource_id, action)`,
    // which resources each acted action may transitively touch; every `(resource_id, action)` the bundle's
    // grants/uses actually exercise (`touched_pairs`) must fall within that ACTION-BOUND declared closure —
    // a resource declared only under a DIFFERENT action does NOT close it for the action acting on it (adversarial review).
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
    let broker_sequence_verified = broker_trust == "sequence_verified";

    // The trust label must never outrank the verdict: if the bundle is not `ok` (e.g. a broken checkpoint
    // chain, an unverified checkpoint, or any other failure), `broker_trust` cannot claim a reduction.
    let broker_trust = if ok {
        broker_trust
    } else {
        "assumed".to_string()
    };

    let relevant_roles: Vec<&RecordTrust> = record_trust
        .iter()
        .filter(|rt| {
            committed.contains(&rt.content_hash)
                && matches!(
                    rt.broker_role.as_str(),
                    "broker" | "resource" | "grant_void"
                )
        })
        .collect();
    let body_bound_role_evidence = !relevant_roles.is_empty()
        && relevant_roles
            .iter()
            .all(|rt| rt.authority == AuthorityTrust::Verified);
    let mut report = VerifyReport {
        ok,
        claims: ClaimResults::fatal(),
        project_id,
        keys_externally_pinned,
        body_bound_role_evidence,
        records_total: records.len(),
        records_proven,
        record_trust,
        dag_ok,
        dag_heads,
        collapsed_duplicates,
        checkpoints_total: checkpoints.len(),
        checkpoints_verified,
        checkpoints_anchored,
        checkpoints_anchors_attached,
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
        revocation_status,
        revoked_grants_matched,
        revoked_uses_blocked,
        revocation_merkle_status,
        revocation_nonmembership_verified,
        native_credential_present,
        introspection_transcripts_total,
        introspection_transcripts_verified,
        introspection_scope_narrowed,
        introspection_status,
        federation_status,
        brokers_total,
        brokers_seq_verified,
        cross_broker_suppression,
        per_broker_trust,
        transitive_grants,
        resource_trust: "assumed_truthful".to_string(),
        coverage_manifest,
        unclosed_side_effects,
        side_effect_closure_status,
        issues,
        first_broken_link,
    };
    // Claims are decided from checked pass outputs once, before the mutable diagnostic report is
    // handed to callers. A later edit to a public counter or string cannot mint a trusted fact.
    let structural_integrity = report.records_total > 0
        && report.records_proven == report.records_total
        && report.dag_ok
        && report.chain_ok
        && !duplicate_record_id
        && !checkpoint_project_conflict
        && report.checkpoints_total > 0
        && report.checkpoints_verified == report.checkpoints_total;
    let pinned_role_authority = (!opts.broker_authority_keys.is_empty()
        || !opts.federated_broker_keys.is_empty())
        && !opts.resource_authority_keys.is_empty()
        && report.grant_total > 0
        && report.grant_verified == report.grant_total
        && body_bound_role_evidence;
    let brokered_use_valid = report.uses_total > 0
        && report.uses_matched == report.uses_total
        && report.uses_pop_reverified == report.uses_matched
        && report.unmatched_violation == 0
        && report.unmatched_pending == 0
        && report.taxonomy_status == "validated"
        && report.uses_action_unverified == 0;
    let introspected_use_valid = report.native_credential_present
        && report.introspection_status == "attested"
        && report.introspection_transcripts_total > 0
        && report.introspection_transcripts_verified == report.introspection_transcripts_total;
    let pinned_signer_keys: Vec<[u8; 32]> = opts
        .trusted_keys
        .as_ref()
        .map(|set| set.iter().map(|k| k.vk.to_bytes()).collect())
        .unwrap_or_default();
    let pinned_record_seals: Vec<PinnedRecordSeal> = report
        .record_trust
        .iter()
        .filter_map(|rt| {
            if rt.trust != TrustLevel::IntegrityProven {
                return None;
            }
            let rec_key = records[rt.index].get("key")?;
            let id = s(rec_key, "signing_key_id")?;
            let epoch = rec_key.get("key_epoch")?.as_int()?;
            let key_bytes = keys.get(&(id, epoch))?.vk.to_bytes();
            if !pinned_signer_keys.contains(&key_bytes) {
                return None;
            }
            Some(PinnedRecordSeal {
                record_hash: rt.content_hash.clone(),
                key_bytes,
            })
        })
        .collect();
    let anchors: Vec<AnchoredCheckpoint> = anchored_cp_ids
        .iter()
        .map(
            |(sequence, checkpoint_hash, timestamp, _)| AnchoredCheckpoint {
                sequence: *sequence,
                checkpoint_hash: checkpoint_hash.clone(),
                timestamp: timestamp.clone(),
            },
        )
        .collect();
    let facts = ValidatedFacts {
        structural_integrity,
        record_count: report.records_total,
        pinned_record_seals,
        pinned_signer_keys,
        pinned_role_authority,
        latest_checkpoint_sequence: latest_cp_seq,
        anchors,
        attestation_valid: report.attestation_status == "attested_claims",
        brokered_use_valid,
        introspected_use_valid,
        capstone: CapstoneFacts {
            manifest: report
                .coverage_manifest
                .as_ref()
                .is_some_and(|m| !m.is_null()),
            two_phase: !report.one_phase_use_present,
            no_incomplete_intent: report.intent_without_outcome == 0,
            taxonomy: report.taxonomy_status == "validated",
            every_action_verified: report.uses_action_unverified == 0,
            every_pop_reverified: report.uses_pop_reverified == report.uses_matched,
            grant_log: broker_sequence_verified,
            attestation: report.attestation_status == "attested_claims",
            no_violation: report.unmatched_violation == 0,
            no_pending: report.unmatched_pending == 0,
            bounded_reuse: report.bounded_reuse_overspent == 0
                && report.bounded_reuse_seq_replays == 0,
            cosignatures: report.cosig_threshold_failures == 0
                && (report.cosigned_grants_total == 0
                    || report.cosigned_grants_satisfied == report.cosigned_grants_total),
            delegation: (report.delegation_chains_total == 0
                || report.delegation_chains_verified == report.delegation_chains_total)
                && report.delegation_monotonicity_violations == 0,
            revocation: !matches!(
                report.revocation_status.as_str(),
                "stale" | "revoked_present" | "missing"
            ) && report.revoked_uses_blocked == 0
                && report.revocation_merkle_status != "stale",
            federation: report.cross_broker_suppression == 0
                && report.brokers_seq_verified == report.brokers_total,
            coverage: report.side_effect_closure_status == "closed",
            brokered_surface: report.uses_matched > 0 && !report.native_credential_present,
            introspected_surface: report.uses_matched == 0
                && report.native_credential_present
                && report.introspection_status == "attested",
        },
        immutable_record_contradiction: duplicate_record_id
            || checkpoint_project_conflict
            || !grant_equivocations.is_empty(),
        checked_contradiction: report.unmatched_violation > 0
            || semantic_record_conflict
            || committed_grant_rejected
            || void_contradiction
            || grant_contradiction
            || broker_log_contradiction
            || report.bounded_reuse_overspent > 0
            || report.bounded_reuse_seq_replays > 0
            || report.cosig_threshold_failures > 0
            || report.delegation_monotonicity_violations > 0
            || report.cross_broker_suppression > 0,
        adverse_disclosure: report.cred_label_checks > report.cred_label_matched,
        adverse_anchor: !anchor_order_valid,
        revoked_membership: revoked_membership_found,
        revocation_issuer_pinned: !opts.revocation_keys.is_empty(),
        disclosed_revocation_fresh: revocation.status == "fresh",
        merkle_revocation_fresh: merkle_rev.status == "fresh",
        merkle_nonmembership_complete: merkle_rev.root.is_some()
            && report.revoked_uses_blocked == 0
            && report.revocation_nonmembership_verified
                == report.uses_total + native_grants_by_id.len(),
        disclosure_complete: !required_descriptor_record_ids.is_empty()
            && required_descriptor_record_ids.is_subset(&matched_descriptor_record_ids),
        policy: opts.claim_policy,
    };
    report.claims = facts.decide();
    report
}
