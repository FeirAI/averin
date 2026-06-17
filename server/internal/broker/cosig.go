package broker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// cosigApprovalTag domain-separates the M-of-N grant-approval challenge (ADR 0005 M6) from every other
// signed preimage, so an approval signature can never be repurposed in another context.
const cosigApprovalTag = "feir.broker.cosig.approval.v1"

// Cosignature is one approver's M-of-N grant approval (ADR 0005 M6). ApproverKid is the KeyID of the
// approver's pinned public key; Sig is the base64url-no-pad Ed25519 signature over CosigApprovalChallenge.
type Cosignature struct {
	ApproverKid string `json:"approver_kid"`
	Sig         string `json:"sig"`
}

// CosigApprovalChallenge re-derives the 32-byte digest an approver signs to approve a grant (ADR 0005 M6),
// byte-identically to the Rust verifier's cosig_approval_challenge:
//
//	sha256( LP4(tag) ‖ LP4(grant_id) ‖ LP4(approver_kid) ‖ LP4(credential_binding) ‖ BE8(threshold_m) ‖ BE8(exp) )
//
// LP4 = 4-byte big-endian length prefix; BE8 = 8-byte big-endian int. Binding approver_kid makes an approval
// non-transferable to a different approver; binding credential_binding/threshold_m/exp makes it non-replayable
// onto a re-minted grant, a different threshold, or a different expiry. Kept in sync with the Rust core via
// the SHARED golden vector spec/golden-vectors/broker-preimages.json (loaded by both languages' tests).
func CosigApprovalChallenge(grantID, approverKid, credentialBinding string, thresholdM, exp int64) []byte {
	h := sha256.New()
	for _, part := range []string{cosigApprovalTag, grantID, approverKid, credentialBinding} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		h.Write(n[:])
		h.Write([]byte(part))
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(thresholdM))
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], uint64(exp))
	h.Write(b[:])
	return h.Sum(nil)
}

// AttachCosignatures embeds an M-of-N approval requirement into an already-prepared grant's evidence (ADR
// 0005 M6 — dual control at issuance). It is the SECOND phase of the cosig flow: Prepare mints the grant
// (fixing credential_binding + exp), the broker presents (grant_id, credential_binding, threshold, exp) to
// the approvers, collects their cosignatures over CosigApprovalChallenge, then calls this to bind them in
// before the api layer derives evidence_hash and seals.
//
// It is FAIL-CLOSED and self-checking: thresholdM must be >= 1; every provided cosignature must resolve to a
// pinned approver key (by KeyID) and verify under it over the per-approver challenge; and the count of
// DISTINCT valid approvers must reach thresholdM — otherwise the grant is not modified and an error is
// returned. The same approver signing twice counts once (no threshold inflation). On success it sets
// `cosig_threshold` and `cosignatures[]` in p.Evidence (the offline verifier re-checks both independently).
func AttachCosignatures(p *Prepared, thresholdM int, cosigs []Cosignature, approverKeys []ed25519.PublicKey) error {
	if p == nil {
		return errors.New("prepared grant is nil")
	}
	if thresholdM < 1 {
		return errors.New("cosig threshold must be >= 1")
	}
	exp, ok := p.Evidence["exp"].(int64)
	if !ok {
		return errors.New("prepared grant_evidence has no int64 exp")
	}
	if p.CredentialBinding == "" || p.GrantID == "" {
		return errors.New("prepared grant is missing credential_binding/grant_id")
	}
	// kid -> pinned approver key (KeyID is a deterministic function of the key, matching the verifier).
	pinned := make(map[string]ed25519.PublicKey, len(approverKeys))
	for _, pub := range approverKeys {
		pinned[KeyID(pub)] = pub
	}
	credited := make(map[string]struct{})
	for i, c := range cosigs {
		pub, found := pinned[c.ApproverKid]
		if !found {
			return fmt.Errorf("cosignature %d: approver_kid %q is not a pinned approver key", i, c.ApproverKid)
		}
		sig, err := base64.RawURLEncoding.DecodeString(c.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("cosignature %d: sig must be a base64url-no-pad ed25519 signature (64 bytes)", i)
		}
		challenge := CosigApprovalChallenge(p.GrantID, c.ApproverKid, p.CredentialBinding, int64(thresholdM), exp)
		if !ed25519.Verify(pub, challenge, sig) {
			return fmt.Errorf("cosignature %d: signature does not verify under approver %q", i, c.ApproverKid)
		}
		credited[c.ApproverKid] = struct{}{}
	}
	if len(credited) < thresholdM {
		return fmt.Errorf("cosig threshold not met: %d distinct valid approver signatures, need %d", len(credited), thresholdM)
	}
	// Bind the requirement + the approvals into the SIGNED grant_evidence. The verifier re-counts distinct
	// valid approvals under its own pinned cosig_approver_keys and re-checks threshold independently.
	embedded := make([]map[string]any, len(cosigs))
	for i, c := range cosigs {
		embedded[i] = map[string]any{"approver_kid": c.ApproverKid, "sig": c.Sig}
	}
	p.Evidence["cosig_threshold"] = thresholdM
	p.Evidence["cosignatures"] = embedded
	return nil
}
