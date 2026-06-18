package broker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// delegationHopTag domain-separates the per-hop re-delegation challenge (ADR 0005 M2) from every other
// signed preimage, so a hop assertion can never be repurposed in another context.
const delegationHopTag = "feir.broker.delegation.hop.v1"

// DelegationHop is one signed re-delegation step (ADR 0005 M2). DelegatorCnf/DelegateCnf are base64url-no-pad
// ed25519 PUBLIC keys; Sig is the base64url-no-pad signature by the DELEGATOR's key over DelegationHopChallenge.
// The verifier derives each cnf_kid from the carried pubkey, so the producer carries keys, not kids.
type DelegationHop struct {
	DelegatorCnf string `json:"delegator_cnf"`
	DelegateCnf  string `json:"delegate_cnf"`
	Scope        string `json:"scope"`
	Action       string `json:"action"`
	ResourceID   string `json:"resource_id"`
	Exp          int64  `json:"exp"`
	Sig          string `json:"sig"`
}

// DelegationHopChallenge re-derives the 32-byte digest a delegator signs to authorize one re-delegation hop
// (ADR 0005 M2), byte-identically to the Rust verifier's delegation_hop_challenge:
//
//	sha256( LP4(tag) ‖ LP4(grant_id) ‖ BE8(hop_index) ‖ LP4(delegator_kid) ‖ LP4(delegate_kid) ‖
//	        LP4(scope) ‖ LP4(action) ‖ LP4(resource_id) ‖ BE8(exp) )
//
// LP4 = 4-byte big-endian length prefix; BE8 = 8-byte big-endian int. Binding the kids + hop_index makes a
// hop non-transferable to a different delegator/delegate/position; binding scope/action/resource/exp makes it
// non-replayable onto a different authority or window. Kept in sync with the Rust core via the SHARED golden
// vector spec/golden-vectors/broker-preimages.json.
func DelegationHopChallenge(grantID string, hopIndex int64, delegatorKid, delegateKid, scope, action, resourceID string, exp int64) []byte {
	h := sha256.New()
	lp4 := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	be8 := func(v int64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v))
		h.Write(b[:])
	}
	lp4(delegationHopTag)
	lp4(grantID)
	be8(hopIndex)
	lp4(delegatorKid)
	lp4(delegateKid)
	lp4(scope)
	lp4(action)
	lp4(resourceID)
	be8(exp)
	return h.Sum(nil)
}

// AttachDelegation embeds a verified re-delegation chain into an already-prepared grant's evidence (ADR 0005
// M2). It is the second phase of the delegation flow: Prepare mints the grant (fixing cnf_kid / scope /
// action / resource_id / exp), the agents sign their hops out-of-band over DelegationHopChallenge, then the
// broker calls this to bind the chain in before the api layer derives evidence_hash and seals.
//
// It is FAIL-CLOSED and self-checking, re-walking exactly as the offline verifier does: hop 0's delegator must
// be the grant's cnf (the credential's original holder); each hop's delegator must equal the previous hop's
// delegate; each sig must verify under the delegator key; and (demonstrator monotonicity = equality) each
// hop's scope/action/resource_id must equal the grant's. On success it sets `delegation_assertions[]` in
// p.Evidence; on any failure the grant is unchanged and an error is returned. The verifier re-checks all of
// this independently and binds the use to the leaf cnf.
//
// NOTE: this uses ed25519.Verify; the offline verifier uses the stricter verify_strict (rejects malleable /
// low-order signatures). Honest hops (ed25519.Sign output) pass both, so there is no asymmetry for chains the
// broker assembles itself. A pre-supplied malleable signature that passed here would still be rejected by the
// verifier — fail-closed at verify time, never a false accept.
func AttachDelegation(p *Prepared, hops []DelegationHop) error {
	if p == nil {
		return errors.New("prepared grant is nil")
	}
	if len(hops) == 0 {
		return errors.New("delegation chain is empty")
	}
	grantID, _ := p.Evidence["grant_id"].(string)
	rootKid, _ := p.Evidence["cnf_kid"].(string)
	grantScope, _ := p.Evidence["scope"].(string)
	grantAction, _ := p.Evidence["action"].(string)
	grantResource, _ := p.Evidence["resource_id"].(string)
	if grantID == "" || rootKid == "" {
		return errors.New("prepared grant_evidence is missing grant_id/cnf_kid")
	}

	expectedDelegatorKid := rootKid // hop 0's delegator must be the grant's cnf
	for i, hop := range hops {
		delegatorPub, err := decodeAgentKey(hop.DelegatorCnf)
		if err != nil {
			return fmt.Errorf("hop %d: delegator_cnf: %w", i, err)
		}
		delegatePub, err := decodeAgentKey(hop.DelegateCnf)
		if err != nil {
			return fmt.Errorf("hop %d: delegate_cnf: %w", i, err)
		}
		delegatorKid := KeyID(delegatorPub)
		delegateKid := KeyID(delegatePub)
		if delegatorKid != expectedDelegatorKid {
			return fmt.Errorf("hop %d: delegator is not the %s (broken chain / wrong root)", i, expectedKidLabel(i))
		}
		// monotonicity (demonstrator = equality): a hop may not change scope/action/resource.
		if hop.Scope != grantScope || hop.Action != grantAction || hop.ResourceID != grantResource {
			return fmt.Errorf("hop %d: widens scope/action/resource beyond the grant (monotonicity)", i)
		}
		sig, err := base64.RawURLEncoding.DecodeString(hop.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("hop %d: sig must be a base64url-no-pad ed25519 signature (64 bytes)", i)
		}
		challenge := DelegationHopChallenge(grantID, int64(i), delegatorKid, delegateKid, hop.Scope, hop.Action, hop.ResourceID, hop.Exp)
		if !ed25519.Verify(delegatorPub, challenge, sig) {
			return fmt.Errorf("hop %d: signature does not verify under the delegator key", i)
		}
		expectedDelegatorKid = delegateKid
	}

	embedded := make([]map[string]any, len(hops))
	for i, hop := range hops {
		embedded[i] = map[string]any{
			"delegator_cnf": hop.DelegatorCnf,
			"delegate_cnf":  hop.DelegateCnf,
			"scope":         hop.Scope,
			"action":        hop.Action,
			"resource_id":   hop.ResourceID,
			"exp":           hop.Exp,
			"sig":           hop.Sig,
		}
	}
	p.Evidence["delegation_assertions"] = embedded
	return nil
}

func decodeAgentKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("not a base64url-no-pad ed25519 public key (32 bytes)")
	}
	return ed25519.PublicKey(raw), nil
}

func expectedKidLabel(i int) string {
	if i == 0 {
		return "grant's cnf (root)"
	}
	return "previous hop's delegate"
}
