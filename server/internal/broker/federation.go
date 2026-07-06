package broker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
)

// federationCertTag domain-separates the cross-broker certificate challenge (ADR 0005 M4, OPTIONAL transitive
// trust) from every other signed preimage. A cross-broker cert is a statement by a PINNED issuer broker A that
// an (otherwise-unpinned) subject broker B's KEY is authorized for a scope over a resource until not_after.
const federationCertTag = "averin.broker.federation.cert.v1"

// FederationCertChallenge re-derives the 32-byte digest the ISSUER broker signs to vouch for a subject broker's
// key (ADR 0005 M4), byte-identically to the Rust verifier's federation_cert_challenge:
//
//	sha256( LP4(tag) ‖ LP4(issuer_broker_id) ‖ LP4(subject_broker_id) ‖ LP4(subject_kid) ‖ LP4(scope) ‖
//	        LP4(resource_id) ‖ BE8(not_after) )
//
// LP4 = 4-byte big-endian length prefix; BE8 = 8-byte big-endian int. subject_kid (= KeyID(subject_pubkey)) is
// IN the preimage so the cert is bound to a SPECIFIC key, not just a broker id — without it, A's (public) cert
// could be replayed over a grant signed by any key claiming B's id (key substitution). Kept in sync with the
// Rust core via the SHARED golden vector spec/golden-vectors/broker-preimages.json.
func FederationCertChallenge(issuerBrokerID, subjectBrokerID, subjectKid, scope, resourceID string, notAfter int64) []byte {
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
	lp4(federationCertTag)
	lp4(issuerBrokerID)
	lp4(subjectBrokerID)
	lp4(subjectKid)
	lp4(scope)
	lp4(resourceID)
	be8(notAfter)
	return h.Sum(nil)
}

// CrossBrokerCert builds the cross_broker_cert object the issuer broker A embeds in subject B's grant_evidence
// (under grant_evidence.cross_broker_cert) so an offline verifier that pins ONLY A can still elevate B's grant
// to "transitive" trust (ADR 0005 M4). issuerKey is A's authority key (the verifier re-checks the sig under the
// pinned federated_broker_keys[issuer]); subjectPub is B's authority public key (the verifier requires B's
// grant evidence_sig to verify under it). The verifier additionally enforces issuer != subject, the grant's own
// scope/resource_id/broker_id == the cert's, not_after >= the grant's issued_at, and that subjectPub is NOT a
// non-broker role key (R2 role-disjointness). Producing a cert is NOT sufficient to trust a grant — the grant
// must independently be signed by subjectPub.
func CrossBrokerCert(issuerBrokerID, subjectBrokerID string, subjectPub ed25519.PublicKey, scope, resourceID string, notAfter int64, issuerKey ed25519.PrivateKey) map[string]any {
	subjectKid := KeyID(subjectPub)
	challenge := FederationCertChallenge(issuerBrokerID, subjectBrokerID, subjectKid, scope, resourceID, notAfter)
	sig := ed25519.Sign(issuerKey, challenge)
	return map[string]any{
		"issuer_broker_id":  issuerBrokerID,
		"subject_broker_id": subjectBrokerID,
		"subject_pubkey":    base64.RawURLEncoding.EncodeToString(subjectPub),
		"scope":             scope,
		"resource_id":       resourceID,
		"not_after":         notAfter,
		"sig":               base64.RawURLEncoding.EncodeToString(sig),
	}
}
