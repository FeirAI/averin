package broker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
)

// introspectionTranscriptTag domain-separates the M3 native/STS introspection-transcript challenge (ADR 0005
// M3) from every other signed preimage, so a resource's effective-scope attestation can never be repurposed.
const introspectionTranscriptTag = "feir.resource.introspection.v1"

// IntrospectionTranscriptChallenge re-derives the 32-byte digest a RESOURCE signs to attest an externally-minted
// (token_exchange/STS) credential's effective scope (ADR 0005 M3), byte-identically to the Rust verifier's
// introspection_transcript_challenge:
//
//	sha256( LP4(tag) ‖ LP4(grant_id) ‖ LP4(credential_ref) ‖ LP4(effective_scope) ‖ LP4(resource_id) ‖ BE8(introspected_at) ‖ BE8(effective_exp) )
//
// LP4 = 4-byte big-endian length prefix; BE8 = 8-byte big-endian int. Binding grant_id ties the transcript to
// the broker grant authorizing the exchange; binding credential_ref (the lease) / effective_scope / resource_id /
// effective_exp makes the attested scope+window non-malleable and non-replayable onto a different lease. Kept in
// sync with the Rust core via the SHARED golden vector spec/golden-vectors/broker-preimages.json (loaded by both
// languages' tests).
func IntrospectionTranscriptChallenge(grantID, credentialRef, effectiveScope, resourceID string, introspectedAt, effectiveExp int64) []byte {
	h := sha256.New()
	for _, part := range []string{introspectionTranscriptTag, grantID, credentialRef, effectiveScope, resourceID} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		h.Write(n[:])
		h.Write([]byte(part))
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(introspectedAt))
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], uint64(effectiveExp))
	h.Write(b[:])
	return h.Sum(nil)
}

// NativeGrantEvidence builds the signed grant_evidence for a native (token_exchange / external-IdP-or-STS) grant
// (ADR 0005 M3). Unlike a brokered grant (broker.Prepare), a native credential is minted out-of-band, so it has
// NO broker credential_binding and NO cnf-key PoP — the verifier accounts it on a separate channel keyed on
// `mode == "token_exchange"`, and its use is attested ONLY by a resource-signed introspection_transcript. The
// `lease_id` is the external credential reference the transcript's credential_ref must equal. `broker_seq` keeps
// the native grant in the D6 grant-transparency log (so it can reach broker_trust:sequence_verified).
func NativeGrantEvidence(grantID, action, resourceID, scope, leaseID string, brokerSeq, issuedAt, exp int64) map[string]any {
	return map[string]any{
		"kind":              "grant",
		"grant_id":          grantID,
		"mode":              "token_exchange",
		"grant_type":        "oauth-scope",
		"lease_id":          leaseID,
		"action":            action,
		"resource_id":       resourceID,
		"scope":             scope,
		"scope_class":       string(ScopeSession),
		"conformance_level": ConformanceL1GrantOnly,
		"broker_seq":        brokerSeq,
		"issued_at":         issuedAt,
		"exp":               exp,
	}
}

// IntrospectionEvidence builds a RESOURCE-signed introspection_evidence payload (ADR 0005 M3) — the resource's
// statement of an externally-minted credential's effective scope, to be embedded under
// extensions.broker.introspection_evidence of an introspection_transcript record. The `sig` is the base64url-no-pad
// Ed25519 signature by `resourceKey` over IntrospectionTranscriptChallenge (the M3 signature domain). The offline
// verifier re-derives the same challenge and re-checks the sig under its pinned, role-separated
// resource_authority_keys, plus credential_ref == grant.lease_id, effective_scope ⊆ grant.scope, and the window.
func IntrospectionEvidence(resourceKey ed25519.PrivateKey, grantID, credentialRef, effectiveScope, resourceID, transcriptHash string, introspectedAt, effectiveExp int64) map[string]any {
	challenge := IntrospectionTranscriptChallenge(grantID, credentialRef, effectiveScope, resourceID, introspectedAt, effectiveExp)
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(resourceKey, challenge))
	return map[string]any{
		"kind":            "introspection_transcript",
		"grant_id":        grantID,
		"credential_ref":  credentialRef,
		"effective_scope": effectiveScope,
		"resource_id":     resourceID,
		"transcript_hash": transcriptHash,
		"introspected_at": introspectedAt,
		"effective_exp":   effectiveExp,
		"sig":             sig,
	}
}
