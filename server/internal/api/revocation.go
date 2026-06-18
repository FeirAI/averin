package api

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/feir-dev/feir/server/internal/broker"
)

// BuildRevocationList constructs a signed, time-bounded revocation_list (ADR 0005 M5) — the top-level bundle
// object the offline verifier evaluates under a pinned, role-separated `revocation_keys` issuer. It mirrors
// buildDeploymentAttestation: the `sig` (domain feir.revocation.v1) is ed25519 over
// sha256(RCP-canonical(list minus sig)) — so the disclosed `revoked_grant_ids` are authenticated directly,
// and the verifier recomputes the identical digest via the same RCP canonicalizer. `revKey` is the revocation
// authority's key (which MUST be role-separated from the broker/resource/etc. it governs — the verifier
// rejects an overlap as a fatal config error). `issuedAt`/`notAfter` are canonical RFC3339 ms-UTC timestamps;
// the verifier requires the latest anchored checkpoint time to fall within them for the list to read `fresh`.
//
// `canon` is any core handle used only for the keyless RCP canonicalization (RcpEvidenceHash is deterministic
// and signing-key-independent), NOT for signing — the revocation authority signs with revKey directly.
func BuildRevocationList(canon Sealer, revKey ed25519.PrivateKey, issuedAt, notAfter string, revokedGrantIDs []string) (map[string]any, error) {
	if revokedGrantIDs == nil {
		revokedGrantIDs = []string{}
	}
	body := map[string]any{
		"issuer_kid":        broker.KeyID(revKey.Public().(ed25519.PublicKey)),
		"issued_at":         issuedAt,
		"not_after":         notAfter,
		"revoked_grant_ids": revokedGrantIDs,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal revocation_list: %w", err)
	}
	// digest = sha256(RCP-canonical(list minus sig)) — exactly what the verifier recomputes (it strips `sig`
	// and re-canonicalizes). We sign BEFORE adding `sig`, so the digest covers the whole list verbatim.
	digest, err := canon.RcpEvidenceHash(string(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("revocation_list digest: %w", err)
	}
	body["sig"] = signTagged("feir.revocation.v1", digest, revKey)
	return body, nil
}

// BuildRevocationMerkleRoot constructs a signed revocation_merkle_root (ADR 0005 M5 Merkle-non-disclosure) — a
// commitment to the SORTED revoked-grant set that does NOT disclose it. The `sig` (domain
// feir.broker.revocation.merkleroot.v1) is ed25519 over sha256(RCP-canonical(root object minus sig)), exactly
// mirroring BuildRevocationList; the verifier recomputes the identical digest and then checks each use's
// per-grant proof (broker.RevocationTree.NonMembershipProof / MembershipProof) against the committed `root`.
func BuildRevocationMerkleRoot(canon Sealer, revKey ed25519.PrivateKey, issuedAt, notAfter string, tree *broker.RevocationTree) (map[string]any, error) {
	body := map[string]any{
		"issuer_kid": broker.KeyID(revKey.Public().(ed25519.PublicKey)),
		"issued_at":  issuedAt,
		"not_after":  notAfter,
		"leaf_count": tree.LeafCount(),
		"root":       tree.RootHex(),
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal revocation_merkle_root: %w", err)
	}
	// digest = sha256(RCP-canonical(root minus sig)) — exactly what the verifier recomputes.
	digest, err := canon.RcpEvidenceHash(string(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("revocation_merkle_root digest: %w", err)
	}
	body["sig"] = signTagged("feir.broker.revocation.merkleroot.v1", digest, revKey)
	return body, nil
}
