package api

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/feirai/averin/server/internal/broker"
	"github.com/feirai/averin/server/internal/store"
)

// BuildRevocationList constructs a signed, time-bounded revocation_list (ADR 0005 M5) — the top-level bundle
// object the offline verifier evaluates under a pinned, role-separated `revocation_keys` issuer. It mirrors
// buildDeploymentAttestation: the `sig` (domain averin.revocation.v1) is ed25519 over
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
	body["sig"] = signTagged("averin.revocation.v1", digest, revKey)
	return body, nil
}

// BuildRevocationMerkleRoot constructs a signed revocation_merkle_root (ADR 0005 M5 Merkle-non-disclosure) — a
// commitment to the SORTED revoked-grant set that does NOT disclose it. The `sig` (domain
// averin.broker.revocation.merkleroot.v1) is ed25519 over sha256(RCP-canonical(root object minus sig)), exactly
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
	body["sig"] = signTagged("averin.broker.revocation.merkleroot.v1", digest, revKey)
	return body, nil
}

// Plan 009 versioned revocation formats. Both carry the signed project and the database snapshot the
// state was read from (boundary time and authorization high watermark); both are signed in their own
// domain so a legacy verifier rejects them instead of misreading them.
const (
	revocationListV2Format = "averin.revocation.list.v2"
	revocationListV2Domain = "averin.revocation.v2"
	merkleRootV2Format     = "averin.revocation.merkleroot.v2"
	merkleRootV2Domain     = "averin.broker.revocation.merkleroot.v2"
)

// RevocationSnapshot identifies the repeatable-read snapshot a revocation state was read from.
type RevocationSnapshot struct {
	ProjectID    string
	BoundaryTime time.Time
	Watermark    int64
}

func (s RevocationSnapshot) canon() (map[string]any, error) {
	if s.ProjectID == "" || s.Watermark < 0 || s.BoundaryTime.IsZero() {
		return nil, fmt.Errorf("revocation snapshot requires project, boundary time and a non-negative watermark")
	}
	return map[string]any{
		// Format truncates to milliseconds, so the signed boundary is never after the snapshot.
		"boundary_time":                ts(s.BoundaryTime),
		"authorization_high_watermark": s.Watermark,
	}, nil
}

// CombineRevocationEvents folds a project's events into one entry per grant, sorted by grant_id:
// any total event makes the grant total; otherwise the earliest prospective cutoff applies.
func CombineRevocationEvents(events []store.RevocationEvent) []broker.RevocationStateEntry {
	byGrant := map[string]broker.RevocationStateEntry{}
	for _, ev := range events {
		prior, seen := byGrant[ev.GrantID]
		switch {
		case ev.Mode == store.RevocationTotal || (seen && prior.Mode == store.RevocationTotal):
			byGrant[ev.GrantID] = broker.RevocationStateEntry{GrantID: ev.GrantID, Mode: store.RevocationTotal}
		case !seen || ev.CutoffOrder < prior.CutoffOrder:
			byGrant[ev.GrantID] = broker.RevocationStateEntry{GrantID: ev.GrantID, Mode: store.RevocationProspective, CutoffOrder: ev.CutoffOrder}
		}
	}
	out := make([]broker.RevocationStateEntry, 0, len(byGrant))
	for _, e := range byGrant {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantID < out[j].GrantID })
	return out
}

// BuildRevocationListV2 signs an `averin.revocation.list.v2`: every revoked grant exactly once with
// its mode (and cutoff for a prospective revocation), plus the snapshot identity. A malformed entry
// is refused, never emitted.
func BuildRevocationListV2(canon Sealer, revKey ed25519.PrivateKey, issuedAt, notAfter string, snap RevocationSnapshot, entries []broker.RevocationStateEntry) (map[string]any, error) {
	snapshot, err := snap.canon()
	if err != nil {
		return nil, err
	}
	revocations := make([]any, 0, len(entries))
	for i, e := range entries {
		if e.GrantID == "" || (i > 0 && entries[i-1].GrantID >= e.GrantID) {
			return nil, fmt.Errorf("revocation_list v2: entries must be sorted, unique and non-empty")
		}
		switch {
		case e.Mode == store.RevocationTotal && e.CutoffOrder == 0:
			revocations = append(revocations, map[string]any{"grant_id": e.GrantID, "mode": e.Mode})
		case e.Mode == store.RevocationProspective && e.CutoffOrder >= 1 && e.CutoffOrder <= snap.Watermark:
			revocations = append(revocations, map[string]any{"grant_id": e.GrantID, "mode": e.Mode, "cutoff_order": e.CutoffOrder})
		default:
			return nil, fmt.Errorf("revocation_list v2: invalid state for grant %q", e.GrantID)
		}
	}
	body := map[string]any{
		"format":      revocationListV2Format,
		"issuer_kid":  broker.KeyID(revKey.Public().(ed25519.PublicKey)),
		"issued_at":   issuedAt,
		"not_after":   notAfter,
		"project_id":  snap.ProjectID,
		"snapshot":    snapshot,
		"revocations": revocations,
	}
	return signRevocationArtifact(canon, revKey, revocationListV2Domain, body)
}

// BuildRevocationMerkleRootV2 signs an `averin.revocation.merkleroot.v2` over tree, whose leaves
// commit each grant's mode and cutoff. Per-grant proofs come from tree.Proof.
func BuildRevocationMerkleRootV2(canon Sealer, revKey ed25519.PrivateKey, issuedAt, notAfter string, snap RevocationSnapshot, tree *broker.RevocationTreeV2) (map[string]any, error) {
	snapshot, err := snap.canon()
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"format":     merkleRootV2Format,
		"issuer_kid": broker.KeyID(revKey.Public().(ed25519.PublicKey)),
		"issued_at":  issuedAt,
		"not_after":  notAfter,
		"project_id": snap.ProjectID,
		"snapshot":   snapshot,
		"leaf_count": tree.LeafCount(),
		"root":       tree.RootHex(),
	}
	return signRevocationArtifact(canon, revKey, merkleRootV2Domain, body)
}

// signRevocationArtifact signs sha256(RCP-canonical(body)) in domain and adds `sig`, exactly what the
// verifier recomputes after stripping `sig`.
func signRevocationArtifact(canon Sealer, revKey ed25519.PrivateKey, domain string, body map[string]any) (map[string]any, error) {
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", domain, err)
	}
	digest, err := canon.RcpEvidenceHash(string(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("%s digest: %w", domain, err)
	}
	body["sig"] = signTagged(domain, digest, revKey)
	return body, nil
}
