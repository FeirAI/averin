package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const authoritySubjectProjection = "averin.authority.subject.v1"

// finalizeSemanticRecord runs before a v3 authority signs and again before the
// recorder seals. A second invocation cannot change any populated semantic
// field. The receipt, DAG frontier, display sequence and record key are recorder
// envelope, so they are filled separately by sealAndStore.
func finalizeSemanticRecord(rec map[string]any, now time.Time) {
	rec["schema_version"] = "2"
	rec["canon_version"] = "rcp-1"
	rec["domain"] = "flightrecorder.record.v2"
	if stringField(rec, "agent_ts") == "" {
		rec["agent_ts"] = ts(now)
	}
	if stringField(rec, "record_id") == "" {
		rec["record_id"] = newUUID()
	}
	if stringField(rec, "span_id") == "" {
		rec["span_id"] = "span-" + newUUID()
	}
	if _, ok := rec["parent_span_id"]; !ok {
		rec["parent_span_id"] = nil
	}
	setDefault(rec, "agent_id", "unknown")
	setDefault(rec, "agent_version", "unknown")
	setDefault(rec, "event_type", "decision")
	setDefault(rec, "action", "")
	setDefault(rec, "observed_via", "sdk")
	setDefault(rec, "status", "ok")
	if extensions, _ := rec["extensions"].(map[string]any); extensions != nil {
		if evidence, _ := extensions["feir_evidence"].(map[string]any); evidence != nil {
			evidence["capture_authority"] = rec["observed_via"]
			evidence["lineage"] = map[string]any{
				"session_id": rec["session_id"], "span_id": rec["span_id"],
				"parent_span_id": rec["parent_span_id"],
			}
		}
	}
}

func authorityV3Claim(rec map[string]any) bool {
	a, _ := rec["authority"].(map[string]any)
	_, version := a["proof_version"]
	_, projection := a["subject_projection"]
	_, digest := a["subject_digest"]
	return version || projection || digest
}

func validateExternalV3Subject(rec map[string]any) error {
	if !authorityV3Claim(rec) {
		return nil
	}
	a, ok := rec["authority"].(map[string]any)
	if !ok || a["proof_version"] != "v3" || a["subject_projection"] != authoritySubjectProjection {
		return errors.New("authority v3 proof_version and subject_projection are required")
	}
	switch a["source"] {
	case "policy_engine_signed", "human_signed", "delegate_signed":
	default:
		return errors.New("generic v3 authority requires a pinned external policy, human, or delegate source")
	}
	// These values cannot be minted by the recorder after an external authority
	// approves its subject. Fixed defaults for other semantic fields are allowed;
	// the signer must have included them in its subject digest.
	for _, field := range []string{"record_id", "span_id", "agent_ts"} {
		if stringField(rec, field) == "" {
			return fmt.Errorf("authority v3 requires explicit %s before signing", field)
		}
	}
	if _, ok := rec["parent_span_id"]; !ok {
		return errors.New("authority v3 requires explicit parent_span_id (null is allowed)")
	}
	for _, field := range []string{"input", "output", "rationale"} {
		if _, ok := rec[field]; ok {
			return fmt.Errorf("authority v3 requires a preapproved %s_commit; raw %s cannot be committed after signing", field, field)
		}
	}
	return nil
}

func (s *Server) validateExternalAuthoritySubject(rec map[string]any) error {
	if err := validateExternalV3Subject(rec); err != nil {
		return err
	}
	if !s.requireBodyBoundAuthority || authorityV3Claim(rec) {
		return nil
	}
	a, _ := rec["authority"].(map[string]any)
	switch a["source"] {
	case "policy_engine_signed", "human_signed", "delegate_signed", "gateway_enforced":
		return errors.New("body-bound authority ingest policy requires proof_version v3")
	}
	return nil
}

func (s *Server) signLocalAuthorityV3(rec map[string]any, signer Sealer) error {
	finalizeSemanticRecord(rec, s.now())
	a, ok := rec["authority"].(map[string]any)
	if !ok || a["source"] != "gateway_enforced" {
		return errors.New("local v3 authority requires gateway_enforced block")
	}
	delete(a, "evidence_sig")
	delete(a, "subject_digest")
	a["proof_version"] = "v3"
	a["subject_projection"] = authoritySubjectProjection
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	proof, err := signer.SignAuthorityRecordV3(string(raw))
	if err != nil {
		return fmt.Errorf("sign local v3 authority: %w", err)
	}
	a["subject_digest"] = proof.SubjectDigest
	a["evidence_sig"] = proof.EvidenceSig
	return s.assertAuthorityV3(rec, signer.PubKey())
}

func (s *Server) assertAuthorityV3(rec map[string]any, pubKey string) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	status, err := s.core.VerifyAuthorityRecord(string(raw), pubKey)
	if err != nil {
		return err
	}
	if status != "verified" {
		return fmt.Errorf("v3 authority does not bind finalized semantic record: %s", status)
	}
	return nil
}

func (s *Server) v3AuthorityKey(rec map[string]any) (string, error) {
	a, _ := rec["authority"].(map[string]any)
	source := stringField(a, "source")
	if source == "gateway_enforced" {
		switch stringField(a, "enforcement_point") {
		case "credential_broker":
			return s.core.PubKey(), nil
		case "tool_gateway":
			if s.resourceCore != nil {
				return s.resourceCore.PubKey(), nil
			}
		}
		return "", errors.New("v3 gateway authority has no role recording key")
	}
	key, ok := s.authorityKeyFor(stringField(rec, "project_id"), source)
	if !ok {
		return "", errors.New("v3 external authority key is not pinned")
	}
	return "ed25519pub:" + base64.RawURLEncoding.EncodeToString(key), nil
}

// Use the same Rust projection/signature verifier after the recorder stamps its
// excluded envelope. This catches any future semantic mutation in sealAndStore.
func (s *Server) assertFinalAuthorityV3(rec map[string]any) error {
	if !authorityV3Claim(rec) {
		return nil
	}
	key, err := s.v3AuthorityKey(rec)
	if err != nil {
		return err
	}
	return s.assertAuthorityV3(rec, key)
}
