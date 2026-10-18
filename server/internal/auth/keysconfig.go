package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/feirai/averin/server/internal/secretfp"
)

// keyConfigEntry is one scoped credential in the JSON form of AVERIN_API_KEYS.
type keyConfigEntry struct {
	Project     string `json:"project"`
	Token       string `json:"token"`
	TokenSHA256 string `json:"token_sha256"`
	Role        string `json:"role"`
	NotAfter    string `json:"not_after"`
}

// ParseKeysConfig parses AVERIN_API_KEYS. Two forms are accepted:
//
//   - legacy "proj-a:tok1,tok2;proj-b:tok3": every token is an admin token with no expiry (kept so
//     existing deployments keep working);
//   - a JSON array (the value starts with "["):
//     [{"project":"p","token":"...","role":"read|write|admin","not_after":"2027-01-01T00:00:00Z"}].
//     Use "token_sha256" (64 hex chars) instead of "token" to keep the secret out of the config.
//     "project" and "role" are required and exactly one of token or token_sha256 is required.
//     "not_after" is optional (omitted = no expiry); when present it must be RFC 3339.
//
// The JSON form rejects unknown fields, an unknown role, a bad expiry, a duplicate project+token and an
// empty array (a silent deny-all) with an error naming the entry index, never the token. It returns the
// store and the number of projects with at least one key.
func ParseKeysConfig(raw string) (*MapStore, int, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "[") {
		ks, n := ParseKeys(raw)
		return ks, n, nil
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var entries []keyConfigEntry
	if err := dec.Decode(&entries); err != nil {
		return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: trailing data after the array")
	}
	if len(entries) == 0 {
		return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: empty array (a silent deny-all); list at least one key")
	}
	ks := &MapStore{keys: map[string][]keyEntry{}, now: time.Now}
	projects := map[string]bool{}
	for i, e := range entries {
		if strings.TrimSpace(e.Project) == "" || e.Project != strings.TrimSpace(e.Project) {
			return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: entry %d: project is required (no surrounding space)", i)
		}
		role, ok := ParseRole(e.Role)
		if !ok {
			return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: entry %d: role must be read, write or admin", i)
		}
		var digest [32]byte
		var fp string
		switch {
		case e.Token != "" && e.TokenSHA256 != "":
			return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: entry %d: give token or token_sha256, not both", i)
		case e.Token != "":
			if e.Token != strings.TrimSpace(e.Token) {
				return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: entry %d: token has surrounding whitespace", i)
			}
			digest = sha256.Sum256([]byte(e.Token))
			fp = secretfp.Fingerprint(e.Token, FingerprintRelationship)
		case e.TokenSHA256 != "":
			b, err := hex.DecodeString(e.TokenSHA256)
			if err != nil || len(b) != 32 {
				return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: entry %d: token_sha256 must be 64 hex characters", i)
			}
			copy(digest[:], b)
			if digest == sha256.Sum256(nil) {
				return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: entry %d: token_sha256 is the digest of the empty token", i)
			}
		default:
			return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: entry %d: token or token_sha256 is required", i)
		}
		var notAfter time.Time
		if e.NotAfter != "" {
			t, err := time.Parse(time.RFC3339, e.NotAfter)
			if err != nil {
				return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: entry %d: not_after must be RFC 3339", i)
			}
			notAfter = t
		}
		for _, ex := range ks.keys[e.Project] {
			if bytes.Equal(ex.digest[:], digest[:]) {
				return nil, 0, fmt.Errorf("AVERIN_API_KEYS JSON: entry %d: duplicate project and token", i)
			}
		}
		ks.addDigest(e.Project, digest, role, notAfter, fp)
		projects[e.Project] = true
	}
	return ks, len(projects), nil
}
