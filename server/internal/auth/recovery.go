package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// RecoveryCredential grants exactly broker_seq:recover for one project. ActorID is a
// stable, non-secret identifier recorded in the recovery evidence; Token is secret.
type RecoveryCredential struct {
	ProjectID string `json:"project_id"`
	ActorID   string `json:"actor_id"`
	Token     string `json:"token"`
}

// RecoveryStore is deliberately separate from KeyStore. Ordinary project keys and
// the dev-only open store never acquire a recovery permission by implication.
type RecoveryStore interface {
	ActorFor(project, token string) (string, bool)
}

type recoveryEntry struct {
	project string
	actor   string
	digest  [32]byte
}

type recoveryMapStore struct{ entries []recoveryEntry }

// ParseRecoveryKeys accepts a JSON array of project/actor/token objects. Duplicate
// project+token entries and tokens shared by two actors or projects are rejected so
// a credential has one unambiguous identity. An empty array is a valid deny-all
// configuration; startup may install it when recovery is not configured.
func ParseRecoveryKeys(raw string, writers ...KeyStore) (RecoveryStore, int, error) {
	if strings.TrimSpace(raw) == "" {
		return recoveryMapStore{}, 0, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var credentials []RecoveryCredential
	if err := dec.Decode(&credentials); err != nil || credentials == nil {
		return nil, 0, errors.New("AVERIN_RECOVERY_KEYS must be a JSON array of project_id, actor_id and token objects")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, 0, errors.New("AVERIN_RECOVERY_KEYS has trailing data")
	}
	store := recoveryMapStore{}
	seen := make(map[[32]byte]struct{}, len(credentials))
	for _, c := range credentials {
		if c.ProjectID == "" || c.ActorID == "" || c.Token == "" ||
			c.ProjectID != strings.TrimSpace(c.ProjectID) || c.ActorID != strings.TrimSpace(c.ActorID) ||
			c.Token != strings.TrimSpace(c.Token) || len(c.ProjectID) > 128 || len(c.ActorID) > 128 ||
			strings.ContainsRune(c.ProjectID, 0) || strings.ContainsRune(c.ActorID, 0) || strings.ContainsRune(c.Token, 0) {
			return nil, 0, errors.New("AVERIN_RECOVERY_KEYS contains an invalid project_id, actor_id or token")
		}
		digest := sha256.Sum256([]byte(c.Token))
		if _, ok := seen[digest]; ok {
			return nil, 0, errors.New("AVERIN_RECOVERY_KEYS contains a duplicate token")
		}
		for _, writer := range writers {
			if writer == nil || IsOpen(writer) {
				continue
			}
			conflict := writer.ValidFor(c.ProjectID, c.Token)
			if inventory, ok := writer.(interface{ ContainsToken(string) bool }); ok {
				conflict = inventory.ContainsToken(c.Token)
			}
			if conflict {
				return nil, 0, errors.New("AVERIN_RECOVERY_KEYS shares a token with AVERIN_API_KEYS for the same project")
			}
		}
		seen[digest] = struct{}{}
		store.entries = append(store.entries, recoveryEntry{c.ProjectID, c.ActorID, digest})
	}
	return store, len(credentials), nil
}

func (s recoveryMapStore) ActorFor(project, token string) (string, bool) {
	if project == "" || token == "" {
		return "", false
	}
	got := sha256.Sum256([]byte(token))
	var actor string
	for _, entry := range s.entries {
		// Visit all entries and compare fixed-width digests. Project equality is
		// tested only after the token match, with no early exit.
		match := subtle.ConstantTimeCompare(got[:], entry.digest[:])
		if match == 1 && entry.project == project {
			actor = entry.actor
		}
	}
	return actor, actor != ""
}

type recoveryActorContextKey struct{}

// RecoveryActor returns the identity authenticated for the recovery route.
func RecoveryActor(ctx context.Context) (string, bool) {
	actor, ok := ctx.Value(recoveryActorContextKey{}).(string)
	return actor, ok && actor != ""
}

// RecoveryMiddleware grants one project-scoped broker_seq:recover action. It
// requires a ?project= scope even when ordinary API authentication is dev-open.
func RecoveryMiddleware(rs RecoveryStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			project := r.URL.Query().Get("project")
			var actor string
			var ok bool
			if rs != nil && len(r.URL.Query()["project"]) == 1 {
				actor, ok = rs.ActorFor(project, tokenFromRequest(r))
			}
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden"}`))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), recoveryActorContextKey{}, actor)))
		})
	}
}
