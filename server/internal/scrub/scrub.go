// Package scrub redacts credentials from captured I/O before it is ever stored or hashed. A
// recording product that leaks API keys is an existential failure (spec §14.8), so the proxy and
// SDK ingestion paths run untrusted content through Redact by default.
//
// Scrubbing is **best-effort defense in depth** — Go's RE2 regexes are linear-time (no ReDoS) but
// cannot catch every secret shape. The primary protection is that in self-host the data never
// leaves customer infra, and customers should not put secrets in prompts. The proxy reassembles
// SSE streams before redacting so a secret split across deltas cannot be reconstructed.
package scrub

import (
	"fmt"
	"regexp"
	"sync"
)

type rule struct {
	re   *regexp.Regexp
	repl string // may reference $1 to keep a non-secret prefix
}

var rules = []rule{
	// PEM private key — redact the WHOLE block, not just the header.
	{regexp.MustCompile(`(?s)-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----`), "[REDACTED:private-key]"},
	// provider API keys (anthropic before openai so the longer prefix wins)
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{16,}`), "[REDACTED:anthropic]"},
	{regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_-]{16,}`), "[REDACTED:openai]"},
	{regexp.MustCompile(`xai-[A-Za-z0-9]{16,}`), "[REDACTED:xai]"},
	{regexp.MustCompile(`(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}`), "[REDACTED:stripe]"},
	{regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "[REDACTED:google]"},
	{regexp.MustCompile(`(?:github_pat|ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}`), "[REDACTED:github]"},
	{regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), "[REDACTED:slack]"},
	{regexp.MustCompile(`SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`), "[REDACTED:sendgrid]"},
	{regexp.MustCompile(`hf_[A-Za-z0-9]{16,}`), "[REDACTED:huggingface]"},
	{regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`), "[REDACTED:aws-akid]"},
	// JWTs and HTTP auth schemes
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), "[REDACTED:jwt]"},
	{regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{16,}`), "[REDACTED:bearer]"},
	{regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/=]{16,}`), "[REDACTED:basic]"},
	// generic key:value / key=value secrets — keep the field name, redact the value ($1 = prefix)
	{regexp.MustCompile(`(?i)("?(?:api[_-]?key|secret|client_secret|access_token|refresh_token|auth_token|password|passwd|private_key|session_token)"?\s*[:=]\s*"?)[A-Za-z0-9._\-+/=]{8,}`), "${1}[REDACTED:kv]"},
	// high-entropy hex fallback (40+ hex; below this risks redacting legitimate ids/hashes)
	{regexp.MustCompile(`\b[A-Fa-f0-9]{40,}\b`), "[REDACTED:hex-secret]"},
}

var extra struct {
	sync.RWMutex
	rules []rule
}

// ConfigurePatterns atomically replaces operator-supplied RE2 patterns. An
// invalid pattern rejects the whole update so a typo cannot silently create a
// secret-capture gap.
func ConfigurePatterns(patterns []string) error {
	compiled := make([]rule, 0, len(patterns))
	for i, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("secret pattern %d: %w", i, err)
		}
		compiled = append(compiled, rule{re: re, repl: "[REDACTED:configured]"})
	}
	extra.Lock()
	extra.rules = compiled
	extra.Unlock()
	return nil
}

// Redact replaces credential-shaped substrings with a typed `[REDACTED:...]` marker.
func Redact(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	extra.RLock()
	defer extra.RUnlock()
	for _, r := range extra.rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// HasSecret reports whether s appears to contain a credential.
func HasSecret(s string) bool {
	for _, r := range rules {
		if r.re.MatchString(s) {
			return true
		}
	}
	extra.RLock()
	defer extra.RUnlock()
	for _, r := range extra.rules {
		if r.re.MatchString(s) {
			return true
		}
	}
	return false
}
