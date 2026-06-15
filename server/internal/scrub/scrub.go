// Package scrub redacts credentials from captured I/O before it is ever stored or hashed. A
// recording product that leaks API keys is an existential failure (spec §14.8), so the proxy and
// SDK ingestion paths run untrusted content through Redact by default.
package scrub

import "regexp"

// Each pattern matches a secret-shaped token; the whole match is replaced with a typed marker so
// the record still shows that a secret was present (and where) without leaking it.
var patterns = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`), "openai"},
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{16,}`), "anthropic"},
	{regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{16,}`), "bearer"},
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws-akid"},
	{regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`), "github"},
	{regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), "slack"},
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), "private-key"},
	// long high-entropy hex / base64-ish blobs (likely keys/tokens)
	{regexp.MustCompile(`\b[A-Fa-f0-9]{40,}\b`), "hex-secret"},
}

// Redact replaces credential-shaped substrings with `[REDACTED:<kind>]`.
func Redact(s string) string {
	for _, p := range patterns {
		s = p.re.ReplaceAllString(s, "[REDACTED:"+p.kind+"]")
	}
	return s
}

// HasSecret reports whether s appears to contain a credential (used to flag, not just redact).
func HasSecret(s string) bool {
	for _, p := range patterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	return false
}
