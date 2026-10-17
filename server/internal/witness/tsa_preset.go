package witness

import (
	"fmt"
	"sort"
	"strings"
)

// TSAPreset is a named, ready-to-use timestamp authority: where to send the request and the key an
// operator or auditor pins to trust its answers.
type TSAPreset struct {
	Name string
	URL  string
	// SPKIB64 is the base64url (no padding) DER SubjectPublicKeyInfo of the TSA signing certificate,
	// the value AVERIN_VERIFY_TSA_SPKI_B64 and opts.json tsa_keys take. Pinning is a trust decision
	// the operator makes; the preset only saves them looking the key up. See docs/dev/TIMESTAMPS.md.
	SPKIB64 string
	Note    string
}

// tsaPresets is deliberately short. FreeTSA is the free default the owner chose; paid authorities are
// configured with AVERIN_TSA_URL (and AVERIN_TSA_AUTH_HEADER when they need credentials).
var tsaPresets = map[string]TSAPreset{
	"freetsa": {
		Name: "freetsa",
		URL:  "https://freetsa.org/tsr",
		// Signing certificate "www.freetsa.org" (ECDSA P-384, valid to 2040-02-02), taken from a live
		// response on 2026-10-15; cross-check against https://freetsa.org/files/tsa.crt before relying on it.
		SPKIB64: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEohXhobLWy4cYsdKOFALpjUsB1FJTntwwb7PH2LOfNMAA1ufaKhkgsdeW6etU0pl5MC5tSVuPF52yy4sz-mbY3L7IVdx_bs9m0ud7IA14YNcC2yIQLa2gvnxwsrR3rlWr",
		Note:    "free service, no uptime guarantee, no SLA",
	},
}

// LookupTSAPreset returns the preset for name (case-insensitive) or an error naming the valid ones.
func LookupTSAPreset(name string) (TSAPreset, error) {
	p, ok := tsaPresets[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		names := make([]string, 0, len(tsaPresets))
		for n := range tsaPresets {
			names = append(names, n)
		}
		sort.Strings(names)
		return TSAPreset{}, fmt.Errorf("witness: unknown TSA preset %q (known: %s)", name, strings.Join(names, ", "))
	}
	return p, nil
}
