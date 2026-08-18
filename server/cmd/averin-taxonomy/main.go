// Command averin-taxonomy signs an operation taxonomy (ADR 0004 D4 / threat F8) so a deployment can AUTHOR
// and ROTATE the artifact the offline verifier pins. It prints the signed taxonomy JSON to stdout (or
// --out) and the pinning triple (taxonomy_digest, taxonomy_version, taxonomy issuer public key) to stderr.
// The issuer holds NO runtime authority over grants/uses — its key must be role-separated from the
// broker/resource/tsa/attestation keys (the verifier fatal-aborts on overlap). Rotation = bump --version
// (and optionally the key) and re-pin.
//
// Example:
//
//	averin-taxonomy --key <64-hex-seed> --version 1 --from 1718000000 --until 1760000000 \
//	  --single orders-db=db.query:orders-ro --escalating orders-db=db.admin:drop
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/averin-dev/averin/server/internal/core"
	"github.com/averin-dev/averin/server/internal/taxonomy"
)

// entryList collects repeatable resource_id=action flags into taxonomy entries.
type entryList []taxonomy.Entry

func (e *entryList) String() string { return fmt.Sprintf("%v", *e) }

func (e *entryList) Set(v string) error {
	i := strings.IndexByte(v, '=')
	if i <= 0 || i == len(v)-1 {
		return fmt.Errorf("want resource_id=action, got %q", v)
	}
	*e = append(*e, taxonomy.Entry{ResourceID: v[:i], Action: v[i+1:]})
	return nil
}

func main() {
	keyHex := flag.String("key", "", "taxonomy issuer signing key: 64 hex chars (a 32-byte ed25519 seed)")
	keyFile := flag.String("key-file", "", "owner-only file containing the 64-hex taxonomy issuer seed")
	version := flag.Int64("version", 1, "taxonomy version (bump to rotate; pinned as taxonomy_version)")
	from := flag.Int64("from", 0, "effective_from, unix seconds")
	until := flag.Int64("until", 0, "effective_until, unix seconds (must be >= from)")
	out := flag.String("out", "", "write the signed taxonomy JSON here (default: stdout)")
	var single, escalating entryList
	flag.Var(&single, "single", "a single_operation entry resource_id=action (repeatable)")
	flag.Var(&escalating, "escalating", "an escalating entry resource_id=action (repeatable)")
	flag.Parse()

	seedHex, err := loadSeedHex(*keyHex, *keyFile)
	if err != nil {
		fatal(err.Error())
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		fatal("taxonomy seed must be 64 hex chars (a 32-byte ed25519 seed)")
	}
	taxKey := ed25519.NewKeyFromSeed(seed)

	// The core is needed only for the RCP-canonical digest (a keyless hash); any valid seed works for it.
	c, err := core.New(strings.Repeat("0", 64))
	if err != nil {
		fatal("init core: " + err.Error())
	}
	taxJSON, digest, ver, err := taxonomy.Sign(c, taxKey, *version, *from, *until, single, escalating)
	if err != nil {
		fatal(err.Error())
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(taxJSON+"\n"), 0o644); err != nil {
			fatal("write " + *out + ": " + err.Error())
		}
	} else {
		fmt.Println(taxJSON)
	}
	pub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(taxKey.Public().(ed25519.PublicKey))
	fmt.Fprintf(os.Stderr, "pin these with the bundle to validate the taxonomy:\n  taxonomy_digest  = %s\n  taxonomy_version = %d\n  taxonomy_keys    = [%q]\n", digest, ver, pub)
}

func loadSeedHex(keyHex, keyFile string) (string, error) {
	keyHex = strings.TrimSpace(keyHex)
	keyFile = strings.TrimSpace(keyFile)
	if (keyHex == "") == (keyFile == "") {
		return "", fmt.Errorf("exactly one of --key or --key-file is required")
	}
	if keyFile == "" {
		return keyHex, nil
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		return "", fmt.Errorf("stat --key-file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("--key-file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("--key-file must be owner-only (mode 0600)")
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("read --key-file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "averin-taxonomy: "+msg)
	os.Exit(1)
}
