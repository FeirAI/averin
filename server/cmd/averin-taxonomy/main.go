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
//
// Verify mode checks an existing artifact against pins offline (exit 0 only when signature, version and
// digest all match; never prints key material):
//
//	averin-taxonomy --verify --file taxonomy.json --pubkey ed25519pub:... --digest sha256:... --version 8
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/feirai/averin/server/internal/core"
	"github.com/feirai/averin/server/internal/taxonomy"
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

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is main with injectable streams so the CLI is testable; it returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("averin-taxonomy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyHex := fs.String("key", "", "taxonomy issuer signing key: 64 hex chars (a 32-byte ed25519 seed)")
	keyFile := fs.String("key-file", "", "owner-only file containing the 64-hex taxonomy issuer seed")
	version := fs.Int64("version", 1, "taxonomy version (bump to rotate; pinned as taxonomy_version)")
	from := fs.Int64("from", 0, "effective_from, unix seconds")
	until := fs.Int64("until", 0, "effective_until, unix seconds (must be >= from)")
	out := fs.String("out", "", "write the signed taxonomy JSON here (default: stdout)")
	verify := fs.Bool("verify", false, "verify mode: check --file against --pubkey, --digest and --version; exit non-zero on any mismatch")
	file := fs.String("file", "", "verify mode: the signed taxonomy artifact")
	pubkey := fs.String("pubkey", "", "verify mode: pinned issuer public key (ed25519pub:...); repeatable as a comma list")
	digest := fs.String("digest", "", "verify mode: pinned taxonomy_digest (sha256:...)")
	var single, escalating entryList
	fs.Var(&single, "single", "a single_operation entry resource_id=action (repeatable)")
	fs.Var(&escalating, "escalating", "an escalating entry resource_id=action (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(msg string) int {
		fmt.Fprintln(stderr, "averin-taxonomy: "+msg)
		return 1
	}
	if *verify {
		versionSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "version" {
				versionSet = true
			}
		})
		return runVerify(*file, *pubkey, *digest, *version, versionSet, stdout, stderr)
	}

	seedHex, err := loadSeedHex(*keyHex, *keyFile)
	if err != nil {
		return fail(err.Error())
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return fail("taxonomy seed must be 64 hex chars (a 32-byte ed25519 seed)")
	}
	taxKey := ed25519.NewKeyFromSeed(seed)

	// The core is needed only for the RCP-canonical digest (a keyless hash); any valid seed works for it.
	c, err := core.New(strings.Repeat("0", 64))
	if err != nil {
		return fail("init core: " + err.Error())
	}
	taxJSON, dig, ver, err := taxonomy.Sign(c, taxKey, *version, *from, *until, single, escalating)
	if err != nil {
		return fail(err.Error())
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(taxJSON+"\n"), 0o644); err != nil {
			return fail("write " + *out + ": " + err.Error())
		}
	} else {
		fmt.Fprintln(stdout, taxJSON)
	}
	pub := "ed25519pub:" + base64.RawURLEncoding.EncodeToString(taxKey.Public().(ed25519.PublicKey))
	fmt.Fprintf(stderr, "pin these with the bundle to validate the taxonomy:\n  taxonomy_digest  = %s\n  taxonomy_version = %d\n  taxonomy_keys    = [%q]\n", dig, ver, pub)
	return 0
}

// runVerify is the --verify mode: exit 0 only when the artifact's signature, version and digest all match
// the given pins. It never prints key material, only which pin failed.
func runVerify(file, pubkey, digest string, version int64, versionSet bool, stdout, stderr io.Writer) int {
	fail := func(msg string) int {
		fmt.Fprintln(stderr, "averin-taxonomy: verify FAILED: "+msg)
		return 1
	}
	if file == "" || strings.TrimSpace(pubkey) == "" || strings.TrimSpace(digest) == "" || !versionSet {
		return fail("--verify needs --file, --pubkey, --digest and --version")
	}
	artifact, err := os.ReadFile(file)
	if err != nil {
		return fail("read --file: " + err.Error())
	}
	c, err := core.New(strings.Repeat("0", 64))
	if err != nil {
		return fail("init core: " + err.Error())
	}
	var keys []string
	for _, k := range strings.Split(pubkey, ",") {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
	}
	if err := taxonomy.Verify(c, artifact, keys, strings.TrimSpace(digest), version); err != nil {
		return fail(err.Error())
	}
	fmt.Fprintf(stdout, "taxonomy verify: OK (version %d, digest %s)\n", version, strings.TrimSpace(digest))
	return 0
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
