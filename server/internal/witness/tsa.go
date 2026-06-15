package witness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TSA is the RFC 3161 timestamp-authority client abstraction. Stamp submits the SHA-256 imprint of
// a checkpoint_hash and returns the DER-encoded timestamp token (a CMS SignedData / TimeStampToken).
// The token is later attached to a checkpoint's `anchor` and binds "this hash existed by time T"
// (threat #3 backdating). The TSA is an INDEPENDENT trust anchor from the witness store.
type TSA interface {
	// Stamp returns the DER token for a 32-byte SHA-256 imprint. The caller passes the raw digest
	// bytes (NOT the "sha256:" prefixed string), i.e. sha256.Sum256(checkpoint_hash-input)[:].
	Stamp(ctx context.Context, imprintSHA256 []byte) (tokenDER []byte, err error)
}

// sha256OID is the DER OID for id-sha256 (2.16.840.1.101.3.4.2.1).
var sha256OID = []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}

// BuildTimeStampReq hand-encodes a minimal RFC 3161 TimeStampReq (DER) for a SHA-256 imprint:
//
//	TimeStampReq ::= SEQUENCE {
//	    version       INTEGER { v1(1) },
//	    messageImprint MessageImprint,            -- SEQUENCE { hashAlgorithm AlgorithmIdentifier,
//	                                              --            hashedMessage OCTET STRING }
//	    certReq       BOOLEAN DEFAULT FALSE }      -- we set TRUE to get the TSA cert in the token
//
// The structure is small and fixed-shape (a 32-byte SHA-256 imprint with no AlgorithmIdentifier
// parameters), so the lengths are short-form (< 128) and we encode them directly. This is the only
// ASN.1 we hand-roll; anything larger (parsing the token, CMS) is intentionally out of scope here.
func BuildTimeStampReq(imprintSHA256 []byte) ([]byte, error) {
	if len(imprintSHA256) != sha256.Size {
		return nil, fmt.Errorf("witness: SHA-256 imprint must be %d bytes, got %d", sha256.Size, len(imprintSHA256))
	}

	// AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
	// Many TSAs require an explicit NULL parameters for hash algorithms; we include it.
	algParams := []byte{0x05, 0x00} // NULL
	algID := derSeq(concat(sha256OID, algParams))

	// hashedMessage OCTET STRING (the imprint)
	hashedMessage := derOctetString(imprintSHA256)

	// MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
	messageImprint := derSeq(concat(algID, hashedMessage))

	// version INTEGER 1
	version := []byte{0x02, 0x01, 0x01}

	// certReq BOOLEAN TRUE — request the TSA's signing cert chain in the response token.
	certReq := []byte{0x01, 0x01, 0xFF}

	return derSeq(concat(version, messageImprint, certReq)), nil
}

// derSeq wraps content in a DER SEQUENCE with a definite (short or long form) length.
func derSeq(content []byte) []byte {
	return concat([]byte{0x30}, derLen(len(content)), content)
}

// derOctetString wraps content in a DER OCTET STRING.
func derOctetString(content []byte) []byte {
	return concat([]byte{0x04}, derLen(len(content)), content)
}

// derLen encodes a definite-form DER length. For our fixed small structures this is always
// short-form, but we implement long-form too so the encoder is correct for any content size.
func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0xFF)}, tmp...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(tmp))}, tmp...)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TSQBuilder builds an RFC 3161 TimeStampQuery (the DER request body) from a SHA-256 imprint.
// HTTPTSA defaults to BuildTimeStampReq, but a deployment can inject a different builder (e.g. one
// that adds a nonce or a policy OID, or one backed by crypto/x509-style encoding) without changing
// the HTTP plumbing.
type TSQBuilder func(imprintSHA256 []byte) ([]byte, error)

// HTTPTSA POSTs an RFC 3161 TimeStampQuery to a TSA endpoint and returns the raw response body
// (the DER TimeStampToken / TimeStampResp). It is a thin transport: it does NOT verify the returned
// token here — token verification (signature, imprint match, cert chain, anchor time extraction) is
// performed by the offline verifier against the out-of-band-pinned TSA cert (RCP §10.1). Pinning and
// verification are what give the timestamp its trust; this client only obtains the bytes.
type HTTPTSA struct {
	URL string
	// Build encodes the request DER. Defaults to BuildTimeStampReq when nil.
	Build TSQBuilder
	// Client is the HTTP client; defaults to a 10s-timeout client when nil.
	Client *http.Client
	// ContentType is the request content type; defaults to the RFC 3161 timestamp-query media type.
	ContentType string
	// MaxResponseBytes caps the response read to avoid an unbounded body from a hostile/buggy TSA.
	MaxResponseBytes int64
}

const tsqContentType = "application/timestamp-query"

func (t *HTTPTSA) Stamp(ctx context.Context, imprintSHA256 []byte) ([]byte, error) {
	if t.URL == "" {
		return nil, errors.New("witness: HTTPTSA.URL required")
	}
	build := t.Build
	if build == nil {
		build = BuildTimeStampReq
	}
	tsq, err := build(imprintSHA256)
	if err != nil {
		return nil, fmt.Errorf("witness: build TSQ: %w", err)
	}

	ct := t.ContentType
	if ct == "" {
		ct = tsqContentType
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(tsq))
	if err != nil {
		return nil, fmt.Errorf("witness: new request: %w", err)
	}
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Accept", "application/timestamp-reply")

	cl := t.Client
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("witness: TSA request: %w", err)
	}
	defer resp.Body.Close()

	max := t.MaxResponseBytes
	if max <= 0 {
		max = 1 << 20 // 1 MiB is far larger than any RFC 3161 token; bound it anyway
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max))
	if err != nil {
		return nil, fmt.Errorf("witness: read TSA response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Do not leak the body verbatim into logs upstream; return the status for the caller to
		// surface. The body may contain a DER error structure, not useful as a plain string.
		return nil, fmt.Errorf("witness: TSA returned HTTP %d", resp.StatusCode)
	}
	if len(body) == 0 {
		return nil, errors.New("witness: TSA returned empty token")
	}
	// A real TSA returns a TimeStampResp { status PKIStatusInfo, timeStampToken ContentInfo }, but
	// the verifier (and our anchor block) wants the bare timeStampToken (a CMS ContentInfo). Unwrap
	// the envelope; if the body is already a bare token, return it unchanged.
	return extractTimeStampToken(body)
}

// extractTimeStampToken returns the DER timeStampToken (a CMS ContentInfo) from a TSA response. If
// `der` is a TimeStampResp (outer SEQUENCE whose first element is the PKIStatusInfo SEQUENCE), it
// returns the second element; if `der` is already a ContentInfo (first element is the signedData
// OID), it returns `der` unchanged. This is what the offline verifier parses with ContentInfo::from_der.
func extractTimeStampToken(der []byte) ([]byte, error) {
	tag, content, _, err := readTLV(der)
	if err != nil {
		return nil, fmt.Errorf("witness: parse TSA response: %w", err)
	}
	if tag != 0x30 { // SEQUENCE
		return nil, fmt.Errorf("witness: TSA response is not a DER SEQUENCE (tag 0x%02x)", tag)
	}
	// Peek the first inner element's tag to tell a TimeStampResp from a bare ContentInfo.
	firstTag, _, rest, err := readTLV(content)
	if err != nil {
		return nil, fmt.Errorf("witness: parse TSA response body: %w", err)
	}
	switch firstTag {
	case 0x06: // OID -> the outer SEQUENCE is already a ContentInfo (bare timeStampToken).
		return der, nil
	case 0x30: // SEQUENCE -> PKIStatusInfo; the timeStampToken is the next element.
		tokTag, _, _, err := readTLV(rest)
		if err != nil {
			return nil, fmt.Errorf("witness: TimeStampResp has no timeStampToken: %w", err)
		}
		if tokTag != 0x30 {
			return nil, fmt.Errorf("witness: timeStampToken is not a ContentInfo SEQUENCE (tag 0x%02x)", tokTag)
		}
		// readTLV already validated the element's bounds; return its full TLV bytes.
		full, _, err := tlvBytes(rest)
		if err != nil {
			return nil, err
		}
		return full, nil
	default:
		return nil, fmt.Errorf("witness: unexpected first element in TSA response (tag 0x%02x)", firstTag)
	}
}

// readTLV parses one DER TLV at the front of b, returning its tag, content bytes, and the remaining
// bytes after this element. Supports definite-length short and long form (up to 4 length octets).
func readTLV(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("truncated TLV")
	}
	tag = b[0]
	n := int(b[1])
	i := 2
	if n&0x80 != 0 { // long form: low 7 bits = number of length octets
		nbytes := n & 0x7f
		if nbytes == 0 || nbytes > 4 {
			return 0, nil, nil, fmt.Errorf("unsupported DER length (%d octets)", nbytes)
		}
		if len(b) < i+nbytes {
			return 0, nil, nil, errors.New("truncated DER length")
		}
		n = 0
		for j := 0; j < nbytes; j++ {
			n = (n << 8) | int(b[i+j])
		}
		i += nbytes
	}
	if n < 0 || len(b) < i+n {
		return 0, nil, nil, errors.New("DER content exceeds buffer")
	}
	return tag, b[i : i+n], b[i+n:], nil
}

// tlvBytes returns the full TLV (tag+length+content) at the front of b, and the remaining bytes.
func tlvBytes(b []byte) (full, rest []byte, err error) {
	_, content, after, err := readTLV(b)
	if err != nil {
		return nil, nil, err
	}
	n := len(b) - len(after)
	_ = content
	return b[:n], after, nil
}

// StubTSA is a deterministic fake TSA for tests. It returns reproducible bytes derived from the
// imprint so tests can assert on the token without any network call. It is NOT a real timestamp:
// the bytes are not a valid CMS token and must never be presented as a verifiable anchor.
type StubTSA struct {
	// Prefix is prepended to the deterministic token (default "STUBTSAv1").
	Prefix string
}

func (s StubTSA) Stamp(_ context.Context, imprintSHA256 []byte) ([]byte, error) {
	if len(imprintSHA256) != sha256.Size {
		return nil, fmt.Errorf("witness: SHA-256 imprint must be %d bytes, got %d", sha256.Size, len(imprintSHA256))
	}
	prefix := s.Prefix
	if prefix == "" {
		prefix = "STUBTSAv1"
	}
	// Deterministic: hash(prefix || imprint) — same imprint always yields the same fake token.
	h := sha256.New()
	h.Write([]byte(prefix))
	h.Write(imprintSHA256)
	return concat([]byte(prefix), h.Sum(nil)), nil
}
