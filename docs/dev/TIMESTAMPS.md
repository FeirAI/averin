# Trusted timestamps (RFC 3161)

averin can have each sealed checkpoint stamped by an outside timestamp authority (TSA). The stamp says the
checkpoint hash, and with it every earlier checkpoint it chains to, existed by the time the TSA signed. That is
what stops a recorder from quietly backdating history, and it is what the anchored-before rule after a key
compromise and the detection of removed sessions rely on ([SECURITY.md](SECURITY.md), threats #3, #9 and #15).

## Default: off

With nothing configured no checkpoint is anchored and those protections are off. Turning them on sends one
request per checkpoint to the TSA URL you choose (the FreeTSA preset is https; a plain `http` `AVERIN_TSA_URL` is accepted unless `AVERIN_TSA_AUTH_HEADER` is set), carrying only the SHA-256 of the checkpoint hash, never
any record content. Whether that outbound call is acceptable on your infrastructure is your decision.

## Turning it on

| Setting | Effect |
|---|---|
| `AVERIN_TSA_PRESET=freetsa` | One setting: stamp at https://freetsa.org/tsr. The server logs the TSA signing key to pin. |
| `AVERIN_TSA_URL=<url>` | Any other authority (DigiCert, Sectigo, GlobalSign, a private one). Setting both this and the preset is fatal. |
| `AVERIN_TSA_AUTH_HEADER=<value>` | The `Authorization` header a paid authority needs (for example `Basic ...`). Read from the environment and sent as is. Start-up is refused unless the TSA URL is https, so the credential never travels in clear text. |

An unknown preset name is fatal at start-up. Anchoring is best-effort: a TSA outage stores the checkpoint
un-anchored and is reported, it never stops the chain.

### Back-anchoring a checkpoint that missed its stamp

Two paths stamp an older un-anchored checkpoint later, both through the same code as the first stamp
(the imprint is the SHA-256 of the `checkpoint_hash` string, 10 s timeout each, stored with the insert-only
`PutAnchor`):

- **Automatic, per cut.** After a new checkpoint's own stamp succeeds, the server stamps up to 3 older
  un-anchored checkpoints of the same project, oldest first, and stops at the first failure. If the new
  checkpoint's own stamp failed, it makes no sweep. This runs only while new cuts happen: a quiet system
  retries nothing by itself.
- **Operator, on demand.** `POST /v2/anchors/backfill?project=<id>` (admin, like `POST /v2/checkpoints`) runs
  the same sweep with a bound of 100 and stops at the first failure. It returns
  `{"back_anchored": n, "remaining_unanchored": m, "stopped_on_error": bool}` (`remaining_unanchored` is
  counted up to 10000), or `409` when no TSA is configured. Call it again until `remaining_unanchored` is 0.

Counters: `averin_checkpoint_backanchored_total` and `averin_checkpoint_backanchor_failures_total`. Each
back-anchor logs one line; a sweep that stops on an error logs an `ALERT:` line.

A back-anchor's genTime is later than the checkpoint's `created_ts`, so it proves the checkpoint existed by
that later time, not by `created_ts`. (The chain already bounds it: a stamp on a newer checkpoint commits every
older checkpoint it chains to.) **Known conflict with the offline verifier:** the backdating gate requires
verified anchor times to be non-decreasing with checkpoint seq. A back-anchor stamped after a newer checkpoint
was anchored therefore makes the bundle fail with `anchor time decreased across checkpoints ...`, although
every checkpoint then counts as anchored. A test pins this behaviour; see `LIMITATIONS.md`.

FreeTSA is a free service with no uptime guarantee and no service level. For anything you need to rely on, use a
paid authority through `AVERIN_TSA_URL`.

## Pinning the authority

A stamp is only as good as the key you trust for it. The verifier does not walk the TSA's certificate chain: you
pin the TSA **signing certificate's public key** (its SubjectPublicKeyInfo) out of band, in `opts.json` as
`tsa_spki_b64` (base64url, no padding) or, for `/v2/verify`, `AVERIN_VERIFY_TSA_SPKI_B64`. For the FreeTSA preset
the key printed at start-up is the one in the certificate at https://freetsa.org/files/tsa.crt on 2026-10-15 (ECDSA
P-384, valid to 2040); compare it before relying on it. To extract the key from any authority's response:

```
openssl ts -reply -in resp.tsr -token_out -out token.der
openssl pkcs7 -inform DER -in token.der -print_certs > certs.pem   # the first certificate is the signer
openssl x509 -in signer.pem -pubkey -noout | openssl pkey -pubin -outform DER | basenc --base64url | tr -d '='
```

## What the verifier accepts

The native verifier (built with the `rfc3161` feature, which is not a default feature: `make core`, the server Dockerfile and CI pass `--features rfc3161`, while a plain `cargo build` of the CLI or the staticlib leaves it out and reports an RFC 3161 anchor as `Unsupported`) accepts a
`SignedData` whose single `SignerInfo` signs with:

| Signature | Digest |
|---|---|
| ECDSA P-256 | SHA-256 |
| ECDSA P-384 | SHA-512 |
| RSA PKCS#1 v1.5 (named-hash OID or bare `rsaEncryption`) | SHA-256, SHA-384, SHA-512 |
| RSASSA-PSS (hash and MGF1 hash equal to the digest, trailer 1, salt up to 64 bytes) | SHA-256, SHA-384, SHA-512 |

RSA keys under 2048 bits are refused. A named hash that disagrees with the `SignerInfo` digest, a PSS parameter set
that disagrees with it, and every other algorithm are rejected as unsupported, never passed. The timestamp request
and the `messageImprint` are always SHA-256. The browser/WASM verifier is built without the feature and reports an
RFC 3161 anchor as `Unsupported`, never a silent pass.

## What is tested against real authorities

`core/tests/fixtures/tsa/` holds responses recorded from live authorities on 2026-10-15 for one message: FreeTSA
(ECDSA P-384 with SHA-512), DigiCert (RSA PKCS#1 v1.5 with SHA-256) and Sectigo (RSA PKCS#1 v1.5 with SHA-384). The
Rust tests verify each against the signing certificate's key, check the message binding and the `genTime`, and fail
them under another authority's key or with a flipped signature bit. The Go client's request is byte-identical to the
one those authorities accepted, and `HTTPTSA.Stamp` unwraps each recorded `TimeStampResp` to exactly the recorded token.

This is a recorded round trip, not a standing one: no CI job stamps at a live authority, so an authority changing its
signing algorithm or certificate shows up when you next anchor, not in CI. It also does not validate the TSA's
certificate chain (you pin the key), the TSA's policy, or the accuracy of its clock. A TSA bounds when a checkpoint
existed, not when the events inside it happened.
