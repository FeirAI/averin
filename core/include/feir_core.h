/* feir decision-core — C FFI (cgo). See core/src/ffi.rs.
 *
 * Memory: every non-NULL char* returned must be freed with feir_string_free().
 * All strings are UTF-8, null-terminated. Thread-safe (no shared mutable state). */
#ifndef FEIR_CORE_H
#define FEIR_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Verify an export bundle (UTF-8 JSON). Returns a JSON report string (caller frees), or NULL on
 * NULL/invalid-UTF-8 input. The report always parses; check its "ok" field. */
char *feir_verify_bundle_json(const char *input);

/* Canonicalize a JSON document under RCP v1. Returns the canonical string (caller frees), which
 * begins with "ERROR:" on a parse error; NULL on NULL/invalid-UTF-8 input. */
char *feir_rcp_canonicalize(const char *input);

/* Seal a Decision Record / checkpoint body (UTF-8 JSON) with an Ed25519 key (64 hex chars = 32
 * bytes). Returns sealed JSON with content_hash/checkpoint_hash + sig set, or {"error":"..."}.
 * NULL on NULL/invalid-UTF-8. Self-host signing key; production backs signing with a KMS. */
char *feir_seal_record(const char *body, const char *seed_hex);
char *feir_seal_checkpoint(const char *body, const char *seed_hex);

/* Return the ed25519pub: public key for a seed (for the server's published key list). */
char *feir_pubkey_from_seed(const char *seed_hex);

/* Mint a fresh 32-byte hiding-commitment nonce, returned as 64 lowercase hex chars (caller frees).
 * Returns {"error":"..."} if the library was built without the std feature (e.g. WASM). */
char *feir_random_nonce(void);

/* Compute a hiding commitment over a low-entropy field (RCP §9.3). domain is "input"|"output"|
 * "rationale"; value_b64 is base64url-no-pad of the raw value bytes; nonce_hex is 64 hex chars.
 * Returns "sha256:<hex>" or {"error":"..."}. */
char *feir_commit(const char *domain, const char *value_b64, const char *nonce_hex);

/* Verify a disclosed (value, nonce) against a commitment. Returns "true"/"false", or
 * {"error":"..."} on malformed input. */
char *feir_verify_commitment(const char *commitment, const char *domain, const char *value_b64,
                             const char *nonce_hex);

/* Free a string returned by this library. */
void feir_string_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* FEIR_CORE_H */
