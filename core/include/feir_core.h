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

/* Free a string returned by this library. */
void feir_string_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* FEIR_CORE_H */
