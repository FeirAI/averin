/* Cross-language FFI smoke test (stands in for cgo). Proves the Go services can call the Rust
 * integrity core through its C ABI.
 *
 * Build the library, then compile + run:
 *   cargo build                 # produces target/debug/libfeir_decision_core.{a,dylib,so}
 *   cc -I core/include core/examples/ffi_smoke.c \
 *      -L target/debug -lfeir_decision_core -o /tmp/ffi_smoke
 *   DYLD_LIBRARY_PATH=target/debug /tmp/ffi_smoke   # (LD_LIBRARY_PATH on Linux)
 *
 * Expected: prints the canonical JSON report and "verdict: PASS (ok:true)".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "feir_core.h"

static char *slurp(const char *p) {
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc(n + 1);
    fread(b, 1, n, f);
    b[n] = 0;
    fclose(f);
    return b;
}

int main(void) {
    char *bundle = slurp("spec/fixtures/bundle-valid.json");
    if (!bundle) { fprintf(stderr, "cannot read bundle\n"); return 2; }
    char *report = feir_verify_bundle_json(bundle);
    if (!report) { fprintf(stderr, "FFI returned null\n"); return 2; }
    printf("FFI report (first 200 chars):\n%.200s\n", report);
    int ok = (NULL != strstr(report, "\"ok\":true"));
    feir_string_free(report);
    free(bundle);
    printf("verdict: %s\n", ok ? "PASS (ok:true)" : "FAIL");
    return ok ? 0 : 1;
}
