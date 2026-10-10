#!/usr/bin/env python3
"""Generate vectors/params-commitment.v1.json: golden vectors for the params hiding commitment.

averin owns the commitment (core/src/commit.rs, RCP section 9.3):
  commitment = "sha256:" + hex(SHA256(LP("averin.commit.v1") || LP(domain) || LP(nonce32) || LP(value)))
with LP(b) = uint32_be(len(b)) || b. vultrino computes the same commitment in Rust for its use PoP
(src/averin/pop.rs params_commitment), taking the nonce as 64 lowercase hex characters. This file is
produced by an independent reference (Python hashlib, no averin code) so the two Rust
implementations are checked against a third, and vultrino keeps a byte-identical copy pinned in
vectors.lock.

Python standard library only. From the repo root:
  python3 scripts/vectors/gen_params_commitment.py > vectors/params-commitment.v1.json
  python3 scripts/vectors/gen_params_commitment.py --check   # fail if the committed file is stale
"""
import hashlib
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def lp(b):
    return struct.pack(">I", len(b)) + b


def commit(domain, nonce, value):
    pre = lp(b"averin.commit.v1") + lp(domain.encode()) + lp(nonce) + lp(value)
    return "sha256:" + hashlib.sha256(pre).hexdigest()


ACCEPT = [
    ("empty-value", "input", bytes(32), b""),
    ("json-object", "input", bytes(range(32)), b'{"q":1}'),
    ("ascii-text", "input", bytes([0xAB]) * 32, b"hello"),
    ("multibyte-utf8", "input", bytes([0x5A]) * 32, "café 資源 \U0001f511".encode("utf-8")),
    ("nul-and-high-bytes", "input", bytes([0xFF]) * 32, bytes([0, 1, 2, 0xFE, 0xFF, 0])),
    ("length-255", "input", bytes(range(32, 64)), bytes([0x61]) * 255),
    ("length-256-two-byte-prefix", "input", bytes(range(32, 64)), bytes([0x62]) * 256),
    ("length-1024", "input", bytes(range(64, 96)), bytes([0x63]) * 1024),
    ("domain-output", "output", bytes(range(32)), b"same value, other domain"),
    ("domain-rationale", "rationale", bytes(range(32)), b"same value, other domain"),
    ("domain-credential", "credential", bytes(range(32)), b"same value, other domain"),
]

# Rejected by vultrino's string API (params_nonce is 64 LOWERCASE hex characters = 32 bytes).
REJECT = [
    ("nonce-31-bytes", "ab" * 31),
    ("nonce-33-bytes", "ab" * 33),
    ("nonce-empty", ""),
    ("nonce-not-hex", "zz" * 32),
    ("nonce-uppercase-hex", "AB" * 32),
    ("nonce-mixed-case-hex", "aB" * 32),
    ("nonce-0x-prefix", "0x" + "ab" * 31),
    ("nonce-odd-length", "a" * 63),
]


def build():
    vectors = []
    for name, domain, nonce, value in ACCEPT:
        vectors.append(
            {
                "id": name,
                "domain": domain,
                "nonce_hex": nonce.hex(),
                "value_hex": value.hex(),
                "expect": commit(domain, nonce, value),
            }
        )
    out = {
        "format": "averin.params-commitment",
        "version": 1,
        "owner": "averin",
        "generator": "scripts/vectors/gen_params_commitment.py (independent Python reference, stdlib only)",
        "spec": [
            "commitment = 'sha256:' + lowercase hex of SHA-256 over LP('averin.commit.v1') || LP(domain) || LP(nonce) || LP(value), where LP(b) = uint32 big-endian length || b.",
            "nonce is 32 raw bytes (nonce_hex is 64 lowercase hex characters); value is the raw bytes (value_hex). The nonce and the value are bound as raw byte strings, never re-encoded.",
            "domain is the closed registry input | output | rationale | credential. vultrino's use PoP always uses 'input'.",
            "vultrino's params_commitment takes the nonce as a string and refuses every entry of reject_nonce_hex (wrong length, not hex, uppercase or mixed case hex, odd length, 0x prefix); averin's FFI refuses the same strings.",
        ],
        "consumers": [
            "averin core/src/commit.rs commit (tests: core/tests/params_commitment_vectors.rs)",
            "vultrino src/averin/pop.rs params_commitment (vendored copy, domain 'input' entries only)",
        ],
        "vectors": vectors,
        "reject_nonce_hex": [{"id": n, "nonce_hex": h} for n, h in REJECT],
    }
    return json.dumps(out, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    text = build()
    if "--check" in sys.argv:
        path = os.path.join(ROOT, "vectors", "params-commitment.v1.json")
        with open(path, "rb") as f:
            if f.read().decode("utf-8") != text:
                sys.stderr.write("vectors/params-commitment.v1.json is stale: rerun scripts/vectors/gen_params_commitment.py\n")
                sys.exit(1)
        print("ok   vectors/params-commitment.v1.json matches its generator")
    else:
        sys.stdout.write(text)
