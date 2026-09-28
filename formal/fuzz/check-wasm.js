// Replay the exact corpus emitted and checked by core/tests/rcp_fuzz.rs through the
// browser verifier's public WASM canonicalize entrypoint. Run with pinned Bun 1.3.14.
import { readFileSync } from "node:fs";
import { initAverin, sha256Hex } from "../../verifier/averin.js";

if (process.argv.length !== 5 || !/^[1-9][0-9]*$/.test(process.argv[4])) {
  throw new Error("usage: bun check-wasm.js WASM CORPUS EXPECTED_CASES");
}
const expectedCases = Number(process.argv[4]);
const wasm = new Uint8Array(readFileSync(process.argv[2]));
const pin = await sha256Hex(wasm);
const verifier = await initAverin(wasm, { expectedSha256: pin });
const decoder = new TextDecoder("utf-8", { fatal: true });
const unhex = (hex) => decoder.decode(Uint8Array.from(hex.match(/../g) ?? [], (b) => parseInt(b, 16)));
let count = 0;
for (const line of readFileSync(process.argv[3], "utf8").trimEnd().split("\n")) {
  const [kind, inputHex, canonicalHex] = line.split("\t");
  if (!/^[AR]$/.test(kind) || !/^(?:[0-9a-f]{2})*$/.test(inputHex) ||
      !/^(?:[0-9a-f]{2})*$/.test(canonicalHex)) throw new Error(`malformed corpus line ${count + 1}`);
  const input = unhex(inputHex);
  const expected = unhex(canonicalHex);
  let result;
  try { result = verifier.canonicalize(input); }
  catch (error) {
    if (kind === "A") throw new Error(`WASM rejected accepted case ${count + 1}: ${error}`);
    result = "ERROR: " + error;
  }
  if (kind === "A" ? result !== expected : !result.startsWith("ERROR:")) {
    throw new Error(`WASM mismatch case ${count + 1}: kind=${kind} input=${JSON.stringify(input)} result=${JSON.stringify(result)}`);
  }
  count++;
}
// The corpus must be exactly the generated cases plus the fixed cases (run-fuzz.sh computes the
// number), so a truncated or empty corpus cannot pass.
if (count !== expectedCases) throw new Error(`WASM replay saw ${count} cases, expected exactly ${expectedCases}`);
console.log(`WASM RCP differential passed: ${count} cases, pinned build sha256:${pin}`);
