import { describe, it, expect } from "vitest";
import { buildWaterfall, type Rec } from "./trace";

function r(hash: string, seq: number, parents: string[] = []): Rec {
  return {
    content_hash: hash,
    causal_prev_hashes: parents,
    display_seq: seq,
    event_type: "tool_call",
    action: "x",
    status: "ok",
    observed_via: "sdk",
  };
}

describe("buildWaterfall", () => {
  it("sorts by display_seq and computes linear depth", () => {
    const rows = buildWaterfall([r("c", 2, ["b"]), r("a", 0), r("b", 1, ["a"])]);
    expect(rows.map((x) => x.rec.content_hash)).toEqual(["a", "b", "c"]);
    expect(rows.map((x) => x.depth)).toEqual([0, 1, 2]);
  });

  it("computes depth as the longest causal chain for a diamond", () => {
    // a -> b, a -> c, (b,c) -> d : d depth = 2
    const rows = buildWaterfall([r("a", 0), r("b", 1, ["a"]), r("c", 2, ["a"]), r("d", 3, ["b", "c"])]);
    const depthOf = (h: string) => rows.find((x) => x.rec.content_hash === h)!.depth;
    expect(depthOf("a")).toBe(0);
    expect(depthOf("b")).toBe(1);
    expect(depthOf("d")).toBe(2);
  });

  it("handles missing parents and cycles without throwing", () => {
    expect(() => buildWaterfall([r("a", 0, ["missing"])])).not.toThrow();
    expect(() => buildWaterfall([r("a", 0, ["b"]), r("b", 1, ["a"])])).not.toThrow();
  });

  it("does not overflow the stack on a very deep chain", () => {
    const recs: Rec[] = [];
    for (let i = 0; i < 20000; i++) recs.push(r(`h${i}`, i, i > 0 ? [`h${i - 1}`] : []));
    const rows = buildWaterfall(recs);
    expect(rows[rows.length - 1].depth).toBe(19999);
  });
});
