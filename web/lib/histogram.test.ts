import { describe, expect, it } from "vitest";
import {
  brushReducer,
  fillBuckets,
  keyToBrushAction,
  maxCount,
  rangeFromSelection,
  selectionBounds,
  totalCount,
} from "./histogram";

const S = 1_000_000_000;

describe("fillBuckets", () => {
  it("fills gaps with zero counts and sorts", () => {
    const filled = fillBuckets(
      [
        { start_ns: 3 * S, count: 2 },
        { start_ns: 0, count: 5 },
      ],
      S,
    );
    expect(filled).toEqual([
      { start_ns: 0, count: 5 },
      { start_ns: S, count: 0 },
      { start_ns: 2 * S, count: 0 },
      { start_ns: 3 * S, count: 2 },
    ]);
  });

  it("returns the sparse series when too many buckets would be created", () => {
    const sparse = [
      { start_ns: 0, count: 1 },
      { start_ns: 10_000 * S, count: 1 },
    ];
    expect(fillBuckets(sparse, S, 100)).toEqual(sparse);
  });

  it("handles empty input and invalid bucket sizes", () => {
    expect(fillBuckets([], S)).toEqual([]);
    expect(fillBuckets([{ start_ns: 0, count: 1 }], 0)).toEqual([]);
  });

  it("keeps realistic nanosecond timestamps exact", () => {
    const base = 1_710_406_800 * S;
    const filled = fillBuckets(
      [
        { start_ns: base, count: 1 },
        { start_ns: base + 2 * 3600 * S, count: 4 },
      ],
      3600 * S,
    );
    expect(filled.map((b) => b.start_ns)).toEqual([base, base + 3600 * S, base + 7200 * S]);
  });
});

describe("counts and ranges", () => {
  const buckets = [
    { start_ns: 0, count: 1 },
    { start_ns: S, count: 7 },
    { start_ns: 2 * S, count: 3 },
  ];
  it("summarizes", () => {
    expect(maxCount(buckets)).toBe(7);
    expect(totalCount(buckets)).toBe(11);
    expect(maxCount([])).toBe(0);
  });
  it("converts a selection into a half-open range regardless of order", () => {
    expect(rangeFromSelection(buckets, S, 2, 1)).toEqual({ start_ns: S, end_ns: 3 * S });
    expect(rangeFromSelection(buckets, S, 0, 0)).toEqual({ start_ns: 0, end_ns: S });
    expect(rangeFromSelection(buckets, S, -5, 99)).toEqual({ start_ns: 0, end_ns: 3 * S });
    expect(rangeFromSelection([], S, 0, 0)).toBeNull();
  });
});

describe("keyboard brushing", () => {
  it("moves the cursor and extends a selection with Shift", () => {
    let s = { cursor: 0, anchor: null as number | null };
    s = brushReducer(s, { type: "move", delta: 1, extend: false, length: 10 });
    expect(s).toEqual({ cursor: 1, anchor: null });
    s = brushReducer(s, { type: "move", delta: 3, extend: true, length: 10 });
    expect(s).toEqual({ cursor: 4, anchor: 1 });
    expect(selectionBounds(s)).toEqual([1, 4]);
    s = brushReducer(s, { type: "home", extend: true, length: 10 });
    expect(selectionBounds(s)).toEqual([0, 1]);
    s = brushReducer(s, { type: "end", extend: false, length: 10 });
    expect(s).toEqual({ cursor: 9, anchor: null });
    expect(selectionBounds(s)).toBeNull();
    s = brushReducer(s, { type: "set", index: 42, extend: true, length: 10 });
    expect(s).toEqual({ cursor: 9, anchor: 9 });
    s = brushReducer(s, { type: "clear" });
    expect(s.anchor).toBeNull();
    expect(
      brushReducer({ cursor: 3, anchor: null }, { type: "move", delta: -1, extend: false, length: 0 }).cursor,
    ).toBe(0);
  });

  it("maps keys to actions", () => {
    expect(keyToBrushAction("ArrowRight", false, 5)).toEqual({
      type: "move",
      delta: 1,
      extend: false,
      length: 5,
    });
    expect(keyToBrushAction("ArrowUp", true, 5)).toEqual({ type: "move", delta: 1, extend: true, length: 5 });
    expect(keyToBrushAction("ArrowLeft", true, 5)).toEqual({
      type: "move",
      delta: -1,
      extend: true,
      length: 5,
    });
    expect(keyToBrushAction("ArrowDown", false, 5)?.type).toBe("move");
    expect(keyToBrushAction("PageUp", false, 50, 10)).toEqual({
      type: "move",
      delta: 10,
      extend: false,
      length: 50,
    });
    expect(keyToBrushAction("PageDown", false, 50, 10)).toEqual({
      type: "move",
      delta: -10,
      extend: false,
      length: 50,
    });
    expect(keyToBrushAction("Home", true, 5)).toEqual({ type: "home", extend: true, length: 5 });
    expect(keyToBrushAction("End", false, 5)).toEqual({ type: "end", extend: false, length: 5 });
    expect(keyToBrushAction("Escape", false, 5)).toEqual({ type: "clear" });
    expect(keyToBrushAction("x", false, 5)).toBeNull();
  });
});
