/** Histogram bucketing and keyboard brushing. */
import type { HistogramBucket } from "./types";

export const MAX_BUCKETS = 2000;

/**
 * Turn the sparse API buckets into a dense, gap-free series so bars are evenly spaced in time.
 * Falls back to the sorted sparse series when filling would exceed `maxBuckets`.
 */
export function fillBuckets(
  buckets: HistogramBucket[],
  bucketNs: number,
  maxBuckets = MAX_BUCKETS,
): HistogramBucket[] {
  if (!buckets.length || bucketNs <= 0) return [];
  const sorted = [...buckets].sort((a, b) => a.start_ns - b.start_ns);
  const first = sorted[0];
  const last = sorted[sorted.length - 1];
  if (!first || !last) return [];
  const n = Math.round((last.start_ns - first.start_ns) / bucketNs) + 1;
  if (n > maxBuckets) return sorted;
  const counts = new Map(sorted.map((b) => [Math.round((b.start_ns - first.start_ns) / bucketNs), b.count]));
  return Array.from({ length: n }, (_, i) => ({
    start_ns: first.start_ns + i * bucketNs,
    count: counts.get(i) ?? 0,
  }));
}

export function maxCount(buckets: HistogramBucket[]): number {
  return buckets.reduce((m, b) => Math.max(m, b.count), 0);
}

export function totalCount(buckets: HistogramBucket[]): number {
  return buckets.reduce((s, b) => s + b.count, 0);
}

/** Half-open time range covered by buckets[a..b] (in either order). */
export function rangeFromSelection(
  buckets: HistogramBucket[],
  bucketNs: number,
  a: number,
  b: number,
): { start_ns: number; end_ns: number } | null {
  const lo = Math.max(0, Math.min(a, b));
  const hi = Math.min(buckets.length - 1, Math.max(a, b));
  const first = buckets[lo];
  const last = buckets[hi];
  if (!first || !last) return null;
  return { start_ns: first.start_ns, end_ns: last.start_ns + bucketNs };
}

export interface BrushState {
  cursor: number;
  anchor: number | null;
}

export type BrushAction =
  | { type: "move"; delta: number; extend: boolean; length: number }
  | { type: "home"; extend: boolean; length: number }
  | { type: "end"; extend: boolean; length: number }
  | { type: "set"; index: number; extend: boolean; length: number }
  | { type: "clear" };

function clampIndex(i: number, length: number): number {
  return length <= 0 ? 0 : Math.min(length - 1, Math.max(0, i));
}

export function brushReducer(state: BrushState, action: BrushAction): BrushState {
  if (action.type === "clear") return { cursor: state.cursor, anchor: null };
  let target: number;
  switch (action.type) {
    case "move":
      target = state.cursor + action.delta;
      break;
    case "home":
      target = 0;
      break;
    case "end":
      target = action.length - 1;
      break;
    case "set":
      target = action.index;
      break;
  }
  const cursor = clampIndex(target, action.length);
  const anchor = action.extend ? (state.anchor ?? state.cursor) : null;
  return { cursor, anchor };
}

export function selectionBounds(s: BrushState): [number, number] | null {
  if (s.anchor === null) return null;
  return [Math.min(s.anchor, s.cursor), Math.max(s.anchor, s.cursor)];
}

/** Map a key press to a brush action. Returns null for keys the histogram does not handle. */
export function keyToBrushAction(
  key: string,
  shift: boolean,
  length: number,
  pageStep = 10,
): BrushAction | null {
  switch (key) {
    case "ArrowLeft":
    case "ArrowDown":
      return { type: "move", delta: -1, extend: shift, length };
    case "ArrowRight":
    case "ArrowUp":
      return { type: "move", delta: 1, extend: shift, length };
    case "PageDown":
      return { type: "move", delta: -pageStep, extend: shift, length };
    case "PageUp":
      return { type: "move", delta: pageStep, extend: shift, length };
    case "Home":
      return { type: "home", extend: shift, length };
    case "End":
      return { type: "end", extend: shift, length };
    case "Escape":
      return { type: "clear" };
    default:
      return null;
  }
}
