/** Pure data shaping and geometry for the hand-rolled SVG charts (no DOM, fully unit-tested). */
import type { HistogramBucket } from "./types";

/** Round up to 1, 2, 2.5 or 5 times a power of ten (0 stays 0). */
export function niceMax(n: number): number {
  if (!Number.isFinite(n) || n <= 0) return 0;
  const p = 10 ** Math.floor(Math.log10(n));
  const m = n / p;
  const step = m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10;
  return step * p;
}

/** Evenly spaced axis ticks from 0 to niceMax(max), inclusive. */
export function axisTicks(max: number, count = 4): number[] {
  const top = niceMax(max);
  if (top === 0) return [0];
  return Array.from({ length: count + 1 }, (_, i) => (top * i) / count);
}

/** Merge adjacent buckets so a series has at most `maxPoints` points (counts are summed). */
export function downsample(buckets: HistogramBucket[], maxPoints: number): HistogramBucket[] {
  if (maxPoints <= 0) return [];
  if (buckets.length <= maxPoints) return buckets;
  const size = Math.ceil(buckets.length / maxPoints);
  const out: HistogramBucket[] = [];
  for (let i = 0; i < buckets.length; i += size) {
    const chunk = buckets.slice(i, i + size);
    const first = chunk[0];
    if (first) out.push({ start_ns: first.start_ns, count: chunk.reduce((s, b) => s + b.count, 0) });
  }
  return out;
}

export interface Point {
  x: number;
  y: number;
}

/** Map values to points in a width x height box (y grows downward; 0 sits on the baseline). */
export function toPoints(values: number[], width: number, height: number, max?: number): Point[] {
  const top = max ?? Math.max(0, ...values);
  const n = values.length;
  return values.map((v, i) => ({
    x: n <= 1 ? width / 2 : (i / (n - 1)) * width,
    y: top > 0 ? height - (Math.max(0, v) / top) * height : height,
  }));
}

const fmt = (n: number) => Number(n.toFixed(2)).toString();

export function linePath(points: Point[]): string {
  return points.map((p, i) => `${i === 0 ? "M" : "L"}${fmt(p.x)},${fmt(p.y)}`).join(" ");
}

/** Closed area under a line down to `baseline`. */
export function areaPath(points: Point[], baseline: number): string {
  const first = points[0];
  const last = points[points.length - 1];
  if (!first || !last) return "";
  return `${linePath(points)} L${fmt(last.x)},${fmt(baseline)} L${fmt(first.x)},${fmt(baseline)} Z`;
}

/** Cumulative count series of `times` over `bins` equal slices of [min, max]. */
export function cumulativeSeries(times: number[], bins = 16): number[] {
  const valid = times.filter((t) => Number.isFinite(t)).sort((a, b) => a - b);
  if (!valid.length || bins <= 0) return [];
  const lo = valid[0] ?? 0;
  const hi = valid[valid.length - 1] ?? 0;
  const span = hi - lo;
  const counts = new Array<number>(bins).fill(0);
  for (const t of valid) {
    const i = span === 0 ? bins - 1 : Math.min(bins - 1, Math.floor(((t - lo) / span) * bins));
    counts[i] = (counts[i] ?? 0) + 1;
  }
  let acc = 0;
  return counts.map((c) => (acc += c));
}

export interface Slice {
  key: string;
  value: number;
}

export interface Arc extends Slice {
  fraction: number;
  start: number;
  end: number;
  path: string;
}

function polar(cx: number, cy: number, r: number, angle: number): Point {
  // 0 rad at 12 o'clock, clockwise.
  return { x: cx + r * Math.sin(angle), y: cy - r * Math.cos(angle) };
}

/** SVG path for a ring segment between two angles (radians, clockwise from 12 o'clock). */
export function ringSegment(
  cx: number,
  cy: number,
  outer: number,
  inner: number,
  start: number,
  end: number,
): string {
  const sweep = end - start;
  if (sweep <= 0) return "";
  // A full circle cannot be drawn with one arc; split it in two halves.
  if (sweep >= Math.PI * 2 - 1e-6) {
    const mid = start + Math.PI;
    return `${ringSegment(cx, cy, outer, inner, start, mid)} ${ringSegment(cx, cy, outer, inner, mid, start + Math.PI * 2 - 1e-6)}`;
  }
  const large = sweep > Math.PI ? 1 : 0;
  const o1 = polar(cx, cy, outer, start);
  const o2 = polar(cx, cy, outer, end);
  const i1 = polar(cx, cy, inner, end);
  const i2 = polar(cx, cy, inner, start);
  return [
    `M${fmt(o1.x)},${fmt(o1.y)}`,
    `A${fmt(outer)},${fmt(outer)} 0 ${large} 1 ${fmt(o2.x)},${fmt(o2.y)}`,
    `L${fmt(i1.x)},${fmt(i1.y)}`,
    `A${fmt(inner)},${fmt(inner)} 0 ${large} 0 ${fmt(i2.x)},${fmt(i2.y)}`,
    "Z",
  ].join(" ");
}

/**
 * Donut arcs for non-zero slices, in input order. `gap` (radians) is left between segments so
 * adjacent fills never touch; a single slice gets no gap.
 */
export function donutArcs(
  slices: Slice[],
  opts: { cx: number; cy: number; outer: number; inner: number; gap?: number },
): Arc[] {
  const shown = slices.filter((s) => s.value > 0);
  const total = shown.reduce((s, x) => s + x.value, 0);
  if (total <= 0) return [];
  const gap = shown.length > 1 ? (opts.gap ?? 0.03) : 0;
  let angle = 0;
  return shown.map((s) => {
    const fraction = s.value / total;
    const start = angle;
    const end = angle + fraction * Math.PI * 2;
    angle = end;
    const a = start + gap / 2;
    const b = Math.max(a + 0.001, end - gap / 2);
    return {
      ...s,
      fraction,
      start,
      end,
      path: ringSegment(opts.cx, opts.cy, opts.outer, opts.inner, a, b),
    };
  });
}

/** Largest `n` values; the remainder is summed into one "Other" entry when non-zero. */
export function topWithOther(
  values: { value: string; count: number }[],
  n: number,
  otherLabel = "Other",
): { label: string; count: number; other: boolean }[] {
  const sorted = values
    .filter((v) => v.value !== "")
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
  const head = sorted.slice(0, n).map((v) => ({ label: v.value, count: v.count, other: false }));
  const rest = sorted.slice(n).reduce((s, v) => s + v.count, 0);
  return rest > 0 ? [...head, { label: otherLabel, count: rest, other: true }] : head;
}

export interface StackedBucket {
  start_ns: number;
  total: number;
  /** Count per layer key, in layer order. */
  layers: number[];
  /** Events in the bucket not covered by any layer. */
  other: number;
}

/**
 * Split each dense bucket of the overall histogram into per-layer counts (layers fetched with
 * the same bucket width). Anything not covered by a layer becomes `other`; layer counts are
 * clamped so the stack never exceeds the bucket total.
 */
export function stackBuckets(base: HistogramBucket[], layers: HistogramBucket[][]): StackedBucket[] {
  const maps = layers.map((l) => new Map(l.map((b) => [b.start_ns, b.count])));
  return base.map((b) => {
    let remaining = b.count;
    const counts = maps.map((m) => {
      const c = Math.min(remaining, Math.max(0, m.get(b.start_ns) ?? 0));
      remaining -= c;
      return c;
    });
    return { start_ns: b.start_ns, total: b.count, layers: counts, other: remaining };
  });
}

/** Proportional bar width (0..100 %) with a visible minimum for non-zero values. */
export function barPercent(value: number, max: number, minVisible = 2): number {
  if (max <= 0 || value <= 0) return 0;
  return Math.max(minVisible, Math.min(100, (value / max) * 100));
}

/** Compact number for tight labels: 950, 1.2k, 34k, 1.5M. */
export function compactNumber(n: number): string {
  const abs = Math.abs(n);
  if (abs < 1000) return String(Math.round(n));
  if (abs < 1e6) return `${Number((n / 1000).toFixed(abs < 10_000 ? 1 : 0))}k`;
  return `${Number((n / 1e6).toFixed(abs < 1e7 ? 1 : 0))}M`;
}
