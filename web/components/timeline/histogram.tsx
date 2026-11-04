"use client";

import { useReducer, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { Button } from "@/components/ui/button";
import { compactNumber, type StackedBucket } from "@/lib/charts";
import { formatDuration, formatNs, formatNsShort } from "@/lib/format";
import {
  brushReducer,
  keyToBrushAction,
  maxCount,
  rangeFromSelection,
  selectionBounds,
  totalCount,
  type BrushState,
} from "@/lib/histogram";
import type { HistogramBucket } from "@/lib/types";
import { cn } from "@/lib/utils";

const HEIGHT = 84;

export interface HistogramStack {
  /** One entry per layer, bottom to top; "other" is drawn last in the neutral colour. */
  layers: { key: string; label: string; color: string }[];
  /** Aligned with `buckets`. */
  rows: StackedBucket[];
}

export interface HistogramProps {
  buckets: HistogramBucket[];
  bucketNs: number;
  onRange: (range: { start_ns: number; end_ns: number }) => void;
  loading?: boolean;
  /** Optional per-category breakdown; without it bars use a single colour. */
  stack?: HistogramStack | null;
}

/**
 * Event-count histogram with mouse and keyboard brushing. Focus the chart, move with the arrow
 * keys, hold Shift to extend a selection, press Enter to filter to it and Escape to clear.
 */
export function Histogram({ buckets, bucketNs, onRange, loading, stack }: HistogramProps) {
  const [brush, dispatch] = useReducer(brushReducer, { cursor: 0, anchor: null } satisfies BrushState);
  const [showTable, setShowTable] = useState(false);
  const [focused, setFocused] = useState(false);
  const dragging = useRef(false);
  const svgRef = useRef<SVGSVGElement>(null);
  const n = buckets.length;
  const max = maxCount(buckets) || 1;
  const bounds = selectionBounds(brush);
  const cursorBucket = buckets[Math.min(brush.cursor, n - 1)];

  const apply = (a: number, b: number) => {
    const r = rangeFromSelection(buckets, bucketNs, a, b);
    if (r) onRange(r);
    dispatch({ type: "clear" });
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (!n) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const [a, b] = bounds ?? [brush.cursor, brush.cursor];
      apply(a, b);
      return;
    }
    const action = keyToBrushAction(e.key, e.shiftKey, n, Math.max(1, Math.round(n / 10)));
    if (action) {
      e.preventDefault();
      e.stopPropagation();
      dispatch(action);
    }
  };

  const indexAt = (clientX: number): number => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect || rect.width === 0) return 0;
    return Math.min(n - 1, Math.max(0, Math.floor(((clientX - rect.left) / rect.width) * n)));
  };

  const onPointerDown = (e: PointerEvent<SVGSVGElement>) => {
    if (!n) return;
    dragging.current = true;
    e.currentTarget.setPointerCapture(e.pointerId);
    const i = indexAt(e.clientX);
    dispatch({ type: "set", index: i, extend: false, length: n });
    dispatch({ type: "set", index: i, extend: true, length: n });
  };
  const onPointerMove = (e: PointerEvent<SVGSVGElement>) => {
    if (dragging.current) dispatch({ type: "set", index: indexAt(e.clientX), extend: true, length: n });
  };
  const onPointerUp = () => {
    if (!dragging.current) return;
    dragging.current = false;
    const [a, b] = bounds ?? [brush.cursor, brush.cursor];
    apply(a, b);
  };

  const describe = () => {
    if (!cursorBucket) return "";
    const base = `${formatNsShort(cursorBucket.start_ns)}: ${cursorBucket.count.toLocaleString()} events`;
    if (!bounds) return base;
    const r = rangeFromSelection(buckets, bucketNs, bounds[0], bounds[1]);
    const count = totalCount(buckets.slice(bounds[0], bounds[1] + 1));
    return r
      ? `Selected ${formatNsShort(r.start_ns)} to ${formatNsShort(r.end_ns)}, ${count.toLocaleString()} events. Press Enter to filter.`
      : base;
  };

  if (!n) {
    return loading ? (
      <div className="bg-card grid gap-1 rounded-lg border p-2" aria-busy="true">
        <span className="sr-only" role="status">
          Loading histogram…
        </span>
        <div className="bg-muted h-[84px] animate-pulse rounded-md" />
      </div>
    ) : (
      <p className="text-muted-foreground bg-card rounded-lg border border-dashed px-3 py-4 text-center text-xs">
        No timed events match the current filters.
      </p>
    );
  }
  const stackRows = stack && stack.rows.length === n ? stack.rows : null;
  const hasOther = stackRows?.some((r) => r.other > 0) ?? false;

  const first = buckets[0];
  const last = buckets[n - 1];
  const barW = 100 / n;

  return (
    <div className="grid gap-1">
      <div
        tabIndex={0}
        role="group"
        aria-roledescription="histogram"
        aria-label={`Event histogram, ${n} buckets of ${formatDuration(bucketNs)}. Arrow keys move, Shift plus arrows select a range, Enter filters to it, Escape clears.`}
        aria-describedby="histogram-status"
        onKeyDown={onKeyDown}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        className="bg-card focus-visible:ring-ring relative rounded-lg border px-1.5 pt-1.5 pb-1 focus-visible:ring-2 focus-visible:outline-none"
        data-testid="histogram"
      >
        <span
          aria-hidden
          className="text-muted-foreground tabular pointer-events-none absolute top-1 left-2 text-[10px]"
        >
          {compactNumber(max)}
        </span>
        <svg
          ref={svgRef}
          viewBox={`0 0 100 ${HEIGHT}`}
          preserveAspectRatio="none"
          className="block h-[84px] w-full touch-none select-none"
          aria-hidden="true"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
        >
          {[0.25, 0.5, 0.75].map((f) => (
            <line
              key={f}
              x1={0}
              x2={100}
              y1={HEIGHT - f * (HEIGHT - 2)}
              y2={HEIGHT - f * (HEIGHT - 2)}
              stroke="var(--chart-grid)"
              strokeWidth={1}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {bounds ? (
            <rect
              x={bounds[0] * barW}
              width={(bounds[1] - bounds[0] + 1) * barW}
              y={0}
              height={HEIGHT}
              className="fill-chart-selected"
              opacity={0.16}
            />
          ) : null}
          {buckets.map((b, i) => {
            const h = b.count ? Math.max(1.5, (b.count / max) * (HEIGHT - 2)) : 0;
            const selected = bounds !== null && i >= bounds[0] && i <= bounds[1];
            const x = i * barW + barW * 0.1;
            const w = barW * 0.8;
            const row = stackRows?.[i];
            if (!row || !h) {
              return (
                <rect
                  key={b.start_ns}
                  x={x}
                  width={w}
                  y={HEIGHT - h}
                  height={h}
                  className={cn("motion-grow", selected ? "fill-chart-selected" : "fill-chart-bar")}
                />
              );
            }
            let y = HEIGHT;
            const segs = [
              ...row.layers.map((c, li) => ({ c, color: stack?.layers[li]?.color })),
              {
                c: row.other,
                color: "var(--cat-other)",
              },
            ];
            return (
              <g key={b.start_ns} className="motion-grow" opacity={bounds && !selected ? 0.55 : 1}>
                {segs.map((sg, si) => {
                  if (!sg.c) return null;
                  const sh = (sg.c / row.total) * h;
                  y -= sh;
                  return <rect key={si} x={x} width={w} y={y} height={sh} fill={sg.color} />;
                })}
              </g>
            );
          })}
          {focused ? (
            <rect
              x={brush.cursor * barW}
              width={barW}
              y={0}
              height={HEIGHT}
              className="stroke-foreground fill-none"
              strokeWidth={0.4}
              vectorEffect="non-scaling-stroke"
            />
          ) : null}
        </svg>
      </div>
      <div className="text-muted-foreground flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className="font-mono text-[11px]">{first ? formatNsShort(first.start_ns) : ""}</span>
        <span id="histogram-status" role="status" aria-live="polite" className="text-foreground">
          {focused || bounds
            ? describe()
            : `${totalCount(buckets).toLocaleString()} events, ${formatDuration(bucketNs)} per bar`}
        </span>
        <span className="font-mono text-[11px]">{last ? formatNsShort(last.start_ns + bucketNs) : ""}</span>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Button
          variant="link"
          size="sm"
          className="h-6 px-0"
          aria-expanded={showTable}
          onClick={() => setShowTable((v) => !v)}
        >
          {showTable ? "Hide histogram data table" : "Show histogram data table"}
        </Button>
        {stackRows && stack ? (
          <ul
            className="text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1 text-xs"
            aria-label="Histogram legend"
          >
            {stack.layers.map((l) => (
              <li key={l.key} className="flex items-center gap-1.5">
                <span aria-hidden className="size-2.5 rounded-sm" style={{ background: l.color }} />
                {l.label}
              </li>
            ))}
            {hasOther ? (
              <li className="flex items-center gap-1.5">
                <span
                  aria-hidden
                  className="size-2.5 rounded-sm"
                  style={{ background: "var(--cat-other)" }}
                />
                Other
              </li>
            ) : null}
          </ul>
        ) : null}
        {showTable ? (
          <div className="max-h-60 w-full overflow-auto rounded-md border">
            <table className="w-full text-xs">
              <caption className="sr-only">Events per time bucket</caption>
              <thead>
                <tr className="border-b">
                  <th scope="col" className="px-2 py-1 text-left">
                    Bucket start (UTC)
                  </th>
                  <th scope="col" className="px-2 py-1 text-right">
                    Events
                  </th>
                  {stackRows && stack
                    ? [...stack.layers.map((l) => l.label), ...(hasOther ? ["Other"] : [])].map((label) => (
                        <th key={label} scope="col" className="px-2 py-1 text-right font-normal">
                          {label}
                        </th>
                      ))
                    : null}
                  <th scope="col" className="px-2 py-1">
                    <span className="sr-only">Filter</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {buckets
                  .map((b, i) => ({ b, i }))
                  .filter(({ b }) => b.count > 0)
                  .map(({ b, i }) => (
                    <tr key={b.start_ns} className="border-b last:border-0">
                      <td className="px-2 py-0.5 font-mono">{formatNs(b.start_ns)}</td>
                      <td className="tabular px-2 py-0.5 text-right">{b.count.toLocaleString()}</td>
                      {stackRows
                        ? [
                            ...(stackRows[i]?.layers ?? []),
                            ...(hasOther ? [stackRows[i]?.other ?? 0] : []),
                          ].map((c, ci) => (
                            <td key={ci} className="tabular text-muted-foreground px-2 py-0.5 text-right">
                              {c.toLocaleString()}
                            </td>
                          ))
                        : null}
                      <td className="px-2 py-0.5 text-right">
                        <Button variant="ghost" size="sm" className="h-6" onClick={() => apply(i, i)}>
                          Filter to bucket
                        </Button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </div>
  );
}
