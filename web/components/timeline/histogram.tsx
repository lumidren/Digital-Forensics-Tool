"use client";

import { useReducer, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { Button } from "@/components/ui/button";
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

const HEIGHT = 72;

export interface HistogramProps {
  buckets: HistogramBucket[];
  bucketNs: number;
  onRange: (range: { start_ns: number; end_ns: number }) => void;
  loading?: boolean;
}

/**
 * Event-count histogram with mouse and keyboard brushing. Focus the chart, move with the arrow
 * keys, hold Shift to extend a selection, press Enter to filter to it and Escape to clear.
 */
export function Histogram({ buckets, bucketNs, onRange, loading }: HistogramProps) {
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
    return (
      <p className="text-muted-foreground text-xs">
        {loading ? "Loading histogram…" : "No timed events match the current filters."}
      </p>
    );
  }

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
        className="bg-card focus-visible:ring-ring rounded-md border p-1 focus-visible:ring-2 focus-visible:outline-none"
        data-testid="histogram"
      >
        <svg
          ref={svgRef}
          viewBox={`0 0 100 ${HEIGHT}`}
          preserveAspectRatio="none"
          className="block h-[72px] w-full touch-none select-none"
          aria-hidden="true"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
        >
          {buckets.map((b, i) => {
            const h = b.count ? Math.max(1.5, (b.count / max) * (HEIGHT - 2)) : 0;
            const selected = bounds !== null && i >= bounds[0] && i <= bounds[1];
            return (
              <rect
                key={b.start_ns}
                x={i * barW + barW * 0.08}
                width={barW * 0.84}
                y={HEIGHT - h}
                height={h}
                className={cn(selected ? "fill-chart-selected" : "fill-chart-bar")}
              />
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
        <span>{first ? formatNsShort(first.start_ns) : ""}</span>
        <span id="histogram-status" role="status" aria-live="polite" className="text-foreground">
          {focused || bounds
            ? describe()
            : `${totalCount(buckets).toLocaleString()} events, ${formatDuration(bucketNs)} per bar`}
        </span>
        <span>{last ? formatNsShort(last.start_ns + bucketNs) : ""}</span>
      </div>
      <div>
        <Button
          variant="link"
          size="sm"
          className="h-6 px-0"
          aria-expanded={showTable}
          onClick={() => setShowTable((v) => !v)}
        >
          {showTable ? "Hide histogram data table" : "Show histogram data table"}
        </Button>
        {showTable ? (
          <div className="max-h-60 overflow-auto rounded-md border">
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
