"use client";

/**
 * Small, dependency-free SVG charts. Every chart exposes an accessible name and its data as a
 * visually hidden table (or a visible legend), so nothing is conveyed by colour or shape alone.
 */
import Link from "next/link";
import { useId, useState, type PointerEvent, type ReactNode } from "react";
import {
  areaPath,
  axisTicks,
  barPercent,
  compactNumber,
  donutArcs,
  linePath,
  niceMax,
  toPoints,
} from "@/lib/charts";
import { cn } from "@/lib/utils";

/** Decorative trend line; the surrounding text carries the value. */
export function Sparkline({
  values,
  color = "var(--chart-area)",
  height = 32,
  className,
}: {
  values: number[];
  color?: string;
  height?: number;
  className?: string;
}) {
  const gid = useId().replace(/:/g, "");
  if (values.length < 2) return null;
  const W = 100;
  const pts = toPoints(values, W, height - 2).map((p) => ({ x: p.x, y: p.y + 1 }));
  return (
    <svg
      viewBox={`0 0 ${W} ${height}`}
      preserveAspectRatio="none"
      className={cn("block w-full overflow-visible", className)}
      style={{ height }}
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id={`sg-${gid}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.28" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={areaPath(pts, height)} fill={`url(#sg-${gid})`} />
      <path
        d={linePath(pts)}
        fill="none"
        stroke={color}
        strokeWidth={1.75}
        vectorEffect="non-scaling-stroke"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export interface SeriesPoint {
  label: string;
  value: number;
}

/**
 * Area chart over time with a hover crosshair and tooltip. `points` are ordered in time; the
 * hidden table lists every non-empty point.
 */
export function AreaChart({
  points,
  label,
  valueLabel = "Events",
  height = 180,
  footer,
}: {
  points: SeriesPoint[];
  label: string;
  valueLabel?: string;
  height?: number;
  footer?: ReactNode;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const gid = useId().replace(/:/g, "");
  const W = 600;
  const H = height;
  const PAD_T = 6;
  const plotH = H - PAD_T - 1;
  const values = points.map((p) => p.value);
  const top = niceMax(Math.max(0, ...values));
  const ticks = axisTicks(top, 4);
  const pts = toPoints(values, W, plotH, top).map((p) => ({ x: p.x, y: p.y + PAD_T }));
  const total = values.reduce((s, v) => s + v, 0);
  const peak = points.reduce<SeriesPoint | null>((m, p) => (!m || p.value > m.value ? p : m), null);
  const onMove = (e: PointerEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    if (!r.width || points.length === 0) return;
    const i = Math.round(((e.clientX - r.left) / r.width) * (points.length - 1));
    setHover(Math.min(points.length - 1, Math.max(0, i)));
  };
  const hp = hover !== null ? pts[hover] : undefined;
  const hv = hover !== null ? points[hover] : undefined;
  const yPct = (v: number) => ((PAD_T + plotH - (top ? (v / top) * plotH : 0)) / H) * 100;
  const summary = `${label}. ${total.toLocaleString()} ${valueLabel.toLowerCase()} in total${
    peak && peak.value > 0 ? `; peak ${peak.value.toLocaleString()} at ${peak.label}` : ""
  }. A data table follows.`;

  return (
    <figure className="m-0">
      <div className="grid grid-cols-[2.25rem_minmax(0,1fr)]">
        <div aria-hidden className="relative" style={{ height: H }}>
          {ticks.map((t) => (
            <span
              key={t}
              className="text-muted-foreground tabular absolute right-2 -translate-y-1/2 text-[10px] leading-none"
              style={{ top: `${yPct(t)}%` }}
            >
              {compactNumber(t)}
            </span>
          ))}
        </div>
        <div className="relative touch-none" onPointerMove={onMove} onPointerLeave={() => setHover(null)}>
          <svg
            viewBox={`0 0 ${W} ${H}`}
            preserveAspectRatio="none"
            className="block w-full"
            style={{ height: H }}
            role="img"
            aria-label={summary}
          >
            <defs>
              <linearGradient id={`ag-${gid}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stopColor="var(--chart-area)" stopOpacity="0.32" />
                <stop offset="1" stopColor="var(--chart-area)" stopOpacity="0.02" />
              </linearGradient>
            </defs>
            {ticks.map((t) => {
              const y = (yPct(t) / 100) * H;
              return (
                <line
                  key={t}
                  x1={0}
                  x2={W}
                  y1={y}
                  y2={y}
                  stroke="var(--chart-grid)"
                  strokeWidth={1}
                  vectorEffect="non-scaling-stroke"
                />
              );
            })}
            <path d={areaPath(pts, PAD_T + plotH)} fill={`url(#ag-${gid})`} />
            <path
              d={linePath(pts)}
              fill="none"
              stroke="var(--chart-area)"
              strokeWidth={2}
              strokeLinejoin="round"
              vectorEffect="non-scaling-stroke"
            />
            {hp ? (
              <line
                x1={hp.x}
                x2={hp.x}
                y1={PAD_T}
                y2={PAD_T + plotH}
                stroke="var(--muted-foreground)"
                strokeDasharray="3 3"
                vectorEffect="non-scaling-stroke"
              />
            ) : null}
          </svg>
          {hp && hv ? (
            <>
              <span
                aria-hidden
                className="border-card pointer-events-none absolute size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-2"
                style={{
                  left: `${(hp.x / W) * 100}%`,
                  top: `${(hp.y / H) * 100}%`,
                  background: "var(--chart-area)",
                }}
              />
              <div
                aria-hidden
                className="bg-popover text-popover-foreground pointer-events-none absolute top-0 z-10 rounded-md border px-2 py-1 text-xs whitespace-nowrap shadow-md"
                style={{
                  left: `${(hp.x / W) * 100}%`,
                  transform: hp.x / W > 0.65 ? "translateX(calc(-100% - 10px))" : "translateX(10px)",
                }}
              >
                <span className="text-muted-foreground block">{hv.label}</span>
                <span className="tabular font-semibold">{hv.value.toLocaleString()}</span>{" "}
                {valueLabel.toLowerCase()}
              </div>
            </>
          ) : null}
        </div>
      </div>
      {footer ? (
        <figcaption className="text-muted-foreground mt-1.5 pl-9 text-xs">{footer}</figcaption>
      ) : null}
      <div className="sr-only">
        <table>
          <caption>{label}</caption>
          <thead>
            <tr>
              <th scope="col">Period</th>
              <th scope="col">{valueLabel}</th>
            </tr>
          </thead>
          <tbody>
            {points
              .filter((p) => p.value > 0)
              .map((p) => (
                <tr key={p.label}>
                  <td>{p.label}</td>
                  <td>{p.value}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </figure>
  );
}

export interface DonutSlice {
  key: string;
  label: string;
  value: number;
  color: string;
}

/** Ring chart with the total in the centre and a visible legend that doubles as the data list. */
export function Donut({
  slices,
  label,
  centerLabel = "total",
  size = 132,
  legendExtra,
}: {
  slices: DonutSlice[];
  label: string;
  centerLabel?: string;
  size?: number;
  legendExtra?: (s: DonutSlice) => ReactNode;
}) {
  const [hover, setHover] = useState<string | null>(null);
  const total = slices.reduce((s, x) => s + x.value, 0);
  const R = 50;
  const arcs = donutArcs(
    slices.map((s) => ({ key: s.key, value: s.value })),
    { cx: R, cy: R, outer: R, inner: R * 0.68, gap: 0.04 },
  );
  const byKey = new Map(slices.map((s) => [s.key, s]));
  const hovered = hover ? byKey.get(hover) : undefined;
  const summary = `${label}: ${slices.map((s) => `${s.value} ${s.label}`).join(", ")}; ${total} ${centerLabel}.`;
  return (
    <div className="flex flex-wrap items-center gap-5">
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg viewBox={`0 0 ${R * 2} ${R * 2}`} className="size-full" role="img" aria-label={summary}>
          {total === 0 ? (
            <circle
              cx={R}
              cy={R}
              r={R * 0.84}
              fill="none"
              stroke="var(--chart-grid)"
              strokeWidth={R * 0.32}
            />
          ) : null}
          {arcs.map((a) => (
            <path
              key={a.key}
              d={a.path}
              fill={byKey.get(a.key)?.color}
              className="transition-opacity duration-150"
              opacity={hover && hover !== a.key ? 0.35 : 1}
              onPointerEnter={() => setHover(a.key)}
              onPointerLeave={() => setHover(null)}
            />
          ))}
        </svg>
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 grid place-content-center text-center"
        >
          <span className="tabular text-2xl leading-none font-semibold">
            {hovered ? hovered.value : total}
          </span>
          <span className="text-muted-foreground mt-1 text-[11px]">
            {hovered ? hovered.label : centerLabel}
          </span>
        </div>
      </div>
      <ul className="grid min-w-36 flex-1 gap-1 text-sm" aria-label={`${label} legend`}>
        {slices.map((s) => (
          <li
            key={s.key}
            className={cn(
              "flex items-center gap-2 rounded-md px-1.5 py-0.5 transition-colors",
              hover === s.key && "bg-muted",
            )}
            onPointerEnter={() => setHover(s.key)}
            onPointerLeave={() => setHover(null)}
          >
            <span aria-hidden className="size-2.5 shrink-0 rounded-sm" style={{ background: s.color }} />
            <span className="min-w-0 flex-1 truncate">{legendExtra ? legendExtra(s) : s.label}</span>
            <span className="tabular text-muted-foreground text-xs">
              {total ? `${Math.round((s.value / total) * 100)}%` : "0%"}
            </span>
            <span className="tabular w-8 text-right font-medium">{s.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface BarItem {
  label: string;
  value: number;
  href?: string;
  color?: string;
  muted?: boolean;
}

/** Horizontal bar list (top-N); each row is plain text plus a decorative proportional bar. */
export function BarList({ items, label, empty }: { items: BarItem[]; label: string; empty?: ReactNode }) {
  const max = Math.max(0, ...items.map((i) => i.value));
  if (!items.length) return <>{empty}</>;
  return (
    <ul className="grid gap-1" aria-label={label}>
      {items.map((it, idx) => {
        const pct = barPercent(it.value, max);
        const content = (
          <>
            <span
              aria-hidden
              className="motion-grow-x absolute inset-y-0.5 left-0 rounded-[5px]"
              style={{
                width: `${pct}%`,
                background: it.color ?? "var(--chart-area)",
                opacity: it.muted ? 0.12 : 0.16,
                animationDelay: `${idx * 40}ms`,
              }}
            />
            <span
              aria-hidden
              className="absolute inset-y-1.5 left-0 w-[3px] rounded-full"
              style={{ background: it.muted ? "var(--cat-other)" : (it.color ?? "var(--chart-area)") }}
            />
            <span
              className={cn("relative min-w-0 flex-1 truncate pl-2.5", it.muted && "text-muted-foreground")}
            >
              {it.label}
            </span>
            <span className="tabular relative text-xs font-medium">{it.value.toLocaleString()}</span>
          </>
        );
        return (
          <li key={it.label}>
            {it.href ? (
              <Link
                href={it.href}
                className="hover:bg-muted/70 focus-visible:ring-ring relative flex h-7 items-center gap-2 rounded-md pr-2 text-sm focus-visible:ring-2 focus-visible:outline-none"
                title={`Show ${it.label} in the timeline`}
              >
                {content}
              </Link>
            ) : (
              <div className="relative flex h-7 items-center gap-2 pr-2 text-sm">{content}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
