"use client";

import Link from "next/link";
import { SEVERITY_COLOR } from "@/components/common";
import { attackUrl, tacticMatrix, techniqueInfo } from "@/lib/attack";
import type { Finding, Severity } from "@/lib/types";
import { SEVERITIES } from "@/lib/types";
import { cn } from "@/lib/utils";

const CELL: Record<Severity, string> = {
  critical: "bg-sev-critical-soft border-sev-critical/40",
  high: "bg-sev-high-soft border-sev-high/40",
  medium: "bg-sev-medium-soft border-sev-medium/40",
  low: "bg-sev-low-soft border-sev-low/40",
  info: "bg-sev-info-soft border-sev-info/30",
};

/**
 * ATT&CK tactic heatmap: one column per Enterprise tactic in kill-chain order, one cell per
 * technique seen in live (non-rejected) findings, tinted by the worst severity among them.
 * Each technique cell links to the findings list filtered on it.
 */
export function AttackMatrix({ findings, caseId }: { findings: Finding[]; caseId: string }) {
  const { columns, unmapped } = tacticMatrix(findings);
  const active = columns.filter((c) => c.techniques.length > 0).length;
  const enc = encodeURIComponent(caseId);
  return (
    <div className="grid grid-cols-1 gap-3">
      <div className="text-muted-foreground flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        <span>
          <span className="text-foreground tabular font-medium">{active}</span> of {columns.length} tactics
          observed
        </span>
        <span className="flex flex-wrap items-center gap-2" aria-label="Severity legend">
          {SEVERITIES.map((s) => (
            <span key={s} className="flex items-center gap-1">
              <span aria-hidden className={cn("size-2.5 rounded-sm border", CELL[s])} />
              {s}
            </span>
          ))}
        </span>
      </div>
      <div className="relative -mx-1 overflow-x-auto px-1 pb-1">
        <ol className="grid min-w-[72rem] grid-cols-14 gap-1.5" aria-label="ATT&CK tactics">
          {columns.map((c) => {
            const has = c.techniques.length > 0;
            return (
              <li key={c.tactic.key} className="grid content-start gap-1.5">
                <div
                  className={cn(
                    "rounded-md border px-1.5 py-1.5",
                    has ? "bg-accent border-transparent" : "bg-muted/40 border-dashed",
                  )}
                  title={`${c.tactic.name} (${c.tactic.id})`}
                >
                  <p
                    className={cn(
                      "truncate text-[11px] leading-tight font-semibold",
                      !has && "text-muted-foreground font-medium",
                    )}
                  >
                    {c.tactic.short}
                  </p>
                  <p className="text-muted-foreground tabular text-[10px] leading-tight">
                    {has
                      ? `${c.techniques.length} tech · ${c.findings} finding${c.findings === 1 ? "" : "s"}`
                      : "none"}
                  </p>
                </div>
                {has ? (
                  <ul className="grid gap-1" aria-label={`${c.tactic.name} techniques`}>
                    {c.techniques.map((t) => (
                      <li key={t.id}>
                        <Link
                          href={`/cases/${enc}/findings?technique=${encodeURIComponent(t.id)}`}
                          className={cn(
                            "focus-visible:ring-ring block rounded-md border px-1.5 py-1 transition-[filter] hover:brightness-95 focus-visible:ring-2 focus-visible:outline-none dark:hover:brightness-125",
                            CELL[t.severity],
                          )}
                          title={`${techniqueInfo(t.id).name}: ${t.findings} finding${t.findings === 1 ? "" : "s"}, worst severity ${t.severity}`}
                        >
                          <span className="flex items-center gap-1">
                            <span
                              aria-hidden
                              className="size-1.5 shrink-0 rounded-full"
                              style={{ background: SEVERITY_COLOR[t.severity] }}
                            />
                            <span className="font-mono text-[10px] font-semibold">{t.id}</span>
                            {t.findings > 1 ? (
                              <span className="tabular ml-auto text-[10px] font-medium">×{t.findings}</span>
                            ) : null}
                          </span>
                          <span className="line-clamp-2 text-[10.5px] leading-snug">{t.name}</span>
                          <span className="sr-only">
                            , {t.findings} finding{t.findings === 1 ? "" : "s"}, worst severity {t.severity}
                          </span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </li>
            );
          })}
        </ol>
      </div>
      {unmapped.length ? (
        <p className="text-muted-foreground text-xs">
          Not in the local ATT&amp;CK table:{" "}
          {unmapped.map((t, i) => (
            <span key={t.id}>
              {i ? ", " : ""}
              <a
                href={attackUrl(t.id)}
                target="_blank"
                rel="noreferrer noopener"
                className="font-mono underline"
              >
                {t.id}
              </a>
            </span>
          ))}
        </p>
      ) : null}
    </div>
  );
}
