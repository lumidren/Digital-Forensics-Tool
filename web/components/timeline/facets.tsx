"use client";

import { useQueries } from "@tanstack/react-query";
import { api } from "@/lib/api-instance";
import { barPercent } from "@/lib/charts";
import { dataTypeCategory } from "@/lib/data-types";
import { LIST_FIELDS, type TimelineFilters } from "@/lib/filters";
import { shortHash } from "@/lib/format";
import type { Evidence, SearchBody } from "@/lib/types";
import { cn } from "@/lib/utils";

export function FacetSidebar({
  caseId,
  body,
  filters,
  evidence,
  onToggle,
}: {
  caseId: string;
  body: SearchBody;
  filters: TimelineFilters;
  evidence: Evidence[];
  onToggle: (column: string, value: string) => void;
}) {
  const results = useQueries({
    queries: LIST_FIELDS.map((f) => ({
      queryKey: ["facets", caseId, f.column, body],
      queryFn: () => api.facets(caseId, f.column, body),
      staleTime: 15_000,
    })),
  });
  const evName = new Map(evidence.map((e) => [e.sha256, `${e.id} ${e.name}`]));

  return (
    <nav aria-label="Facets" className="grid gap-4 text-sm">
      {LIST_FIELDS.map((f, i) => {
        const values = (results[i]?.data ?? []).filter((v) => v.value !== "");
        const top = Math.max(0, ...values.map((v) => v.count));
        return (
          <section key={f.field} aria-labelledby={`facet-${f.field}`}>
            <h2 id={`facet-${f.field}`} className="eyebrow text-muted-foreground mb-1.5">
              {f.label}
            </h2>
            {results[i]?.isLoading ? (
              <div className="grid gap-1.5" aria-busy="true">
                <span className="sr-only">Loading…</span>
                {[0, 1, 2].map((k) => (
                  <span key={k} aria-hidden className="bg-muted h-5 animate-pulse rounded-sm" />
                ))}
              </div>
            ) : values.length === 0 ? (
              <p className="text-muted-foreground text-xs">No values</p>
            ) : (
              <ul className="grid gap-0.5">
                {values.slice(0, 12).map((v) => {
                  const active = filters[f.field].includes(v.value);
                  const label =
                    f.column === "evidence_sha256" ? (evName.get(v.value) ?? shortHash(v.value)) : v.value;
                  return (
                    <li key={v.value}>
                      <button
                        type="button"
                        aria-pressed={active}
                        onClick={() => onToggle(f.column, v.value)}
                        className={cn(
                          "hover:bg-accent focus-visible:ring-ring relative flex min-h-7 w-full items-center gap-2 overflow-hidden rounded-md px-1.5 text-left focus-visible:ring-2 focus-visible:outline-none",
                          active && "bg-accent ring-primary/40 font-medium ring-1",
                        )}
                        title={v.value}
                      >
                        <span
                          aria-hidden
                          className="bg-primary/[0.07] absolute inset-y-0 left-0"
                          style={{ width: `${barPercent(v.count, top)}%` }}
                        />
                        {f.column === "data_type" ? (
                          <span
                            aria-hidden
                            className="relative size-2 shrink-0 rounded-full"
                            style={{ background: dataTypeCategory(v.value).color }}
                          />
                        ) : null}
                        <span className="relative min-w-0 flex-1 truncate">{label}</span>
                        <span className="text-muted-foreground tabular relative text-xs">
                          {v.count.toLocaleString()}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>
        );
      })}
    </nav>
  );
}
