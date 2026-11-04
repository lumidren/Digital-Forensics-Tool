"use client";

import { Link2Icon, Link2OffIcon, MoreVerticalIcon } from "lucide-react";
import { CustodyKindIcon } from "@/components/custody-kind";
import { abbreviateHash, linkState } from "@/lib/custody";
import { formatDate } from "@/lib/format";
import type { CustodyEntry } from "@/lib/types";
import { cn } from "@/lib/utils";

/**
 * Vertical ledger chain: one node per entry with its kind icon, and a connector that shows whether
 * the entry's prev_hash matches the previous entry's hash. A filtered view shows gaps instead.
 */
export function CustodyChain({ entries }: { entries: CustodyEntry[] }) {
  return (
    <ol className="grid" aria-label="Ledger chain">
      {entries.map((e, i) => {
        const state = linkState(entries[i - 1], e);
        return (
          <li key={e.entry_hash} className="relative grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-3">
            {i > 0 ? (
              <div className="col-span-2 grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-3">
                <div className="flex h-7 flex-col items-center">
                  <span
                    aria-hidden
                    className={cn(
                      "w-px flex-1",
                      state === "linked" && "bg-success/60",
                      state === "broken" && "bg-destructive",
                      state === "gap" && "border-muted-foreground/50 border-l border-dashed",
                    )}
                  />
                </div>
                <p
                  className={cn(
                    "flex items-center gap-1 self-center text-[11px]",
                    state === "broken" ? "text-destructive font-medium" : "text-muted-foreground",
                  )}
                >
                  {state === "linked" ? (
                    <>
                      <Link2Icon aria-hidden className="text-success size-3" />
                      prev_hash matches #{entries[i - 1]?.seq}
                    </>
                  ) : state === "broken" ? (
                    <>
                      <Link2OffIcon aria-hidden className="size-3" />
                      prev_hash does not match #{entries[i - 1]?.seq}
                    </>
                  ) : (
                    <>
                      <MoreVerticalIcon aria-hidden className="size-3" />
                      {e.seq - (entries[i - 1]?.seq ?? 0) - 1} entries not shown
                    </>
                  )}
                </p>
              </div>
            ) : null}
            <CustodyKindIcon kind={e.kind} className="ring-card mt-0.5 ring-4" />
            <div className="min-w-0 pb-1">
              <p className="flex min-w-0 flex-wrap items-baseline gap-x-2">
                <span className="text-muted-foreground font-mono text-xs">#{e.seq}</span>
                <span className="text-sm font-medium">{e.kind}</span>
                <span className="text-muted-foreground min-w-0 truncate text-sm">{e.purpose}</span>
              </p>
              <p className="text-muted-foreground flex flex-wrap gap-x-3 text-xs">
                <span>{e.actor}</span>
                <span>{formatDate(typeof e.timestamp === "string" ? e.timestamp : null)}</span>
                {e.evidence_id ? <span className="font-mono">{e.evidence_id}</span> : null}
                <span className="font-mono" title={e.entry_hash}>
                  hash {abbreviateHash(e.entry_hash)}
                </span>
              </p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
