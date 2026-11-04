"use client";

import { useVirtualizer } from "@tanstack/react-virtual";
import { BookmarkIcon } from "lucide-react";
import { useEffect, useRef } from "react";
import { formatNs } from "@/lib/format";
import type { TimelineEvent } from "@/lib/types";
import { cn } from "@/lib/utils";

export const ROW_HEIGHT = 30;
const COLS = "grid-cols-[13.5rem_9rem_13rem_8rem_8rem_minmax(20rem,1fr)]";

export interface ResultsTableProps {
  total: number;
  rowAt: (index: number) => TimelineEvent | undefined;
  onRangeChange: (first: number, last: number) => void;
  selected: number | null;
  onSelect: (index: number) => void;
  onOpen: (index: number) => void;
  onPivot: (column: string, value: string) => void;
  bookmarked: Set<number>;
}

function PivotCell({
  column,
  value,
  onPivot,
}: {
  column: string;
  value: string | undefined;
  onPivot: ResultsTableProps["onPivot"];
}) {
  if (!value) return <span role="gridcell" className="text-muted-foreground truncate" />;
  return (
    <span role="gridcell" className="min-w-0">
      <button
        type="button"
        tabIndex={-1}
        className="max-w-full truncate rounded-sm text-left hover:underline"
        title={`Filter on ${column} = ${value}`}
        onClick={(e) => {
          e.stopPropagation();
          onPivot(column, value);
        }}
      >
        {value}
      </button>
    </span>
  );
}

/** Virtualized, paged results grid. Only rows near the viewport are rendered or fetched. */
export function ResultsTable({
  total,
  rowAt,
  onRangeChange,
  selected,
  onSelect,
  onOpen,
  onPivot,
  bookmarked,
}: ResultsTableProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: total,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });
  const items = virtualizer.getVirtualItems();
  const first = items[0]?.index ?? 0;
  const last = items[items.length - 1]?.index ?? 0;

  useEffect(() => {
    onRangeChange(first, last);
  }, [first, last, onRangeChange]);

  useEffect(() => {
    if (selected === null) return;
    virtualizer.scrollToIndex(selected, { align: "auto" });
    const el = scrollRef.current?.querySelector<HTMLElement>(`[data-index="${selected}"]`);
    if (el && document.activeElement !== el && scrollRef.current?.contains(document.activeElement))
      el.focus();
  }, [selected, virtualizer]);

  return (
    <div
      ref={scrollRef}
      className="bg-card h-[min(65vh,720px)] overflow-auto rounded-md border text-sm"
      data-testid="results"
    >
      <div
        role="grid"
        aria-label="Timeline events"
        aria-rowcount={total + 1}
        aria-colcount={6}
        aria-multiselectable={false}
        className="min-w-[72rem]"
      >
        <div role="rowgroup" className="bg-muted text-muted-foreground sticky top-0 z-10 border-b text-xs">
          <div role="row" aria-rowindex={1} className={cn("grid gap-2 px-2 py-1.5", COLS)}>
            <span role="columnheader">Time (UTC)</span>
            <span role="columnheader">Description</span>
            <span role="columnheader">Data type</span>
            <span role="columnheader">Host</span>
            <span role="columnheader">User</span>
            <span role="columnheader">Message</span>
          </div>
        </div>
        <div role="rowgroup" style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {items.map((item) => {
            const e = rowAt(item.index);
            const isSel = selected === item.index;
            return (
              <div
                key={item.key}
                role="row"
                data-index={item.index}
                aria-rowindex={item.index + 2}
                aria-selected={isSel}
                tabIndex={isSel || (selected === null && item.index === first) ? 0 : -1}
                onClick={() => onSelect(item.index)}
                onDoubleClick={() => onOpen(item.index)}
                onKeyDown={(k) => {
                  if (k.key === "Enter") {
                    k.preventDefault();
                    onOpen(item.index);
                  }
                }}
                onFocus={() => {
                  if (!isSel) onSelect(item.index);
                }}
                className={cn(
                  "focus-visible:ring-ring absolute left-0 grid w-full cursor-default items-center gap-2 border-b px-2 outline-none focus-visible:ring-2 focus-visible:ring-inset",
                  COLS,
                  isSel ? "bg-accent text-accent-foreground" : "hover:bg-muted/60",
                )}
                style={{ top: item.start, height: ROW_HEIGHT }}
              >
                {e ? (
                  <>
                    <span
                      role="gridcell"
                      className="flex items-center gap-1 font-mono text-xs whitespace-nowrap"
                    >
                      {bookmarked.has(e.id) ? (
                        <BookmarkIcon
                          className="text-primary size-3.5 shrink-0"
                          aria-label="Bookmarked"
                          role="img"
                        />
                      ) : (
                        <span className="w-3.5" />
                      )}
                      {formatNs(e.timestamp)}
                    </span>
                    <span role="gridcell" className="truncate text-xs" title={e.timestamp_desc}>
                      {e.timestamp_desc}
                    </span>
                    <PivotCell column="data_type" value={e.data_type} onPivot={onPivot} />
                    <PivotCell column="host" value={e.host} onPivot={onPivot} />
                    <PivotCell column="user" value={e.user} onPivot={onPivot} />
                    <span role="gridcell" className="truncate" title={e.message}>
                      {e.message}
                    </span>
                  </>
                ) : (
                  <span role="gridcell" className="text-muted-foreground col-span-6 text-xs">
                    Loading row {item.index + 1}…
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
