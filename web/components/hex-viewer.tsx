"use client";

import { useQueries } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ChevronFirstIcon, ChevronLastIcon, ChevronDownIcon, ChevronUpIcon, InfoIcon } from "lucide-react";
import { useMemo, useRef, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert } from "@/components/ui/misc";
import { api } from "@/lib/api-instance";
import { formatBytes } from "@/lib/format";
import {
  alignOffset,
  BYTES_PER_ROW,
  byteToHex,
  chunkForRow,
  formatOffset,
  formatRow,
  hexToBytes,
  offsetWidth,
  parseOffset,
  rowCount,
  rowForOffset,
} from "@/lib/hex";
import { cn } from "@/lib/utils";

export const CHUNK_BYTES = 64 * 1024;
const ROWS_PER_CHUNK = CHUNK_BYTES / BYTES_PER_ROW;
const ROW_HEIGHT = 22;

export function HexViewer({
  caseId,
  evidenceId,
  size,
}: {
  caseId: string;
  evidenceId: string;
  size: number;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [cursor, setCursor] = useState<number | null>(null);
  const [goto, setGoto] = useState("");
  const [gotoError, setGotoError] = useState<string | null>(null);
  const rows = rowCount(size);
  const width = offsetWidth(size);

  const virtualizer = useVirtualizer({
    count: rows,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 16,
  });
  const items = virtualizer.getVirtualItems();
  const firstRow = items[0]?.index ?? 0;
  const lastRow = items[items.length - 1]?.index ?? 0;

  const chunks = useMemo(() => {
    if (!rows) return [];
    const out: number[] = [];
    for (let c = chunkForRow(firstRow, ROWS_PER_CHUNK); c <= chunkForRow(lastRow, ROWS_PER_CHUNK); c += 1)
      out.push(c);
    return out;
  }, [firstRow, lastRow, rows]);

  const results = useQueries({
    queries: chunks.map((c) => ({
      queryKey: ["bytes", caseId, evidenceId, c],
      queryFn: async () => {
        const offset = c * CHUNK_BYTES;
        const res = await api.evidenceBytes(caseId, evidenceId, offset, Math.min(CHUNK_BYTES, size - offset));
        return hexToBytes(res.hex);
      },
      staleTime: Number.POSITIVE_INFINITY,
      gcTime: 60_000,
    })),
  });
  const loaded = new Map<number, Uint8Array>();
  chunks.forEach((c, i) => {
    const d = results[i]?.data;
    if (d) loaded.set(c, d);
  });
  const failed = results.find((r) => r.error)?.error;

  const jump = (offset: number) => {
    const aligned = alignOffset(offset, size);
    setCursor(Math.min(Math.max(0, offset), Math.max(0, size - 1)));
    virtualizer.scrollToIndex(rowForOffset(aligned), { align: "start" });
  };

  const onGoto = (e: FormEvent) => {
    e.preventDefault();
    const off = parseOffset(goto);
    if (off === null || off >= size) {
      setGotoError(`Enter an offset between 0 and ${size - 1} (decimal, or hex as 0x…).`);
      return;
    }
    setGotoError(null);
    jump(off);
  };

  const pageRows = Math.max(1, items.length - 4);
  const cursorRowBytes =
    cursor !== null ? loaded.get(chunkForRow(rowForOffset(cursor), ROWS_PER_CHUNK)) : undefined;
  const cursorByte =
    cursor !== null && cursorRowBytes
      ? cursorRowBytes[cursor - chunkForRow(rowForOffset(cursor), ROWS_PER_CHUNK) * CHUNK_BYTES]
      : undefined;

  if (size === 0) return <p className="text-muted-foreground text-sm">This evidence object is empty.</p>;

  return (
    <div className="grid gap-3">
      <Alert className="flex items-start gap-2">
        <InfoIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>
          Each view of evidence bytes is recorded as a signed <strong>access</strong> entry in the custody
          ledger (offset and length are logged). Bytes are fetched in {formatBytes(CHUNK_BYTES)} blocks as you
          scroll.
        </span>
      </Alert>
      <div className="flex flex-wrap items-end gap-2">
        <form onSubmit={onGoto} className="flex items-end gap-2">
          <div className="grid gap-1">
            <Label htmlFor="hex-goto">Go to offset</Label>
            <Input
              id="hex-goto"
              value={goto}
              onChange={(e) => setGoto(e.target.value)}
              placeholder="0x200 or 512"
              className="w-40 font-mono"
              data-search
              aria-invalid={gotoError ? true : undefined}
              aria-describedby={gotoError ? "hex-goto-error" : undefined}
            />
          </div>
          <Button type="submit" variant="secondary">
            Go
          </Button>
        </form>
        <div className="flex gap-1" role="group" aria-label="Offset navigation">
          <Button variant="outline" size="icon" aria-label="Start of object" onClick={() => jump(0)}>
            <ChevronFirstIcon aria-hidden />
          </Button>
          <Button
            variant="outline"
            size="icon"
            aria-label="Previous page"
            onClick={() => jump(Math.max(0, (firstRow - pageRows) * BYTES_PER_ROW))}
          >
            <ChevronUpIcon aria-hidden />
          </Button>
          <Button
            variant="outline"
            size="icon"
            aria-label="Next page"
            onClick={() => jump(Math.min(size - 1, (firstRow + pageRows) * BYTES_PER_ROW))}
          >
            <ChevronDownIcon aria-hidden />
          </Button>
          <Button variant="outline" size="icon" aria-label="End of object" onClick={() => jump(size - 1)}>
            <ChevronLastIcon aria-hidden />
          </Button>
        </div>
        <p
          className="text-muted-foreground text-xs"
          role="status"
          aria-live="polite"
          data-testid="hex-position"
        >
          Rows {formatOffset(firstRow * BYTES_PER_ROW, width)}–
          {formatOffset(Math.min(size, (lastRow + 1) * BYTES_PER_ROW) - 1, width)} of {formatBytes(size)}
          {cursor !== null ? (
            <>
              {" "}
              · cursor 0x{formatOffset(cursor, width)} ({cursor})
              {cursorByte !== undefined ? ` = 0x${byteToHex(cursorByte)}` : ""}
            </>
          ) : null}
        </p>
      </div>
      {gotoError ? (
        <p id="hex-goto-error" className="text-destructive text-xs" role="alert">
          {gotoError}
        </p>
      ) : null}
      {failed ? (
        <Alert variant="destructive" role="alert">
          {failed instanceof Error ? failed.message : "Failed to read bytes"}
        </Alert>
      ) : null}
      <div
        ref={scrollRef}
        tabIndex={0}
        role="region"
        aria-label="Hex view. Use arrow keys and Page Up/Down to scroll."
        className="bg-card h-[min(60vh,560px)] overflow-auto rounded-md border font-mono text-xs"
      >
        <div role="table" aria-label="Evidence bytes" aria-rowcount={rows + 1} className="min-w-max">
          <div
            role="row"
            aria-rowindex={1}
            className="bg-muted text-muted-foreground sticky top-0 z-10 flex gap-4 border-b px-3 py-1"
          >
            <span role="columnheader" style={{ width: `${width}ch` }}>
              Offset
            </span>
            <span role="columnheader" className="w-[47ch]">
              {Array.from({ length: BYTES_PER_ROW }, (_, i) => byteToHex(i).toUpperCase()).join(" ")}
            </span>
            <span role="columnheader">ASCII</span>
          </div>
          <div role="rowgroup" style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {items.map((item) => {
              const offset = item.index * BYTES_PER_ROW;
              const chunk = chunkForRow(item.index, ROWS_PER_CHUNK);
              const data = loaded.get(chunk);
              const start = offset - chunk * CHUNK_BYTES;
              const bytes = data?.subarray(start, start + BYTES_PER_ROW);
              const row = bytes ? formatRow(bytes, offset, width) : null;
              const cursorCol =
                cursor !== null && cursor >= offset && cursor < offset + BYTES_PER_ROW ? cursor - offset : -1;
              return (
                <div
                  key={item.key}
                  role="row"
                  aria-rowindex={item.index + 2}
                  className={cn(
                    "absolute left-0 flex w-full gap-4 px-3 leading-[22px]",
                    cursorCol >= 0 && "bg-accent",
                  )}
                  style={{ top: item.start, height: ROW_HEIGHT }}
                >
                  <span role="cell" className="text-muted-foreground" style={{ width: `${width}ch` }}>
                    {formatOffset(offset, width)}
                  </span>
                  <span role="cell" className="w-[47ch] whitespace-pre">
                    {row
                      ? row.hex.map((h, i) => (
                          <span
                            key={i}
                            className={cn(i === cursorCol && "bg-primary text-primary-foreground rounded-sm")}
                          >
                            {h}
                            {i < row.hex.length - 1 ? " " : ""}
                          </span>
                        ))
                      : "…"}
                  </span>
                  <span role="cell" className="whitespace-pre">
                    {row?.ascii ?? ""}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
