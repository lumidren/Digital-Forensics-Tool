"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BookmarkIcon, FilterIcon } from "lucide-react";
import Link from "next/link";
import { useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";
import { ArtifactViewer } from "@/components/artifact-viewers";
import { Mono, QueryStatus } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { api } from "@/lib/api-instance";
import { viewerKind } from "@/lib/artifacts";
import { attrFilterValue } from "@/lib/filters";
import { formatDate, formatNs, stringifyValue } from "@/lib/format";
import type { Access } from "@/lib/roles";
import { atLeast } from "@/lib/roles";
import type { Evidence } from "@/lib/types";

export interface EventDrawerProps {
  caseId: string;
  eventId: number | null;
  unmask: boolean;
  access: Access;
  evidence: Evidence[];
  onClose: () => void;
  onPivot: (column: string, value: string) => void;
}

function PivotButton({
  column,
  value,
  onPivot,
}: {
  column: string;
  value: string;
  onPivot: (c: string, v: string) => void;
}) {
  return (
    <Button
      variant="ghost"
      size="icon-sm"
      className="size-7 shrink-0"
      aria-label={`Filter on ${column} = ${value.slice(0, 80)}`}
      title="Add as filter"
      onClick={() => onPivot(column, value)}
    >
      <FilterIcon aria-hidden />
    </Button>
  );
}

function ProvRow({
  label,
  children,
  pivot = null,
  onPivot,
}: {
  label: string;
  children: ReactNode;
  pivot?: { column: string; value: string } | null;
  onPivot?: (c: string, v: string) => void;
}) {
  return (
    <div className="grid grid-cols-[8rem_1fr] items-center gap-x-2">
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="flex min-w-0 items-center justify-between gap-1">
        <span className="min-w-0">{children}</span>
        {pivot && onPivot ? (
          <PivotButton column={pivot.column} value={pivot.value} onPivot={onPivot} />
        ) : null}
      </dd>
    </div>
  );
}

export function EventDrawer({
  caseId,
  eventId,
  unmask,
  access,
  evidence,
  onClose,
  onPivot,
}: EventDrawerProps) {
  const qc = useQueryClient();
  const open = eventId !== null;
  const ev = useQuery({
    queryKey: ["event", caseId, eventId, unmask],
    queryFn: () => api.getEvent(caseId, eventId ?? 0, unmask),
    enabled: open,
  });
  const bookmarks = useQuery({
    queryKey: ["bookmarks", caseId],
    queryFn: () => api.listBookmarks(caseId),
    enabled: open,
  });
  const notes = useQuery({
    queryKey: ["notes", caseId, "event", eventId],
    queryFn: () => api.listNotes(caseId, "event", String(eventId)),
    enabled: open,
  });
  const [label, setLabel] = useState("");
  const [tags, setTags] = useState("");
  const [note, setNote] = useState("");
  const canEdit = atLeast(access, "examiner");

  const addBookmark = useMutation({
    mutationFn: () =>
      api.createBookmark(caseId, {
        event_id: eventId ?? 0,
        label: label.trim(),
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      }),
    onSuccess: () => {
      toast.success("Event bookmarked");
      setLabel("");
      setTags("");
      void qc.invalidateQueries({ queryKey: ["bookmarks", caseId] });
    },
  });
  const addNote = useMutation({
    mutationFn: () =>
      api.createNote(caseId, { target_type: "event", target_id: String(eventId), body: note.trim() }),
    onSuccess: () => {
      setNote("");
      void qc.invalidateQueries({ queryKey: ["notes", caseId, "event", eventId] });
    },
  });

  const e = ev.data;
  const evidenceItem = e ? evidence.find((x) => x.sha256 === e.evidence_sha256) : undefined;
  const myBookmarks = (bookmarks.data ?? []).filter((b) => b.event_id === eventId);

  const submitBookmark = (f: FormEvent) => {
    f.preventDefault();
    addBookmark.mutate();
  };
  const submitNote = (f: FormEvent) => {
    f.preventDefault();
    if (note.trim()) addNote.mutate();
  };

  return (
    <Sheet open={open} onOpenChange={(o) => (!o ? onClose() : undefined)}>
      <SheetContent aria-describedby="event-drawer-desc">
        <SheetHeader>
          <SheetTitle>Event {eventId}</SheetTitle>
          <SheetDescription id="event-drawer-desc">
            {e ? `${e.data_type} · ${formatNs(e.timestamp)} · ${e.timestamp_desc}` : "Loading event…"}
            {unmask ? " · PII unmasked (audited)" : " · PII masked"}
          </SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto px-4 py-3">
          <QueryStatus isLoading={ev.isLoading} error={ev.error}>
            {e ? (
              <div className="grid gap-5">
                <p className="text-sm break-words">{e.message}</p>
                <section aria-labelledby="ev-artifact" className="grid gap-2">
                  <h3 id="ev-artifact" className="text-sm font-semibold">
                    {viewerKind(e.data_type) === "generic"
                      ? "Artifact"
                      : `Artifact (${viewerKind(e.data_type)})`}
                  </h3>
                  <ArtifactViewer event={e} />
                </section>

                <section aria-labelledby="ev-prov" className="grid gap-1">
                  <h3 id="ev-prov" className="text-sm font-semibold">
                    Provenance
                  </h3>
                  <dl className="grid gap-y-0.5 text-sm">
                    <ProvRow label="Evidence">
                      {evidenceItem ? (
                        <Link
                          className="text-primary underline"
                          href={`/cases/${encodeURIComponent(caseId)}/evidence/${encodeURIComponent(evidenceItem.id)}`}
                        >
                          {evidenceItem.id} ({evidenceItem.name})
                        </Link>
                      ) : (
                        "—"
                      )}
                    </ProvRow>
                    <ProvRow
                      label="Evidence SHA-256"
                      pivot={
                        e.evidence_sha256 ? { column: "evidence_sha256", value: e.evidence_sha256 } : null
                      }
                      onPivot={onPivot}
                    >
                      <Mono>{e.evidence_sha256 || "—"}</Mono>
                    </ProvRow>
                    <ProvRow label="Path">
                      <Mono>{e.evidence_path || "—"}</Mono>
                    </ProvRow>
                    <ProvRow label="Offset / record">
                      <span className="tabular">{e.offset}</span>
                    </ProvRow>
                    <ProvRow
                      label="Parser"
                      pivot={e.parser ? { column: "parser", value: e.parser } : null}
                      onPivot={onPivot}
                    >
                      {e.parser} <span className="text-muted-foreground">v{e.parser_version || "?"}</span>
                    </ProvRow>
                    <ProvRow
                      label="Data type"
                      pivot={{ column: "data_type", value: e.data_type }}
                      onPivot={onPivot}
                    >
                      {e.data_type}
                    </ProvRow>
                    <ProvRow
                      label="Host"
                      pivot={e.host ? { column: "host", value: e.host } : null}
                      onPivot={onPivot}
                    >
                      {e.host ?? "—"}
                    </ProvRow>
                    <ProvRow
                      label="User"
                      pivot={e.user ? { column: "user", value: e.user } : null}
                      onPivot={onPivot}
                    >
                      {e.user ?? "—"}
                    </ProvRow>
                    <ProvRow label="Source">
                      {e.source_short} {e.source_long ? `· ${e.source_long}` : ""}
                    </ProvRow>
                    <ProvRow label="Clock skew">
                      <span className="tabular">
                        {e.skew_ns} ns{e.timezone ? ` · source tz ${e.timezone}` : ""}
                      </span>
                    </ProvRow>
                  </dl>
                </section>

                <section aria-labelledby="ev-attrs" className="grid gap-1">
                  <h3 id="ev-attrs" className="text-sm font-semibold">
                    All attributes ({Object.keys(e.attrs).length})
                  </h3>
                  <table className="w-full text-sm" aria-labelledby="ev-attrs">
                    <tbody>
                      {Object.entries(e.attrs).map(([k, v]) => {
                        const fv = attrFilterValue(v);
                        return (
                          <tr key={k} className="border-b last:border-0">
                            <th
                              scope="row"
                              className="text-muted-foreground w-40 py-1 pr-2 text-left align-top font-mono text-xs font-medium"
                            >
                              {k}
                            </th>
                            <td className="py-1 font-mono text-xs break-all">{stringifyValue(v)}</td>
                            <td className="w-8 py-0.5 align-top">
                              {fv !== null ? (
                                <PivotButton column={`attrs.${k}`} value={fv} onPivot={onPivot} />
                              ) : null}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </section>

                <section aria-labelledby="ev-bm" className="grid gap-2">
                  <h3 id="ev-bm" className="text-sm font-semibold">
                    Bookmarks and tags
                  </h3>
                  {myBookmarks.length ? (
                    <ul className="grid gap-1 text-sm">
                      {myBookmarks.map((b) => (
                        <li key={b.id} className="flex flex-wrap items-center gap-1">
                          <BookmarkIcon className="size-3.5" aria-hidden />
                          <span>{b.label || "(no label)"}</span>
                          {b.tags.map((t) => (
                            <Badge key={t} variant="secondary">
                              {t}
                            </Badge>
                          ))}
                          <span className="text-muted-foreground text-xs">by {b.user_id}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-muted-foreground text-xs">Not bookmarked.</p>
                  )}
                  {canEdit ? (
                    <form
                      onSubmit={submitBookmark}
                      className="grid gap-2 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
                    >
                      <div className="grid gap-1">
                        <Label htmlFor="bm-label">Label</Label>
                        <Input id="bm-label" value={label} onChange={(x) => setLabel(x.target.value)} />
                      </div>
                      <div className="grid gap-1">
                        <Label htmlFor="bm-tags">Tags (comma-separated)</Label>
                        <Input id="bm-tags" value={tags} onChange={(x) => setTags(x.target.value)} />
                      </div>
                      <Button type="submit" variant="secondary" disabled={addBookmark.isPending}>
                        <BookmarkIcon aria-hidden /> Bookmark
                      </Button>
                    </form>
                  ) : null}
                </section>

                <section aria-labelledby="ev-notes" className="grid gap-2">
                  <h3 id="ev-notes" className="text-sm font-semibold">
                    Notes
                  </h3>
                  {(notes.data ?? []).length ? (
                    <ul className="grid gap-2">
                      {(notes.data ?? []).map((n) => (
                        <li key={n.id} className="rounded-md border p-2 text-sm">
                          <p className="whitespace-pre-wrap">{n.body}</p>
                          <p className="text-muted-foreground mt-1 text-xs">
                            {n.user_id} · {formatDate(n.created)}
                          </p>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-muted-foreground text-xs">No notes.</p>
                  )}
                  {canEdit ? (
                    <form onSubmit={submitNote} className="grid gap-2">
                      <Label htmlFor="ev-note">Add note</Label>
                      <Textarea
                        id="ev-note"
                        value={note}
                        onChange={(x) => setNote(x.target.value)}
                        maxLength={20000}
                      />
                      <Button
                        type="submit"
                        variant="secondary"
                        disabled={!note.trim() || addNote.isPending}
                        className="justify-self-start"
                      >
                        Save note
                      </Button>
                    </form>
                  ) : null}
                </section>
              </div>
            ) : null}
          </QueryStatus>
        </div>
      </SheetContent>
    </Sheet>
  );
}
