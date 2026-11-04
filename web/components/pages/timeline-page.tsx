"use client";

import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { DownloadIcon, SaveIcon, SearchIcon, XIcon } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { PageHeader } from "@/components/common";
import { EventDrawer } from "@/components/timeline/event-drawer";
import { FacetSidebar } from "@/components/timeline/facets";
import { Histogram } from "@/components/timeline/histogram";
import { ResultsTable } from "@/components/timeline/results-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, EmptyState } from "@/components/ui/misc";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useCase } from "@/hooks/use-case";
import { useHotkeys } from "@/hooks/use-hotkeys";
import { useTableNav } from "@/hooks/use-table-nav";
import { ApiError } from "@/lib/api";
import { api } from "@/lib/api-instance";
import { saveBlob } from "@/lib/download";
import {
  addPivot,
  filterChips,
  filtersFromParams,
  filtersFromUnknown,
  filtersToParams,
  EMPTY_FILTERS,
  hasFilters,
  PIVOT_COLUMNS,
  toSearchBody,
  type TimelineFilters,
} from "@/lib/filters";
import { fillBuckets } from "@/lib/histogram";
import { PAGE_SIZE, pageOf, pagesForRange } from "@/lib/paging";
import { formatNs, isoToNs, nsToInput } from "@/lib/format";
import { atLeast } from "@/lib/roles";
import type { SearchResult, TimelineEvent } from "@/lib/types";

export function TimelinePage() {
  const { caseId, access } = useCase();
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const qc = useQueryClient();
  const paramString = params.toString();
  const filters = useMemo(() => filtersFromParams(new URLSearchParams(paramString)), [paramString]);
  const eventParam = params.get("event");
  const [drawerId, setDrawerId] = useState<number | null>(
    eventParam && /^\d+$/.test(eventParam) ? Number(eventParam) : null,
  );
  const [unmask, setUnmask] = useState(false);
  const [text, setText] = useState(filters.text);
  const [from, setFrom] = useState(nsToInput(filters.start_ns));
  const [to, setTo] = useState(nsToInput(filters.end_ns));
  const [attrKey, setAttrKey] = useState("");
  const [attrValue, setAttrValue] = useState("");
  const [viewName, setViewName] = useState("");
  const [saveOpen, setSaveOpen] = useState(false);
  const [range, setRange] = useState<[number, number]>([0, 0]);
  const [syncedParams, setSyncedParams] = useState(paramString);

  if (syncedParams !== paramString) {
    // Filters changed from outside the inputs (pivot, facet, saved view, back button).
    setSyncedParams(paramString);
    setText(filters.text);
    setFrom(nsToInput(filters.start_ns));
    setTo(nsToInput(filters.end_ns));
  }

  const setFilters = useCallback(
    (f: TimelineFilters) => {
      const p = filtersToParams(f);
      const qs = p.toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
    [pathname, router],
  );

  const body = useMemo(() => toSearchBody(filters, { unmask }), [filters, unmask]);
  const histBody = useMemo(() => toSearchBody(filters), [filters]);

  const evidence = useQuery({ queryKey: ["evidence", caseId], queryFn: () => api.listEvidence(caseId) });
  const firstPage = useQuery({
    queryKey: ["search", caseId, body, 0],
    queryFn: () => api.search(caseId, { ...body, limit: PAGE_SIZE, offset: 0 }),
    placeholderData: (prev) => prev,
  });
  const total = firstPage.data?.total ?? 0;
  const pages = pagesForRange(range[0], range[1], total).filter((p) => p > 0);
  const pageQueries = useQueries({
    queries: pages.map((p) => ({
      queryKey: ["search", caseId, body, p],
      queryFn: () => api.search(caseId, { ...body, limit: PAGE_SIZE, offset: p * PAGE_SIZE }),
      staleTime: 30_000,
    })),
  });
  const pageData = new Map<number, SearchResult>();
  if (firstPage.data) pageData.set(0, firstPage.data);
  pages.forEach((p, i) => {
    const d = pageQueries[i]?.data;
    if (d) pageData.set(p, d);
  });
  const rowAt = (i: number): TimelineEvent | undefined => {
    const { page, offset } = pageOf(i);
    return pageData.get(page)?.events[offset];
  };

  const histogram = useQuery({
    queryKey: ["histogram", caseId, histBody],
    queryFn: () => api.histogram(caseId, histBody),
    placeholderData: (prev) => prev,
  });
  const buckets = useMemo(
    () => fillBuckets(histogram.data?.buckets ?? [], histogram.data?.bucket_ns ?? 0),
    [histogram.data],
  );

  const views = useQuery({ queryKey: ["views", caseId], queryFn: () => api.listViews(caseId) });
  const bookmarks = useQuery({ queryKey: ["bookmarks", caseId], queryFn: () => api.listBookmarks(caseId) });
  const bookmarked = useMemo(() => new Set((bookmarks.data ?? []).map((b) => b.event_id)), [bookmarks.data]);
  const canExport = atLeast(access, "examiner");

  const { selected, setSelected } = useTableNav(total, {
    onOpen: (i) => {
      const e = rowAt(i);
      if (e) setDrawerId(e.id);
    },
    enabled: drawerId === null,
  });

  const bookmark = useMutation({
    mutationFn: (eventId: number) => api.createBookmark(caseId, { event_id: eventId, label: "", tags: [] }),
    onSuccess: (_r, eventId) => {
      toast.success(`Bookmarked event ${eventId}`);
      void qc.invalidateQueries({ queryKey: ["bookmarks", caseId] });
    },
  });

  useHotkeys(
    {
      b: () => {
        const e = selected !== null ? rowAt(selected) : undefined;
        if (!e) return;
        if (!canExport) {
          toast.error("Bookmarking requires the examiner role.");
          return;
        }
        bookmark.mutate(e.id);
      },
    },
    { enabled: drawerId === null },
  );

  const pivot = (column: string, value: string) => {
    const next = addPivot(filters, column, value);
    if (next !== filters) {
      setFilters(next);
      toast.message(`Filter added: ${column} = ${value.length > 60 ? `${value.slice(0, 60)}…` : value}`);
    }
  };

  const toggleFacet = (column: string, value: string) => {
    const next = addPivot(filters, column, value);
    if (next !== filters) {
      setFilters(next);
      return;
    }
    const field = PIVOT_COLUMNS[column];
    if (field) setFilters({ ...filters, [field]: filters[field].filter((x) => x !== value) });
  };

  const onSearch = (e: FormEvent) => {
    e.preventDefault();
    setSelected(null);
    setFilters({ ...filters, text, start_ns: isoToNs(from), end_ns: isoToNs(to) });
  };

  const addAttr = (e: FormEvent) => {
    e.preventDefault();
    if (!attrKey.trim()) return;
    setFilters({ ...filters, attr_equals: { ...filters.attr_equals, [attrKey.trim()]: attrValue } });
    setAttrKey("");
    setAttrValue("");
  };

  const saveView = useMutation({
    mutationFn: () => api.createView(caseId, { name: viewName.trim(), query: { ...filters } }),
    onSuccess: () => {
      toast.success("View saved");
      setSaveOpen(false);
      setViewName("");
      void qc.invalidateQueries({ queryKey: ["views", caseId] });
    },
  });

  const doExport = async (fmt: "csv" | "jsonl" | "plaso") => {
    try {
      const d = await api.exportTimeline(caseId, fmt, unmask);
      saveBlob(d.blob, d.filename);
      toast.success(
        `Exported ${fmt.toUpperCase()} (SHA-256 ${d.headers.get("X-Content-SHA256")?.slice(0, 16) ?? "?"}…), recorded in custody`,
      );
    } catch (err) {
      toast.error(err instanceof ApiError ? err.detail : "Export failed");
    }
  };

  const onRangeChange = useCallback((a: number, b: number) => setRange([a, b]), []);
  const chips = filterChips(filters, formatNs);

  return (
    <>
      <PageHeader
        title="Timeline"
        description={
          <span role="status" aria-live="polite" data-testid="result-count">
            {firstPage.isFetching && !firstPage.data
              ? "Searching…"
              : `${total.toLocaleString()} events${firstPage.data ? ` · ${firstPage.data.ms} ms` : ""}`}
          </span>
        }
        actions={
          <>
            {access.canUnmask ? (
              <div className="flex items-center gap-2">
                <Switch id="unmask" checked={unmask} onCheckedChange={setUnmask} />
                <Label htmlFor="unmask">Unmask PII</Label>
              </div>
            ) : (
              <Badge variant="outline" title="PII is masked; unmasking requires the pii.unmask permission">
                PII masked
              </Badge>
            )}
            <Button variant="outline" onClick={() => setSaveOpen(true)}>
              <SaveIcon aria-hidden /> Save view
            </Button>
            {canExport ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline">
                    <DownloadIcon aria-hidden /> Export
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuLabel>
                    Whole case timeline{unmask ? " (unmasked)" : " (masked)"}
                  </DropdownMenuLabel>
                  <DropdownMenuItem onSelect={() => void doExport("csv")}>CSV</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => void doExport("jsonl")}>JSON Lines</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => void doExport("plaso")}>
                    Plaso JSON Lines
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : null}
          </>
        }
      />

      <form
        onSubmit={onSearch}
        className="grid gap-2 md:grid-cols-[1fr_auto_auto_auto] md:items-end"
        role="search"
        aria-label="Timeline search"
      >
        <div className="grid gap-1">
          <Label htmlFor="tl-search">Full-text search</Label>
          <Input
            id="tl-search"
            data-search
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder='mimikatz OR "explicit credentials"'
            aria-keyshortcuts="/"
            onKeyDown={(e) => {
              if (e.key === "Escape") e.currentTarget.blur();
            }}
          />
        </div>
        <div className="grid gap-1">
          <Label htmlFor="tl-from">From (UTC)</Label>
          <Input
            id="tl-from"
            type="datetime-local"
            step={1}
            value={from}
            onChange={(e) => setFrom(e.target.value)}
          />
        </div>
        <div className="grid gap-1">
          <Label htmlFor="tl-to">Before (UTC)</Label>
          <Input
            id="tl-to"
            type="datetime-local"
            step={1}
            value={to}
            onChange={(e) => setTo(e.target.value)}
          />
        </div>
        <Button type="submit">
          <SearchIcon aria-hidden /> Search
        </Button>
      </form>

      <div className="mt-3">
        <Histogram
          buckets={buckets}
          bucketNs={histogram.data?.bucket_ns ?? 0}
          loading={histogram.isLoading}
          onRange={(r) => {
            setSelected(null);
            setFilters({ ...filters, ...r });
          }}
        />
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-1.5" aria-label="Active filters" role="list">
        {chips.map((c) => (
          <span role="listitem" key={c.key}>
            <Badge variant="secondary" className="gap-1 py-0 pr-0">
              <span className="text-muted-foreground">{c.label}:</span>
              <span className="max-w-[18rem] truncate">{c.value}</span>
              <Button
                variant="ghost"
                size="icon-sm"
                className="size-7"
                aria-label={`Remove filter ${c.label} ${c.value}`}
                onClick={() => setFilters(c.remove(filters))}
              >
                <XIcon aria-hidden />
              </Button>
            </Badge>
          </span>
        ))}
        {hasFilters(filters) ? (
          <span role="listitem">
            <Button variant="link" size="sm" onClick={() => setFilters(EMPTY_FILTERS)}>
              Clear all
            </Button>
          </span>
        ) : null}
      </div>

      <div className="mt-3 grid gap-4 lg:grid-cols-[16rem_minmax(0,1fr)]">
        <aside aria-label="Filters and bookmarks" className="order-2 lg:order-1">
          <Tabs defaultValue="facets">
            <TabsList className="w-full">
              <TabsTrigger value="facets">Facets</TabsTrigger>
              <TabsTrigger value="bookmarks">Bookmarks</TabsTrigger>
              <TabsTrigger value="views">Views</TabsTrigger>
            </TabsList>
            <TabsContent value="facets" className="grid gap-4">
              <FacetSidebar
                caseId={caseId}
                body={histBody}
                filters={filters}
                evidence={evidence.data ?? []}
                onToggle={toggleFacet}
              />
              <form onSubmit={addAttr} className="grid gap-1.5 border-t pt-3" aria-label="Attribute filter">
                <h2 className="text-muted-foreground text-xs font-semibold uppercase">Attribute equals</h2>
                <Label htmlFor="attr-key" className="sr-only">
                  Attribute name
                </Label>
                <Input
                  id="attr-key"
                  placeholder="event_identifier"
                  value={attrKey}
                  onChange={(e) => setAttrKey(e.target.value)}
                />
                <Label htmlFor="attr-value" className="sr-only">
                  Attribute value
                </Label>
                <Input
                  id="attr-value"
                  placeholder="4624"
                  value={attrValue}
                  onChange={(e) => setAttrValue(e.target.value)}
                />
                <Button type="submit" variant="secondary" size="sm" disabled={!attrKey.trim()}>
                  Add attribute filter
                </Button>
              </form>
            </TabsContent>
            <TabsContent value="bookmarks">
              {(bookmarks.data ?? []).length ? (
                <ul className="grid gap-1 text-sm" aria-label="Bookmarked events">
                  {(bookmarks.data ?? []).map((b) => (
                    <li key={b.id} className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="min-w-0 flex-1 justify-start"
                        onClick={() => setDrawerId(b.event_id)}
                      >
                        <span className="truncate">
                          #{b.event_id} {b.label}
                        </span>
                      </Button>
                      {b.tags.map((t) => (
                        <Badge key={t} variant="outline">
                          {t}
                        </Badge>
                      ))}
                      {canExport ? (
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={`Delete bookmark on event ${b.event_id}`}
                          onClick={() =>
                            void api
                              .deleteBookmark(caseId, b.id)
                              .then(() => qc.invalidateQueries({ queryKey: ["bookmarks", caseId] }))
                          }
                        >
                          <XIcon aria-hidden />
                        </Button>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState title="No bookmarks">Select a row and press B.</EmptyState>
              )}
            </TabsContent>
            <TabsContent value="views">
              {(views.data ?? []).length ? (
                <ul className="grid gap-1 text-sm" aria-label="Saved views">
                  {(views.data ?? []).map((v) => (
                    <li key={v.id}>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="w-full justify-start"
                        onClick={() => setFilters(filtersFromUnknown(v.query))}
                      >
                        <span className="truncate">{v.name}</span>
                        <span className="text-muted-foreground ml-auto text-xs">{v.user_id}</span>
                      </Button>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState title="No saved views" />
              )}
            </TabsContent>
          </Tabs>
        </aside>
        <section aria-label="Results" className="order-1 min-w-0 lg:order-2">
          {firstPage.error ? (
            <Alert variant="destructive" role="alert">
              {firstPage.error instanceof ApiError ? firstPage.error.detail : "Search failed"}
            </Alert>
          ) : total === 0 && !firstPage.isLoading ? (
            <EmptyState title="No events match">Adjust the search or remove filters.</EmptyState>
          ) : (
            <ResultsTable
              total={total}
              rowAt={rowAt}
              onRangeChange={onRangeChange}
              selected={selected}
              onSelect={setSelected}
              onOpen={(i) => {
                const e = rowAt(i);
                if (e) setDrawerId(e.id);
              }}
              onPivot={pivot}
              bookmarked={bookmarked}
            />
          )}
          <p className="text-muted-foreground mt-1 text-xs">
            J/K select · Enter opens details · B bookmarks · click a host, user or type to filter on it.
          </p>
        </section>
      </div>

      <EventDrawer
        caseId={caseId}
        eventId={drawerId}
        unmask={unmask}
        access={access}
        evidence={evidence.data ?? []}
        onClose={() => setDrawerId(null)}
        onPivot={(c, v) => {
          setDrawerId(null);
          pivot(c, v);
        }}
      />

      <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
        <DialogContent>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (viewName.trim()) saveView.mutate();
            }}
          >
            <DialogHeader>
              <DialogTitle>Save view</DialogTitle>
              <DialogDescription>
                Saves the current search and filters for everyone on the case.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-1.5">
              <Label htmlFor="view-name">Name</Label>
              <Input
                id="view-name"
                value={viewName}
                onChange={(e) => setViewName(e.target.value)}
                autoFocus
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setSaveOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={!viewName.trim() || saveView.isPending}>
                Save
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
