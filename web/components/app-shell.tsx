"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CommandIcon,
  CpuIcon,
  FileTextIcon,
  FlagIcon,
  HardDriveIcon,
  KeyboardIcon,
  LayersIcon,
  LayoutDashboardIcon,
  LinkIcon,
  LogOutIcon,
  ScanSearchIcon,
  ShieldIcon,
  UserIcon,
  WaypointsIcon,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { BrandMark } from "@/components/brand";
import { CommandPalette } from "@/components/command-palette";
import { ShortcutSheet } from "@/components/shortcut-sheet";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Kbd, Skeleton } from "@/components/ui/misc";
import { useHotkeys } from "@/hooks/use-hotkeys";
import { useHydrated, useMe, useToken } from "@/hooks/use-session";
import { api } from "@/lib/api-instance";
import {
  activeSection,
  CASE_SECTIONS,
  caseIdFromPath,
  forgetCase,
  lastCase,
  rememberCase,
  shortcutTarget,
} from "@/lib/nav";
import { clearToken } from "@/lib/token-store";
import { cn } from "@/lib/utils";

const SECTION_ICON: Record<string, LucideIcon> = {
  dashboard: LayoutDashboardIcon,
  evidence: HardDriveIcon,
  timeline: LayersIcon,
  memory: CpuIcon,
  graph: WaypointsIcon,
  findings: FlagIcon,
  iocs: ScanSearchIcon,
  reports: FileTextIcon,
  custody: LinkIcon,
};

export function focusSearch(doc: Document = document): boolean {
  const el = doc.querySelector<HTMLElement>("[data-search]");
  if (!el) return false;
  el.focus();
  if (el instanceof HTMLInputElement) el.select();
  return true;
}

export function AppShell({ children }: { children: ReactNode }) {
  const token = useToken();
  const hydrated = useHydrated();
  const router = useRouter();
  const pathname = usePathname();
  const qc = useQueryClient();
  const me = useMe();
  const caseId = caseIdFromPath(pathname);
  const section = activeSection(pathname);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [sheetOpen, setSheetOpen] = useState(false);

  const caseQuery = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => api.getCase(caseId ?? ""),
    enabled: token !== null && caseId !== null,
  });

  useEffect(() => {
    if (hydrated && token === null) {
      router.replace(`/login?next=${encodeURIComponent(pathname || "/cases")}`);
    }
  }, [hydrated, token, router, pathname]);

  useEffect(() => {
    if (caseId) rememberCase(caseId);
  }, [caseId]);

  const logout = () => {
    clearToken();
    forgetCase();
    qc.clear();
    router.replace("/login");
  };

  const go = (seq: string) => () => {
    const target = shortcutTarget(seq, caseId ?? lastCase());
    if (target) router.push(target);
  };

  useHotkeys(
    {
      "mod+k": () => setPaletteOpen((o) => !o),
      "?": () => setSheetOpen(true),
      "/": () => {
        focusSearch();
      },
      "g c": go("g c"),
      "g d": go("g d"),
      "g e": go("g e"),
      "g t": go("g t"),
      "g f": go("g f"),
      "g i": go("g i"),
      "g r": go("g r"),
      "g l": go("g l"),
    },
    { scope: "global", enabled: token !== null },
  );

  if (!hydrated || token === null) {
    return (
      <div className="p-6" aria-busy="true">
        <p className="sr-only" role="status">
          Checking session…
        </p>
        <Skeleton className="h-8 w-48" />
      </div>
    );
  }

  const caseName = caseQuery.data?.name;

  return (
    <div className="flex min-h-dvh flex-col">
      <a
        href="#main"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById("main")?.focus();
        }}
        className="bg-primary text-primary-foreground sr-only z-[60] rounded-md px-3 py-2 focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
      >
        Skip to main content
      </a>
      <header className="bg-background/95 supports-[backdrop-filter]:bg-background/80 sticky top-0 z-40 border-b backdrop-blur">
        <div className="flex h-12 items-center gap-2 px-3 sm:px-4">
          <Link
            href="/cases"
            className="flex items-center gap-2 rounded-md px-1 font-semibold tracking-tight"
          >
            <BrandMark />
            <span>Veritas</span>
            <span className="text-muted-foreground hidden rounded border px-1 py-px text-[10px] font-medium tracking-wide uppercase md:inline">
              DFIR
            </span>
          </Link>
          {caseId ? (
            <>
              <span aria-hidden className="text-muted-foreground">
                /
              </span>
              <Link
                href={`/cases/${encodeURIComponent(caseId)}`}
                className="min-w-0 truncate rounded-md px-1 text-sm hover:underline"
                title={caseName ?? caseId}
              >
                <span className="text-muted-foreground font-mono text-xs">{caseId}</span>
                {caseName ? <span className="ml-2 hidden font-medium sm:inline">{caseName}</span> : null}
              </Link>
            </>
          ) : null}
          <div className="ml-auto flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPaletteOpen(true)}
              title="Open command palette"
              aria-keyshortcuts="Control+K Meta+K"
              className="hidden sm:inline-flex"
            >
              <CommandIcon aria-hidden />
              <span>Commands</span>
              <Kbd>Ctrl K</Kbd>
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setSheetOpen(true)}
              aria-label="Keyboard shortcuts"
              aria-keyshortcuts="?"
            >
              <KeyboardIcon aria-hidden />
            </Button>
            <ThemeToggle />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={`Account menu for ${me.data?.display_name ?? "current user"}`}
                >
                  <UserIcon aria-hidden />
                  <span className="hidden max-w-32 truncate md:inline">{me.data?.display_name ?? "…"}</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>
                  {me.data?.user_id ?? ""}
                  {me.data?.is_admin ? " · admin" : ""}
                  <span className="mt-0.5 block font-mono text-[11px]">
                    key {me.data?.signing_key_id ?? "—"}
                  </span>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                {me.data?.is_admin ? (
                  <DropdownMenuItem onSelect={() => router.push("/admin")}>
                    <ShieldIcon aria-hidden /> Administration
                  </DropdownMenuItem>
                ) : null}
                <DropdownMenuItem onSelect={logout}>
                  <LogOutIcon aria-hidden /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
        {caseId ? (
          <nav aria-label="Case sections" className="overflow-x-auto px-2 sm:px-3">
            <ul className="flex min-w-max gap-0.5">
              {CASE_SECTIONS.map((s) => {
                const active = section === s.key;
                const Icon = SECTION_ICON[s.key];
                return (
                  <li key={s.key} className="relative py-1">
                    <Link
                      href={s.path(encodeURIComponent(caseId))}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "hover:bg-accent hover:text-accent-foreground inline-flex h-8 items-center gap-1.5 rounded-md px-2.5 text-sm transition-colors",
                        active ? "text-foreground font-medium" : "text-muted-foreground",
                      )}
                    >
                      {Icon ? (
                        <Icon aria-hidden className={cn("size-4", active ? "text-primary" : "opacity-80")} />
                      ) : null}
                      {s.label}
                    </Link>
                    {active ? (
                      <span
                        aria-hidden
                        className="bg-primary absolute inset-x-2 bottom-0 h-0.5 rounded-full"
                      />
                    ) : null}
                  </li>
                );
              })}
            </ul>
          </nav>
        ) : null}
      </header>
      <main
        id="main"
        tabIndex={-1}
        className="mx-auto w-full max-w-[1600px] flex-1 px-3 py-5 outline-none sm:px-5"
      >
        {children}
      </main>
      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        caseId={caseId}
        me={me.data}
        onShowShortcuts={() => setSheetOpen(true)}
        onLogout={logout}
      />
      <ShortcutSheet open={sheetOpen} onOpenChange={setSheetOpen} />
    </div>
  );
}
