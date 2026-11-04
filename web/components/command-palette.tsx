"use client";

import { useQuery } from "@tanstack/react-query";
import { BriefcaseIcon, KeyboardIcon, LogOutIcon, MoonIcon, ShieldIcon, CompassIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Kbd } from "@/components/ui/misc";
import { nextTheme } from "@/components/theme-toggle";
import { api } from "@/lib/api-instance";
import { CASE_SECTIONS } from "@/lib/nav";
import { shortcutLabel } from "@/lib/shortcuts";
import type { Me } from "@/lib/types";

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  caseId: string | null;
  me: Me | undefined;
  onShowShortcuts: () => void;
  onLogout: () => void;
}

export function CommandPalette({
  open,
  onOpenChange,
  caseId,
  me,
  onShowShortcuts,
  onLogout,
}: CommandPaletteProps) {
  const router = useRouter();
  const { theme, setTheme } = useTheme();
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => api.listCases(), enabled: open });

  const run = (fn: () => void) => {
    onOpenChange(false);
    fn();
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl overflow-hidden p-0">
        <DialogTitle className="sr-only">Command palette</DialogTitle>
        <DialogDescription className="sr-only">
          Type to filter commands, use arrow keys and Enter to run one.
        </DialogDescription>
        <Command label="Command palette" loop>
          <CommandInput placeholder="Type a command or search cases…" aria-label="Command" />
          <CommandList>
            <CommandEmpty>No matching commands.</CommandEmpty>
            {caseId ? (
              <CommandGroup heading="This case">
                {CASE_SECTIONS.map((s) => (
                  <CommandItem
                    key={s.key}
                    value={`go ${s.label}`}
                    onSelect={() => run(() => router.push(s.path(encodeURIComponent(caseId))))}
                  >
                    <CompassIcon aria-hidden />
                    <span>Go to {s.label}</span>
                    {s.shortcut ? (
                      <span className="ml-auto flex gap-1">
                        {shortcutLabel(s.shortcut).map((k) => (
                          <Kbd key={k}>{k}</Kbd>
                        ))}
                      </span>
                    ) : null}
                  </CommandItem>
                ))}
              </CommandGroup>
            ) : null}
            <CommandGroup heading="Cases">
              <CommandItem value="go all cases" onSelect={() => run(() => router.push("/cases"))}>
                <BriefcaseIcon aria-hidden />
                <span>All cases</span>
              </CommandItem>
              {(cases.data ?? []).slice(0, 30).map((c) => (
                <CommandItem
                  key={c.id}
                  value={`case ${c.id} ${c.name}`}
                  onSelect={() => run(() => router.push(`/cases/${encodeURIComponent(c.id)}`))}
                >
                  <BriefcaseIcon aria-hidden />
                  <span className="truncate">{c.name}</span>
                  <span className="text-muted-foreground ml-auto font-mono text-xs">{c.id}</span>
                </CommandItem>
              ))}
            </CommandGroup>
            <CommandGroup heading="General">
              {me?.is_admin ? (
                <CommandItem value="administration admin" onSelect={() => run(() => router.push("/admin"))}>
                  <ShieldIcon aria-hidden />
                  <span>Administration</span>
                </CommandItem>
              ) : null}
              <CommandItem
                value="toggle theme dark light"
                onSelect={() => run(() => setTheme(nextTheme(theme)))}
              >
                <MoonIcon aria-hidden />
                <span>Toggle theme</span>
              </CommandItem>
              <CommandItem value="keyboard shortcuts help" onSelect={() => run(onShowShortcuts)}>
                <KeyboardIcon aria-hidden />
                <span>Keyboard shortcuts</span>
                <span className="ml-auto">
                  <Kbd>?</Kbd>
                </span>
              </CommandItem>
              <CommandItem value="sign out logout" onSelect={() => run(onLogout)}>
                <LogOutIcon aria-hidden />
                <span>Sign out</span>
              </CommandItem>
            </CommandGroup>
          </CommandList>
        </Command>
      </DialogContent>
    </Dialog>
  );
}
