"use client";

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Kbd } from "@/components/ui/misc";
import { GLOBAL_SHORTCUTS, shortcutLabel } from "@/lib/shortcuts";

export function ShortcutSheet({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const groups = [...new Set(GLOBAL_SHORTCUTS.map((s) => s.group))];
  const apple = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            Sequences such as <Kbd>G</Kbd> <Kbd>T</Kbd> are typed one key after the other. Shortcuts are
            paused while typing in a field.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 sm:grid-cols-2">
          {groups.map((g) => (
            <section key={g} aria-labelledby={`sc-${g}`}>
              <h3 id={`sc-${g}`} className="text-muted-foreground mb-1.5 text-xs font-semibold uppercase">
                {g}
              </h3>
              <dl className="grid gap-1 text-sm">
                {GLOBAL_SHORTCUTS.filter((s) => s.group === g).map((s) => (
                  <div key={s.keys} className="flex items-center justify-between gap-3">
                    <dt>{s.description}</dt>
                    <dd className="flex gap-1">
                      {shortcutLabel(s.keys, apple).map((k, i) => (
                        <Kbd key={`${k}-${i}`}>{k}</Kbd>
                      ))}
                    </dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
        <p className="text-muted-foreground text-xs">
          The histogram takes arrow keys, Shift+arrows to extend a range, Enter to apply and Escape to clear.
        </p>
      </DialogContent>
    </Dialog>
  );
}
