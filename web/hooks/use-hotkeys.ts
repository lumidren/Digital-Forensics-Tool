"use client";

import { useEffect, useRef } from "react";
import { isEditableTarget, isInteractiveTarget, normalizeKey, SequenceMatcher } from "@/lib/shortcuts";

export type HotkeyHandler = (e: KeyboardEvent) => void;

export interface HotkeyOptions {
  enabled?: boolean;
  /** Page-scoped bindings are suspended while a modal dialog is open. */
  scope?: "global" | "page";
  target?: Window | null;
}

/** Bindings that still fire while focus is in a text field. */
const ALWAYS = new Set(["mod+k", "escape"]);

export function modalOpen(doc: Document): boolean {
  return (
    doc.querySelector('[role="dialog"][data-state="open"], [role="alertdialog"][data-state="open"]') !== null
  );
}

/**
 * Bind keyboard shortcuts. Keys are normalized (`mod+k`, `?`, `j`) and may be sequences (`g t`).
 * Handlers are read through a ref so callers can pass inline closures without re-binding.
 */
export function useHotkeys(bindings: Record<string, HotkeyHandler>, opts: HotkeyOptions = {}): void {
  const { enabled = true, scope = "page" } = opts;
  const target = opts.target === undefined ? (typeof window === "undefined" ? null : window) : opts.target;
  const handlers = useRef(bindings);
  handlers.current = bindings;
  const signature = Object.keys(bindings).sort().join("|");

  useEffect(() => {
    if (!enabled || !target) return;
    const matcher = new SequenceMatcher(signature.split("|").filter(Boolean));
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.isComposing) return;
      const key = normalizeKey(e);
      if (key === "shift" || key === "control" || key === "meta" || key === "alt") return;
      const editable = isEditableTarget(e.target);
      if (editable && !ALWAYS.has(key)) return;
      if (scope === "page" && modalOpen(document)) return;
      if ((key === "enter" || key === "space") && isInteractiveTarget(e.target)) return;
      const { match } = matcher.feed(key, e.timeStamp || performance.now());
      if (!match) return;
      const fn = handlers.current[match];
      if (fn) {
        e.preventDefault();
        fn(e);
      }
    };
    target.addEventListener("keydown", onKey as EventListener);
    return () => target.removeEventListener("keydown", onKey as EventListener);
  }, [enabled, scope, signature, target]);
}
