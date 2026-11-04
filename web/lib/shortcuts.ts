/** Keyboard shortcut parsing and multi-key sequence matching (e.g. `g t`). */
export interface KeyLike {
  key: string;
  ctrlKey: boolean;
  metaKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
}

export interface ShortcutDef {
  keys: string;
  description: string;
  group: string;
}

/** Shortcuts the application binds; listed in the `?` sheet. */
export const GLOBAL_SHORTCUTS: ShortcutDef[] = [
  { keys: "mod+k", description: "Open command palette", group: "General" },
  { keys: "?", description: "Show keyboard shortcuts", group: "General" },
  { keys: "/", description: "Focus search", group: "General" },
  { keys: "escape", description: "Close dialog or drawer", group: "General" },
  { keys: "g c", description: "Go to cases", group: "Navigation" },
  { keys: "g d", description: "Go to case dashboard", group: "Navigation" },
  { keys: "g e", description: "Go to evidence", group: "Navigation" },
  { keys: "g t", description: "Go to timeline", group: "Navigation" },
  { keys: "g f", description: "Go to findings", group: "Navigation" },
  { keys: "g i", description: "Go to IOCs", group: "Navigation" },
  { keys: "g r", description: "Go to reports", group: "Navigation" },
  { keys: "g l", description: "Go to custody ledger", group: "Navigation" },
  { keys: "j", description: "Select next row", group: "Tables" },
  { keys: "k", description: "Select previous row", group: "Tables" },
  { keys: "enter", description: "Open selected row", group: "Tables" },
  { keys: "b", description: "Bookmark selected event", group: "Timeline" },
];

/** Canonical name of a key press: `mod+k`, `shift+arrowup`, `?`, `g`. `mod` is Ctrl or Cmd. */
export function normalizeKey(e: KeyLike): string {
  const key = e.key.toLowerCase();
  const parts: string[] = [];
  if (e.ctrlKey || e.metaKey) parts.push("mod");
  if (e.altKey) parts.push("alt");
  // Shift is implied by printable symbols such as "?"; only record it for named keys.
  if (e.shiftKey && e.key.length > 1) parts.push("shift");
  parts.push(key === " " ? "space" : key);
  return parts.join("+");
}

export function isEditableTarget(target: EventTarget | null): boolean {
  if (!target || typeof (target as HTMLElement).tagName !== "string") return false;
  const el = target as HTMLElement;
  const tag = el.tagName.toLowerCase();
  if (tag === "textarea" || tag === "select") return true;
  if (tag === "input") {
    const type = ((el as HTMLInputElement).type || "text").toLowerCase();
    return !["button", "checkbox", "radio", "submit", "reset", "range", "color", "file"].includes(type);
  }
  return el.isContentEditable || el.getAttribute("contenteditable") === "true";
}

const INTERACTIVE =
  'a[href],button,summary,select,input,textarea,[role="button"],[role="link"],[role="menuitem"],[role="tab"],[role="option"],[role="checkbox"],[role="switch"],[role="slider"],[role="treeitem"],[contenteditable="true"]';

/** Elements whose own Enter/Space activation must not be replaced by a shortcut. */
export function isInteractiveTarget(target: EventTarget | null): boolean {
  const el = target as Element | null;
  return !!el && typeof el.closest === "function" && el.closest(INTERACTIVE) !== null;
}

export interface MatchResult {
  match: string | null;
  pending: boolean;
}

/**
 * Feeds normalized keys and reports when a binding (space-separated sequence) completes.
 * A prefix of a longer binding is held for `timeoutMs`; an unrelated key resets the buffer.
 */
export class SequenceMatcher {
  private buffer: string[] = [];
  private last = Number.NEGATIVE_INFINITY;
  private readonly bindings: string[][];
  private readonly timeoutMs: number;

  constructor(bindings: string[], timeoutMs = 1200) {
    this.bindings = bindings.map((b) => b.toLowerCase().split(" ").filter(Boolean));
    this.timeoutMs = timeoutMs;
  }

  reset(): void {
    this.buffer = [];
  }

  feed(key: string, now: number): MatchResult {
    if (now - this.last > this.timeoutMs) this.buffer = [];
    this.last = now;
    const k = key.toLowerCase();
    const candidates = this.buffer.length ? [[...this.buffer, k], [k]] : [[k]];
    for (const candidate of candidates) {
      const exact = this.bindings.find(
        (b) => b.length === candidate.length && b.every((x, i) => x === candidate[i]),
      );
      if (exact) {
        this.buffer = [];
        return { match: exact.join(" "), pending: false };
      }
      const prefix = this.bindings.some(
        (b) => b.length > candidate.length && candidate.every((x, i) => b[i] === x),
      );
      if (prefix) {
        this.buffer = candidate;
        return { match: null, pending: true };
      }
    }
    this.buffer = [];
    return { match: null, pending: false };
  }
}

function keyName(k: string, apple: boolean): string {
  if (k === "mod") return apple ? "⌘" : "Ctrl";
  if (k.length === 1) return k.toUpperCase();
  return k.charAt(0).toUpperCase() + k.slice(1);
}

/** Human-readable label for each chord of a binding, e.g. `mod+k` -> [`Ctrl K`]. */
export function shortcutLabel(keys: string, apple = false): string[] {
  return keys.split(" ").map((chord) =>
    chord
      .split("+")
      .map((k) => keyName(k, apple))
      .join(" "),
  );
}

/** Next selection index for j/k navigation, clamped to the list. */
export function stepSelection(current: number | null, delta: number, length: number): number | null {
  if (length <= 0) return null;
  if (current === null) return delta > 0 ? 0 : length - 1;
  return Math.min(length - 1, Math.max(0, current + delta));
}
