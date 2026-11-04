import { describe, expect, it } from "vitest";
import {
  GLOBAL_SHORTCUTS,
  isEditableTarget,
  isInteractiveTarget,
  normalizeKey,
  SequenceMatcher,
  shortcutLabel,
  stepSelection,
} from "./shortcuts";

const key = (
  k: string,
  mods: Partial<{ ctrlKey: boolean; metaKey: boolean; altKey: boolean; shiftKey: boolean }> = {},
) => ({
  key: k,
  ctrlKey: false,
  metaKey: false,
  altKey: false,
  shiftKey: false,
  ...mods,
});

describe("normalizeKey", () => {
  it("normalizes modifiers and printable keys", () => {
    expect(normalizeKey(key("k", { ctrlKey: true }))).toBe("mod+k");
    expect(normalizeKey(key("K", { metaKey: true }))).toBe("mod+k");
    expect(normalizeKey(key("?", { shiftKey: true }))).toBe("?");
    expect(normalizeKey(key("ArrowUp", { shiftKey: true }))).toBe("shift+arrowup");
    expect(normalizeKey(key("x", { altKey: true }))).toBe("alt+x");
    expect(normalizeKey(key(" "))).toBe("space");
    expect(normalizeKey(key("Enter"))).toBe("enter");
  });
});

describe("isEditableTarget", () => {
  it("detects text inputs, textareas, selects and contenteditable", () => {
    const text = document.createElement("input");
    const check = document.createElement("input");
    check.type = "checkbox";
    const div = document.createElement("div");
    const editable = document.createElement("div");
    editable.setAttribute("contenteditable", "true");
    expect(isEditableTarget(text)).toBe(true);
    expect(isEditableTarget(check)).toBe(false);
    expect(isEditableTarget(document.createElement("textarea"))).toBe(true);
    expect(isEditableTarget(document.createElement("select"))).toBe(true);
    expect(isEditableTarget(div)).toBe(false);
    expect(isEditableTarget(editable)).toBe(true);
    expect(isEditableTarget(null)).toBe(false);
    expect(isEditableTarget(window)).toBe(false);
  });
});

describe("isInteractiveTarget", () => {
  it("recognizes controls and their descendants", () => {
    const button = document.createElement("button");
    const icon = document.createElement("span");
    button.appendChild(icon);
    const link = document.createElement("a");
    link.href = "#x";
    const row = document.createElement("div");
    row.setAttribute("role", "row");
    expect(isInteractiveTarget(button)).toBe(true);
    expect(isInteractiveTarget(icon)).toBe(true);
    expect(isInteractiveTarget(link)).toBe(true);
    expect(isInteractiveTarget(row)).toBe(false);
    expect(isInteractiveTarget(document.body)).toBe(false);
    expect(isInteractiveTarget(null)).toBe(false);
    expect(isInteractiveTarget(window)).toBe(false);
  });
});

describe("SequenceMatcher", () => {
  it("matches single keys and two-key sequences", () => {
    const m = new SequenceMatcher(["g t", "g c", "j", "?"], 1000);
    expect(m.feed("j", 0)).toEqual({ match: "j", pending: false });
    expect(m.feed("g", 10)).toEqual({ match: null, pending: true });
    expect(m.feed("t", 20)).toEqual({ match: "g t", pending: false });
    expect(m.feed("?", 30).match).toBe("?");
  });

  it("drops a stale prefix after the timeout", () => {
    const m = new SequenceMatcher(["g t"], 500);
    m.feed("g", 0);
    expect(m.feed("t", 2000)).toEqual({ match: null, pending: false });
  });

  it("restarts from an unrelated key and supports reset", () => {
    const m = new SequenceMatcher(["g t", "j"], 1000);
    m.feed("g", 0);
    expect(m.feed("j", 10).match).toBe("j");
    m.feed("g", 20);
    m.reset();
    expect(m.feed("t", 30).match).toBeNull();
    m.feed("g", 40);
    expect(m.feed("g", 50)).toEqual({ match: null, pending: true });
    expect(m.feed("x", 60)).toEqual({ match: null, pending: false });
  });
});

describe("shortcutLabel and stepSelection", () => {
  it("renders chords", () => {
    expect(shortcutLabel("mod+k")).toEqual(["Ctrl K"]);
    expect(shortcutLabel("mod+k", true)).toEqual(["⌘ K"]);
    expect(shortcutLabel("g t")).toEqual(["G", "T"]);
    expect(shortcutLabel("escape")).toEqual(["Escape"]);
  });

  it("clamps selection", () => {
    expect(stepSelection(null, 1, 0)).toBeNull();
    expect(stepSelection(null, 1, 5)).toBe(0);
    expect(stepSelection(null, -1, 5)).toBe(4);
    expect(stepSelection(4, 1, 5)).toBe(4);
    expect(stepSelection(0, -1, 5)).toBe(0);
    expect(stepSelection(2, 1, 5)).toBe(3);
  });

  it("documents every navigation shortcut", () => {
    for (const k of ["mod+k", "?", "/", "g c", "g t", "g f", "j", "k", "b"]) {
      expect(GLOBAL_SHORTCUTS.some((s) => s.keys === k)).toBe(true);
    }
  });
});
