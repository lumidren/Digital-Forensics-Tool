import { describe, expect, it, vi } from "vitest";
import {
  asList,
  asRecord,
  pick,
  siFnComparison,
  timestompIndicators,
  usnReasons,
  viewerKind,
} from "./artifacts";
import { oidcConfig } from "./config";
import { copyText, saveBlob, sha256Hex, toHex, verifyCommand } from "./download";
import { distinct, filterFindings, groupByState, parseIdList, parseTechniques } from "./findings";
import {
  formatBytes,
  formatDate,
  formatDuration,
  formatNs,
  formatNsShort,
  formatPercent,
  isoToNs,
  nsToInput,
  shortHash,
  stringifyValue,
} from "./format";
import { activeSection, caseIdFromPath, forgetCase, lastCase, rememberCase, shortcutTarget } from "./nav";
import { pageOf, pagesForRange } from "./paging";
import type { Finding } from "./types";
import { cn } from "./utils";

const S = 1_000_000_000;

describe("format", () => {
  it("formats nanosecond timestamps with microseconds", () => {
    expect(formatNs(1_710_406_800 * S + 123_456_000)).toBe("2024-03-14T09:00:00.123456Z");
    expect(formatNs(null)).toBe("—");
    expect(formatNs(undefined)).toBe("—");
    expect(formatNs(Number.NaN)).toBe("—");
    expect(formatNs(1e30)).toBe("—");
    expect(formatNsShort(1_710_406_800 * S)).toBe("2024-03-14 09:00:00");
  });
  it("parses input times as UTC", () => {
    expect(isoToNs("2024-03-14T09:00:00")).toBe(1_710_406_800 * S);
    expect(isoToNs("2024-03-14T10:00:00+01:00")).toBe(1_710_406_800 * S);
    expect(isoToNs("2024-03-14T09:00:00Z")).toBe(1_710_406_800 * S);
    expect(isoToNs("")).toBeNull();
    expect(isoToNs("garbage")).toBeNull();
    expect(nsToInput(1_710_406_800 * S)).toBe("2024-03-14T09:00:00");
    expect(nsToInput(null)).toBe("");
  });
  it("formats sizes, durations, hashes, dates and values", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5.0 GiB");
    expect(formatBytes(-1)).toBe("—");
    expect(formatDuration(S)).toBe("1 s");
    expect(formatDuration(60 * S)).toBe("1 min");
    expect(formatDuration(3600 * S)).toBe("1 h");
    expect(formatDuration(86400 * S)).toBe("1 d");
    expect(shortHash("abcdef0123456789", 6)).toBe("abcdef…");
    expect(shortHash("abc")).toBe("abc");
    expect(shortHash(null)).toBe("—");
    expect(formatDate("2024-03-14T09:00:00.5+00:00")).toBe("2024-03-14 09:00:00Z");
    expect(formatDate(null)).toBe("—");
    expect(formatDate("not a date")).toBe("not a date");
    expect(formatPercent(0.456)).toBe("46%");
    expect(formatPercent(2)).toBe("100%");
    expect(stringifyValue(null)).toBe("");
    expect(stringifyValue("x")).toBe("x");
    expect(stringifyValue(3)).toBe("3");
    expect(stringifyValue(false)).toBe("false");
    expect(stringifyValue({ a: [1] })).toBe('{"a":[1]}');
  });
});

describe("artifacts", () => {
  it("classifies data types into viewers", () => {
    const cases: [string, string][] = [
      ["windows:evtx:record", "evtx"],
      ["windows:evt:record", "evtx"],
      ["windows:prefetch:execution", "prefetch"],
      ["windows:registry:run", "registry"],
      ["windows:lnk:link", "lnk"],
      ["windows:jump_list:automatic_destination", "lnk"],
      ["chrome:history:file_downloaded", "browser"],
      ["fs:ntfs:usn_change", "usn"],
      ["fs:stat:ntfs", "fs"],
      ["memory:process", "memory-process"],
      ["memory:process:cmdline", "memory-process"],
      ["memory:network:connection", "memory-network"],
      ["memory:injection", "memory-injection"],
      ["memory:module", "memory"],
      ["network:dns", "network"],
      ["aws:cloudtrail:entry", "cloud"],
      ["m365:ual:entry", "cloud"],
      ["text:line", "generic"],
    ];
    for (const [dt, kind] of cases) expect(viewerKind(dt)).toBe(kind);
  });
  it("picks attributes and normalizes lists", () => {
    expect(pick({ a: "", b: null, c: 0 }, "a", "b", "c")).toBe(0);
    expect(pick({}, "a")).toBeUndefined();
    expect(asRecord({ x: 1 })).toEqual({ x: 1 });
    expect(asRecord([1])).toBeNull();
    expect(asRecord(undefined)).toBeNull();
    expect(asList([1, 2])).toEqual([1, 2]);
    expect(asList("a")).toEqual(["a"]);
    expect(asList(undefined)).toEqual([]);
    expect(asList(null)).toEqual([]);
  });
  it("flags SI/FN timestamp inconsistencies", () => {
    const attrs = {
      si_crtime_ns: 10 * S,
      fn_crtime_ns: 20 * S + 5,
      si_mtime: 30 * S,
      fn_mtime: 30 * S,
      si_atime_ns: "7",
    };
    const rows = siFnComparison(attrs);
    expect(rows.map((r) => r.field)).toEqual(["crtime", "mtime", "atime"]);
    expect(rows[0]?.flags).toEqual(["SI earlier than FN", "SI has zero sub-second precision"]);
    expect(rows[1]?.flags).toEqual([]);
    expect(rows[2]).toEqual({ field: "atime", si: 7, fn: null, flags: [] });
    expect(timestompIndicators({ ...attrs, timestomp_indicators: ["si_before_fn"] })).toEqual([
      "si_before_fn",
      "Created: SI earlier than FN",
      "Created: SI has zero sub-second precision",
    ]);
  });
  it("splits USN reasons", () => {
    expect(usnReasons({ update_reason_flags: "FILE_DELETE|CLOSE" })).toEqual(["FILE_DELETE", "CLOSE"]);
    expect(usnReasons({ reasons: ["A", "B"] })).toEqual(["A", "B"]);
    expect(usnReasons({})).toEqual([]);
  });
});

describe("config", () => {
  it("enables OIDC only when an issuer is configured", () => {
    expect(oidcConfig({})).toBeNull();
    expect(oidcConfig({ NEXT_PUBLIC_OIDC_ISSUER: " " })).toBeNull();
    expect(oidcConfig({ NEXT_PUBLIC_OIDC_ISSUER: "https://idp.test/realms/x/" })).toEqual({
      issuer: "https://idp.test/realms/x",
      clientId: "veritas-web",
      scope: "openid profile email",
    });
    expect(
      oidcConfig({
        NEXT_PUBLIC_OIDC_ISSUER: "https://idp",
        NEXT_PUBLIC_OIDC_CLIENT_ID: "c",
        NEXT_PUBLIC_OIDC_SCOPE: "openid",
      }),
    ).toEqual({
      issuer: "https://idp",
      clientId: "c",
      scope: "openid",
    });
    expect(oidcConfig()).toBeNull();
  });
});

describe("download helpers", () => {
  it("hashes blobs and buffers", async () => {
    const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(await sha256Hex(new ArrayBuffer(0))).toBe(empty);
    expect(await sha256Hex(new Blob(["abc"]))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(toHex(new Uint8Array([0, 15, 255]).buffer)).toBe("000fff");
  });
  it("saves a blob through a temporary link", () => {
    vi.useFakeTimers();
    const create = vi.fn(() => "blob:x");
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    saveBlob(new Blob(["x"]), "a.txt");
    expect(click).toHaveBeenCalledOnce();
    expect(document.querySelector("a[download]")).toBeNull();
    vi.runAllTimers();
    expect(revoke).toHaveBeenCalledWith("blob:x");
    vi.useRealTimers();
  });
  it("copies text and reports failure", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    expect(await copyText("x", { writeText })).toBe(true);
    expect(await copyText("x", { writeText: () => Promise.reject(new Error("denied")) })).toBe(false);
    expect(await copyText("x", undefined)).toBe(false);
  });
  it("builds the verifier command with safe quoting", () => {
    expect(verifyCommand("C-1-custody.json")).toBe("veritas-verify export C-1-custody.json");
    expect(verifyCommand("my file$.json")).toBe('veritas-verify export "my file\\$.json"');
  });
});

describe("findings helpers", () => {
  const f = (over: Partial<Finding>) =>
    ({
      severity: "high",
      rule: "lateral_movement",
      attack_techniques: ["T1021.002"],
      state: "proposed",
      ...over,
    }) as Finding;
  const items = [
    f({ id: "a" }),
    f({ id: "b", severity: "low", rule: "execution", attack_techniques: ["T1003.001"], state: "approved" }),
  ];
  it("filters by severity, rule and technique prefix", () => {
    expect(filterFindings(items, { severity: "", rule: "", technique: "" })).toHaveLength(2);
    expect(filterFindings(items, { severity: "low", rule: "", technique: "" }).map((x) => x.id)).toEqual([
      "b",
    ]);
    expect(
      filterFindings(items, { severity: "", rule: "lateral_movement", technique: "" }).map((x) => x.id),
    ).toEqual(["a"]);
    expect(filterFindings(items, { severity: "", rule: "", technique: "t1003" }).map((x) => x.id)).toEqual([
      "b",
    ]);
  });
  it("groups in workflow order and lists distinct values", () => {
    expect(groupByState(items).map((g) => [g.state, g.items.length])).toEqual([
      ["proposed", 1],
      ["confirmed", 0],
      ["approved", 1],
      ["rejected", 0],
    ]);
    expect(distinct(items, (x) => x.attack_techniques)).toEqual(["T1003.001", "T1021.002"]);
  });
  it("parses id and technique lists", () => {
    expect(parseIdList("1, 2 2;3")).toEqual([1, 2, 3]);
    expect(parseIdList("")).toEqual([]);
    expect(parseIdList("1, x")).toBeNull();
    expect(parseTechniques("t1021.002, T1078 junk T12")).toEqual(["T1021.002", "T1078"]);
  });
});

describe("nav and paging", () => {
  it("parses case paths", () => {
    expect(caseIdFromPath("/cases/C-1/timeline")).toBe("C-1");
    expect(caseIdFromPath("/cases/C%201")).toBe("C 1");
    expect(caseIdFromPath("/cases")).toBeNull();
    expect(caseIdFromPath(null)).toBeNull();
    expect(activeSection("/cases/C-1")).toBe("dashboard");
    expect(activeSection("/cases/C-1/findings")).toBe("findings");
    expect(activeSection("/admin")).toBeNull();
  });
  it("resolves g-sequences", () => {
    expect(shortcutTarget("g c", null)).toBe("/cases");
    expect(shortcutTarget("g t", "C 1")).toBe("/cases/C%201/timeline");
    expect(shortcutTarget("g f", null)).toBe("/cases");
    expect(shortcutTarget("g z", "C-1")).toBeNull();
  });
  it("remembers the last case in session storage", () => {
    rememberCase("C-7");
    expect(lastCase()).toBe("C-7");
    forgetCase();
    expect(lastCase()).toBeNull();
    expect(lastCase(null)).toBeNull();
  });
  it("computes pages for a visible row range", () => {
    expect(pagesForRange(0, 10, 0)).toEqual([]);
    expect(pagesForRange(0, 10, 100, 50)).toEqual([0]);
    expect(pagesForRange(40, 160, 1000, 50)).toEqual([0, 1, 2, 3]);
    expect(pagesForRange(990, 2000, 1000, 50)).toEqual([19]);
    expect(pageOf(1234, 500)).toEqual({ page: 2, offset: 234 });
    expect(pageOf(7)).toEqual({ page: 0, offset: 7 });
  });
  it("merges class names", () => {
    expect(cn("px-2", false, "px-4", "text-sm")).toBe("px-4 text-sm");
  });
});
