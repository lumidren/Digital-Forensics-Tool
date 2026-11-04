import { describe, expect, it } from "vitest";
import {
  addPivot,
  attrFilterValue,
  EMPTY_FILTERS,
  filterChips,
  filtersFromParams,
  filtersFromUnknown,
  filtersToParams,
  hasFilters,
  pivotableFields,
  toSearchBody,
  type TimelineFilters,
} from "./filters";
import type { TimelineEvent } from "./types";

const full: TimelineFilters = {
  text: "  mimikatz ",
  start_ns: 1_710_406_800_000_000_000,
  end_ns: 1_710_410_400_000_000_000,
  data_types: ["windows:evtx:record"],
  hosts: ["WS01", "FS01"],
  users: ["bob"],
  evidence: ["ab".repeat(32)],
  parsers: ["evtx"],
  attr_equals: { event_identifier: "4624", "event_data.LogonType": "3" },
};

describe("toSearchBody", () => {
  it("omits empty fields", () => {
    expect(toSearchBody(EMPTY_FILTERS)).toEqual({});
  });
  it("serializes every filter and paging option", () => {
    expect(toSearchBody(full, { limit: 500, offset: 1000, unmask: true, descending: true })).toEqual({
      text: "mimikatz",
      start_ns: full.start_ns,
      end_ns: full.end_ns,
      data_types: ["windows:evtx:record"],
      hosts: ["WS01", "FS01"],
      users: ["bob"],
      evidence: ["ab".repeat(32)],
      parsers: ["evtx"],
      attr_equals: { event_identifier: "4624", "event_data.LogonType": "3" },
      limit: 500,
      offset: 1000,
      unmask: true,
      descending: true,
    });
  });
  it("keeps exact nanosecond integers when stringified", () => {
    expect(JSON.stringify(toSearchBody(full))).toContain('"start_ns":1710406800000000000');
  });
});

describe("URL round trip", () => {
  it("round-trips through query parameters", () => {
    const p = filtersToParams(full);
    expect(p.getAll("host")).toEqual(["WS01", "FS01"]);
    expect(p.getAll("attr")).toEqual(["event_data.LogonType=3", "event_identifier=4624"]);
    const back = filtersFromParams(new URLSearchParams(p.toString()));
    expect(back).toEqual({ ...full, text: "mimikatz" });
  });
  it("ignores malformed parameters and duplicates", () => {
    const f = filtersFromParams(
      new URLSearchParams("from=abc&to=12&host=a&host=a&attr=novalue&attr==x&attr=k=v=w"),
    );
    expect(f.start_ns).toBeNull();
    expect(f.end_ns).toBe(12);
    expect(f.hosts).toEqual(["a"]);
    expect(f.attr_equals).toEqual({ k: "v=w" });
  });
  it("detects whether any filter is active", () => {
    expect(hasFilters(EMPTY_FILTERS)).toBe(false);
    expect(hasFilters({ ...EMPTY_FILTERS, users: ["x"] })).toBe(true);
  });
});

describe("saved view parsing", () => {
  it("keeps only well-formed fields", () => {
    expect(filtersFromUnknown({})).toEqual(EMPTY_FILTERS);
    expect(
      filtersFromUnknown({
        text: "x",
        start_ns: 5,
        end_ns: "bad",
        hosts: ["a", 3],
        attr_equals: { a: "1", b: 2 },
        users: "nope",
      }),
    ).toEqual({ ...EMPTY_FILTERS, text: "x", start_ns: 5, hosts: ["a"], attr_equals: { a: "1" } });
  });
});

describe("pivots and chips", () => {
  it("adds column and attribute pivots without duplicates", () => {
    const a = addPivot(EMPTY_FILTERS, "host", "WS01");
    expect(a.hosts).toEqual(["WS01"]);
    expect(addPivot(a, "host", "WS01")).toBe(a);
    const b = addPivot(a, "attrs.event_identifier", "4624");
    expect(b.attr_equals).toEqual({ event_identifier: "4624" });
    expect(addPivot(b, "attrs.event_identifier", "4624")).toBe(b);
    expect(addPivot(b, "attrs.", "x")).toBe(b);
    expect(addPivot(b, "message", "x")).toBe(b);
    expect(addPivot(b, "evidence_sha256", "ff").evidence).toEqual(["ff"]);
  });

  it("lists removable chips", () => {
    const chips = filterChips(full, (ns) => `t${ns}`);
    expect(chips.map((c) => c.key)).toEqual([
      "q",
      "from",
      "to",
      "data_types:windows:evtx:record",
      "hosts:WS01",
      "hosts:FS01",
      "users:bob",
      `evidence:${"ab".repeat(32)}`,
      "parsers:evtx",
      "attr:event_identifier",
      "attr:event_data.LogonType",
    ]);
    let f = full;
    for (const c of filterChips(full, String)) f = c.remove(f);
    expect(f).toEqual(EMPTY_FILTERS);
  });

  it("enumerates pivotable event fields and attribute values", () => {
    const e = {
      id: 1,
      data_type: "windows:evtx:record",
      host: "WS01",
      user: "bob",
      parser: "evtx",
      evidence_sha256: "ff",
    } as TimelineEvent;
    expect(pivotableFields(e).map((p) => p.column)).toEqual([
      "data_type",
      "host",
      "user",
      "parser",
      "evidence_sha256",
    ]);
    expect(
      pivotableFields({ ...e, host: undefined, user: undefined, parser: "", evidence_sha256: "" }).length,
    ).toBe(1);
    expect(attrFilterValue("a")).toBe("a");
    expect(attrFilterValue(4624)).toBe("4624");
    expect(attrFilterValue(true)).toBe("1");
    expect(attrFilterValue(false)).toBe("0");
    expect(attrFilterValue(Number.NaN)).toBeNull();
    expect(attrFilterValue({ a: 1 })).toBeNull();
    expect(attrFilterValue(null)).toBeNull();
  });
});
