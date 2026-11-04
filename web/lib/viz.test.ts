import { describe, expect, it } from "vitest";
import {
  attackUrl,
  maxSeverity,
  primaryTactic,
  TACTICS,
  tacticColor,
  tacticMatrix,
  tacticName,
  techniqueInfo,
} from "./attack";
import {
  areaPath,
  axisTicks,
  barPercent,
  compactNumber,
  cumulativeSeries,
  donutArcs,
  downsample,
  linePath,
  niceMax,
  ringSegment,
  stackBuckets,
  toPoints,
  topWithOther,
} from "./charts";
import {
  categoryByKey,
  DATA_CATEGORIES,
  dataTypeCategory,
  groupDataTypes,
  OTHER_CATEGORY,
} from "./data-types";
import { aggregateEdges, classifyHost, edgeFamily, hostKindLabel, isIpAddress, isPrivateIp } from "./graph";
import { layoutGraph } from "./graph-layout";
import type { Finding, LateralEdge } from "./types";

const finding = (over: Partial<Finding>): Finding => ({
  id: "f",
  case_id: "C-1",
  rule: "r",
  title: "t",
  description: "",
  severity: "medium",
  confidence: 1,
  category: "c",
  attack_techniques: [],
  event_ids: [],
  evidence_sha256: [],
  details: {},
  first_ns: null,
  last_ns: null,
  state: "proposed",
  origin: "rule",
  confirmed_by: null,
  confirmed_at: null,
  approved_by: null,
  approved_at: null,
  examiner_rationale: null,
  reviewer_comment: null,
  ...over,
});

describe("ATT&CK mapping", () => {
  it("names techniques and sub-techniques and inherits parent tactics", () => {
    expect(techniqueInfo("T1021.002")).toEqual({
      id: "T1021.002",
      name: "Remote Services: SMB/Windows Admin Shares",
      short: "SMB/Windows Admin Shares",
      tactics: ["lateral-movement"],
      known: true,
    });
    expect(techniqueInfo(" t1078 ").tactics).toContain("initial-access");
    expect(techniqueInfo("T1078").short).toBe("Valid Accounts");
    // Unknown sub-technique of a known parent falls back to the parent name.
    expect(techniqueInfo("T1003.999").name).toBe("OS Credential Dumping");
    expect(techniqueInfo("T9999")).toMatchObject({ known: false, name: "T9999", tactics: [] });
  });

  it("resolves the primary tactic, colour and URL", () => {
    expect(primaryTactic("T1003.001")?.name).toBe("Credential Access");
    expect(primaryTactic("T9999")).toBeNull();
    expect(attackUrl("t1021.002")).toBe("https://attack.mitre.org/techniques/T1021/002/");
    expect(tacticColor("lateral-movement")).toBe("var(--cat-1)");
    expect(tacticColor("impact")).toBe("var(--cat-other)");
    expect(tacticName("execution")).toBe("Execution");
    expect(tacticName("nope")).toBe("Other");
    expect(TACTICS).toHaveLength(14);
  });

  it("keeps the most severe severity", () => {
    expect(maxSeverity("high", "critical")).toBe("critical");
    expect(maxSeverity("low", "info")).toBe("low");
  });

  it("builds the tactic matrix from live findings only", () => {
    const { columns, unmapped } = tacticMatrix([
      finding({ id: "a", severity: "high", attack_techniques: ["T1021.002", "T1550.002"] }),
      finding({ id: "b", severity: "critical", state: "confirmed", attack_techniques: ["t1021.002"] }),
      finding({ id: "c", severity: "critical", state: "rejected", attack_techniques: ["T1486"] }),
      finding({ id: "d", severity: "low", attack_techniques: ["T4242", "T4242"] }),
    ]);
    const lateral = columns.find((c) => c.tactic.key === "lateral-movement");
    expect(lateral?.findings).toBe(2);
    expect(lateral?.techniques[0]).toEqual({
      id: "T1021.002",
      name: "SMB/Windows Admin Shares",
      findings: 2,
      severity: "critical",
    });
    expect(lateral?.techniques.map((t) => t.id)).toEqual(["T1021.002", "T1550.002"]);
    expect(columns.find((c) => c.tactic.key === "defense-evasion")?.techniques).toHaveLength(1);
    expect(columns.find((c) => c.tactic.key === "impact")?.techniques).toEqual([]);
    expect(unmapped).toEqual([{ id: "T4242", name: "T4242", findings: 1, severity: "low" }]);
    expect(columns.map((c) => c.tactic.key)).toEqual(TACTICS.map((t) => t.key));
  });
});

describe("chart data shaping", () => {
  it("computes nice maxima and ticks", () => {
    expect(niceMax(0)).toBe(0);
    expect(niceMax(-3)).toBe(0);
    expect(niceMax(1)).toBe(1);
    expect(niceMax(7)).toBe(10);
    expect(niceMax(13)).toBe(20);
    expect(niceMax(220)).toBe(250);
    expect(niceMax(2004)).toBe(2500);
    expect(niceMax(4100)).toBe(5000);
    expect(axisTicks(0)).toEqual([0]);
    expect(axisTicks(90, 2)).toEqual([0, 50, 100]);
  });

  it("downsamples by summing adjacent buckets", () => {
    const b = [1, 2, 3, 4, 5].map((c, i) => ({ start_ns: i * 10, count: c }));
    expect(downsample(b, 10)).toBe(b);
    expect(downsample(b, 2)).toEqual([
      { start_ns: 0, count: 6 },
      { start_ns: 30, count: 9 },
    ]);
    expect(downsample(b, 0)).toEqual([]);
  });

  it("maps values to points and paths", () => {
    const pts = toPoints([0, 5, 10], 100, 50);
    expect(pts).toEqual([
      { x: 0, y: 50 },
      { x: 50, y: 25 },
      { x: 100, y: 0 },
    ]);
    expect(toPoints([3], 100, 50, 0)).toEqual([{ x: 50, y: 50 }]);
    expect(linePath(pts)).toBe("M0,50 L50,25 L100,0");
    expect(areaPath(pts, 50)).toBe("M0,50 L50,25 L100,0 L100,50 L0,50 Z");
    expect(areaPath([], 50)).toBe("");
  });

  it("builds cumulative series", () => {
    expect(cumulativeSeries([], 4)).toEqual([]);
    expect(cumulativeSeries([5, 5], 3)).toEqual([0, 0, 2]);
    expect(cumulativeSeries([0, 10, 5, Number.NaN], 2)).toEqual([1, 3]);
  });

  it("draws donut arcs with gaps and skips empty slices", () => {
    const arcs = donutArcs(
      [
        { key: "a", value: 1 },
        { key: "b", value: 0 },
        { key: "c", value: 3 },
      ],
      { cx: 50, cy: 50, outer: 40, inner: 28 },
    );
    expect(arcs.map((a) => a.key)).toEqual(["a", "c"]);
    expect(arcs[0]?.fraction).toBeCloseTo(0.25);
    expect(arcs[1]?.end).toBeCloseTo(Math.PI * 2);
    expect(arcs[0]?.path.startsWith("M")).toBe(true);
    const single = donutArcs([{ key: "x", value: 2 }], { cx: 0, cy: 0, outer: 10, inner: 5 });
    expect(single).toHaveLength(1);
    expect(single[0]?.path.split("M")).toHaveLength(3); // full ring = two half arcs
    expect(donutArcs([{ key: "x", value: 0 }], { cx: 0, cy: 0, outer: 1, inner: 0 })).toEqual([]);
    expect(ringSegment(0, 0, 10, 5, 1, 1)).toBe("");
    expect(ringSegment(0, 0, 10, 5, 0, 4)).toContain(" 0 1 1 ");
  });

  it("keeps the top values and folds the rest into Other", () => {
    const v = [
      { value: "b", count: 5 },
      { value: "a", count: 5 },
      { value: "c", count: 1 },
      { value: "", count: 99 },
      { value: "d", count: 2 },
    ];
    expect(topWithOther(v, 2)).toEqual([
      { label: "a", count: 5, other: false },
      { label: "b", count: 5, other: false },
      { label: "Other", count: 3, other: true },
    ]);
    expect(topWithOther(v, 10)).toHaveLength(4);
  });

  it("stacks layer histograms into the overall buckets", () => {
    const base = [
      { start_ns: 0, count: 10 },
      { start_ns: 1, count: 4 },
      { start_ns: 2, count: 0 },
    ];
    const stacked = stackBuckets(base, [
      [
        { start_ns: 0, count: 6 },
        { start_ns: 1, count: 9 },
      ],
      [{ start_ns: 0, count: 3 }],
    ]);
    expect(stacked).toEqual([
      { start_ns: 0, total: 10, layers: [6, 3], other: 1 },
      { start_ns: 1, total: 4, layers: [4, 0], other: 0 },
      { start_ns: 2, total: 0, layers: [0, 0], other: 0 },
    ]);
  });

  it("formats bars and compact numbers", () => {
    expect(barPercent(0, 10)).toBe(0);
    expect(barPercent(5, 0)).toBe(0);
    expect(barPercent(1, 1000)).toBe(2);
    expect(barPercent(5, 10)).toBe(50);
    expect(compactNumber(950)).toBe("950");
    expect(compactNumber(1234)).toBe("1.2k");
    expect(compactNumber(34_500)).toBe("35k");
    expect(compactNumber(1_500_000)).toBe("1.5M");
    expect(compactNumber(25_000_000)).toBe("25M");
  });
});

describe("data-type categories", () => {
  it("maps data types to fixed categories", () => {
    expect(dataTypeCategory("windows:evtx:record").key).toBe("eventlog");
    expect(dataTypeCategory("fs:stat:ntfs").key).toBe("filesystem");
    expect(dataTypeCategory("fs:ntfs:usn_change").key).toBe("filesystem");
    expect(dataTypeCategory("windows:prefetch:execution").key).toBe("execution");
    expect(dataTypeCategory("chrome:history:file_downloaded").key).toBe("browser");
    expect(dataTypeCategory("windows:registry:key_value").key).toBe("registry");
    expect(dataTypeCategory("memory:process").key).toBe("memory");
    expect(dataTypeCategory("pcap:flow").key).toBe("network");
    expect(dataTypeCategory("email:message").key).toBe("messaging");
    expect(dataTypeCategory("something:else")).toBe(OTHER_CATEGORY);
    expect(dataTypeCategory("")).toBe(OTHER_CATEGORY);
    expect(dataTypeCategory(undefined)).toBe(OTHER_CATEGORY);
    expect(categoryByKey("memory").color).toBe("var(--cat-7)");
    expect(categoryByKey("zzz")).toBe(OTHER_CATEGORY);
    expect(new Set(DATA_CATEGORIES.map((c) => c.color)).size).toBe(8);
  });

  it("groups facet values by category, largest first", () => {
    const groups = groupDataTypes([
      { value: "windows:evtx:record", count: 2000 },
      { value: "memory:process", count: 15 },
      { value: "fs:stat:ntfs", count: 1 },
      { value: "fs:ntfs:usn_change", count: 1 },
      { value: "mystery", count: 50 },
      { value: "", count: 3 },
    ]);
    expect(groups.map((g) => [g.category.key, g.count])).toEqual([
      ["eventlog", 2000],
      ["memory", 15],
      ["filesystem", 2],
    ]);
    expect(groups[2]?.dataTypes).toEqual(["fs:stat:ntfs", "fs:ntfs:usn_change"]);
    expect(groupDataTypes([{ value: "memory:x", count: 1 }], 0)).toEqual([]);
  });
});

describe("graph shaping", () => {
  const edge = (over: Partial<LateralEdge>): LateralEdge => ({
    src: "A",
    dst: "B",
    user: "",
    technique: "",
    kind: "k",
    count: 1,
    event_ids: [],
    first_ns: null,
    last_ns: null,
    ...over,
  });

  it("classifies hosts and addresses", () => {
    expect(classifyHost("remote")).toBe("remote");
    expect(classifyHost("10.0.0.66")).toBe("ip");
    expect(classifyHost("fe80::1:2")).toBe("ip");
    expect(classifyHost("FS01")).toBe("host");
    expect(isIpAddress("300.1.1.1")).toBe(false);
    expect(isPrivateIp("10.1.2.3")).toBe(true);
    expect(isPrivateIp("172.20.0.1")).toBe(true);
    expect(isPrivateIp("172.40.0.1")).toBe(false);
    expect(isPrivateIp("192.168.1.1")).toBe(true);
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("fd00::1")).toBe(true);
    expect(isPrivateIp("2001:db8::1")).toBe(false);
    expect(hostKindLabel("remote")).toMatch(/remote/);
    expect(hostKindLabel("8.8.8.8")).toBe("External IP address");
    expect(hostKindLabel("10.0.0.1")).toBe("Internal IP address");
    expect(hostKindLabel("WS01")).toBe("Host");
  });

  it("picks the dominant tactic family", () => {
    expect(edgeFamily([])).toBe("other");
    expect(edgeFamily(["T1021.002", "T1550.002"])).toBe("lateral-movement");
    expect(edgeFamily(["T1003", "T1021.001"])).toBe("lateral-movement");
    expect(edgeFamily(["T1003"])).toBe("credential-access");
    expect(edgeFamily(["T1078"])).toBe("initial-access");
    expect(edgeFamily(["T1486"])).toBe("impact");
  });

  it("aggregates parallel edges", () => {
    const agg = aggregateEdges([
      edge({
        src: "10.0.0.66",
        dst: "FS01",
        kind: "logon_type_3",
        technique: "T1021.002",
        user: "svc",
        count: 1,
        event_ids: [5],
        first_ns: 20,
        last_ns: 20,
      }),
      edge({
        src: "10.0.0.66",
        dst: "FS01",
        kind: "ntlm",
        technique: "T1550.002",
        user: "svc",
        count: 2,
        event_ids: [5, 6],
        first_ns: 10,
        last_ns: 30,
      }),
      edge({
        src: "10.0.0.66",
        dst: "FS01",
        kind: "ntlm",
        technique: "T1550.002",
        user: "",
        count: 1,
        first_ns: null,
        last_ns: null,
      }),
      edge({ src: "WS01", dst: "FS01", technique: "T1078" }),
    ]);
    expect(agg).toHaveLength(2);
    expect(agg[0]).toMatchObject({
      id: "e0",
      kinds: ["logon_type_3", "ntlm"],
      techniques: ["T1021.002", "T1550.002"],
      users: ["svc"],
      count: 4,
      event_ids: [5, 6],
      first_ns: 10,
      last_ns: 30,
      family: "lateral-movement",
    });
    expect(agg[1]?.family).toBe("initial-access");
  });

  it("lays out left to right with dagre", () => {
    const nodes = ["a", "b", "c"].map((id) => ({ id, width: 100, height: 40 }));
    const pos = layoutGraph(nodes, [
      { source: "a", target: "b" },
      { source: "b", target: "c" },
      { source: "c", target: "c" },
      { source: "a", target: "zzz" },
    ]);
    const xa = pos.get("a")?.x ?? 0;
    const xb = pos.get("b")?.x ?? 0;
    const xc = pos.get("c")?.x ?? 0;
    expect(xa).toBeLessThan(xb);
    expect(xb).toBeLessThan(xc);
    const tb = layoutGraph(nodes, [{ source: "a", target: "b" }], { rankdir: "TB" });
    expect(tb.get("a")?.y ?? 0).toBeLessThan(tb.get("b")?.y ?? 0);
    expect(layoutGraph([], []).size).toBe(0);
  });
});

describe("attribute grouping", () => {
  it("groups attributes by key tokens", async () => {
    const { groupAttributes } = await import("./data-types");
    const groups = groupAttributes({
      TargetUserName: "bob",
      logon_type: 3,
      source_network_address: "10.0.0.66",
      process_name: "psexesvc.exe",
      file_name: "a.exe",
      event_identifier: 4624,
      creation_time: "x",
      weird: true,
    });
    expect(groups.map((g) => [g.key, g.entries.map(([k]) => k)])).toEqual([
      ["identity", ["TargetUserName", "logon_type"]],
      ["process", ["process_name"]],
      ["network", ["source_network_address"]],
      ["file", ["file_name"]],
      ["time", ["creation_time"]],
      ["event", ["event_identifier"]],
      ["other", ["weird"]],
    ]);
    expect(groupAttributes({})).toEqual([]);
  });
});

describe("custody chain", () => {
  it("classifies links between consecutive entries", async () => {
    const { abbreviateHash, linkState } = await import("./custody");
    const e = (seq: number, hash: string, prev?: string) =>
      ({
        seq,
        ledger_id: "L",
        kind: "note",
        actor: "a",
        purpose: "",
        entry_hash: hash,
        prev_hash: prev,
      }) as const;
    expect(linkState(undefined, e(0, "a"))).toBe("start");
    expect(linkState(undefined, e(3, "d", "c"))).toBe("gap");
    expect(linkState(e(0, "a"), e(1, "b", "a"))).toBe("linked");
    expect(linkState(e(0, "a"), e(1, "b", "x"))).toBe("broken");
    expect(linkState(e(0, "a"), e(2, "c", "b"))).toBe("gap");
    expect(abbreviateHash(null)).toBe("—");
    expect(abbreviateHash("abc")).toBe("abc");
    expect(abbreviateHash("0123456789abcdefghijklmnop")).toBe("0123456789…klmnop");
  });
});
