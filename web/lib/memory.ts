/**
 * Process tree from `memory:*` timeline events (Volatility 3 rows normalized by the pipeline).
 *
 * Flags:
 * - `malfind`: a `memory:injection` row from malfind for the PID (injected, executable private memory).
 * - `hollowing`: a `memory:injection` row from hollowprocesses for the PID.
 * - `hidden`: seen by psscan (pool scanning) but absent from pslist (the active process list).
 * - `orphan`: the parent PID is not among the observed processes.
 */
import type { AttrValue, TimelineEvent } from "./types";

export type ProcessFlag = "malfind" | "hollowing" | "hidden" | "orphan";

export interface ProcessNode {
  pid: number;
  ppid: number | null;
  name: string;
  createNs: number | null;
  sources: string[];
  flags: ProcessFlag[];
  eventIds: number[];
  connections: number;
  children: ProcessNode[];
}

export interface ProcessTree {
  roots: ProcessNode[];
  byPid: Map<number, ProcessNode>;
  flagged: ProcessNode[];
}

function attr(attrs: Record<string, AttrValue>, ...keys: string[]): AttrValue | undefined {
  for (const k of keys) {
    const v = attrs[k];
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return undefined;
}

function toInt(v: AttrValue | undefined): number | null {
  if (typeof v === "number" && Number.isInteger(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return null;
}

function plugin(e: TimelineEvent): string {
  const p = e.attrs.plugin;
  return typeof p === "string" ? (p.split(".").pop() ?? p).toLowerCase() : "";
}

export function pidOf(e: TimelineEvent): number | null {
  return toInt(attr(e.attrs, "PID", "pid", "Pid"));
}

export function buildProcessTree(events: TimelineEvent[]): ProcessTree {
  const byPid = new Map<number, ProcessNode>();
  const pslist = new Set<number>();
  const psscan = new Set<number>();
  const injections: { pid: number; kind: ProcessFlag; id: number }[] = [];
  const connections = new Map<number, number>();

  for (const e of events) {
    const pid = pidOf(e);
    if (pid === null) continue;
    if (e.data_type === "memory:process") {
      const src = plugin(e);
      if (src === "pslist" || src === "pstree") pslist.add(pid);
      if (src === "psscan") psscan.add(pid);
      let node = byPid.get(pid);
      if (!node) {
        node = {
          pid,
          ppid: null,
          name: "",
          createNs: null,
          sources: [],
          flags: [],
          eventIds: [],
          connections: 0,
          children: [],
        };
        byPid.set(pid, node);
      }
      node.ppid ??= toInt(attr(e.attrs, "PPID", "ppid"));
      if (!node.name) {
        const name = attr(e.attrs, "ImageFileName", "Name", "COMM", "name");
        if (typeof name === "string") node.name = name;
      }
      if (e.timestamp !== null && (node.createNs === null || e.timestamp < node.createNs))
        node.createNs = e.timestamp;
      if (src && !node.sources.includes(src)) node.sources.push(src);
      node.eventIds.push(e.id);
    } else if (e.data_type === "memory:injection") {
      injections.push({ pid, kind: plugin(e).includes("hollow") ? "hollowing" : "malfind", id: e.id });
    } else if (e.data_type === "memory:network:connection") {
      connections.set(pid, (connections.get(pid) ?? 0) + 1);
    }
  }

  for (const inj of injections) {
    const node = byPid.get(inj.pid);
    if (!node) continue;
    if (!node.flags.includes(inj.kind)) node.flags.push(inj.kind);
    node.eventIds.push(inj.id);
  }
  const roots: ProcessNode[] = [];
  for (const node of byPid.values()) {
    node.connections = connections.get(node.pid) ?? 0;
    if (pslist.size > 0 && psscan.has(node.pid) && !pslist.has(node.pid)) node.flags.push("hidden");
    const parent = node.ppid !== null && node.ppid !== node.pid ? byPid.get(node.ppid) : undefined;
    if (parent) {
      parent.children.push(node);
    } else {
      if (node.ppid !== null && node.ppid !== 0 && node.ppid !== node.pid) node.flags.push("orphan");
      roots.push(node);
    }
  }
  const sortRec = (nodes: ProcessNode[]) => {
    nodes.sort((a, b) => a.pid - b.pid);
    for (const n of nodes) sortRec(n.children);
  };
  sortRec(roots);
  const flagged = [...byPid.values()]
    .filter((n) => n.flags.some((f) => f !== "orphan"))
    .sort((a, b) => a.pid - b.pid);
  return { roots, byPid, flagged };
}

/** Depth-first flattening for rendering a treegrid. */
export function flattenTree(
  roots: ProcessNode[],
  expanded: (pid: number) => boolean,
): { node: ProcessNode; depth: number }[] {
  const out: { node: ProcessNode; depth: number }[] = [];
  const walk = (nodes: ProcessNode[], depth: number) => {
    for (const n of nodes) {
      out.push({ node: n, depth });
      if (n.children.length && expanded(n.pid)) walk(n.children, depth + 1);
    }
  };
  walk(roots, 0);
  return out;
}
