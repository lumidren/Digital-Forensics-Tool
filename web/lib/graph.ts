/**
 * Graph shaping for the lateral-movement and provenance views: node classification and
 * parallel-edge aggregation (so labels never stack on top of each other). Layout lives in
 * graph-layout.ts.
 */
import { TACTICS, techniqueInfo } from "./attack";
import type { LateralEdge } from "./types";

export type HostKind = "remote" | "ip" | "host";

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpAddress(id: string): boolean {
  const m = IPV4.exec(id);
  if (m) return m.slice(1).every((o) => Number(o) <= 255);
  return id.includes(":") && /^[0-9a-f:.]+$/i.test(id) && id.split(":").length > 2;
}

/** RFC 1918 / loopback / link-local IPv4, or IPv6 ULA / link-local / loopback. */
export function isPrivateIp(id: string): boolean {
  const m = IPV4.exec(id);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254)
    );
  }
  const v6 = id.toLowerCase();
  return v6 === "::1" || v6.startsWith("fc") || v6.startsWith("fd") || v6.startsWith("fe80");
}

export function classifyHost(id: string): HostKind {
  if (id.toLowerCase() === "remote") return "remote";
  return isIpAddress(id) ? "ip" : "host";
}

export function hostKindLabel(id: string): string {
  const kind = classifyHost(id);
  if (kind === "remote") return "Unattributed remote source";
  if (kind === "ip") return isPrivateIp(id) ? "Internal IP address" : "External IP address";
  return "Host";
}

export interface AggregatedEdge {
  id: string;
  src: string;
  dst: string;
  kinds: string[];
  techniques: string[];
  users: string[];
  count: number;
  event_ids: number[];
  first_ns: number | null;
  last_ns: number | null;
  /** Tactic key (ATT&CK) that colours the edge, or "other". */
  family: string;
}

const minN = (a: number | null, b: number | null) => (a === null ? b : b === null ? a : Math.min(a, b));
const maxN = (a: number | null, b: number | null) => (a === null ? b : b === null ? a : Math.max(a, b));

/** Tie-break order for edge colouring: movement-centric tactics win in this view. */
export const FAMILY_PREFERENCE = [
  "lateral-movement",
  "credential-access",
  "execution",
  "initial-access",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "command-and-control",
];

/** Tactic shared by most of the techniques (all their tactics count); ties use FAMILY_PREFERENCE. */
export function edgeFamily(techniques: string[]): string {
  const counts = new Map<string, number>();
  for (const t of techniques) {
    for (const tac of techniqueInfo(t).tactics) counts.set(tac, (counts.get(tac) ?? 0) + 1);
  }
  const order = [
    ...FAMILY_PREFERENCE,
    ...TACTICS.map((t) => t.key).filter((k) => !FAMILY_PREFERENCE.includes(k)),
  ];
  let best = "other";
  let bestN = 0;
  for (const key of order) {
    const n = counts.get(key) ?? 0;
    if (n > bestN) {
      best = key;
      bestN = n;
    }
  }
  return best;
}

/** Merge edges with the same source and destination into one, keeping every attribute. */
export function aggregateEdges(edges: LateralEdge[]): AggregatedEdge[] {
  const groups = new Map<string, AggregatedEdge>();
  for (const e of edges) {
    const key = `${e.src}\u0000${e.dst}`;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, {
        id: `e${groups.size}`,
        src: e.src,
        dst: e.dst,
        kinds: [e.kind],
        techniques: e.technique ? [e.technique] : [],
        users: e.user ? [e.user] : [],
        count: e.count,
        event_ids: [...e.event_ids],
        first_ns: e.first_ns,
        last_ns: e.last_ns,
        family: "other",
      });
      continue;
    }
    if (!g.kinds.includes(e.kind)) g.kinds.push(e.kind);
    if (e.technique && !g.techniques.includes(e.technique)) g.techniques.push(e.technique);
    if (e.user && !g.users.includes(e.user)) g.users.push(e.user);
    g.count += e.count;
    for (const id of e.event_ids) if (!g.event_ids.includes(id)) g.event_ids.push(id);
    g.first_ns = minN(g.first_ns, e.first_ns);
    g.last_ns = maxN(g.last_ns, e.last_ns);
  }
  return [...groups.values()].map((g) => ({ ...g, family: edgeFamily(g.techniques) }));
}
