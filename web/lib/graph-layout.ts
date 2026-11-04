/** Deterministic left-to-right layered layout (dagre); kept separate so dagre loads with the graph view only. */
import dagre from "@dagrejs/dagre";

export interface LayoutNode {
  id: string;
  width: number;
  height: number;
}

export interface LayoutOptions {
  rankdir?: "LR" | "TB";
  ranksep?: number;
  nodesep?: number;
}

/** Top-left positions for each node from a dagre layered layout (deterministic for an input). */
export function layoutGraph(
  nodes: LayoutNode[],
  edges: { source: string; target: string }[],
  opts: LayoutOptions = {},
): Map<string, { x: number; y: number }> {
  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({
    rankdir: opts.rankdir ?? "LR",
    ranksep: opts.ranksep ?? 110,
    nodesep: opts.nodesep ?? 36,
    marginx: 8,
    marginy: 8,
  });
  g.setDefaultEdgeLabel(() => ({}));
  const ids = new Set(nodes.map((n) => n.id));
  for (const n of nodes) g.setNode(n.id, { width: n.width, height: n.height });
  edges.forEach((e, i) => {
    if (e.source !== e.target && ids.has(e.source) && ids.has(e.target))
      g.setEdge(e.source, e.target, {}, `e${i}`);
  });
  dagre.layout(g);
  const out = new Map<string, { x: number; y: number }>();
  for (const n of nodes) {
    const p = g.node(n.id) as { x: number; y: number } | undefined;
    out.set(n.id, { x: (p?.x ?? 0) - n.width / 2, y: (p?.y ?? 0) - n.height / 2 });
  }
  return out;
}
