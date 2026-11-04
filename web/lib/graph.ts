/**
 * Layered (Sugiyama-style, simplified) layout for directed graphs: longest-path layering on the
 * graph with back edges ignored, then barycentric ordering inside each layer to reduce crossings.
 * Deterministic for a given input, so screenshots and tests are stable.
 */
export interface LayoutEdge {
  src: string;
  dst: string;
}

export interface Positioned {
  id: string;
  layer: number;
  order: number;
  x: number;
  y: number;
}

export interface LayoutOptions {
  layerGap?: number;
  nodeGap?: number;
}

export function assignLayers(nodes: string[], edges: LayoutEdge[]): Map<string, number> {
  const ids = [...new Set(nodes)].sort();
  const out = new Map<string, string[]>(ids.map((id) => [id, []]));
  const indeg = new Map<string, number>(ids.map((id) => [id, 0]));
  for (const e of edges) {
    if (e.src === e.dst || !out.has(e.src) || !out.has(e.dst)) continue;
    out.get(e.src)?.push(e.dst);
    indeg.set(e.dst, (indeg.get(e.dst) ?? 0) + 1);
  }
  // Kahn's algorithm; nodes left in cycles are released in id order and treated as sources.
  const layer = new Map<string, number>();
  const remaining = new Map(indeg);
  const queue = ids.filter((id) => remaining.get(id) === 0);
  const done = new Set<string>();
  const release = () => {
    const next = ids.find((id) => !done.has(id) && !queue.includes(id));
    if (next !== undefined) queue.push(next);
  };
  if (!queue.length) release();
  while (done.size < ids.length) {
    const id = queue.shift();
    if (id === undefined) {
      release();
      continue;
    }
    if (done.has(id)) continue;
    done.add(id);
    const l = layer.get(id) ?? 0;
    layer.set(id, l);
    for (const d of out.get(id) ?? []) {
      if (done.has(d)) continue;
      layer.set(d, Math.max(layer.get(d) ?? 0, l + 1));
      const r = (remaining.get(d) ?? 0) - 1;
      remaining.set(d, r);
      if (r <= 0 && !queue.includes(d)) queue.push(d);
    }
  }
  return layer;
}

export function layeredLayout(
  nodes: string[],
  edges: LayoutEdge[],
  opts: LayoutOptions = {},
): Map<string, Positioned> {
  const layerGap = opts.layerGap ?? 260;
  const nodeGap = opts.nodeGap ?? 90;
  const layers = assignLayers(nodes, edges);
  const byLayer = new Map<number, string[]>();
  for (const [id, l] of [...layers.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    byLayer.set(l, [...(byLayer.get(l) ?? []), id]);
  }
  const order = new Map<string, number>();
  const sortedLayers = [...byLayer.keys()].sort((a, b) => a - b);
  for (const l of sortedLayers) {
    const members = byLayer.get(l) ?? [];
    if (l > 0) {
      const bary = (id: string) => {
        const preds = edges.filter((e) => e.dst === id && order.has(e.src)).map((e) => order.get(e.src) ?? 0);
        return preds.length ? preds.reduce((s, x) => s + x, 0) / preds.length : Number.MAX_SAFE_INTEGER;
      };
      members.sort((a, b) => bary(a) - bary(b) || a.localeCompare(b));
    }
    members.forEach((id, i) => order.set(id, i));
  }
  const maxSize = Math.max(1, ...[...byLayer.values()].map((m) => m.length));
  const result = new Map<string, Positioned>();
  for (const l of sortedLayers) {
    const members = byLayer.get(l) ?? [];
    const offset = ((maxSize - members.length) * nodeGap) / 2;
    members.forEach((id, i) => {
      result.set(id, { id, layer: l, order: i, x: l * layerGap, y: offset + i * nodeGap });
    });
  }
  return result;
}
