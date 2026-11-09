"use client";

import {
  Background,
  BackgroundVariant,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  getBezierPath,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useTheme } from "next-themes";
import { useMemo, useState, type ReactNode } from "react";
import { NODE_KIND_META, type FlowEdgeSpec, type FlowNodeSpec } from "@/components/graph-legend";
import { layoutGraph } from "@/lib/graph-layout";
import { cn } from "@/lib/utils";

const NODE_W = 176;
const NODE_H = 46;

type EntityNode = Node<{ spec: FlowNodeSpec }, "entity">;
type BadgeEdge = Edge<{ spec: FlowEdgeSpec; active: boolean }, "badge">;

function EntityNodeView({ data, selected }: NodeProps<EntityNode>) {
  const { spec } = data;
  const meta = NODE_KIND_META[spec.kind];
  const Icon = meta.icon;
  return (
    <div
      className={cn(
        "bg-card text-card-foreground flex items-center gap-2 rounded-lg border px-2 shadow-sm transition-[box-shadow,border-color]",
        spec.tone === "danger" && "border-sev-critical/60",
        spec.tone === "muted" && "border-dashed",
        selected && "ring-ring ring-2",
      )}
      style={{ width: NODE_W, height: NODE_H }}
    >
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-transparent" />
      <span aria-hidden className={cn("grid size-7 shrink-0 place-items-center rounded-md", meta.tone)}>
        <Icon className="size-4" />
      </span>
      <span className="grid min-w-0 leading-tight">
        <span className="truncate font-mono text-xs font-semibold" title={spec.label}>
          {spec.label}
        </span>
        <span className="text-muted-foreground truncate text-[10px]">{spec.sublabel ?? meta.label}</span>
      </span>
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-transparent" />
    </div>
  );
}

function BadgeEdgeView({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  data,
  selected,
}: EdgeProps<BadgeEdge>) {
  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  });
  const spec = data?.spec;
  const open = Boolean(selected || data?.active);
  if (!spec) return null;
  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{ stroke: spec.color, strokeWidth: open ? 2.5 : 1.75, opacity: open ? 1 : 0.85 }}
        interactionWidth={18}
      />
      <EdgeLabelRenderer>
        <div
          aria-hidden
          className="nodrag nopan pointer-events-none absolute"
          style={{
            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
            zIndex: open ? 10 : 1,
          }}
        >
          {open ? (
            <div className="bg-popover text-popover-foreground grid max-w-64 gap-0.5 rounded-md border px-2 py-1 text-[11px] shadow-md">
              <span className="flex items-center gap-1.5 font-medium">
                <span className="size-2 shrink-0 rounded-full" style={{ background: spec.color }} />
                {spec.label}
              </span>
              {(spec.details ?? []).map((d) => (
                <span key={d} className="text-muted-foreground">
                  {d}
                </span>
              ))}
            </div>
          ) : (
            <span
              className="bg-card text-foreground tabular flex h-5 min-w-5 items-center justify-center rounded-full border px-1.5 text-[10px] font-semibold shadow-xs"
              style={{ borderColor: spec.color }}
            >
              {spec.badge}
            </span>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

const nodeTypes = { entity: EntityNodeView };
const edgeTypes = { badge: BadgeEdgeView };

/**
 * Layered (dagre, left to right), keyboard-focusable directed graph. Edges show a compact badge;
 * the full label appears on hover, focus or selection so labels never overlap. Always pair it
 * with a table alternative.
 */
export function FlowGraph({
  nodes,
  edges,
  label,
  height = 440,
  onNodeActivate,
  legend,
}: {
  nodes: FlowNodeSpec[];
  edges: FlowEdgeSpec[];
  label: string;
  height?: number;
  onNodeActivate?: (id: string) => void;
  legend?: ReactNode;
}) {
  const { resolvedTheme } = useTheme();
  const [hovered, setHovered] = useState<string | null>(null);
  const rfNodes = useMemo<EntityNode[]>(() => {
    const pos = layoutGraph(
      nodes.map((n) => ({ id: n.id, width: NODE_W, height: NODE_H })),
      edges.map((e) => ({ source: e.source, target: e.target })),
      { ranksep: 120, nodesep: 40 },
    );
    return nodes.map((n) => ({
      id: n.id,
      type: "entity",
      position: pos.get(n.id) ?? { x: 0, y: 0 },
      data: { spec: n },
      ariaLabel: `${NODE_KIND_META[n.kind].label} ${n.label}${n.sublabel ? `, ${n.sublabel}` : ""}`,
      width: NODE_W,
      height: NODE_H,
      draggable: true,
      connectable: false,
    }));
  }, [nodes, edges]);
  const rfEdges = useMemo<BadgeEdge[]>(
    () =>
      edges.map((e) => ({
        id: e.id,
        type: "badge",
        source: e.source,
        target: e.target,
        data: { spec: e, active: hovered === e.id },
        ariaLabel: `${e.source} to ${e.target}: ${e.label}`,
        markerEnd: { type: MarkerType.ArrowClosed, color: e.color, width: 16, height: 16 },
      })),
    [edges, hovered],
  );

  return (
    <div className="bg-card min-w-0 overflow-hidden rounded-xl border" role="group" aria-label={label}>
      <div style={{ height }}>
        <ReactFlow
          nodes={rfNodes}
          edges={rfEdges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          colorMode={resolvedTheme === "dark" ? "dark" : "light"}
          fitView
          fitViewOptions={{ padding: 0.25, maxZoom: 1.15 }}
          nodesConnectable={false}
          nodesFocusable
          edgesFocusable
          proOptions={{ hideAttribution: true }}
          onNodeClick={(_e, n) => onNodeActivate?.(n.id)}
          onEdgeMouseEnter={(_e, ed) => setHovered(ed.id)}
          onEdgeMouseLeave={() => setHovered(null)}
          minZoom={0.2}
          maxZoom={2}
        >
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="var(--border)" />
          <Controls showInteractive={false} position="bottom-left" />
          <MiniMap
            pannable
            zoomable
            position="bottom-right"
            className="!rounded-md !border"
            nodeColor="var(--muted-foreground)"
            maskColor="color-mix(in oklch, var(--background) 70%, transparent)"
            style={{ width: 140, height: 90 }}
            ariaLabel="Graph overview"
          />
        </ReactFlow>
      </div>
      {legend ? <div className="bg-muted/30 border-t px-3 py-2 text-xs">{legend}</div> : null}
    </div>
  );
}
