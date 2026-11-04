import {
  CloudIcon,
  FileWarningIcon,
  GlobeIcon,
  MailIcon,
  MonitorIcon,
  NetworkIcon,
  ZapIcon,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/** Graph node/edge specs, node-kind styling and legend pieces (no React Flow import, so pages stay light). */
export type FlowNodeKind = "host" | "ip" | "remote" | "file" | "origin" | "mail" | "action";

export interface FlowNodeSpec {
  id: string;
  label: string;
  kind: FlowNodeKind;
  /** Second line under the label (type, count). */
  sublabel?: string;
  tone?: "default" | "danger" | "muted";
}

export interface FlowEdgeSpec {
  id: string;
  source: string;
  target: string;
  /** Full description used for the accessible name and the expanded label. */
  label: string;
  /** Compact badge text always shown on the edge (e.g. an event count). */
  badge: string;
  /** Extra lines shown when the edge is hovered or selected. */
  details?: string[];
  color: string;
}

export const NODE_KIND_META: Record<FlowNodeKind, { icon: LucideIcon; label: string; tone: string }> = {
  host: { icon: MonitorIcon, label: "Host", tone: "bg-accent text-primary" },
  ip: { icon: NetworkIcon, label: "IP address", tone: "bg-sev-medium-soft text-sev-medium" },
  remote: { icon: CloudIcon, label: "Remote source", tone: "bg-muted text-muted-foreground" },
  file: { icon: FileWarningIcon, label: "File", tone: "bg-sev-critical-soft text-sev-critical" },
  origin: { icon: GlobeIcon, label: "Origin", tone: "bg-sev-medium-soft text-sev-medium" },
  mail: { icon: MailIcon, label: "Mail origin", tone: "bg-sev-medium-soft text-sev-medium" },
  action: { icon: ZapIcon, label: "Action", tone: "bg-sev-low-soft text-sev-low" },
};

export function LegendSwatch({ color, children }: { color: string; children: ReactNode }) {
  return (
    <span className="flex items-center gap-1.5">
      <span aria-hidden className="h-0.5 w-4 rounded-full" style={{ background: color }} />
      {children}
    </span>
  );
}

export function LegendNodeKind({ kind }: { kind: FlowNodeKind }) {
  const meta = NODE_KIND_META[kind];
  const Icon = meta.icon;
  return (
    <span className="flex items-center gap-1.5">
      <span aria-hidden className={cn("grid size-4 place-items-center rounded", meta.tone)}>
        <Icon className="size-3" />
      </span>
      {meta.label}
    </span>
  );
}
