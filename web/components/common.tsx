"use client";

import { CheckIcon, CopyIcon } from "lucide-react";
import { useState, type ComponentType, type ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, Skeleton } from "@/components/ui/misc";
import { ApiError } from "@/lib/api";
import { copyText } from "@/lib/download";
import type { FindingState, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

export type IconType = ComponentType<{ className?: string; "aria-hidden"?: boolean }>;

export function PageHeader({
  title,
  description,
  actions,
  icon: Icon,
  eyebrow,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  icon?: IconType;
  eyebrow?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="flex min-w-0 items-start gap-3">
        {Icon ? (
          <span className="bg-card text-primary mt-0.5 hidden size-10 shrink-0 place-items-center rounded-lg border shadow-xs sm:grid">
            <Icon className="size-5" aria-hidden />
          </span>
        ) : null}
        <div className="min-w-0">
          {eyebrow ? <p className="eyebrow text-muted-foreground mb-0.5">{eyebrow}</p> : null}
          <h1 className="text-xl leading-tight font-semibold tracking-tight sm:text-[1.375rem]">{title}</h1>
          {description ? <p className="text-muted-foreground mt-1 text-sm">{description}</p> : null}
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant={severity} className="text-[11px] tracking-wide uppercase">
      <span aria-hidden className="size-1.5 rounded-full" style={{ background: SEVERITY_COLOR[severity] }} />
      {severity}
    </Badge>
  );
}

const STATE_VARIANT: Record<FindingState, "low" | "warning" | "success" | "muted"> = {
  proposed: "low",
  confirmed: "warning",
  approved: "success",
  rejected: "muted",
};

export function StateBadge({ state }: { state: FindingState }) {
  return <Badge variant={STATE_VARIANT[state]}>{state}</Badge>;
}

export function Mono({
  children,
  className,
  title,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span className={cn("font-mono text-xs break-all", className)} title={title}>
      {children}
    </span>
  );
}

export function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      size="icon-sm"
      aria-label={copied ? `${label} copied` : `Copy ${label}`}
      onClick={() => {
        void copyText(text).then((ok) => {
          setCopied(ok);
          if (ok) setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? <CheckIcon aria-hidden /> : <CopyIcon aria-hidden />}
    </Button>
  );
}

export function HashLine({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="grid grid-cols-[6.5rem_1fr_auto] items-center gap-2 py-0.5">
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="col-span-2 flex min-w-0 items-center justify-between gap-2">
        <Mono>{value ?? "—"}</Mono>
        {value ? <CopyButton text={value} label={label} /> : null}
      </dd>
    </div>
  );
}

export function QueryStatus({
  isLoading,
  error,
  children,
  rows = 3,
}: {
  isLoading: boolean;
  error: unknown;
  children: ReactNode;
  rows?: number;
}) {
  if (isLoading) {
    return (
      <div className="grid gap-2" aria-busy="true">
        <span className="sr-only" role="status">
          Loading…
        </span>
        {Array.from({ length: rows }, (_, i) => (
          <Skeleton key={i} className="h-6 w-full" />
        ))}
      </div>
    );
  }
  if (error) {
    return (
      <Alert variant="destructive" role="alert">
        {error instanceof ApiError
          ? error.detail
          : error instanceof Error
            ? error.message
            : "Failed to load."}
      </Alert>
    );
  }
  return <>{children}</>;
}

export function GateNote({ reason }: { reason: string | null }) {
  if (!reason) return null;
  return <p className="text-muted-foreground text-xs">{reason}</p>;
}

export function Stat({
  label,
  value,
  hint,
  icon: Icon,
  tone = "primary",
  chart,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: IconType;
  tone?: "primary" | "critical" | "success" | "warning" | "info";
  /** Small decorative trend (sparkline); the value and hint carry the information. */
  chart?: ReactNode;
}) {
  const toneClass = {
    primary: "bg-accent text-primary",
    critical: "bg-sev-critical-soft text-sev-critical",
    success: "bg-success-soft text-success",
    warning: "bg-warning-soft text-warning",
    info: "bg-sev-info-soft text-sev-info",
  }[tone];
  return (
    <div className="bg-card group relative overflow-hidden rounded-xl border p-3.5 shadow-[0_1px_2px_0_rgb(0_0_0/0.04)] transition-colors hover:border-[color-mix(in_oklch,var(--primary)_35%,var(--border))]">
      <div className="flex items-center gap-2">
        {Icon ? (
          <span className={cn("grid size-7 place-items-center rounded-md", toneClass)}>
            <Icon className="size-4" aria-hidden />
          </span>
        ) : null}
        <p className="text-muted-foreground text-xs font-medium">{label}</p>
      </div>
      <div className="mt-2 flex items-end justify-between gap-2">
        <div className="min-w-0">
          <p className="tabular text-2xl leading-none font-semibold tracking-tight">{value}</p>
          {hint ? <p className="text-muted-foreground mt-1.5 text-xs">{hint}</p> : null}
        </div>
        {chart ? <div className="w-24 shrink-0">{chart}</div> : null}
      </div>
    </div>
  );
}
