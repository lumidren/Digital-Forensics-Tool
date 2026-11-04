"use client";

import { CheckIcon, CopyIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, Skeleton } from "@/components/ui/misc";
import { ApiError } from "@/lib/api";
import { copyText } from "@/lib/download";
import type { FindingState, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="text-muted-foreground mt-0.5 text-sm">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant={severity} className="uppercase">
      {severity}
    </Badge>
  );
}

const STATE_VARIANT: Record<FindingState, "outline" | "warning" | "success" | "secondary"> = {
  proposed: "outline",
  confirmed: "warning",
  approved: "success",
  rejected: "secondary",
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

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="bg-card rounded-lg border p-3">
      <p className="text-muted-foreground text-xs">{label}</p>
      <p className="tabular mt-0.5 text-2xl font-semibold">{value}</p>
      {hint ? <p className="text-muted-foreground text-xs">{hint}</p> : null}
    </div>
  );
}
