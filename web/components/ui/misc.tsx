import * as React from "react";
import { cn } from "@/lib/utils";

export function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      aria-hidden
      className={cn("bg-muted animate-pulse rounded-md", className)}
      {...props}
    />
  );
}

export function Kbd({ className, ...props }: React.ComponentProps<"kbd">) {
  return (
    <kbd
      className={cn(
        "bg-muted text-foreground inline-flex h-5 min-w-5 items-center justify-center rounded border px-1 font-mono text-[11px] font-medium",
        className,
      )}
      {...props}
    />
  );
}

export function Alert({
  className,
  variant = "default",
  ...props
}: React.ComponentProps<"div"> & { variant?: "default" | "destructive" | "success" | "warning" }) {
  return (
    <div
      data-slot="alert"
      className={cn(
        "rounded-lg border px-3 py-2 text-sm",
        variant === "destructive" && "border-destructive/50 bg-destructive-soft text-destructive",
        variant === "success" && "border-success/50 bg-success-soft text-success",
        variant === "warning" && "border-warning/50 bg-warning-soft text-warning",
        className,
      )}
      {...props}
    />
  );
}

export function Separator({ className, ...props }: React.ComponentProps<"hr">) {
  return <hr className={cn("border-border", className)} {...props} />;
}

export function EmptyState({
  title,
  children,
  icon: Icon,
  className,
}: {
  title: string;
  children?: React.ReactNode;
  icon?: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "bg-dot-grid flex flex-col items-center rounded-lg border border-dashed px-6 py-8 text-center",
        className,
      )}
    >
      {Icon ? (
        <span className="bg-card text-muted-foreground mb-3 grid size-10 place-items-center rounded-full border shadow-xs">
          <Icon className="size-5" aria-hidden />
        </span>
      ) : null}
      <p className="text-sm font-medium">{title}</p>
      {children ? <div className="text-muted-foreground mt-1 max-w-md text-sm">{children}</div> : null}
    </div>
  );
}
