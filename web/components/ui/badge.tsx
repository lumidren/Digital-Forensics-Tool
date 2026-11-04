import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/utils";

export const badgeVariants = cva(
  "inline-flex w-fit shrink-0 items-center gap-1 rounded-md border px-1.5 py-0.5 text-xs font-medium whitespace-nowrap [&_svg]:size-3 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        outline: "text-foreground",
        destructive: "border-transparent bg-destructive text-destructive-foreground",
        success: "border-success/40 bg-success-soft text-success",
        warning: "border-warning/40 bg-warning-soft text-warning",
        "destructive-soft": "border-destructive/40 bg-destructive-soft text-destructive",
        critical: "border-sev-critical/45 bg-sev-critical-soft text-sev-critical",
        high: "border-sev-high/45 bg-sev-high-soft text-sev-high",
        medium: "border-sev-medium/45 bg-sev-medium-soft text-sev-medium",
        low: "border-sev-low/45 bg-sev-low-soft text-sev-low",
        info: "border-sev-info/40 bg-sev-info-soft text-sev-info",
        muted: "border-transparent bg-muted text-muted-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export function Badge({
  className,
  variant,
  ...props
}: React.ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return <span data-slot="badge" className={cn(badgeVariants({ variant }), className)} {...props} />;
}
