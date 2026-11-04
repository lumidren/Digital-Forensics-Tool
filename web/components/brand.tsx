import { useId } from "react";
import { cn } from "@/lib/utils";

/**
 * Veritas brand mark: a faceted gradient shield whose inner "V" doubles as a verification tick.
 * Decorative; always pair it with the product name.
 */
export function BrandMark({ className }: { className?: string }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg
      viewBox="0 0 32 32"
      className={cn("size-6 shrink-0", className)}
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id={`vg-${id}`} x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="var(--brand-from)" />
          <stop offset="1" stopColor="var(--brand-to)" />
        </linearGradient>
      </defs>
      <path
        d="M16 2.5 27.5 6.6v8.6c0 7.1-4.8 12.6-11.5 14.6C9.3 27.8 4.5 22.3 4.5 15.2V6.6L16 2.5Z"
        fill={`url(#vg-${id})`}
      />
      <path d="M16 2.5 27.5 6.6v8.6c0 7.1-4.8 12.6-11.5 14.6V2.5Z" fill="#fff" fillOpacity="0.12" />
      <path
        d="m10.2 11.4 5.8 10.4 5.8-10.4"
        fill="none"
        stroke="#fff"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function BrandWordmark({ className, suffix }: { className?: string; suffix?: string }) {
  return (
    <span className={cn("flex items-center gap-2 font-semibold tracking-tight", className)}>
      <BrandMark />
      <span>
        Veritas
        {suffix ? <span className="text-muted-foreground ml-1 font-medium">{suffix}</span> : null}
      </span>
    </span>
  );
}
