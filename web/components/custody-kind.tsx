import {
  AnchorIcon,
  DownloadIcon,
  EyeIcon,
  FileInputIcon,
  KeyRoundIcon,
  KeySquareIcon,
  PackagePlusIcon,
  RefreshCwIcon,
  SproutIcon,
  StickyNoteIcon,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";

export const CUSTODY_KIND_META: Record<string, { icon: LucideIcon; tone: string }> = {
  genesis: { icon: SproutIcon, tone: "bg-success-soft text-success" },
  acquire: { icon: PackagePlusIcon, tone: "bg-sev-low-soft text-sev-low" },
  ingest: { icon: FileInputIcon, tone: "bg-sev-low-soft text-sev-low" },
  access: { icon: EyeIcon, tone: "bg-sev-info-soft text-sev-info" },
  export: { icon: DownloadIcon, tone: "bg-warning-soft text-warning" },
  transform: { icon: RefreshCwIcon, tone: "bg-accent text-primary" },
  key_enrolled: { icon: KeyRoundIcon, tone: "bg-success-soft text-success" },
  key_revoked: { icon: KeySquareIcon, tone: "bg-destructive-soft text-destructive" },
  anchor: { icon: AnchorIcon, tone: "bg-accent text-primary" },
  note: { icon: StickyNoteIcon, tone: "bg-sev-info-soft text-sev-info" },
};

/** Round icon chip for a custody entry kind (decorative; render the kind as text next to it). */
export function CustodyKindIcon({ kind, className }: { kind: string; className?: string }) {
  const meta = CUSTODY_KIND_META[kind] ?? { icon: StickyNoteIcon, tone: "bg-muted text-muted-foreground" };
  const Icon = meta.icon;
  return (
    <span
      aria-hidden
      className={cn("grid size-7 shrink-0 place-items-center rounded-full", meta.tone, className)}
    >
      <Icon className="size-3.5" />
    </span>
  );
}
