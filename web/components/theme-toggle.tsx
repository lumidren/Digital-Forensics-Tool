"use client";

import { MonitorIcon, MoonIcon, SunIcon } from "lucide-react";
import { useTheme } from "next-themes";
import { Button } from "@/components/ui/button";
import { useHydrated } from "@/hooks/use-session";

const ORDER = ["system", "light", "dark"] as const;
const LABEL: Record<string, string> = { system: "System theme", light: "Light theme", dark: "Dark theme" };

export function nextTheme(current: string | undefined): (typeof ORDER)[number] {
  const i = ORDER.indexOf((current ?? "system") as (typeof ORDER)[number]);
  return ORDER[(i + 1) % ORDER.length] ?? "system";
}

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const hydrated = useHydrated();
  const current = hydrated ? (theme ?? "system") : "system";
  const Icon = current === "dark" ? MoonIcon : current === "light" ? SunIcon : MonitorIcon;
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setTheme(nextTheme(current))}
      aria-label={`${LABEL[current] ?? "Theme"}; switch to ${LABEL[nextTheme(current)]?.toLowerCase() ?? "next theme"}`}
      title="Toggle theme"
    >
      <Icon aria-hidden />
    </Button>
  );
}
