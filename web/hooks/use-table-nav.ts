"use client";

import { useCallback, useState } from "react";
import { stepSelection } from "@/lib/shortcuts";
import { useHotkeys } from "./use-hotkeys";

export interface TableNavOptions {
  enabled?: boolean;
  onOpen?: (index: number) => void;
  onSelect?: (index: number) => void;
}

/** `j`/`k` move the selection, `Enter` opens the selected row. */
export function useTableNav(length: number, opts: TableNavOptions = {}) {
  const { enabled = true, onOpen, onSelect } = opts;
  const [selected, setSelectedState] = useState<number | null>(null);
  const current = selected !== null && selected >= length ? (length ? length - 1 : null) : selected;

  const setSelected = useCallback(
    (i: number | null) => {
      setSelectedState(i);
      if (i !== null) onSelect?.(i);
    },
    [onSelect],
  );

  const move = (delta: number) => setSelected(stepSelection(current, delta, length));

  useHotkeys(
    {
      j: () => move(1),
      k: () => move(-1),
      enter: () => {
        if (current !== null) onOpen?.(current);
      },
    },
    { enabled: enabled && length > 0 },
  );

  return { selected: current, setSelected };
}
