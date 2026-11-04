/** Chain-of-custody helpers for the ledger visualisation. */
import type { CustodyEntry } from "./types";

export type LinkState = "linked" | "broken" | "gap" | "start";

/** How an entry attaches to the entry shown before it (only adjacent sequence numbers can be checked). */
export function linkState(prev: CustodyEntry | undefined, cur: CustodyEntry): LinkState {
  if (!prev) return cur.seq === 0 ? "start" : "gap";
  if (cur.seq !== prev.seq + 1) return "gap";
  return cur.prev_hash === prev.entry_hash ? "linked" : "broken";
}

/** "13cfb089aa…af0f12" style abbreviation for long hashes. */
export function abbreviateHash(h: string | null | undefined, head = 10, tail = 6): string {
  if (!h) return "—";
  return h.length <= head + tail + 1 ? h : `${h.slice(0, head)}…${h.slice(-tail)}`;
}
