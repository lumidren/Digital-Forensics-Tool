/** Paging arithmetic for the virtualized timeline grid. */
export const PAGE_SIZE = 500;

/** Pages (0-based) covering rows [first, last] of a result set of `total` rows. */
export function pagesForRange(first: number, last: number, total: number, pageSize = PAGE_SIZE): number[] {
  if (total <= 0) return [];
  const a = Math.floor(Math.min(total - 1, Math.max(0, first)) / pageSize);
  const b = Math.floor(Math.min(total - 1, Math.max(first, last)) / pageSize);
  return Array.from({ length: b - a + 1 }, (_, i) => a + i);
}

/** Locate row `index` within its page. */
export function pageOf(index: number, pageSize = PAGE_SIZE): { page: number; offset: number } {
  return { page: Math.floor(index / pageSize), offset: index % pageSize };
}
