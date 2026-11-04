/** Hex viewer arithmetic and formatting. */
export const BYTES_PER_ROW = 16;

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : hex.slice(0, -1);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const b = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    out[i] = Number.isNaN(b) ? 0 : b;
  }
  return out;
}

export function byteToHex(b: number): string {
  return (b & 0xff).toString(16).padStart(2, "0");
}

export function toAsciiChar(b: number): string {
  return b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
}

/** Width of the offset column: at least 8 hex digits, more for large objects. */
export function offsetWidth(size: number): number {
  return Math.max(8, Math.max(0, size - 1).toString(16).length);
}

export function formatOffset(offset: number, width = 8): string {
  return offset.toString(16).toUpperCase().padStart(width, "0");
}

export interface HexRow {
  offset: number;
  offsetLabel: string;
  hex: string[];
  ascii: string;
}

export function formatRow(bytes: Uint8Array, offset: number, width = 8): HexRow {
  const hex: string[] = [];
  let ascii = "";
  for (const b of bytes) {
    hex.push(byteToHex(b));
    ascii += toAsciiChar(b);
  }
  return { offset, offsetLabel: formatOffset(offset, width), hex, ascii };
}

export function rowCount(size: number): number {
  return Math.ceil(Math.max(0, size) / BYTES_PER_ROW);
}

export function rowForOffset(offset: number): number {
  return Math.floor(Math.max(0, offset) / BYTES_PER_ROW);
}

export function chunkForRow(row: number, rowsPerChunk: number): number {
  return Math.floor(row / rowsPerChunk);
}

/**
 * Parse a user-entered offset: `0x1F00`, `1F00h`, `$1F00` (hex) or `7936` (decimal).
 * Returns null for anything else.
 */
export function parseOffset(input: string): number | null {
  const t = input.trim().replace(/[_\s]/g, "");
  if (!t) return null;
  const hex = /^(?:0x|\$)([0-9a-f]+)$/i.exec(t) ?? /^([0-9a-f]+)h$/i.exec(t);
  if (hex?.[1]) return Number.parseInt(hex[1], 16);
  const dec = /^(\d+)$/.exec(t);
  if (dec?.[1]) return Number.parseInt(dec[1], 10);
  return null;
}

/** Clamp an offset into [0, size) and align it to the start of its row. */
export function alignOffset(offset: number, size: number): number {
  if (size <= 0) return 0;
  const clamped = Math.min(Math.max(0, offset), size - 1);
  return clamped - (clamped % BYTES_PER_ROW);
}
