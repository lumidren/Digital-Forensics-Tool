import { describe, expect, it } from "vitest";
import {
  alignOffset,
  byteToHex,
  chunkForRow,
  formatOffset,
  formatRow,
  hexToBytes,
  offsetWidth,
  parseOffset,
  rowCount,
  rowForOffset,
  toAsciiChar,
} from "./hex";

describe("hex formatting", () => {
  it("decodes hex strings", () => {
    expect([...hexToBytes("4d5a9000")]).toEqual([0x4d, 0x5a, 0x90, 0x00]);
    expect([...hexToBytes("4d5")]).toEqual([0x4d]);
    expect([...hexToBytes("zz")]).toEqual([0]);
  });

  it("formats bytes, ASCII and offsets", () => {
    expect(byteToHex(0)).toBe("00");
    expect(byteToHex(255)).toBe("ff");
    expect(byteToHex(256 + 10)).toBe("0a");
    expect(toAsciiChar(0x41)).toBe("A");
    expect(toAsciiChar(0x7f)).toBe(".");
    expect(toAsciiChar(0x1f)).toBe(".");
    expect(formatOffset(0x1f0)).toBe("000001F0");
    expect(formatOffset(0x1f0, 4)).toBe("01F0");
    expect(offsetWidth(16)).toBe(8);
    expect(offsetWidth(0x1_0000_0001)).toBe(9);
    expect(offsetWidth(0)).toBe(8);
  });

  it("builds a row with hex and ASCII columns", () => {
    const row = formatRow(new Uint8Array([0x4d, 0x5a, 0x00, 0x7e]), 32);
    expect(row).toEqual({
      offset: 32,
      offsetLabel: "00000020",
      hex: ["4d", "5a", "00", "7e"],
      ascii: "MZ.~",
    });
  });

  it("computes rows and chunks", () => {
    expect(rowCount(0)).toBe(0);
    expect(rowCount(16)).toBe(1);
    expect(rowCount(17)).toBe(2);
    expect(rowCount(-5)).toBe(0);
    expect(rowForOffset(31)).toBe(1);
    expect(rowForOffset(-1)).toBe(0);
    expect(chunkForRow(4095, 4096)).toBe(0);
    expect(chunkForRow(4096, 4096)).toBe(1);
  });

  it("parses offsets in hex and decimal", () => {
    expect(parseOffset("0x1F00")).toBe(0x1f00);
    expect(parseOffset("$ff")).toBe(255);
    expect(parseOffset("1F00h")).toBe(0x1f00);
    expect(parseOffset("7 936")).toBe(7936);
    expect(parseOffset("1_024")).toBe(1024);
    expect(parseOffset("")).toBeNull();
    expect(parseOffset("-5")).toBeNull();
    expect(parseOffset("0xZZ")).toBeNull();
  });

  it("aligns and clamps offsets to rows", () => {
    expect(alignOffset(35, 100)).toBe(32);
    expect(alignOffset(500, 100)).toBe(96);
    expect(alignOffset(-3, 100)).toBe(0);
    expect(alignOffset(5, 0)).toBe(0);
  });
});
