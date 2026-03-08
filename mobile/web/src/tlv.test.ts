import { describe, it, expect } from "vitest";
import { criticalType, encodeTlv, i64ToBeBytes, u16ToBeBytes, TlvRecord } from "./tlv";

describe("criticalType", () => {
  it("sets the high bit (0x8000)", () => {
    expect(criticalType(0x0201)).toBe(0x8201);
  });

  it("is idempotent when bit already set", () => {
    expect(criticalType(0x8201)).toBe(0x8201);
  });

  it("works for zero base", () => {
    expect(criticalType(0)).toBe(0x8000);
  });
});

describe("u16ToBeBytes", () => {
  it("encodes zero", () => {
    expect(u16ToBeBytes(0)).toEqual(new Uint8Array([0, 0]));
  });

  it("encodes 256 as big-endian", () => {
    expect(u16ToBeBytes(256)).toEqual(new Uint8Array([1, 0]));
  });

  it("encodes 0xFFFF", () => {
    expect(u16ToBeBytes(0xffff)).toEqual(new Uint8Array([0xff, 0xff]));
  });

  it("encodes 1 correctly", () => {
    expect(u16ToBeBytes(1)).toEqual(new Uint8Array([0, 1]));
  });
});

describe("i64ToBeBytes", () => {
  it("encodes zero as 8 zero bytes", () => {
    expect(i64ToBeBytes(0)).toEqual(new Uint8Array(8));
  });

  it("encodes 1 correctly", () => {
    const result = i64ToBeBytes(1);
    expect(result).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1]));
  });

  it("encodes 256", () => {
    const result = i64ToBeBytes(256);
    expect(result).toEqual(new Uint8Array([0, 0, 0, 0, 0, 0, 1, 0]));
  });

  it("encodes large positive number", () => {
    // 2^32 = 4294967296
    const result = i64ToBeBytes(4294967296);
    expect(result).toEqual(new Uint8Array([0, 0, 0, 1, 0, 0, 0, 0]));
  });

  it("encodes negative number (two's complement)", () => {
    const result = i64ToBeBytes(-1);
    expect(result).toEqual(new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
  });
});

describe("encodeTlv", () => {
  it("encodes empty record list", () => {
    expect(encodeTlv([])).toEqual(new Uint8Array(0));
  });

  it("encodes a single record", () => {
    const records: TlvRecord[] = [
      { ty: 0x0102, value: new Uint8Array([0xaa, 0xbb]) },
    ];
    const result = encodeTlv(records);
    // type: 01 02, length: 00 02, value: aa bb
    expect(result).toEqual(new Uint8Array([0x01, 0x02, 0x00, 0x02, 0xaa, 0xbb]));
  });

  it("encodes multiple records", () => {
    const records: TlvRecord[] = [
      { ty: 0x0001, value: new Uint8Array([0x10]) },
      { ty: 0x0002, value: new Uint8Array([0x20, 0x30]) },
    ];
    const result = encodeTlv(records);
    expect(result).toEqual(
      new Uint8Array([
        0x00, 0x01, 0x00, 0x01, 0x10,       // record 1
        0x00, 0x02, 0x00, 0x02, 0x20, 0x30,  // record 2
      ])
    );
  });

  it("encodes empty value", () => {
    const records: TlvRecord[] = [
      { ty: 0x0001, value: new Uint8Array(0) },
    ];
    const result = encodeTlv(records);
    expect(result).toEqual(new Uint8Array([0x00, 0x01, 0x00, 0x00]));
  });

  it("throws on value exceeding 0xFFFF bytes", () => {
    const records: TlvRecord[] = [
      { ty: 0x0001, value: new Uint8Array(0x10000) },
    ];
    expect(() => encodeTlv(records)).toThrow("tlv value too large");
  });

  it("encodes critical type correctly", () => {
    const ty = criticalType(0x0201); // 0x8201
    const records: TlvRecord[] = [
      { ty, value: new Uint8Array([0xff]) },
    ];
    const result = encodeTlv(records);
    expect(result).toEqual(new Uint8Array([0x82, 0x01, 0x00, 0x01, 0xff]));
  });
});
