import { describe, it, expect } from "vitest";
import {
  bytesToBase64,
  base64ToBytes,
  utf8ToBytes,
  bytesToUtf8,
  bytesToHex,
  concatBytes,
  randomBytes,
} from "./base64";

describe("bytesToBase64 / base64ToBytes", () => {
  it("round-trips arbitrary bytes", () => {
    const original = new Uint8Array([0, 1, 127, 128, 255]);
    const b64 = bytesToBase64(original);
    const decoded = base64ToBytes(b64);
    expect(decoded).toEqual(original);
  });

  it("round-trips empty array", () => {
    const empty = new Uint8Array(0);
    const b64 = bytesToBase64(empty);
    expect(b64).toBe("");
    expect(base64ToBytes(b64)).toEqual(empty);
  });

  it("produces valid base64 for known input", () => {
    // "Hello" = SGVsbG8=
    const bytes = new Uint8Array([72, 101, 108, 108, 111]);
    expect(bytesToBase64(bytes)).toBe("SGVsbG8=");
  });

  it("decodes known base64", () => {
    const decoded = base64ToBytes("SGVsbG8=");
    expect(Array.from(decoded)).toEqual([72, 101, 108, 108, 111]);
  });

  it("round-trips all 256 byte values", () => {
    const all = new Uint8Array(256);
    for (let i = 0; i < 256; i++) all[i] = i;
    expect(base64ToBytes(bytesToBase64(all))).toEqual(all);
  });
});

describe("utf8ToBytes / bytesToUtf8", () => {
  it("round-trips ASCII", () => {
    const text = "hello world";
    expect(bytesToUtf8(utf8ToBytes(text))).toBe(text);
  });

  it("round-trips empty string", () => {
    expect(bytesToUtf8(utf8ToBytes(""))).toBe("");
  });

  it("round-trips unicode", () => {
    const text = "héllo wörld 🌍";
    expect(bytesToUtf8(utf8ToBytes(text))).toBe(text);
  });

  it("round-trips CJK characters", () => {
    const text = "你好世界";
    expect(bytesToUtf8(utf8ToBytes(text))).toBe(text);
  });
});

describe("bytesToHex", () => {
  it("converts bytes to lowercase hex", () => {
    expect(bytesToHex(new Uint8Array([0x0a, 0xff, 0x00]))).toBe("0aff00");
  });

  it("handles empty array", () => {
    expect(bytesToHex(new Uint8Array(0))).toBe("");
  });

  it("pads single-digit hex values", () => {
    expect(bytesToHex(new Uint8Array([0, 1, 2]))).toBe("000102");
  });

  it("handles all 0xff", () => {
    expect(bytesToHex(new Uint8Array([255, 255]))).toBe("ffff");
  });
});

describe("concatBytes", () => {
  it("concatenates multiple arrays", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4, 5]);
    const c = new Uint8Array([6]);
    expect(concatBytes([a, b, c])).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
  });

  it("returns empty for empty input list", () => {
    expect(concatBytes([])).toEqual(new Uint8Array(0));
  });

  it("handles single array", () => {
    const a = new Uint8Array([7, 8, 9]);
    expect(concatBytes([a])).toEqual(a);
  });

  it("handles arrays with empty elements", () => {
    const a = new Uint8Array([1]);
    const empty = new Uint8Array(0);
    const b = new Uint8Array([2]);
    expect(concatBytes([a, empty, b])).toEqual(new Uint8Array([1, 2]));
  });
});

describe("randomBytes", () => {
  it("returns correct length", () => {
    expect(randomBytes(16).length).toBe(16);
    expect(randomBytes(0).length).toBe(0);
    expect(randomBytes(32).length).toBe(32);
  });

  it("returns Uint8Array", () => {
    expect(randomBytes(8)).toBeInstanceOf(Uint8Array);
  });

  it("two calls produce different output (probabilistic)", () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    // Probability of collision is 2^-256, effectively impossible
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});
