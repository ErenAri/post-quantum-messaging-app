import { concatBytes } from "./base64";

export type TlvRecord = {
  ty: number;
  value: Uint8Array;
};

export function criticalType(base: number): number {
  return base | 0x8000;
}

export function encodeTlv(records: TlvRecord[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const record of records) {
    if (record.value.length > 0xffff) {
      throw new Error("tlv value too large");
    }
    const header = new Uint8Array(4);
    header[0] = (record.ty >> 8) & 0xff;
    header[1] = record.ty & 0xff;
    header[2] = (record.value.length >> 8) & 0xff;
    header[3] = record.value.length & 0xff;
    chunks.push(header, record.value);
  }
  return concatBytes(chunks);
}

export function i64ToBeBytes(value: number): Uint8Array {
  const big = BigInt(value);
  const out = new Uint8Array(8);
  for (let idx = 0; idx < 8; idx += 1) {
    const shift = BigInt((7 - idx) * 8);
    out[idx] = Number((big >> shift) & 0xffn);
  }
  return out;
}

export function u16ToBeBytes(value: number): Uint8Array {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}
