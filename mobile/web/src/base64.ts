export function bytesToBase64(bytes: Uint8Array): string {
  let out = "";
  for (const value of bytes) {
    out += String.fromCharCode(value);
  }
  return btoa(out);
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function utf8ToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function bytesToUtf8(value: Uint8Array): string {
  return new TextDecoder().decode(value);
}

export function bytesToHex(value: Uint8Array): string {
  let out = "";
  for (const byte of value) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}
