/**
 * WASM wrapper for pqmsg-core crypto operations.
 *
 * Dynamically loads the WASM module built from `crates/pqmsg-core`
 * with `wasm-pack build --features wasm --no-default-features --target web`.
 *
 * Provides the same interface shape as the WebCrypto fallback in crypto.ts.
 */

// These types match the Rust WasmIdentityKeys struct
export interface WasmIdentityKeys {
  user_id: string;
  device_id: string;
  identity_key_id: string;
  identity_pub: Uint8Array;
  identity_secret: Uint8Array;
  signed_prekey_id: string;
  signed_prekey_pub: Uint8Array;
  signed_prekey_secret: Uint8Array;
}

export interface WasmOtpk {
  key_id: string;
  public: Uint8Array;
  secret: Uint8Array;
}

// Lazy-loaded WASM module — typed as any since the pkg may not exist at build time
let wasmModule: Record<string, (...args: unknown[]) => unknown> | null = null;
let wasmLoadAttempted = false;

/** Try to load the WASM module. Returns true if available. */
export async function initWasm(): Promise<boolean> {
  if (wasmModule) return true;
  if (wasmLoadAttempted) return false;
  wasmLoadAttempted = true;
  try {
    // Use variable to prevent Rollup from resolving at build time
    const wasmPath = "../../pkg/pqmsg_core";
    const mod = await import(/* @vite-ignore */ wasmPath);
    await mod.default(); // initialize WASM
    wasmModule = mod;
    return true;
  } catch {
    return false;
  }
}

/** Check if WASM crypto is available (without loading). */
export function wasmAvailable(): boolean {
  return wasmModule !== null;
}

/** Generate identity keys (X25519) via WASM. */
export function generateIdentityKeys(userId: string, deviceId: string): WasmIdentityKeys {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_generate_identity_keys(userId, deviceId) as WasmIdentityKeys;
}

/** Generate a one-time prekey via WASM. */
export function generateOneTimePreKey(keyId: string): WasmOtpk {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_generate_one_time_prekey(keyId) as WasmOtpk;
}

/** AEAD encrypt via WASM (ChaCha20-Poly1305). */
export function encrypt(key: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_encrypt(key, plaintext, ad) as unknown as Uint8Array;
}

/** AEAD decrypt via WASM (ChaCha20-Poly1305). */
export function decrypt(key: Uint8Array, ciphertextWithNonce: Uint8Array, ad: Uint8Array): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_decrypt(key, ciphertextWithNonce, ad) as unknown as Uint8Array;
}

/** HKDF-SHA256 via WASM. */
export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, outLen: number): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_hkdf_sha256(ikm, salt, info, outLen) as unknown as Uint8Array;
}

/** X25519 Diffie-Hellman via WASM. */
export function x25519Dh(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_x25519_dh(secretKey, publicKey) as unknown as Uint8Array;
}

/** Generate X25519 keypair via WASM. Returns 64 bytes: secret || public. */
export function x25519Keypair(): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_x25519_keypair() as unknown as Uint8Array;
}

/** Wrap secret bytes with Argon2id + AEAD for at-rest storage. */
export function wrapSecret(passphrase: string, plaintext: Uint8Array): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_wrap_secret(passphrase, plaintext) as unknown as Uint8Array;
}

/** Unwrap secret bytes from at-rest storage. */
export function unwrapSecret(passphrase: string, wrappedJson: Uint8Array): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_unwrap_secret(passphrase, wrappedJson) as unknown as Uint8Array;
}

/** Build conversation associated data. */
export function conversationAd(sender: string, recipient: string): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  return wasmModule.wasm_conversation_ad(sender, recipient) as unknown as Uint8Array;
}
