/**
 * WASM wrapper for pqmsg-core crypto operations.
 *
 * Dynamically loads the WASM module built from `crates/pqmsg-core`
 * with `wasm-pack build --features wasm-pq --no-default-features --target web`.
 *
 * Provides both low-level primitives and the real hybrid PQ direct-message
 * handshake/session exports used by the web client.
 */

// These types match the Rust wasm-bindgen payloads.
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

export interface WasmSessionKeys {
  userId: string;
  deviceId: string;
  suite: "ml-kem-768" | "kyber768";
  identityX25519Pub: string;
  identityX25519Secret: string;
  identitySigPub: string;
  identitySigSecret: string;
  identityPqSigPub: string;
  identityPqSigSecret: string;
  signedPrekeyX25519Pub: string;
  signedPrekeyX25519Secret: string;
  pqSignedPrekeyPubMlkem768: string;
  pqSignedPrekeySecretMlkem768: string;
  oneTimePrekeysX25519: string[];
  oneTimePrekeysX25519Secret: string[];
  oneTimePrekeysMlkem768: string[];
  oneTimePrekeysMlkem768Secret: string[];
}

export interface WasmServerBundle {
  user_id: string;
  identity_x25519_pub: string;
  identity_sig_pub: string;
  identity_pq_sig_pub: string;
  signed_prekey_x25519_pub: string;
  sig_over_spk: string;
  pq_signed_prekey_pub_mlkem768: string;
  sig_over_pqspk: string;
  pq_sig_over_spk: string;
  pq_sig_over_pqspk: string;
  one_time_prekey_x25519: string | null;
  one_time_prekey_mlkem768: string | null;
}

export interface WasmDirectSendResult {
  message_bytes_base64: string;
  session_json: string;
  used_handshake: boolean;
}

export interface WasmDirectDecryptResult {
  plaintext_utf8: string;
  plaintext_base64: string;
  session_json: string;
  used_handshake: boolean;
  updated_keys: WasmSessionKeys;
}

export interface WasmOpenedCertifiedSealedMessage {
  sender_user_id: string;
  sender_device_id: string;
  payload_message_bytes_base64: string;
}

export interface WasmTransparencyVerificationResult {
  verified: boolean;
  consistency_verified: boolean;
  leaf_user_id: string;
  leaf_version: number;
  tree_size: number;
  epoch: number;
}

export type PrivateGroupRole = "Owner" | "Admin" | "Member";

export interface PrivateGroupAttributes {
  title: string;
  description: string | null;
  avatar_hash_sha256: string | null;
  disappearing_message_timer_seconds: number | null;
}

export interface PrivateGroupMember {
  user_id: string;
  role: PrivateGroupRole;
}

export interface PrivateGroupCiphertextEnvelope {
  nonce: number[];
  ciphertext: number[];
  aad: number[];
}

export interface PrivateGroupEncryptedSnapshot {
  group_id: string;
  epoch: number;
  state_commitment_sha256: number[];
  ciphertext: PrivateGroupCiphertextEnvelope;
}

export interface PrivateGroupInvitePackage {
  group_id: string;
  epoch: number;
  root_secret: number[];
  snapshot: PrivateGroupEncryptedSnapshot;
}

export interface PrivateGroupMemberCredential {
  group_id: string;
  epoch: number;
  member_user_id: string;
  role: PrivateGroupRole;
  credential_secret: number[];
}

export interface PrivateGroupJoinPackage {
  invite: PrivateGroupInvitePackage;
  member_credential: PrivateGroupMemberCredential;
}

export interface PrivateGroupState {
  group_id: string;
  epoch: number;
  root_secret: number[];
  attributes: PrivateGroupAttributes;
  members: PrivateGroupMember[];
  created_at_unix_seconds: number;
  updated_at_unix_seconds: number;
}

export interface PrivateGroupCredentialMaterial {
  membership_handle_sha256: string;
  member_commitment_sha256: string;
  fetch_key_base64: string;
  fetch_key_sha256: string;
  publish_key_base64: string | null;
  publish_key_sha256: string | null;
}

export interface PrivateGroupRestoreResult {
  state: PrivateGroupState;
  member_credential: PrivateGroupMemberCredential;
}

export interface PrivateGroupEpochTransition {
  next_state: PrivateGroupState;
  member_credentials: PrivateGroupMemberCredential[];
  added_member_join_package: PrivateGroupJoinPackage | null;
}

export interface KemKeyPair {
  public_key: Uint8Array;
  secret_key: Uint8Array;
}

export interface KemEncapsulateResult {
  ciphertext: Uint8Array;
  shared_secret: Uint8Array;
}

export interface PqSigKeyPair {
  public_key: Uint8Array;
  secret_key: Uint8Array;
}

// Lazy-loaded WASM module typed as any because the pkg may not exist at build time.
let wasmModule: Record<string, (...args: unknown[]) => unknown> | null = null;
let wasmLoadAttempted = false;

function parseJsonResult<T>(json: unknown): T {
  if (typeof json !== "string") {
    throw new Error("Unexpected WASM JSON payload");
  }
  return JSON.parse(json) as T;
}

/** Try to load the WASM module. Returns true if available. */
export async function initWasm(): Promise<boolean> {
  if (wasmModule) return true;
  if (wasmLoadAttempted) return false;
  wasmLoadAttempted = true;
  try {
    const wasmPath = "../pkg/pqmsg_core";
    const mod = await import(/* @vite-ignore */ wasmPath);
    await mod.default();
    wasmModule = mod;
    return true;
  } catch {
    return false;
  }
}

/** Check if the WASM module has been loaded. */
export function wasmAvailable(): boolean {
  return wasmModule !== null;
}

/** Check if real session-based PQ messaging exports are available. */
export function sessionMessagingAvailable(): boolean {
  return wasmModule !== null
    && typeof wasmModule.wasm_initiate_session_and_encrypt === "function"
    && typeof wasmModule.wasm_encrypt_with_session === "function"
    && typeof wasmModule.wasm_decrypt_message === "function";
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

export function computeSafetyNumber(
  localUserId: string,
  localIdentityX25519PubB64: string,
  localIdentityPqSigPubB64: string,
  peerUserId: string,
  peerIdentityX25519PubB64: string,
  peerIdentityPqSigPubB64: string
): string {
  if (!wasmModule || typeof wasmModule.wasm_compute_safety_number !== "function") {
    throw new Error("WASM PQ runtime is required to compute safety numbers");
  }
  return wasmModule.wasm_compute_safety_number(
    localUserId,
    localIdentityX25519PubB64,
    localIdentityPqSigPubB64,
    peerUserId,
    peerIdentityX25519PubB64,
    peerIdentityPqSigPubB64
  ) as string;
}

export function verifyTransparencyProof(
  proofJson: string,
  serverPubKeyB64: string,
  previousSthJson?: string | null,
): WasmTransparencyVerificationResult {
  if (!wasmModule || typeof wasmModule.wasm_verify_transparency_proof !== "function") {
    throw new Error("WASM PQ runtime is required to verify transparency proofs");
  }
  return wasmModule.wasm_verify_transparency_proof(
    proofJson,
    serverPubKeyB64,
    previousSthJson ?? null,
  ) as WasmTransparencyVerificationResult;
}

/** Check if PQ KEM operations are available in WASM. */
export function kemAvailable(): boolean {
  return wasmModule !== null && typeof wasmModule.wasm_kem_keypair === "function";
}

/** Generate an ML-KEM-768 keypair via WASM. */
export function kemKeypair(): KemKeyPair {
  if (!wasmModule) throw new Error("WASM not initialized");
  if (typeof wasmModule.wasm_kem_keypair !== "function") {
    throw new Error("KEM not available - WASM built without pq-oqs");
  }
  return wasmModule.wasm_kem_keypair() as KemKeyPair;
}

/** Encapsulate a shared secret using an ML-KEM-768 public key. */
export function kemEncapsulate(recipientPublicKey: Uint8Array): KemEncapsulateResult {
  if (!wasmModule) throw new Error("WASM not initialized");
  if (typeof wasmModule.wasm_kem_encapsulate !== "function") {
    throw new Error("KEM not available - WASM built without pq-oqs");
  }
  return wasmModule.wasm_kem_encapsulate(recipientPublicKey) as KemEncapsulateResult;
}

/** Decapsulate a shared secret from a ciphertext using an ML-KEM-768 secret key. */
export function kemDecapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  if (typeof wasmModule.wasm_kem_decapsulate !== "function") {
    throw new Error("KEM not available - WASM built without pq-oqs");
  }
  return wasmModule.wasm_kem_decapsulate(secretKey, ciphertext) as unknown as Uint8Array;
}

/** Check if PQ signature operations are available in WASM. */
export function pqSigAvailable(): boolean {
  return wasmModule !== null && typeof wasmModule.wasm_ml_dsa_keypair === "function";
}

/** Generate an ML-DSA-65 keypair via WASM. */
export function mlDsaKeypair(): PqSigKeyPair {
  if (!wasmModule) throw new Error("WASM not initialized");
  if (typeof wasmModule.wasm_ml_dsa_keypair !== "function") {
    throw new Error("ML-DSA not available - WASM built without pq-oqs");
  }
  return wasmModule.wasm_ml_dsa_keypair() as PqSigKeyPair;
}

/** Sign a message using an ML-DSA-65 secret key. */
export function mlDsaSign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  if (!wasmModule) throw new Error("WASM not initialized");
  if (typeof wasmModule.wasm_ml_dsa_sign !== "function") {
    throw new Error("ML-DSA not available - WASM built without pq-oqs");
  }
  return wasmModule.wasm_ml_dsa_sign(secretKey, message) as unknown as Uint8Array;
}

/** Verify an ML-DSA-65 signature. */
export function mlDsaVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): void {
  if (!wasmModule) throw new Error("WASM not initialized");
  if (typeof wasmModule.wasm_ml_dsa_verify !== "function") {
    throw new Error("ML-DSA not available - WASM built without pq-oqs");
  }
  wasmModule.wasm_ml_dsa_verify(publicKey, message, signature);
}

/** Initiate a real PQ direct-message session and encrypt the first message. */
export function initiateSessionAndEncrypt(
  keys: WasmSessionKeys,
  fromUserId: string,
  peerUserId: string,
  peerBundle: WasmServerBundle,
  plaintextUtf8: string
): WasmDirectSendResult {
  if (!sessionMessagingAvailable()) {
    throw new Error("WASM PQ session messaging is not available");
  }
  return wasmModule!.wasm_initiate_session_and_encrypt(
    keys,
    fromUserId,
    peerUserId,
    peerBundle,
    plaintextUtf8
  ) as WasmDirectSendResult;
}

/** Encrypt a follow-up direct message with an existing session snapshot. */
export function encryptWithSession(
  sessionJson: string,
  senderUserId: string,
  peerUserId: string,
  plaintextUtf8: string
): WasmDirectSendResult {
  if (!sessionMessagingAvailable()) {
    throw new Error("WASM PQ session messaging is not available");
  }
  return wasmModule!.wasm_encrypt_with_session(
    sessionJson,
    senderUserId,
    peerUserId,
    plaintextUtf8
  ) as WasmDirectSendResult;
}

/** Decrypt either an initial handshake message or a follow-up session message. */
export function decryptDirectMessage(
  keys: WasmSessionKeys,
  recipientUserId: string,
  senderUserId: string,
  messageBytesBase64: string,
  existingSessionJson?: string | null
): WasmDirectDecryptResult {
  if (!sessionMessagingAvailable()) {
    throw new Error("WASM PQ session messaging is not available");
  }
  return wasmModule!.wasm_decrypt_message(
    keys,
    recipientUserId,
    senderUserId,
    messageBytesBase64,
    existingSessionJson ?? undefined
  ) as WasmDirectDecryptResult;
}

export function sealMessageWithSenderCert(
  keys: WasmSessionKeys,
  recipientUserId: string,
  recipientIdentityX25519Pub: string,
  payloadMessageBytesBase64: string,
  senderCertificateBase64: string
): string {
  if (!wasmModule || typeof wasmModule.wasm_seal_message_with_sender_cert !== "function") {
    throw new Error("WASM certified sealed sender transport is not available");
  }
  return wasmModule.wasm_seal_message_with_sender_cert(
    keys,
    recipientUserId,
    recipientIdentityX25519Pub,
    payloadMessageBytesBase64,
    senderCertificateBase64
  ) as string;
}

export function openSealedMessageWithSenderCert(
  keys: WasmSessionKeys,
  senderIdentityX25519Pub: string | null | undefined,
  sealedMessageBytesBase64: string,
  serverIssuerEd25519Pub: string
): WasmOpenedCertifiedSealedMessage {
  if (!wasmModule || typeof wasmModule.wasm_open_sealed_message_with_sender_cert !== "function") {
    throw new Error("WASM certified sealed sender transport is not available");
  }
  return wasmModule.wasm_open_sealed_message_with_sender_cert(
    keys,
    senderIdentityX25519Pub ?? null,
    sealedMessageBytesBase64,
    serverIssuerEd25519Pub
  ) as WasmOpenedCertifiedSealedMessage;
}

export function privateGroupBindingsAvailable(): boolean {
  return wasmModule !== null
    && typeof wasmModule.wasm_private_group_create_state === "function"
    && typeof wasmModule.wasm_private_group_describe_member_credential === "function";
}

export function privateGroupCreateState(
  ownerUserId: string,
  attributes: PrivateGroupAttributes,
  initialMembers: PrivateGroupMember[],
  createdAtUnixSeconds: number
): PrivateGroupState {
  if (!privateGroupBindingsAvailable()) {
    throw new Error("WASM private group bindings are not available");
  }
  return parseJsonResult<PrivateGroupState>(
    wasmModule!.wasm_private_group_create_state(
      ownerUserId,
      JSON.stringify(attributes),
      JSON.stringify(initialMembers),
      createdAtUnixSeconds
    )
  );
}

export function privateGroupEncryptSnapshot(state: PrivateGroupState): PrivateGroupEncryptedSnapshot {
  if (!privateGroupBindingsAvailable()) {
    throw new Error("WASM private group bindings are not available");
  }
  return parseJsonResult<PrivateGroupEncryptedSnapshot>(
    wasmModule!.wasm_private_group_encrypt_snapshot(JSON.stringify(state))
  );
}

export function privateGroupExportInvitePackage(
  state: PrivateGroupState
): PrivateGroupInvitePackage {
  if (!privateGroupBindingsAvailable()) {
    throw new Error("WASM private group bindings are not available");
  }
  return parseJsonResult<PrivateGroupInvitePackage>(
    wasmModule!.wasm_private_group_export_invite_package(JSON.stringify(state))
  );
}

export function privateGroupExportJoinPackageForMember(
  state: PrivateGroupState,
  memberUserId: string
): PrivateGroupJoinPackage {
  if (!privateGroupBindingsAvailable()) {
    throw new Error("WASM private group bindings are not available");
  }
  return parseJsonResult<PrivateGroupJoinPackage>(
    wasmModule!.wasm_private_group_export_join_package_for_member(
      JSON.stringify(state),
      memberUserId
    )
  );
}

export function privateGroupRestoreJoinPackage(
  joinPackage: PrivateGroupJoinPackage
): PrivateGroupRestoreResult {
  if (!privateGroupBindingsAvailable()) {
    throw new Error("WASM private group bindings are not available");
  }
  return parseJsonResult<PrivateGroupRestoreResult>(
    wasmModule!.wasm_private_group_restore_join_package(JSON.stringify(joinPackage))
  );
}

export function privateGroupDescribeMemberCredential(
  credential: PrivateGroupMemberCredential
): PrivateGroupCredentialMaterial {
  if (!privateGroupBindingsAvailable()) {
    throw new Error("WASM private group bindings are not available");
  }
  return parseJsonResult<PrivateGroupCredentialMaterial>(
    wasmModule!.wasm_private_group_describe_member_credential(JSON.stringify(credential))
  );
}

export function privateGroupPrepareAddMemberTransition(
  state: PrivateGroupState,
  memberUserId: string,
  role: PrivateGroupRole,
  updatedAtUnixSeconds: number
): PrivateGroupEpochTransition {
  if (!privateGroupBindingsAvailable()) {
    throw new Error("WASM private group bindings are not available");
  }
  return parseJsonResult<PrivateGroupEpochTransition>(
    wasmModule!.wasm_private_group_prepare_add_member_transition(
      JSON.stringify(state),
      memberUserId,
      role,
      updatedAtUnixSeconds
    )
  );
}

export function privateGroupPrepareRemoveMemberTransition(
  state: PrivateGroupState,
  memberUserId: string,
  updatedAtUnixSeconds: number
): PrivateGroupEpochTransition {
  if (!privateGroupBindingsAvailable()) {
    throw new Error("WASM private group bindings are not available");
  }
  return parseJsonResult<PrivateGroupEpochTransition>(
    wasmModule!.wasm_private_group_prepare_remove_member_transition(
      JSON.stringify(state),
      memberUserId,
      updatedAtUnixSeconds
    )
  );
}
