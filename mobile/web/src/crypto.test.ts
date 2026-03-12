import { describe, it, expect, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

vi.mock("./crypto-wasm", () => ({
  initWasm: vi.fn(async () => true),
  wasmAvailable: vi.fn(() => false),
  sessionMessagingAvailable: vi.fn(() => false),
  kemAvailable: vi.fn(() => true),
  kemKeypair: vi.fn(() => ({
    public_key: new Uint8Array(1184).fill(7),
    secret_key: new Uint8Array(2400).fill(9),
  })),
  pqSigAvailable: vi.fn(() => true),
  mlDsaKeypair: vi.fn(() => ({
    public_key: new Uint8Array(1952).fill(5),
    secret_key: new Uint8Array(4032).fill(6),
  })),
  mlDsaSign: vi.fn(() => new Uint8Array(3309).fill(8)),
  mlDsaVerify: vi.fn(),
  encrypt: vi.fn(),
  decrypt: vi.fn(),
  hkdfSha256: vi.fn(),
  x25519Dh: vi.fn(),
  x25519Keypair: vi.fn(),
  wrapSecret: vi.fn(),
  unwrapSecret: vi.fn(),
  conversationAd: vi.fn(),
  initiateSessionAndEncrypt: vi.fn(),
  encryptWithSession: vi.fn(),
  decryptDirectMessage: vi.fn(),
}));

import {
  generateIdentityKeys,
  buildPublishPrekeysPayload,
  buildPrekeysAuthHeaders,
  buildRelayAuthHeaders,
  buildInboxAuthHeaders,
  buildListDevicesAuthHeaders,
  buildLinkDeviceAuthHeaders,
  buildRevokeDeviceAuthHeaders,
  buildRetireDeviceAuthHeaders,
  buildProfileGetAuthHeaders,
  buildProfileUpsertAuthHeaders,
  buildPresenceGetAuthHeaders,
  buildPresenceUpdateAuthHeaders,
  buildTypingGetAuthHeaders,
  buildTypingUpdateAuthHeaders,
  buildSendReceiptAuthHeaders,
  buildGetReceiptsAuthHeaders,
  buildContactsListAuthHeaders,
  buildContactsUpsertAuthHeaders,
  buildContactsRemoveAuthHeaders,
  buildGroupCreateAuthHeaders,
  buildGroupMembersListAuthHeaders,
  buildGroupMembersAddAuthHeaders,
  buildGroupMembersRemoveAuthHeaders,
  buildGroupRelayAuthHeaders,
  buildFileUploadAuthHeaders,
  buildFileDownloadAuthHeaders,
  buildInboxDeleteAuthHeaders,
  buildPrekeysStatusAuthHeaders,
  buildRotateInitAuthHeaders,
  buildRotateConfirmAuthHeaders,
  buildIdentityLogAuthHeaders,
  buildSealedInboxAuthHeaders,
  buildEphemeralRelayAuthHeaders,
  sealJsonWithPassphrase,
  openJsonWithPassphrase,
  encodeWireEnvelopeBase64,
  decodeWireEnvelopeBase64,
  identityFingerprint,
  type GeneratedKeys,
  type WireEnvelope,
} from "./crypto";
import { base64ToBytes, bytesToBase64, bytesToHex, utf8ToBytes } from "./base64";

// Helper: generate a test keyset
function testKeys(): GeneratedKeys {
  return generateIdentityKeys("alice", "device1", "ml-kem-768", 2);
}

describe("generateIdentityKeys", () => {
  it("generates keys with correct metadata", () => {
    const keys = testKeys();
    expect(keys.userId).toBe("alice");
    expect(keys.deviceId).toBe("device1");
    expect(keys.suite).toBe("ml-kem-768");
  });

  it("generates valid X25519 public keys (32 bytes)", () => {
    const keys = testKeys();
    expect(base64ToBytes(keys.identityX25519Pub).length).toBe(32);
    expect(base64ToBytes(keys.signedPrekeyX25519Pub).length).toBe(32);
  });

  it("generates valid Ed25519 public key (32 bytes)", () => {
    const keys = testKeys();
    expect(base64ToBytes(keys.identitySigPub).length).toBe(32);
  });

  it("generates ML-DSA identity keys when PQ support is available", () => {
    const keys = testKeys();
    expect(base64ToBytes(keys.identityPqSigPub).length).toBe(1952);
    expect(base64ToBytes(keys.identityPqSigSecret).length).toBe(4032);
  });

  it("generates correct number of one-time prekeys", () => {
    const keys = generateIdentityKeys("bob", "d2", "ml-kem-768", 5);
    expect(keys.oneTimePrekeysX25519.length).toBe(5);
    expect(keys.oneTimePrekeysX25519Secret.length).toBe(5);
    expect(keys.oneTimePrekeysMlkem768.length).toBe(5);
    expect(keys.oneTimePrekeysMlkem768Secret.length).toBe(5);
  });

  it("rejects count < 1", () => {
    expect(() => generateIdentityKeys("x", "d", "ml-kem-768", 0)).toThrow();
  });

  it("rejects count > 64", () => {
    expect(() => generateIdentityKeys("x", "d", "ml-kem-768", 65)).toThrow();
  });

  it("two generations produce different keys", () => {
    const a = testKeys();
    const b = testKeys();
    expect(a.identityX25519Pub).not.toBe(b.identityX25519Pub);
    expect(a.identitySigPub).not.toBe(b.identitySigPub);
  });
});

describe("buildPublishPrekeysPayload", () => {
  it("returns all expected fields", () => {
    const keys = testKeys();
    const payload = buildPublishPrekeysPayload(keys);
    expect(payload.signed_prekey_x25519_pub).toBe(keys.signedPrekeyX25519Pub);
    expect(payload.pq_signed_prekey_pub_mlkem768).toBe(keys.pqSignedPrekeyPubMlkem768);
    expect(payload.pq_sig_over_spk).toBeTruthy();
    expect(payload.pq_sig_over_pqspk).toBeTruthy();
    expect(payload.one_time_prekeys_x25519).toEqual(keys.oneTimePrekeysX25519);
    expect(payload.one_time_prekeys_mlkem768).toEqual(keys.oneTimePrekeysMlkem768);
  });

  it("produces valid Ed25519 signatures (64 bytes)", () => {
    const keys = testKeys();
    const payload = buildPublishPrekeysPayload(keys);
    expect(base64ToBytes(payload.sig_over_spk).length).toBe(64);
    expect(base64ToBytes(payload.sig_over_pqspk).length).toBe(64);
  });
});

// Helper: validate auth header shape
function assertAuthHeaders(headers: Record<string, string>, userId: string, deviceId: string) {
  expect(headers["x-pqmsg-auth-user"]).toBe(userId);
  expect(headers["x-pqmsg-auth-device"]).toBe(deviceId);
  expect(headers["x-pqmsg-auth-timestamp"]).toMatch(/^\d+$/);
  expect(headers["x-pqmsg-auth-nonce"]).toBeTruthy();
  expect(headers["x-pqmsg-auth-signature"]).toBeTruthy();
  // Signature should be valid base64 encoding of 64 bytes
  expect(base64ToBytes(headers["x-pqmsg-auth-signature"]).length).toBe(64);
}

describe("auth header builders", () => {
  const keys = testKeys();

  it("buildPrekeysAuthHeaders", () => {
    const payload = buildPublishPrekeysPayload(keys);
    const headers = buildPrekeysAuthHeaders(keys, payload);
    assertAuthHeaders(headers, "alice", "device1");
  });

  it("buildRelayAuthHeaders", () => {
    const msgB64 = bytesToBase64(utf8ToBytes("hello"));
    const headers = buildRelayAuthHeaders(keys, "bob", msgB64);
    assertAuthHeaders(headers, "alice", "device1");
  });

  it("buildInboxAuthHeaders", () => {
    const headers = buildInboxAuthHeaders(keys, 0);
    assertAuthHeaders(headers, "alice", "device1");
  });

  it("buildListDevicesAuthHeaders", () => {
    assertAuthHeaders(buildListDevicesAuthHeaders(keys), "alice", "device1");
  });

  it("buildLinkDeviceAuthHeaders", () => {
    assertAuthHeaders(buildLinkDeviceAuthHeaders(keys, "device2"), "alice", "device1");
  });

  it("buildRevokeDeviceAuthHeaders", () => {
    assertAuthHeaders(buildRevokeDeviceAuthHeaders(keys, "device2"), "alice", "device1");
  });

  it("buildRetireDeviceAuthHeaders", () => {
    assertAuthHeaders(buildRetireDeviceAuthHeaders(keys), "alice", "device1");
  });

  it("buildProfileGetAuthHeaders", () => {
    assertAuthHeaders(buildProfileGetAuthHeaders(keys, "bob"), "alice", "device1");
  });

  it("buildProfileUpsertAuthHeaders", () => {
    assertAuthHeaders(
      buildProfileUpsertAuthHeaders(keys, "Alice", "image/png", "base64avatar"),
      "alice", "device1"
    );
  });

  it("buildPresenceGetAuthHeaders", () => {
    assertAuthHeaders(buildPresenceGetAuthHeaders(keys), "alice", "device1");
  });

  it("buildPresenceUpdateAuthHeaders", () => {
    assertAuthHeaders(buildPresenceUpdateAuthHeaders(keys, "online"), "alice", "device1");
  });

  it("buildTypingGetAuthHeaders", () => {
    assertAuthHeaders(buildTypingGetAuthHeaders(keys), "alice", "device1");
  });

  it("buildTypingUpdateAuthHeaders", () => {
    assertAuthHeaders(buildTypingUpdateAuthHeaders(keys, "bob", true), "alice", "device1");
  });

  it("buildSendReceiptAuthHeaders", () => {
    assertAuthHeaders(buildSendReceiptAuthHeaders(keys, 42, "delivered"), "alice", "device1");
  });

  it("buildGetReceiptsAuthHeaders", () => {
    assertAuthHeaders(buildGetReceiptsAuthHeaders(keys, 0), "alice", "device1");
  });

  it("buildContactsListAuthHeaders", () => {
    assertAuthHeaders(buildContactsListAuthHeaders(keys), "alice", "device1");
  });

  it("buildContactsUpsertAuthHeaders", () => {
    assertAuthHeaders(
      buildContactsUpsertAuthHeaders(keys, "bob", "Bob", false, ""),
      "alice", "device1"
    );
  });

  it("buildContactsRemoveAuthHeaders", () => {
    assertAuthHeaders(buildContactsRemoveAuthHeaders(keys, "bob"), "alice", "device1");
  });

  it("buildGroupCreateAuthHeaders", () => {
    assertAuthHeaders(buildGroupCreateAuthHeaders(keys, "g1", ["alice", "bob"]), "alice", "device1");
  });

  it("buildGroupMembersListAuthHeaders", () => {
    assertAuthHeaders(buildGroupMembersListAuthHeaders(keys, "g1"), "alice", "device1");
  });

  it("buildGroupMembersAddAuthHeaders", () => {
    assertAuthHeaders(buildGroupMembersAddAuthHeaders(keys, "g1", "charlie"), "alice", "device1");
  });

  it("buildGroupMembersRemoveAuthHeaders", () => {
    assertAuthHeaders(buildGroupMembersRemoveAuthHeaders(keys, "g1", "charlie"), "alice", "device1");
  });

  it("buildGroupRelayAuthHeaders", () => {
    const msg = bytesToBase64(utf8ToBytes("group msg"));
    assertAuthHeaders(buildGroupRelayAuthHeaders(keys, "g1", msg), "alice", "device1");
  });

  it("buildFileUploadAuthHeaders", () => {
    const blob = bytesToBase64(utf8ToBytes("file data"));
    assertAuthHeaders(buildFileUploadAuthHeaders(keys, "bob", "text/plain", blob), "alice", "device1");
  });

  it("buildFileDownloadAuthHeaders", () => {
    assertAuthHeaders(buildFileDownloadAuthHeaders(keys, "file123"), "alice", "device1");
  });

  it("buildInboxDeleteAuthHeaders", () => {
    assertAuthHeaders(buildInboxDeleteAuthHeaders(keys, [1, 2, 3]), "alice", "device1");
  });

  it("buildInboxDeleteAuthHeaders with deleteBeforeId", () => {
    assertAuthHeaders(buildInboxDeleteAuthHeaders(keys, [1], 100), "alice", "device1");
  });

  it("buildPrekeysStatusAuthHeaders", () => {
    assertAuthHeaders(buildPrekeysStatusAuthHeaders(keys), "alice", "device1");
  });

  it("buildRotateInitAuthHeaders", () => {
    assertAuthHeaders(buildRotateInitAuthHeaders(keys, "newXpub", "newSigPub"), "alice", "device1");
  });

  it("buildRotateConfirmAuthHeaders", () => {
    assertAuthHeaders(
      buildRotateConfirmAuthHeaders(keys, "challenge1", "sigCurrent", "sigNew"),
      "alice", "device1"
    );
  });

  it("buildIdentityLogAuthHeaders", () => {
    assertAuthHeaders(buildIdentityLogAuthHeaders(keys), "alice", "device1");
  });

  it("buildSealedInboxAuthHeaders", () => {
    assertAuthHeaders(buildSealedInboxAuthHeaders(keys, 0), "alice", "device1");
  });

  it("buildEphemeralRelayAuthHeaders", () => {
    assertAuthHeaders(buildEphemeralRelayAuthHeaders(keys, "bob", 30), "alice", "device1");
  });
});

describe("sealJsonWithPassphrase / openJsonWithPassphrase", () => {
  it("round-trips a JSON object", async () => {
    const obj = { foo: "bar", n: 42, arr: [1, 2, 3] };
    const sealed = await sealJsonWithPassphrase(obj, "strongpassphrase");
    const opened = await openJsonWithPassphrase(sealed, "strongpassphrase");
    expect(opened).toEqual(obj);
  });

  it("fails with wrong passphrase", async () => {
    const sealed = await sealJsonWithPassphrase({ key: "value" }, "correct");
    await expect(openJsonWithPassphrase(sealed, "wrong")).rejects.toThrow();
  });

  it("rejects empty passphrase", async () => {
    await expect(sealJsonWithPassphrase({ a: 1 }, "")).rejects.toThrow("passphrase is empty");
  });

  it("rejects whitespace-only passphrase", async () => {
    await expect(sealJsonWithPassphrase({ a: 1 }, "   ")).rejects.toThrow("passphrase is empty");
  });
});

describe("encodeWireEnvelopeBase64 / decodeWireEnvelopeBase64", () => {
  it("round-trips a production wire envelope", () => {
    const envelope: WireEnvelope = {
      v: 1,
      mode: "pqmsg-classical-v1",
      sender: "alice",
      recipient: "bob",
      salt_b64: bytesToBase64(new Uint8Array([1, 2, 3])),
      iv_b64: bytesToBase64(new Uint8Array([4, 5, 6])),
      ct_b64: bytesToBase64(utf8ToBytes("ciphertext")),
    };
    const encoded = encodeWireEnvelopeBase64(envelope);
    expect(typeof encoded).toBe("string");
    const decoded = decodeWireEnvelopeBase64(encoded);
    expect(decoded.v).toBe(1);
    expect(decoded.mode).toBe("pqmsg-classical-v1");
    expect(decoded.sender).toBe("alice");
    expect(decoded.recipient).toBe("bob");
    expect(decoded.ct_b64).toBe(envelope.ct_b64);
  });

  it("rejects unsupported wire version", () => {
    const bad: WireEnvelope = {
      v: 2 as 1,
      mode: "pqmsg-classical-v1",
      sender: "a",
      recipient: "b",
      salt_b64: "",
      iv_b64: "",
      ct_b64: "",
    };
    const encoded = bytesToBase64(utf8ToBytes(JSON.stringify(bad)));
    expect(() => decodeWireEnvelopeBase64(encoded)).toThrow("unsupported wire mode");
  });

  it("rejects unsupported wire mode", () => {
    const bad = {
      v: 1,
      mode: "unknown-mode",
      sender: "a",
      recipient: "b",
      salt_b64: "",
      iv_b64: "",
      ct_b64: "",
    };
    const encoded = bytesToBase64(utf8ToBytes(JSON.stringify(bad)));
    expect(() => decodeWireEnvelopeBase64(encoded)).toThrow("unsupported wire mode");
  });
});

describe("identityFingerprint", () => {
  it("returns a 64-char hex string (sha256)", () => {
    const keys = testKeys();
    const fp = identityFingerprint(keys.identityX25519Pub);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", () => {
    const keys = testKeys();
    const fp1 = identityFingerprint(keys.identityX25519Pub);
    const fp2 = identityFingerprint(keys.identityX25519Pub);
    expect(fp1).toBe(fp2);
  });

  it("different keys produce different fingerprints", () => {
    const a = testKeys();
    const b = testKeys();
    expect(identityFingerprint(a.identityX25519Pub))
      .not.toBe(identityFingerprint(b.identityX25519Pub));
  });

  it("changes when the PQ identity key changes", () => {
    const keys = testKeys();
    expect(identityFingerprint(keys.identityX25519Pub))
      .not.toBe(identityFingerprint(keys.identityX25519Pub, keys.identityPqSigPub));
  });
});
