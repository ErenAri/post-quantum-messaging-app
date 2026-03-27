import { describe, it, expect, vi } from "vitest";
import { ed25519, ristretto255 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

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
  computeSafetyNumber: vi.fn(() => "12345 12345 12345 12345 12345 12345 12345 12345 12345 12345 12345 12345"),
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
  computeSafetyNumber,
  identityFingerprint,
  finalizeContactDiscoveryTokens,
  prepareContactDiscoveryBlindRequest,
  verifyContactDiscoveryManifest,
  verifyContactDiscoveryAttestationDocument,
  verifyContactDiscoveryEvaluationProofs,
  type GeneratedKeys,
  type WireEnvelope,
} from "./crypto";
import { base64ToBytes, bytesToBase64, bytesToHex, concatBytes, utf8ToBytes } from "./base64";

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

describe("verifyContactDiscoveryManifest", () => {
  const attestationSigningSecret = new Uint8Array(32).fill(23);
  const attestationIssuerPub = bytesToBase64(ed25519.getPublicKey(attestationSigningSecret));
  const attestationChallengeNonce = bytesToBase64(new Uint8Array(16).fill(7));

  function signedManifest() {
    const manifestSigningSecret = new Uint8Array(32).fill(19);
    const manifestIssuerPub = bytesToBase64(ed25519.getPublicKey(manifestSigningSecret));
    const payload = {
      service: "pqmsg-discovery",
      protocol_version: 1,
      attestation_mode: "unattested_development",
      attestation_verifier: null,
      enclave_measurement_hex: null,
      attestation_document_format: null,
      attestation_document_sha256: null,
      attestation_challenge_mode: null,
      ticket_format: "base64(json-payload).base64(ed25519-signature)",
      ticket_issuer_ed25519_pub: "ticket-issuer-ed25519-pub",
      ticket_max_ttl_seconds: 300,
      lookup_protocol: "blind_token_directory_preview",
      privacy_mode: "blind_evaluation_preview",
      directory_backend: "simulated_enclave_preview",
      host_enclave_protocol_version: 1,
      enclave_release_id: "simulated-preview",
      match_result_format: "contact_invite_token",
      oprf_suite: "ristretto255-sha512-preview",
      evaluation_proof_mode: "dleq_per_element_preview",
      oprf_public_key_ristretto255: bytesToBase64(ristretto255.Point.BASE.toBytes()),
      signed_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    };
    const signature = bytesToBase64(
      ed25519.sign(utf8ToBytes(JSON.stringify(payload)), manifestSigningSecret),
    );
    return {
      ...payload,
      manifest_issuer_ed25519_pub: manifestIssuerPub,
      manifest_signature_ed25519: signature,
    };
  }

  function signedAttestationResponse(overrides: Partial<Parameters<typeof verifyContactDiscoveryAttestationDocument>[0]> = {}) {
    const payload = {
      attestation_mode: "sgx_preview",
      attestation_verifier: "sgx-dcap-preview",
      enclave_measurement_hex: "aa".repeat(32),
      directory_backend: "simulated_enclave_preview",
      host_enclave_protocol_version: 1,
      enclave_release_id: "simulated-preview",
      attested_oprf_public_key_ristretto255: bytesToBase64(ristretto255.Point.BASE.toBytes()),
      document_format: "opaque_b64_v1",
      document_base64: bytesToBase64(utf8ToBytes("{\"tee\":\"sgx\",\"svn\":1}")),
      document_sha256: "",
      published_at: new Date().toISOString(),
      challenge_nonce_base64: attestationChallengeNonce,
      ...overrides,
    };
    const documentSha256 = Array.from(sha256(base64ToBytes(payload.document_base64)))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    payload.document_sha256 = overrides.document_sha256 ?? documentSha256;
    const signature = bytesToBase64(
      ed25519.sign(utf8ToBytes(JSON.stringify(payload)), attestationSigningSecret),
    );
    return {
      ...payload,
      attestation_signature_ed25519: signature,
    };
  }

  it("accepts a valid signed manifest", () => {
    const manifest = signedManifest();
    expect(() => {
      verifyContactDiscoveryManifest(
        manifest,
        "ticket-issuer-ed25519-pub",
        manifest.manifest_issuer_ed25519_pub,
        null,
        null,
      );
    }).not.toThrow();
  });

  it("rejects a bad manifest signature", () => {
    const manifest = {
      ...signedManifest(),
      manifest_signature_ed25519: bytesToBase64(new Uint8Array(64).fill(1)),
    };
    expect(() => {
      verifyContactDiscoveryManifest(
        manifest,
        "ticket-issuer-ed25519-pub",
        manifest.manifest_issuer_ed25519_pub,
        null,
        null,
      );
    }).toThrow(/signature/i);
  });

  it("verifies a contact discovery attestation document hash", () => {
    const documentBytes = utf8ToBytes("{\"tee\":\"sgx\",\"svn\":1}");
    const documentSha256 = Array.from(sha256(documentBytes))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    expect(() => {
      verifyContactDiscoveryAttestationDocument(
        signedAttestationResponse({
          document_base64: bytesToBase64(documentBytes),
          document_sha256: documentSha256,
        }),
        "sgx_preview",
        "sgx-dcap-preview",
        "aa".repeat(32),
        attestationIssuerPub,
        attestationChallengeNonce,
        "simulated-preview",
        bytesToBase64(ristretto255.Point.BASE.toBytes()),
        documentSha256,
        900,
      );
    }).not.toThrow();
  });

  it("rejects a stale contact discovery attestation document", () => {
    const documentBytes = utf8ToBytes("{\"tee\":\"sgx\",\"svn\":1}");
    const documentSha256 = Array.from(sha256(documentBytes))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    expect(() => {
      verifyContactDiscoveryAttestationDocument(
        signedAttestationResponse({
          document_base64: bytesToBase64(documentBytes),
          document_sha256: documentSha256,
          published_at: new Date(Date.now() - 10_000).toISOString(),
        }),
        "sgx_preview",
        "sgx-dcap-preview",
        "aa".repeat(32),
        attestationIssuerPub,
        attestationChallengeNonce,
        "simulated-preview",
        bytesToBase64(ristretto255.Point.BASE.toBytes()),
        documentSha256,
        1,
      );
    }).toThrow(/stale/i);
  });

  it("rejects a contact discovery attestation OPRF public key mismatch", () => {
    const documentBytes = utf8ToBytes("{\"tee\":\"sgx\",\"svn\":1}");
    const documentSha256 = Array.from(sha256(documentBytes))
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    expect(() => {
      verifyContactDiscoveryAttestationDocument(
        signedAttestationResponse({
          attested_oprf_public_key_ristretto255: bytesToBase64(new Uint8Array(32).fill(7)),
          document_base64: bytesToBase64(documentBytes),
          document_sha256: documentSha256,
        }),
        "sgx_preview",
        "sgx-dcap-preview",
        "aa".repeat(32),
        attestationIssuerPub,
        attestationChallengeNonce,
        "simulated-preview",
        bytesToBase64(ristretto255.Point.BASE.toBytes()),
        documentSha256,
        900,
      );
    }).toThrow(/OPRF public key mismatch/i);
  });

  it("rejects a contact discovery attestation challenge nonce mismatch", () => {
    const response = signedAttestationResponse();
    expect(() => {
      verifyContactDiscoveryAttestationDocument(
        response,
        "sgx_preview",
        "sgx-dcap-preview",
        "aa".repeat(32),
        attestationIssuerPub,
        bytesToBase64(new Uint8Array(16).fill(8)),
        "simulated-preview",
        bytesToBase64(ristretto255.Point.BASE.toBytes()),
        response.document_sha256,
        900,
      );
    }).toThrow(/challenge nonce mismatch/i);
  });

  it("blind-evaluates discovery hashes into finalized tokens", () => {
    const prepared = prepareContactDiscoveryBlindRequest(["11".repeat(32), "22".repeat(32)]);
    const serverScalar = ristretto255.Point.Fn.create(17n);
    const evaluated = prepared.blindedElementsBase64.map((blinded) =>
      bytesToBase64(
        ristretto255.Point
          .fromBytes(base64ToBytes(blinded))
          .multiply(serverScalar)
          .toBytes(),
      )
    );
    const tokens = finalizeContactDiscoveryTokens(
      prepared.blindingScalarsBase64,
      evaluated,
    );
    expect(tokens).toHaveLength(2);
    expect(tokens[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(tokens[1]).toMatch(/^[0-9a-f]{64}$/);
    expect(tokens[0]).not.toBe(tokens[1]);
  });

  it("verifies DLEQ proofs for discovery evaluations", () => {
    const prepared = prepareContactDiscoveryBlindRequest(["11".repeat(32)]);
    const serverScalar = ristretto255.Point.Fn.create(17n);
    const publicKey = ristretto255.Point.BASE.multiply(serverScalar);
    const blindedPoint = ristretto255.Point.fromBytes(base64ToBytes(prepared.blindedElementsBase64[0]));
    const evaluatedPoint = blindedPoint.multiply(serverScalar);
    const nonce = ristretto255.Point.Fn.create(23n);
    const commitmentBase = ristretto255.Point.BASE.multiply(nonce);
    const commitmentBlinded = blindedPoint.multiply(nonce);
    const challengeDigest = sha256(
      concatBytes([
        utf8ToBytes("pqmsg-discovery-dleq-proof-v1"),
        ristretto255.Point.BASE.toBytes(),
        publicKey.toBytes(),
        blindedPoint.toBytes(),
        evaluatedPoint.toBytes(),
        commitmentBase.toBytes(),
        commitmentBlinded.toBytes(),
      ]),
    );
    let challengeBigInt = 0n;
    for (let index = challengeDigest.length - 1; index >= 0; index -= 1) {
      challengeBigInt = (challengeBigInt << 8n) + BigInt(challengeDigest[index]);
    }
    const challenge = ristretto255.Point.Fn.create(challengeBigInt);
    const responseScalar = ristretto255.Point.Fn.add(
      nonce,
      ristretto255.Point.Fn.mul(challenge, serverScalar),
    );

    expect(() => {
      verifyContactDiscoveryEvaluationProofs(
        prepared.blindedElementsBase64,
        {
          evaluation_proof_mode: "dleq_per_element_preview",
          evaluated_elements_base64: [bytesToBase64(evaluatedPoint.toBytes())],
          dleq_proofs: [{
            challenge_scalar_base64: bytesToBase64(ristretto255.Point.Fn.toBytes(challenge)),
            response_scalar_base64: bytesToBase64(ristretto255.Point.Fn.toBytes(responseScalar)),
            commitment_base_base64: bytesToBase64(commitmentBase.toBytes()),
            commitment_blinded_base64: bytesToBase64(commitmentBlinded.toBytes()),
          }],
        },
        bytesToBase64(publicKey.toBytes()),
      );
    }).not.toThrow();
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
      buildProfileUpsertAuthHeaders(keys, "Alice", "@alice.secure", true, "image/png", "base64avatar"),
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

describe("computeSafetyNumber", () => {
  it("delegates to the WASM safety-number implementation", () => {
    const keys = testKeys();
    expect(
      computeSafetyNumber(keys, "bob", keys.identityX25519Pub, keys.identityPqSigPub)
    ).toMatch(/^\d{5}( \d{5}){11}$/);
  });
});
