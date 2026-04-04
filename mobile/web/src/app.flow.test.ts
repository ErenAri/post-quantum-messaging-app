import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { JSDOM } from "jsdom";

type MockKeys = {
  userId: string;
  deviceId: string;
  suite: "ml-kem-768";
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
};

type BootOptions = {
  existingUsers?: string[];
  bundleUsers?: string[];
  identityMismatchUsers?: string[];
  immutableIdentityUsers?: string[];
  rotatedIdentityUsers?: string[];
  transparencyCheckpointOutOfRangeUsers?: string[];
  capabilities?: {
    web_client_policy?: string;
    contact_discovery_supported?: boolean;
    contact_discovery_mode?: string;
    contact_discovery_service_origin?: string | null;
    contact_discovery_manifest_issuer_ed25519_pub?: string | null;
    contact_discovery_ticket_issuer_ed25519_pub?: string;
    contact_discovery_directory_backend?: string | null;
    contact_discovery_host_enclave_protocol_version?: number | null;
    contact_discovery_host_release_id?: string | null;
    contact_discovery_enclave_release_id?: string | null;
    contact_discovery_expected_manifest_contract_sha256?: string | null;
    contact_discovery_attestation_verifier?: string | null;
    contact_discovery_expected_measurement_hex?: string | null;
    contact_discovery_attestation_document_sha256?: string | null;
    contact_discovery_attestation_max_age_seconds?: number | null;
  };
  discoveryManifest?: {
    service?: string;
    protocol_version?: number;
    attestation_mode?: string;
    attestation_verifier?: string | null;
    enclave_measurement_hex?: string | null;
    attestation_document_format?: string | null;
    attestation_document_sha256?: string | null;
    attestation_challenge_mode?: string | null;
    ticket_format?: string;
    ticket_issuer_ed25519_pub?: string;
    ticket_max_ttl_seconds?: number;
    lookup_protocol?: string;
    privacy_mode?: string;
    directory_backend?: string;
    host_enclave_protocol_version?: number;
    host_release_id?: string;
    enclave_release_id?: string;
    match_result_format?: string;
    oprf_suite?: string;
    evaluation_proof_mode?: string;
    oprf_public_key_ristretto255?: string;
    signed_at?: string;
    expires_at?: string;
    manifest_issuer_ed25519_pub?: string;
    manifest_signature_ed25519?: string;
  };
  discoveryAttestationError?: string;
  discoveryTicketResponse?: Partial<{
    service_origin: string;
    ticket: string;
    ticket_nonce: string;
    expires_at: string;
  }>;
  discoveryEvaluateResponse?: Partial<{
    ticket_nonce: string;
    manifest_contract_sha256: string;
    evaluation_proof_mode: string;
    evaluated_elements_base64: string[];
    dleq_proofs: Array<{
      challenge_scalar_base64: string;
      response_scalar_base64: string;
      commitment_base_base64: string;
      commitment_blinded_base64: string;
    }>;
  }>;
  discoveryUploadResponse?: Partial<{
    ticket_nonce: string;
    manifest_contract_sha256: string;
    uploaded_phone_tokens: number;
    uploaded_email_tokens: number;
  }>;
  discoveryMatchResponse?: Partial<{
    ticket_nonce: string;
    manifest_contract_sha256: string;
    matches: Array<{
      token_sha256: string;
      contact_invite_token: string;
      handle_kind: string;
    }>;
  }>;
  profileTokensRequireContact?: boolean;
  transparencyMismatchUsers?: string[];
  prepare?: (storage: typeof import("./storage")) => Promise<void> | void;
};

type FakeMessage = {
  id: string;
  conversationId: string;
  sender: string;
  recipient: string;
  text: string;
  timestamp: number;
  status: "sending" | "sent" | "delivered" | "failed";
  serverMessageId?: number;
  fileId?: string;
  mimeType?: string;
  fileName?: string;
  replyToId?: string;
  replyPreview?: string;
  reactions?: Array<{ emoji: string; sender: string }>;
  editedAt?: number;
  contentType?: "text" | "reply" | "reaction" | "edit";
};

function makeKeys(userId: string, deviceId = `${userId}-device`): MockKeys {
  return {
    userId,
    deviceId,
    suite: "ml-kem-768",
    identityX25519Pub: `x25519-pub-${userId}`,
    identityX25519Secret: `x25519-secret-${userId}`,
    identitySigPub: `sig-pub-${userId}`,
    identitySigSecret: `sig-secret-${userId}`,
    identityPqSigPub: `pq-sig-pub-${userId}`,
    identityPqSigSecret: `pq-sig-secret-${userId}`,
    signedPrekeyX25519Pub: `spk-pub-${userId}`,
    signedPrekeyX25519Secret: `spk-secret-${userId}`,
    pqSignedPrekeyPubMlkem768: `pq-spk-pub-${userId}`,
    pqSignedPrekeySecretMlkem768: `pq-spk-secret-${userId}`,
    oneTimePrekeysX25519: [],
    oneTimePrekeysX25519Secret: [],
    oneTimePrekeysMlkem768: [],
    oneTimePrekeysMlkem768Secret: [],
  };
}

function convId(userId: string, peerId: string): string {
  return [userId, peerId].sort().join(":");
}

function flushPromises(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function eventually(assertion: () => void): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 25; attempt += 1) {
    try {
      assertion();
      return;
    } catch (error) {
      lastError = error;
      await flushPromises();
    }
  }
  throw lastError;
}

function installDom(url = "http://localhost/"): JSDOM {
  const dom = new JSDOM(`<!doctype html><html><body><div id="app"></div></body></html>`, { url });
  const { window } = dom;
  Object.defineProperty(window, "indexedDB", {
    configurable: true,
    value: {},
  });
  Object.defineProperty(window, "crypto", {
    configurable: true,
    value: { subtle: {} },
  });
  Object.defineProperty(window, "isSecureContext", {
    configurable: true,
    value: true,
  });
  Object.defineProperty(window, "crossOriginIsolated", {
    configurable: true,
    value: true,
  });
  const bindings: Record<string, unknown> = {
    window,
    document: window.document,
    navigator: window.navigator,
    localStorage: window.localStorage,
    sessionStorage: window.sessionStorage,
    location: window.location,
    history: window.history,
    HTMLElement: window.HTMLElement,
    HTMLInputElement: window.HTMLInputElement,
    HTMLButtonElement: window.HTMLButtonElement,
    HTMLTextAreaElement: window.HTMLTextAreaElement,
    Node: window.Node,
    Event: window.Event,
    MouseEvent: window.MouseEvent,
    KeyboardEvent: window.KeyboardEvent,
    CustomEvent: window.CustomEvent,
    File: window.File,
    Blob: window.Blob,
    crypto: window.crypto,
    indexedDB: window.indexedDB,
    isSecureContext: window.isSecureContext,
    crossOriginIsolated: window.crossOriginIsolated,
  };
  for (const [key, value] of Object.entries(bindings)) {
    Object.defineProperty(globalThis, key, {
      configurable: true,
      writable: true,
      value,
    });
  }
  vi.stubGlobal("requestAnimationFrame", ((callback: FrameRequestCallback) => {
    return setTimeout(() => callback(Date.now()), 0) as unknown as number;
  }) as typeof requestAnimationFrame);
  vi.stubGlobal("cancelAnimationFrame", ((id: number) => clearTimeout(id)) as typeof cancelAnimationFrame);
  Object.defineProperty(window.navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: vi.fn().mockReturnValue({
      matches: false,
      media: "",
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn().mockReturnValue(false),
    }),
  });
  Object.defineProperty(window, "scrollTo", {
    configurable: true,
    value: vi.fn(),
  });
  return dom;
}

async function bootApp(options: BootOptions = {}) {
  vi.resetModules();
  vi.clearAllMocks();
  const dom = installDom();

  const messagesByConversation = new Map<string, FakeMessage[]>();
  const outbox: Array<{ id: string; userId: string; peerId: string; groupId?: string }> = [];
  const sessionCache = new Map<string, string>();
  const metadataRecords = new Map<string, string>();
  const keyRecords = new Map<string, string>();
  const realtimeState = {
    connectCalls: 0,
  };
  const apiState = {
    existingUsers: new Set(options.existingUsers ?? ["test1", "test2"]),
    bundleUsers: new Set(options.bundleUsers ?? options.existingUsers ?? ["test1", "test2"]),
    identityMismatchUsers: new Set(options.identityMismatchUsers ?? []),
    immutableIdentityUsers: new Set(options.immutableIdentityUsers ?? []),
    rotatedIdentityUsers: new Set(options.rotatedIdentityUsers ?? []),
    transparencyCheckpointOutOfRangeUsers: new Set(options.transparencyCheckpointOutOfRangeUsers ?? []),
    usernames: new Map<string, string>((options.existingUsers ?? ["test1", "test2"]).map((userId) => [userId, userId] as const)),
    usernameLookupEnabledByUser: new Map<string, boolean>((options.existingUsers ?? ["test1", "test2"]).map((userId) => [userId, true] as const)),
    contacts: new Set<string>(),
    resetCalls: [] as string[],
    relays: [] as Array<{ peerId: string; body: string }>,
    presenceCalls: 0,
    typingCalls: 0,
    receiptCalls: 0,
    capabilities: {
      capability_schema_version: 1,
      security_profile: "research",
      deployment_mode: "development",
      tls_required: false,
      tls_enabled: false,
      supported_beta_clients:
        (options.capabilities?.web_client_policy ?? "interop_candidate") === "demo_only"
          ? ["android"]
          : ["android", "web"],
      supported_suite_ids: [1],
      runtime_crypto_profile: {
        protocol_version: 1,
        suite_id: 1,
        kem: "ml-kem-768",
        dh: "x25519",
        kdf: "hkdf-sha256",
        aead: "chacha20-poly1305",
        signature: "ed25519",
        pq_oqs_enabled: true,
        fips_mode: false,
      },
      production_baseline_met: false,
      registration_pow_bits: 0,
      prekey_bundle_reserve_count: 0,
      pq_ratchet_interval: 1,
      contact_discovery_ticket_supported: false,
      presence_supported: false,
      typing_indicators_supported: false,
      read_receipts_supported: false,
      calling_supported: false,
      stories_supported: false,
      channels_supported: false,
      group_messaging_supported: false,
      private_group_state_supported: true,
      private_group_messaging_supported: true,
      sealed_sender_required: true,
      sender_certificate_supported: true,
      key_transparency_supported: true,
      sealed_delivery_tokens_supported: true,
      sender_certificate_issuer_ed25519_pub: "issuer-ed25519-pub",
      transparency_log_issuer_ed25519_pub: "issuer-ed25519-pub",
      authenticated_direct_messaging_supported: false,
      ephemeral_messaging_supported: false,
      web_client_policy: options.capabilities?.web_client_policy ?? "interop_candidate",
      contact_discovery_supported: options.capabilities?.contact_discovery_supported ?? false,
      contact_discovery_mode: options.capabilities?.contact_discovery_mode ?? "manual_only",
      contact_discovery_service_origin:
        options.capabilities?.contact_discovery_service_origin ?? null,
      contact_discovery_manifest_issuer_ed25519_pub:
        options.capabilities?.contact_discovery_manifest_issuer_ed25519_pub ?? null,
      contact_discovery_directory_backend:
        options.capabilities?.contact_discovery_directory_backend
        ?? (options.capabilities?.contact_discovery_mode === "private_service"
          ? "attested_enclave_directory_v1"
          : null),
      contact_discovery_host_enclave_protocol_version:
        options.capabilities?.contact_discovery_host_enclave_protocol_version
        ?? (options.capabilities?.contact_discovery_mode === "private_service" ? 1 : null),
      contact_discovery_host_release_id:
        options.capabilities?.contact_discovery_host_release_id
        ?? (options.capabilities?.contact_discovery_mode === "private_service"
          ? "attested-host-v1"
          : null),
      contact_discovery_enclave_release_id:
        options.capabilities?.contact_discovery_enclave_release_id
        ?? (options.capabilities?.contact_discovery_mode === "private_service"
          ? "attested-enclave-v1"
          : null),
      contact_discovery_expected_manifest_contract_sha256:
        options.capabilities?.contact_discovery_expected_manifest_contract_sha256
        ?? (options.capabilities?.contact_discovery_mode === "private_service"
          ? "placeholder-attestation-contract-hash"
          : null),
      contact_discovery_ticket_issuer_ed25519_pub:
        options.capabilities?.contact_discovery_ticket_issuer_ed25519_pub ?? "issuer-ed25519-pub",
      contact_discovery_attestation_verifier:
        options.capabilities?.contact_discovery_attestation_verifier
        ?? (options.capabilities?.contact_discovery_mode === "private_service"
          ? "aws-nitro-root-v1"
          : null),
      contact_discovery_expected_measurement_hex:
        options.capabilities?.contact_discovery_expected_measurement_hex
        ?? (options.capabilities?.contact_discovery_mode === "private_service"
          ? "ab".repeat(32)
          : null),
      contact_discovery_attestation_document_sha256:
        options.capabilities?.contact_discovery_attestation_document_sha256
        ?? (options.capabilities?.contact_discovery_mode === "private_service"
          ? "cd".repeat(32)
          : null),
      contact_discovery_attestation_max_age_seconds:
        options.capabilities?.contact_discovery_attestation_max_age_seconds
        ?? (options.discoveryManifest?.attestation_document_sha256 ? 86_400 : null),
    },
    contactDiscoveryManifest: {
      service: options.discoveryManifest?.service ?? "pqmsg-discovery",
      protocol_version: options.discoveryManifest?.protocol_version ?? 1,
      attestation_mode: options.discoveryManifest?.attestation_mode ?? "attested_enclave_v1",
      attestation_verifier:
        options.discoveryManifest?.attestation_verifier ?? "aws-nitro-root-v1",
      enclave_measurement_hex:
        options.discoveryManifest?.enclave_measurement_hex ?? "ab".repeat(32),
      attestation_document_format:
        options.discoveryManifest?.attestation_document_format ?? "opaque_b64_v1",
      attestation_document_sha256:
        options.discoveryManifest?.attestation_document_sha256 ?? "cd".repeat(32),
      attestation_challenge_mode:
        options.discoveryManifest?.attestation_challenge_mode ?? "nonce_b64_required_v1",
      ticket_format: options.discoveryManifest?.ticket_format ?? "ed25519-ticket-v1",
      ticket_issuer_ed25519_pub:
        options.discoveryManifest?.ticket_issuer_ed25519_pub
        ?? options.capabilities?.contact_discovery_ticket_issuer_ed25519_pub
        ?? "issuer-ed25519-pub",
      ticket_max_ttl_seconds: options.discoveryManifest?.ticket_max_ttl_seconds ?? 300,
      lookup_protocol:
        options.discoveryManifest?.lookup_protocol ?? "attested_enclave_voprf_directory_v1",
      privacy_mode: options.discoveryManifest?.privacy_mode ?? "enclave_backed_private_discovery_v1",
      directory_backend:
        options.discoveryManifest?.directory_backend ?? "attested_enclave_directory_v1",
      host_enclave_protocol_version:
        options.discoveryManifest?.host_enclave_protocol_version ?? 1,
      host_release_id:
        options.discoveryManifest?.host_release_id ?? "attested-host-v1",
      enclave_release_id:
        options.discoveryManifest?.enclave_release_id ?? "attested-enclave-v1",
      match_result_format: options.discoveryManifest?.match_result_format ?? "contact_invite_token",
      oprf_suite: options.discoveryManifest?.oprf_suite ?? "ristretto255-sha512-v1",
      evaluation_proof_mode:
        options.discoveryManifest?.evaluation_proof_mode ?? "dleq_per_element_v1",
      oprf_public_key_ristretto255:
        options.discoveryManifest?.oprf_public_key_ristretto255 ?? "oprf-pub-1",
      signed_at: options.discoveryManifest?.signed_at ?? "2026-03-26T00:00:00Z",
      expires_at: options.discoveryManifest?.expires_at ?? "2026-03-26T00:05:00Z",
      manifest_issuer_ed25519_pub:
        options.discoveryManifest?.manifest_issuer_ed25519_pub
        ?? options.capabilities?.contact_discovery_manifest_issuer_ed25519_pub
        ?? "manifest-issuer-pub",
      manifest_signature_ed25519:
        options.discoveryManifest?.manifest_signature_ed25519 ?? "manifest-sig",
    },
    contactDiscoveryAttestation: {
      attestation_mode: options.discoveryManifest?.attestation_mode ?? "attested_enclave_v1",
      attestation_verifier: options.discoveryManifest?.attestation_verifier ?? "aws-nitro-root-v1",
      enclave_measurement_hex:
        options.discoveryManifest?.enclave_measurement_hex ?? "ab".repeat(32),
      directory_backend:
        options.discoveryManifest?.directory_backend ?? "attested_enclave_directory_v1",
      host_enclave_protocol_version:
        options.discoveryManifest?.host_enclave_protocol_version ?? 1,
      host_release_id:
        options.discoveryManifest?.host_release_id ?? "attested-host-v1",
      enclave_release_id:
        options.discoveryManifest?.enclave_release_id ?? "attested-enclave-v1",
      manifest_contract_sha256: "placeholder-attestation-contract-hash",
      attested_oprf_public_key_ristretto255:
        options.discoveryManifest?.oprf_public_key_ristretto255 ?? "oprf-pub",
      document_format: options.discoveryManifest?.attestation_document_format ?? "opaque_b64_v1",
      document_base64: "eyJ0ZWUiOiJzZ3gifQ==",
      document_sha256:
        options.discoveryManifest?.attestation_document_sha256 ?? "cd".repeat(32),
      published_at: new Date().toISOString(),
    },
    contactDiscoveryTicket: {
      service_origin: options.capabilities?.contact_discovery_service_origin ?? "https://cdsi.example",
      ticket: options.discoveryTicketResponse?.ticket ?? "signed-discovery-ticket",
      ticket_nonce: options.discoveryTicketResponse?.ticket_nonce ?? "ticket-nonce-1",
      expires_at: options.discoveryTicketResponse?.expires_at ?? "2026-03-26T12:05:00Z",
    },
    contactDiscoveryEvaluate: {
      ticket_nonce: options.discoveryEvaluateResponse?.ticket_nonce ?? "ticket-nonce-1",
      manifest_contract_sha256:
        options.discoveryEvaluateResponse?.manifest_contract_sha256
        ?? "placeholder-attestation-contract-hash",
      evaluation_proof_mode:
        options.discoveryEvaluateResponse?.evaluation_proof_mode
        ?? options.discoveryManifest?.evaluation_proof_mode
        ?? "dleq_per_element_v1",
      evaluated_elements_base64:
        options.discoveryEvaluateResponse?.evaluated_elements_base64 ?? ([] as string[]),
      dleq_proofs:
        options.discoveryEvaluateResponse?.dleq_proofs ?? ([] as Array<{
          challenge_scalar_base64: string;
          response_scalar_base64: string;
          commitment_base_base64: string;
          commitment_blinded_base64: string;
        }>),
    },
    contactDiscoveryUpload: {
      ticket_nonce: options.discoveryUploadResponse?.ticket_nonce ?? "ticket-nonce-1",
      manifest_contract_sha256:
        options.discoveryUploadResponse?.manifest_contract_sha256
        ?? "placeholder-attestation-contract-hash",
      uploaded_phone_tokens: options.discoveryUploadResponse?.uploaded_phone_tokens ?? 1,
      uploaded_email_tokens: options.discoveryUploadResponse?.uploaded_email_tokens ?? 0,
    },
    contactDiscoveryMatch: {
      ticket_nonce: options.discoveryMatchResponse?.ticket_nonce ?? "ticket-nonce-1",
      manifest_contract_sha256:
        options.discoveryMatchResponse?.manifest_contract_sha256
        ?? "placeholder-attestation-contract-hash",
      matches: options.discoveryMatchResponse?.matches ?? [],
    },
  };

  function bundleIdentityVersion(userId: string): number {
    return apiState.rotatedIdentityUsers.has(userId) ? 2 : 1;
  }

  function bundleIdentityX25519(userId: string): string {
    return apiState.rotatedIdentityUsers.has(userId)
      ? `rotated-bundle-x25519-${userId}`
      : `bundle-x25519-${userId}`;
  }

  function bundleIdentitySig(userId: string): string {
    return apiState.rotatedIdentityUsers.has(userId)
      ? `rotated-bundle-sig-${userId}`
      : `bundle-sig-${userId}`;
  }

  function bundleIdentityPqSig(userId: string): string {
    return apiState.rotatedIdentityUsers.has(userId)
      ? `rotated-bundle-pq-sig-${userId}`
      : `bundle-pq-sig-${userId}`;
  }

  function bundleFingerprint(userId: string): string {
    return apiState.rotatedIdentityUsers.has(userId)
      ? `rotated-bundle-fp-${userId}`
      : `bundle-fp-${userId}`;
  }

  vi.doMock("./db", () => ({
    async saveMessage(message: FakeMessage) {
      const list = messagesByConversation.get(message.conversationId) ?? [];
      const index = list.findIndex((item) => item.id === message.id);
      if (index >= 0) {
        list[index] = { ...list[index], ...message };
      } else {
        list.push({ ...message });
      }
      messagesByConversation.set(message.conversationId, list);
    },
    async updateMessageStatus(id: string, status: FakeMessage["status"], serverMessageId?: number) {
      for (const list of messagesByConversation.values()) {
        const found = list.find((item) => item.id === id);
        if (!found) {
          continue;
        }
        found.status = status;
        if (serverMessageId !== undefined) {
          found.serverMessageId = serverMessageId;
        }
      }
    },
    async getMessages(conversationId: string) {
      return [...(messagesByConversation.get(conversationId) ?? [])].sort((lhs, rhs) => lhs.timestamp - rhs.timestamp);
    },
    async clearAllMessages() {
      messagesByConversation.clear();
    },
    async clearOutboxMessages() {
      outbox.length = 0;
    },
    async searchMessages() {
      return [];
    },
    async queueOutboxMessage(message: { id: string; userId: string; peerId: string; groupId?: string }) {
      outbox.push({ ...message });
    },
    async getOutboxMessages(userId: string) {
      return outbox.filter((item) => item.userId === userId);
    },
    async removeOutboxMessage(id: string) {
      const index = outbox.findIndex((item) => item.id === id);
      if (index >= 0) {
        outbox.splice(index, 1);
      }
    },
    async saveSessionCache(userId: string, peerId: string, sealedSession: string) {
      sessionCache.set(`${userId}:${peerId}`, sealedSession);
    },
    async loadSessionCache(userId: string, peerId: string) {
      return sessionCache.get(`${userId}:${peerId}`) ?? null;
    },
    async clearSessionCache(userId: string, peerId: string) {
      sessionCache.delete(`${userId}:${peerId}`);
    },
    async clearAllSessionCache(userId?: string) {
      if (!userId) {
        sessionCache.clear();
        return;
      }
      for (const key of [...sessionCache.keys()]) {
        if (key.startsWith(`${userId}:`)) {
          sessionCache.delete(key);
        }
      }
    },
    async saveMetadataRecord(id: string, rawJson: string) {
      metadataRecords.set(id, rawJson);
    },
    async loadMetadataRecord(id: string) {
      return metadataRecords.get(id) ?? null;
    },
    async clearMetadataRecord(id: string) {
      metadataRecords.delete(id);
    },
    async saveKeyRecord(id: string, sealedKeys: string) {
      keyRecords.set(id, sealedKeys);
    },
    async loadKeyRecord(id: string) {
      return keyRecords.get(id) ?? null;
    },
    async listKeyRecordIds() {
      return [...keyRecords.keys()].sort((lhs, rhs) => lhs.localeCompare(rhs));
    },
    async clearKeyRecord(id: string) {
      keyRecords.delete(id);
    },
    async addReaction() {
      return undefined;
    },
    async editStoredMessage(id: string, text: string) {
      for (const list of messagesByConversation.values()) {
        const found = list.find((item) => item.id === id);
        if (!found) {
          continue;
        }
        found.text = text;
        found.editedAt = Date.now();
        return found;
      }
      return null;
    },
    async getMessage(id: string) {
      for (const list of messagesByConversation.values()) {
        const found = list.find((item) => item.id === id);
        if (found) {
          return found;
        }
      }
      return null;
    },
  }));

  vi.doMock("./realtime", () => ({
    RealtimeInbox: class {
      onMessage() {}
      onReconnect() {}
      connect() {
        realtimeState.connectCalls += 1;
      }
      disconnect() {}
    },
  }));

  vi.doMock("./crypto", () => {
    const emptyHeaders = () => ({});
    return {
      buildInboxAuthHeaders: emptyHeaders,
      buildPrekeysAuthHeaders: emptyHeaders,
      buildPublishPrekeysPayload: () => ({
        signed_prekey_x25519_pub: "spk",
        sig_over_spk: "sig",
        pq_signed_prekey_pub_mlkem768: "pq",
        sig_over_pqspk: "pq-sig",
        pq_sig_over_spk: "pq-sig-spk",
        pq_sig_over_pqspk: "pq-sig-pqspk",
        one_time_prekeys_x25519: [],
        one_time_prekeys_mlkem768: [],
      }),
      buildRelayAuthHeaders: emptyHeaders,
      buildRetireDeviceAuthHeaders: emptyHeaders,
      buildProfileGetAuthHeaders: emptyHeaders,
      buildProfileUpsertAuthHeaders: emptyHeaders,
      buildPresenceGetAuthHeaders: emptyHeaders,
      buildPresenceUpdateAuthHeaders: emptyHeaders,
      buildTypingGetAuthHeaders: emptyHeaders,
      buildTypingUpdateAuthHeaders: emptyHeaders,
      buildSendReceiptAuthHeaders: emptyHeaders,
      buildGetReceiptsAuthHeaders: emptyHeaders,
      buildContactsListAuthHeaders: emptyHeaders,
      buildContactsUpsertAuthHeaders: emptyHeaders,
      buildContactsRemoveAuthHeaders: emptyHeaders,
      buildUserGroupsListAuthHeaders: emptyHeaders,
      buildGroupMembersListAuthHeaders: emptyHeaders,
      buildFileUploadAuthHeaders: emptyHeaders,
      buildFileDownloadAuthHeaders: emptyHeaders,
      buildInboxDeleteAuthHeaders: emptyHeaders,
      buildPrekeysStatusAuthHeaders: emptyHeaders,
      buildRotateInitAuthHeaders: emptyHeaders,
      buildRotateConfirmAuthHeaders: emptyHeaders,
      buildRotateConfirmPayload: vi.fn(() => ({
        challenge_id: "challenge-1",
        sig_by_current_identity: "sig-current",
        sig_by_new_identity: "sig-new",
        pq_sig_by_current_identity: "pq-sig-current",
        pq_sig_by_new_identity: "pq-sig-new",
      })),
      buildIdentityLogAuthHeaders: emptyHeaders,
      verifyTransparencyProof: vi.fn((proofJson: string) => {
        const proof = JSON.parse(proofJson);
        return {
          verified: true,
          consistencyVerified: Boolean(proof.consistency_proof),
          leafUserId: proof.leaf.user_id,
          leafVersion: proof.leaf.version,
          treeSize: proof.signed_tree_head.tree_size,
          epoch: proof.signed_tree_head.epoch,
        };
      }),
      buildSealedInboxAuthHeaders: emptyHeaders,
      buildSenderCertificateAuthHeaders: emptyHeaders,
      buildContactDiscoveryTicketAuthHeaders: emptyHeaders,
      buildEphemeralRelayAuthHeaders: emptyHeaders,
      buildDiscoveryHandlesAuthHeaders: emptyHeaders,
      buildDiscoveryMatchAuthHeaders: emptyHeaders,
      verifyContactDiscoveryManifest: vi.fn(),
      buildContactDiscoveryAttestationChallengeNonce: vi.fn(() => "flow-attestation-nonce"),
      contactDiscoveryManifestContractSha256: vi.fn(
        () => "placeholder-attestation-contract-hash"
      ),
      prepareContactDiscoveryBlindRequest: vi.fn((hashes: string[]) => ({
        blindedElementsBase64: hashes.map((value) => `blind:${value}`),
        blindingScalarsBase64: hashes.map((value) => `scalar:${value}`),
      })),
      verifyContactDiscoveryAttestationDocument: vi.fn(() => {
        if (options.discoveryAttestationError) {
          throw new Error(options.discoveryAttestationError);
        }
      }),
      verifyContactDiscoveryEvaluationProofs: vi.fn(),
      finalizeContactDiscoveryTokens: vi.fn(
        (scalars: string[], evaluated: string[]) =>
          evaluated.map((value, index) => `token:${index}:${scalars[index] ?? "missing"}:${value}`)
      ),
      buildPushTokenAuthHeaders: emptyHeaders,
      buildListDevicesAuthHeaders: emptyHeaders,
      buildLinkDeviceAuthHeaders: emptyHeaders,
      buildRevokeDeviceAuthHeaders: emptyHeaders,
      decodeWireEnvelopeBase64: vi.fn(),
      decryptDirectMessage: vi.fn((activeKeys: MockKeys, senderUserId: string) => ({
        plaintextUtf8: `from ${senderUserId}`,
        sessionJson: "decrypted-session",
        updatedKeys: activeKeys,
      })),
      decryptFallbackMessage: vi.fn(() => ({ plaintext: "fallback" })),
      encryptDirectMessageWithSession: vi.fn((sessionJson: string, senderUserId: string, peerUserId: string, plaintext: string) => ({
        messageBytesBase64: `enc:${senderUserId}:${peerUserId}:${plaintext}`,
        sessionJson: `${sessionJson}:next`,
        usedHandshake: false,
      })),
      generateIdentityKeys: vi.fn((userId: string, deviceId: string) => makeKeys(userId, deviceId)),
      identityFingerprint: vi.fn((value: string) => `fp:${value}`),
      initWasmCrypto: vi.fn().mockResolvedValue(true),
      initiateDirectMessageSession: vi.fn((activeKeys: MockKeys, bundle: { user_id?: string }, plaintext: string) => ({
        messageBytesBase64: `init:${activeKeys.userId}:${bundle.user_id ?? "peer"}:${plaintext}`,
        sessionJson: "handshake-session",
        usedHandshake: true,
      })),
      isPqSessionMessagingAvailable: vi.fn(() => true),
      openTransportEnvelopeWithSenderCert: vi.fn(
        (_activeKeys: MockKeys, expectedSenderUserId: string, _senderIdentityX25519Pub: string, sealedMessageBytesBase64: string) => ({
          senderUserId: expectedSenderUserId,
          senderDeviceId: `${expectedSenderUserId}-device`,
          payloadMessageBytesBase64: sealedMessageBytesBase64,
        })
      ),
      regeneratePublishedPrekeys: vi.fn((activeKeys: MockKeys) => activeKeys),
      sealTransportEnvelopeWithSenderCert: vi.fn(
        (_activeKeys: MockKeys, _recipientUserId: string, _recipientIdentityX25519Pub: string, payloadMessageBytesBase64: string) =>
          payloadMessageBytesBase64
      ),
      sealJsonWithPassphrase: vi.fn(async (value: unknown) => JSON.stringify(value)),
      openJsonWithPassphrase: vi.fn(async (sealed: string) => JSON.parse(sealed)),
    };
  });

  vi.doMock("./server", () => {
    class FakePqmsgApi {
      constructor(readonly baseUrl: string) {}

      async getCapabilities() {
        return apiState.capabilities;
      }

      async registerUser(payload: { user_id: string; device_id: string }) {
        if (apiState.immutableIdentityUsers.has(payload.user_id)) {
          throw new Error(
            'HTTP 409: {"type":"about:blank","title":"Conflict","status":409,"detail":"user_id is already registered with an immutable identity"}',
          );
        }
        apiState.existingUsers.add(payload.user_id);
        apiState.bundleUsers.add(payload.user_id);
        apiState.usernames.set(payload.user_id, payload.user_id);
        apiState.usernameLookupEnabledByUser.set(payload.user_id, false);
        return {
          user_id: payload.user_id,
          device_id: payload.device_id,
          registered_at: "2026-03-11T00:00:00Z",
        };
      }

      async resetDevUserIdentity(userId: string) {
        apiState.resetCalls.push(userId);
        apiState.identityMismatchUsers.delete(userId);
        apiState.immutableIdentityUsers.delete(userId);
        apiState.existingUsers.delete(userId);
        apiState.bundleUsers.delete(userId);
        for (const [username, owner] of [...apiState.usernames.entries()]) {
          if (owner === userId) {
            apiState.usernames.delete(username);
          }
        }
      }

      async publishPrekeys(userId: string) {
        return {
          user_id: userId,
          device_id: `${userId}-device`,
          uploaded_one_time_prekeys_x25519: 16,
          uploaded_one_time_prekeys_mlkem768: 16,
          remaining_one_time_prekeys_x25519: 16,
          remaining_one_time_prekeys_mlkem768: 16,
          low_one_time_prekeys: false,
          minimum_recommended_one_time_prekeys: 16,
          updated_at: "2026-03-11T00:00:00Z",
        };
      }

      async listContacts() {
        return {
          contacts: Array.from(apiState.contacts.values()).map((contact_user_id) => ({
            contact_user_id,
            alias: null,
            verified_by_qr: false,
            verified_fingerprint_sha256: null,
            created_at: "2026-03-11T00:00:00Z",
            updated_at: "2026-03-11T00:00:00Z",
          })),
        };
      }

      async listUserGroups() {
        return { groups: [] };
      }

      async getProfile(userId: string) {
        if (!apiState.existingUsers.has(userId)) {
          throw new Error("HTTP 404: user not found");
        }
        const username = Array.from(apiState.usernames.entries()).find(([, mappedUserId]) => mappedUserId === userId)?.[0] ?? null;
        return {
          user_id: userId,
          display_name: userId,
          username,
          username_lookup_enabled: apiState.usernameLookupEnabledByUser.get(userId) ?? Boolean(username),
          sealed_delivery_token:
              options.profileTokensRequireContact && !apiState.contacts.has(userId)
                ? null
                : `delivery-token:${userId}`,
        };
      }

      async upsertProfile(userId: string, request: { display_name?: string; username?: string; username_lookup_enabled?: boolean }) {
        if (!apiState.existingUsers.has(userId)) {
          throw new Error("HTTP 404: user not found");
        }
        const normalizedUsername = request.username?.trim().replace(/^@/, "").toLowerCase() || "";
        const usernameLookupEnabled = Boolean(normalizedUsername) && (request.username_lookup_enabled ?? true);
        if (normalizedUsername) {
          const owner = apiState.usernames.get(normalizedUsername);
          if (owner && owner !== userId) {
            throw new Error("HTTP 409: username already claimed");
          }
          apiState.usernames.set(normalizedUsername, userId);
          apiState.usernameLookupEnabledByUser.set(userId, usernameLookupEnabled);
        } else {
          for (const [candidate, owner] of [...apiState.usernames.entries()]) {
            if (owner === userId && candidate !== userId) {
              apiState.usernames.delete(candidate);
            }
          }
          apiState.usernameLookupEnabledByUser.set(userId, false);
        }
        return {
          user_id: userId,
          display_name: request.display_name ?? userId,
          username: normalizedUsername || null,
          username_lookup_enabled: usernameLookupEnabled,
          sealed_delivery_token: `delivery-token:${userId}`,
          updated_at: "2026-03-11T00:00:00Z",
        };
      }

      async resolveUsername(username: string) {
        const normalizedUsername = username.trim().replace(/^@/, "").toLowerCase();
        const userId = apiState.usernames.get(normalizedUsername);
        if (!userId || !apiState.usernameLookupEnabledByUser.get(userId)) {
          throw new Error("HTTP 404: username not found");
        }
        return {
          username: normalizedUsername,
          user_id: userId,
        };
      }

      async getBundle(userId: string) {
        if (!apiState.bundleUsers.has(userId)) {
          throw new Error("HTTP 404: bundle not found");
        }
        return {
          user_id: userId,
          identity_x25519_pub: bundleIdentityX25519(userId),
          identity_sig_pub: bundleIdentitySig(userId),
          identity_pq_sig_pub: bundleIdentityPqSig(userId),
          identity_fingerprint_sha256: bundleFingerprint(userId),
          identity_key_version: bundleIdentityVersion(userId),
          signed_prekey_x25519_pub: `spk-${userId}`,
          sig_over_spk: "sig",
          pq_signed_prekey_pub_mlkem768: `pq-${userId}`,
          sig_over_pqspk: "pq-sig",
          pq_sig_over_spk: "pq-sig-spk",
          pq_sig_over_pqspk: "pq-sig-pqspk",
          one_time_prekey_x25519: null,
          one_time_prekey_mlkem768: null,
          bundle_generated_at: "2026-03-11T00:00:00Z",
        };
      }

      async getContactInviteBundle(inviteToken: string) {
        const mappedUserId = inviteToken === "opaque-token-123" ? "test2" : "test2";
        return this.getBundle(mappedUserId);
      }

      async getUsernameBundle(username: string) {
        const normalizedUsername = username.trim().replace(/^@/, "").toLowerCase();
        const userId = apiState.usernames.get(normalizedUsername);
        if (!userId || !apiState.usernameLookupEnabledByUser.get(userId)) {
          throw new Error("HTTP 404: username not found");
        }
        return this.getBundle(userId);
      }

      async getIdentityLog(userId: string) {
        if (apiState.rotatedIdentityUsers.has(userId)) {
          return {
            user_id: userId,
            events: [
              {
                version: 2,
                identity_x25519_pub: bundleIdentityX25519(userId),
                identity_sig_pub: bundleIdentitySig(userId),
                identity_pq_sig_pub: bundleIdentityPqSig(userId),
                device_id: `${userId}-device-rotated`,
                event_type: "rotation",
                changed_at: "2026-03-12T00:00:00Z",
                identity_fingerprint_sha256: `fp:${bundleIdentityX25519(userId)}`,
              },
              {
                version: 1,
                identity_x25519_pub: `bundle-x25519-${userId}`,
                identity_sig_pub: `bundle-sig-${userId}`,
                identity_pq_sig_pub: `bundle-pq-sig-${userId}`,
                device_id: `${userId}-device`,
                event_type: "initial",
                changed_at: "2026-03-11T00:00:00Z",
                identity_fingerprint_sha256: `fp:bundle-x25519-${userId}`,
              },
            ],
          };
        }
        return {
          user_id: userId,
          events: [
            {
              version: 1,
              identity_x25519_pub: `bundle-x25519-${userId}`,
              identity_sig_pub: `bundle-sig-${userId}`,
              identity_pq_sig_pub: `bundle-pq-sig-${userId}`,
              device_id: `${userId}-device`,
              event_type: "initial",
              changed_at: "2026-03-11T00:00:00Z",
              identity_fingerprint_sha256: `fp:bundle-x25519-${userId}`,
            },
          ],
        };
      }

      async getTransparencyProof(userId: string, previousTreeSize?: number) {
        if (
          previousTreeSize
          && apiState.transparencyCheckpointOutOfRangeUsers.has(userId)
        ) {
          throw new Error(
            'HTTP 400: {"type":"about:blank","title":"Bad Request","status":400,"detail":"previous_tree_size must be in 1..=current tree size"}',
          );
        }
        const mismatched = new Set(options.transparencyMismatchUsers ?? []);
        return {
          user_id: userId,
          leaf: {
            user_id: userId,
            version: mismatched.has(userId)
              ? (previousTreeSize ? 2 : 1)
              : bundleIdentityVersion(userId),
            identity_x25519_pub: mismatched.has(userId)
              ? `tampered-x25519-${userId}`
              : bundleIdentityX25519(userId),
            identity_sig_pub: bundleIdentitySig(userId),
            identity_pq_sig_pub: bundleIdentityPqSig(userId),
            timestamp: 1700000000,
          },
          inclusion_proof: {
            leaf_index: 0,
            path: [],
          },
          signed_tree_head: {
            epoch: previousTreeSize ? 2 : 1,
            tree_size: previousTreeSize ? 2 : 1,
            root_hash: "root-hash",
            signature: "root-signature",
          },
          consistency_proof: previousTreeSize
            ? { old_size: previousTreeSize, new_size: 2, proof_hashes: [] }
            : null,
        };
      }

      async relay(peerId: string, request: { message_bytes_base64: string }) {
        apiState.relays.push({ peerId, body: request.message_bytes_base64 });
        return { message_id: apiState.relays.length, received_at: "2026-03-11T00:00:00Z" };
      }

      async relayEphemeral(peerId: string, request: { message_bytes_base64: string }) {
        apiState.relays.push({ peerId, body: request.message_bytes_base64 });
        return { message_id: apiState.relays.length, received_at: "2026-03-11T00:00:00Z" };
      }

      async sealedRelay(
        peerId: string,
        request: { delivery_token: string; message_bytes_base64: string }
      ) {
        apiState.relays.push({ peerId, body: request.message_bytes_base64 });
        return { delivered_device_count: 1 };
      }

      async inbox(userId: string) {
        return { user_id: userId, messages: [] };
      }

      async sealedInbox(userId: string) {
        return { user_id: userId, messages: [] };
      }

      async getSenderCertificate(userId: string) {
        if (apiState.identityMismatchUsers.has(userId)) {
          throw new Error("HTTP 400: x-pqmsg-auth-signature verification failed");
        }
        return {
          user_id: userId,
          device_id: `${userId}-device`,
          certificate_base64: `cert:${userId}`,
          expires_at: "2026-03-12T12:00:00Z",
        };
      }

      async getTyping() {
        apiState.typingCalls += 1;
        return { typing: [] };
      }

      async getReceipts() {
        apiState.receiptCalls += 1;
        return { receipts: [] };
      }

      async getPresence(userId: string) {
        apiState.presenceCalls += 1;
        return { user_id: userId, status: "offline", updated_at: "2026-03-11T00:00:00Z" };
      }

      async updatePresence() {
        apiState.presenceCalls += 1;
        return { ok: true };
      }

      async sendReceipt() {
        apiState.receiptCalls += 1;
        return { ok: true };
      }

      async updateTyping() {
        apiState.typingCalls += 1;
        return { ok: true };
      }

      async upsertContact(_userId: string, request: { contact_user_id: string }) {
        apiState.contacts.add(request.contact_user_id);
        return { ok: true };
      }

      async listGroupMembers(groupId: string) {
        return { group_id: groupId, members: [] };
      }

      async getContactDiscoveryManifest() {
        return apiState.contactDiscoveryManifest;
      }

      async getContactDiscoveryAttestation() {
        return apiState.contactDiscoveryAttestation;
      }

      async issueContactDiscoveryTicket(userId: string) {
        return {
          user_id: userId,
          device_id: `${userId}-device`,
          service_origin: apiState.contactDiscoveryTicket.service_origin,
          ticket: apiState.contactDiscoveryTicket.ticket,
          ticket_nonce: apiState.contactDiscoveryTicket.ticket_nonce,
          expires_at: apiState.contactDiscoveryTicket.expires_at,
        };
      }

      async evaluateDiscoveryElementsAtService(
        _serviceOrigin: string,
        payload: { blinded_elements_base64: string[] },
      ) {
        return {
          user_id: "test1",
          device_id: "test1-device",
          ticket_nonce: apiState.contactDiscoveryEvaluate.ticket_nonce,
          manifest_contract_sha256: apiState.contactDiscoveryEvaluate.manifest_contract_sha256,
          evaluation_proof_mode: apiState.contactDiscoveryEvaluate.evaluation_proof_mode,
          evaluated_elements_base64:
            apiState.contactDiscoveryEvaluate.evaluated_elements_base64.length > 0
              ? apiState.contactDiscoveryEvaluate.evaluated_elements_base64
              : payload.blinded_elements_base64.map((value) => `evaluated:${value}`),
          dleq_proofs: apiState.contactDiscoveryEvaluate.dleq_proofs,
          evaluated_at: "2026-03-26T12:02:30Z",
        };
      }

      async uploadDiscoveryHandlesToService() {
        return {
          user_id: "test1",
          device_id: "test1-device",
          ticket_nonce: apiState.contactDiscoveryUpload.ticket_nonce,
          manifest_contract_sha256: apiState.contactDiscoveryUpload.manifest_contract_sha256,
          uploaded_phone_tokens: apiState.contactDiscoveryUpload.uploaded_phone_tokens,
          uploaded_email_tokens: apiState.contactDiscoveryUpload.uploaded_email_tokens,
          updated_at: "2026-03-26T12:03:00Z",
        };
      }

      async matchDiscoveryHashesAtService() {
        return {
          user_id: "test1",
          ticket_nonce: apiState.contactDiscoveryMatch.ticket_nonce,
          manifest_contract_sha256: apiState.contactDiscoveryMatch.manifest_contract_sha256,
          matches: apiState.contactDiscoveryMatch.matches,
          checked_at: "2026-03-26T12:04:00Z",
        };
      }

      async createInboxWsTicket(userId: string) {
        return { ticket: `ticket-${userId}`, expires_at: "2026-03-11T00:00:30Z" };
      }
    }

    return {
      PqmsgApi: FakePqmsgApi,
    };
  });

  const storage = await import("./storage");
  if (options.prepare) {
    await options.prepare(storage);
  }
  const preparedSetup = storage.loadSetup();
  const shouldResumeSession =
    preparedSetup.userId.length > 0 && storage.hasLocalKeys(preparedSetup.userId);
  const router = await import("./router");
  await import("./app");
  if (shouldResumeSession) {
    await eventually(() => {
      expect(router.getCurrentView()).toEqual({ screen: "conversations" });
    });
  } else {
    await flushPromises();
  }

  return { dom, storage, router, apiState, messagesByConversation, realtimeState };
}

beforeEach(() => {
  vi.useRealTimers();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("web app flow coverage", () => {
  it("signs in from a browser-local account list and lands in conversations", async () => {
    const { router } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
      },
    });

    router.navigateTo({ screen: "sign-in" });
    await flushPromises();

    const quickFill = document.querySelector<HTMLElement>("[data-local-account-fill='test1']");
    expect(quickFill).not.toBeNull();
    quickFill?.click();

    const userInput = document.querySelector<HTMLInputElement>("#onb-uid");
    const passInput = document.querySelector<HTMLInputElement>("#onb-pass");
    expect(userInput?.value).toBe("test1");

    passInput!.value = "pass-1";
    document.querySelector<HTMLButtonElement>("#onb-go")!.click();

    await eventually(() => {
      expect(document.querySelector("#onb-status")?.textContent).toContain("Signed in!");
    });
    await new Promise((resolve) => setTimeout(resolve, 450));

    expect(router.getCurrentView()).toEqual({ screen: "conversations" });
    expect(document.body.textContent).toContain("No conversations yet");
  }, 10000);

  it("repairs a mismatched local identity on a development relay during sign-in", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    const { router, apiState } = await bootApp({
      existingUsers: ["test6"],
      identityMismatchUsers: ["test6"],
      prepare: async (storage) => {
        await storage.saveKeys("test6", "pass-6", makeKeys("test6"));
      },
    });

    router.navigateTo({ screen: "sign-in" });
    await flushPromises();

    document.querySelector<HTMLElement>("[data-local-account-fill='test6']")?.click();
    const passInput = document.querySelector<HTMLInputElement>("#onb-pass");
    passInput!.value = "pass-6";
    document.querySelector<HTMLButtonElement>("#onb-go")!.click();

    await eventually(() => {
      expect(document.querySelector("#onb-status")?.textContent).toContain("Signed in!");
    });
    await new Promise((resolve) => setTimeout(resolve, 450));

    expect(apiState.resetCalls).toEqual(["test6"]);
    expect(router.getCurrentView()).toEqual({ screen: "conversations" });
  }, 10000);

  it("re-registers the same username on a development relay after an immutable-identity conflict", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    const { router, apiState, storage } = await bootApp({
      existingUsers: ["test8"],
      immutableIdentityUsers: ["test8"],
    });

    router.navigateTo({ screen: "create-account" });
    await flushPromises();

    const userInput = document.querySelector<HTMLInputElement>("#onb-user");
    const nameInput = document.querySelector<HTMLInputElement>("#onb-name");
    const passInput = document.querySelector<HTMLInputElement>("#onb-pass");
    const pass2Input = document.querySelector<HTMLInputElement>("#onb-pass2");
    userInput!.value = "test8";
    userInput!.dispatchEvent(new Event("input", { bubbles: true }));
    nameInput!.value = "Test Eight";
    nameInput!.dispatchEvent(new Event("input", { bubbles: true }));
    passInput!.value = "pass-8";
    passInput!.dispatchEvent(new Event("input", { bubbles: true }));
    pass2Input!.value = "pass-8";
    pass2Input!.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>("#onb-go")!.click();

    await eventually(() => {
      expect(document.querySelector("#onb-status")?.textContent).toContain("Ready!");
    });
    await new Promise((resolve) => setTimeout(resolve, 700));

    expect(apiState.resetCalls).toEqual(["test8"]);
    expect(apiState.existingUsers.has("test8")).toBe(true);
    expect(storage.hasLocalKeys("test8")).toBe(true);
    expect(storage.loadSetup().userId).toBe("test8");
    expect(router.getCurrentView()).toEqual({ screen: "conversations" });
    expect(document.body.textContent).toContain("No conversations yet");
  }, 10000);

  it("forgets one local browser profile without clearing another profile's sessions or trust pins", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    const { router, storage } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        await storage.saveKeys("test2", "pass-2", makeKeys("test2"));
        await storage.saveDirectMessageSession("test1", "peer-a", "pass-1", "session-1");
        await storage.saveDirectMessageSession("test2", "peer-b", "pass-2", "session-2");
        storage.writeIdentityPin("test1", "peer-a", {
          fingerprintSha256: "fp-a",
          identityKeyVersion: 1,
          identityX25519Pub: "x-a",
          identitySigPub: "sig-a",
          identityPqSigPub: "pq-sig-a",
          observedAt: "2026-03-11T00:00:00Z",
        });
        storage.writeIdentityPin("test2", "peer-b", {
          fingerprintSha256: "fp-b",
          identityKeyVersion: 1,
          identityX25519Pub: "x-b",
          identitySigPub: "sig-b",
          identityPqSigPub: "pq-sig-b",
          observedAt: "2026-03-11T00:00:00Z",
        });
      },
    });

    router.navigateTo({ screen: "sign-in" });
    await flushPromises();

    document.querySelector<HTMLElement>("[data-local-account-forget='test1']")?.click();

    await eventually(() => {
      expect(storage.hasLocalKeys("test1")).toBe(false);
      expect(storage.hasLocalKeys("test2")).toBe(true);
      expect(document.querySelector("[data-local-account-fill='test1']")).toBeNull();
      expect(document.querySelector("[data-local-account-fill='test2']")).not.toBeNull();
    });

    await expect(storage.loadDirectMessageSession("test1", "peer-a", "pass-1")).resolves.toBeNull();
    await expect(storage.loadDirectMessageSession("test2", "peer-b", "pass-2")).resolves.toContain(
      "session-2",
    );
    expect(storage.listIdentityPins("test1")).toEqual([]);
    expect(storage.listIdentityPins("test2")).toHaveLength(1);
  }, 10000);

  it("rejects a nonexistent new-chat target and keeps local conversations unchanged", async () => {
    const { storage, router } = await bootApp({
      existingUsers: ["test1"],
      bundleUsers: ["test1"],
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "new-chat" });
    await flushPromises();

    const peerInput = document.querySelector<HTMLInputElement>("#nc-peer");
    peerInput!.value = "ghost";
    document.querySelector<HTMLButtonElement>("#nc-start")!.click();

    await eventually(() => {
      expect(document.querySelector("#nc-status")?.textContent).toContain("User @ghost was not found on this server");
    });

    expect(storage.loadConversations("test1")).toEqual([]);
  });

  it("sends a direct message through the PQ session path and updates local message state", async () => {
    const { router, apiState, messagesByConversation } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        await storage.saveDirectMessageSession(
          "test1",
          "test2",
          "pass-1",
          JSON.stringify({ snapshot: { pq_ratchet: { interval: 1 } } }),
        );
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "test2",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "chat", peerId: "test2" });
    await eventually(() => {
      expect(document.querySelector<HTMLInputElement>("#chat-input")).not.toBeNull();
    });

    const input = document.querySelector<HTMLInputElement>("#chat-input")!;
    input.value = "hello from web";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>("#chat-send")!.click();

    await eventually(() => {
      expect(apiState.relays).toHaveLength(1);
    });

    const saved = messagesByConversation.get(convId("test1", "test2")) ?? [];
    expect(saved).toHaveLength(1);
    expect(saved[0].text).toBe("hello from web");
    expect(saved[0].status).toBe("sent");
    expect(document.body.textContent).toContain("hello from web");
  });

  it("creates a contact before sending when delivery tokens are contact-scoped", async () => {
    const { router, apiState } = await bootApp({
      profileTokensRequireContact: true,
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        await storage.saveDirectMessageSession(
          "test1",
          "test2",
          "pass-1",
          JSON.stringify({ snapshot: { pq_ratchet: { interval: 1 } } }),
        );
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "test2",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "chat", peerId: "test2" });
    await eventually(() => {
      expect(document.querySelector<HTMLInputElement>("#chat-input")).not.toBeNull();
    });

    const input = document.querySelector<HTMLInputElement>("#chat-input")!;
    input.value = "hello contact scoped";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>("#chat-send")!.click();

    await eventually(() => {
      expect(apiState.contacts.has("test2")).toBe(true);
      expect(apiState.relays).toHaveLength(1);
    });
  });

  it("blocks direct messaging when the peer transparency proof does not match the pinned identity", async () => {
    const { router, apiState, messagesByConversation } = await bootApp({
      transparencyMismatchUsers: ["test2"],
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        await storage.saveDirectMessageSession(
          "test1",
          "test2",
          "pass-1",
          JSON.stringify({ snapshot: { pq_ratchet: { interval: 1 } } }),
        );
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "test2",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "chat", peerId: "test2" });
    await eventually(() => {
      expect(document.querySelector<HTMLInputElement>("#chat-input")).not.toBeNull();
    });

    const input = document.querySelector<HTMLInputElement>("#chat-input")!;
    input.value = "blocked by transparency";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>("#chat-send")!.click();

    await eventually(() => {
      const saved = messagesByConversation.get(convId("test1", "test2")) ?? [];
      expect(saved).toHaveLength(1);
      expect(saved[0].status).toBe("failed");
      expect(apiState.relays).toHaveLength(0);
    });
  });

  it("blocks direct messaging from an existing session when the peer rotated identity and the saved trust pin is stale", async () => {
    const { router, apiState, messagesByConversation, storage } = await bootApp({
      rotatedIdentityUsers: ["test2"],
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        await storage.saveDirectMessageSession(
          "test1",
          "test2",
          "pass-1",
          JSON.stringify({ snapshot: { pq_ratchet: { interval: 1 } } }),
        );
        storage.writeIdentityPin("test1", "test2", {
          fingerprintSha256: "bundle-fp-test2",
          identityKeyVersion: 1,
          identityX25519Pub: "bundle-x25519-test2",
          identitySigPub: "bundle-sig-test2",
          identityPqSigPub: "bundle-pq-sig-test2",
          observedAt: "2026-03-11T00:00:00Z",
        });
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "test2",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "chat", peerId: "test2" });
    await eventually(() => {
      expect(document.querySelector<HTMLInputElement>("#chat-input")).not.toBeNull();
    });

    const input = document.querySelector<HTMLInputElement>("#chat-input")!;
    input.value = "blocked by rotated identity";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>("#chat-send")!.click();

    await eventually(() => {
      const saved = messagesByConversation.get(convId("test1", "test2")) ?? [];
      expect(saved).toHaveLength(1);
      expect(saved[0].status).toBe("failed");
      expect(apiState.relays).toHaveLength(0);
    });

    await expect(storage.loadDirectMessageSession("test1", "test2", "pass-1")).resolves.toContain(
      "\"pq_ratchet\"",
    );
  });

  it("clears legacy stored sessions and re-establishes them with a fresh handshake", async () => {
    const { storage, router, apiState } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        await storage.saveDirectMessageSession(
          "test1",
          "test2",
          "pass-1",
          JSON.stringify({ snapshot: { pq_ratchet: { interval: 50 } } }),
        );
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "test2",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "chat", peerId: "test2" });
    await eventually(() => {
      expect(document.querySelector<HTMLInputElement>("#chat-input")).not.toBeNull();
    });

    const input = document.querySelector<HTMLInputElement>("#chat-input")!;
    input.value = "reset legacy session";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>("#chat-send")!.click();

    await eventually(() => {
      expect(apiState.relays).toHaveLength(1);
    });

    await expect(storage.loadDirectMessageSession("test1", "test2", "pass-1")).resolves.toBe(
      "handshake-session",
    );
  });

  it("does not emit presence, typing, or receipt metadata when those capabilities are disabled", async () => {
    const { router, apiState } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "test2",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "chat", peerId: "test2" });
    await eventually(() => {
      expect(document.querySelector<HTMLInputElement>("#chat-input")).not.toBeNull();
    });

    const input = document.querySelector<HTMLInputElement>("#chat-input")!;
    input.value = "hello";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flushPromises();

    expect(document.body.textContent).toContain("secure chat");
    expect(apiState.presenceCalls).toBe(0);
    expect(apiState.typingCalls).toBe(0);
    expect(apiState.receiptCalls).toBe(0);
  });

  it("connects realtime on the sealed-sender web profile", async () => {
    const { realtimeState } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    expect(realtimeState.connectCalls).toBe(1);
  });

  it("starts a direct conversation from a shareable username", async () => {
    const { router } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "",
          displayName: "test1",
          username: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "new-chat" });
    await eventually(() => {
      expect(document.querySelector<HTMLInputElement>("#nc-peer")).not.toBeNull();
    });

    const input = document.querySelector<HTMLInputElement>("#nc-peer")!;
    input.value = "@test2";
    document.querySelector<HTMLButtonElement>("#nc-start")!.click();

    await eventually(() => {
      expect(router.getCurrentView()).toEqual({ screen: "chat", peerId: "test2" });
    });
  });

  it("shows verified transparency status in the identity log view", async () => {
    const { router } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "test2",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "identity-log" });
    await eventually(() => {
      expect(document.body.textContent).toContain("Transparency");
      expect(document.body.textContent).toContain("Verified.");
    });
  });

  it("fails closed when the discovery manifest continuity changes on this device", async () => {
    const { router } = await bootApp({
      capabilities: {
        contact_discovery_supported: true,
        contact_discovery_mode: "private_service",
        contact_discovery_service_origin: "https://cdsi.example",
        contact_discovery_manifest_issuer_ed25519_pub: "manifest-issuer-pub",
        contact_discovery_ticket_issuer_ed25519_pub: "ticket-issuer-pub",
        contact_discovery_directory_backend: "attested_enclave_directory_v1",
        contact_discovery_host_enclave_protocol_version: 1,
        contact_discovery_host_release_id: "attested-host-v1",
        contact_discovery_enclave_release_id: "attested-enclave-v1",
        contact_discovery_expected_manifest_contract_sha256: "placeholder-attestation-contract-hash",
        contact_discovery_attestation_verifier: "aws-nitro-root-v1",
        contact_discovery_expected_measurement_hex: "ab".repeat(32),
        contact_discovery_attestation_document_sha256: "cd".repeat(32),
        contact_discovery_attestation_max_age_seconds: 86_400,
      },
      discoveryManifest: {
        ticket_issuer_ed25519_pub: "ticket-issuer-pub",
        manifest_issuer_ed25519_pub: "manifest-issuer-pub",
        oprf_public_key_ristretto255: "oprf-pub-2",
        attestation_verifier: "aws-nitro-root-v1",
        enclave_measurement_hex: "ab".repeat(32),
        attestation_document_format: "opaque_b64_v1",
        attestation_document_sha256: "cd".repeat(32),
        attestation_challenge_mode: "nonce_b64_required_v1",
      },
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "",
          displayName: "test1",
        });
        storage.writeContactDiscoveryCheckpoint("http://localhost:3000", "test1", {
          service_origin: "https://cdsi.example",
          manifest_issuer_ed25519_pub: "manifest-issuer-pub",
          ticket_issuer_ed25519_pub: "ticket-issuer-pub",
          protocol_version: 1,
          ticket_format: "ed25519-ticket-v1",
          lookup_protocol: "attested_enclave_voprf_directory_v1",
          privacy_mode: "enclave_backed_private_discovery_v1",
          directory_backend: "attested_enclave_directory_v1",
          host_enclave_protocol_version: 1,
          host_release_id: "attested-host-v1",
          enclave_release_id: "attested-enclave-v1",
          match_result_format: "contact_invite_token",
          oprf_suite: "ristretto255-sha512-v1",
          evaluation_proof_mode: "dleq_per_element_v1",
          oprf_public_key_ristretto255: "oprf-pub-1",
          attestation_mode: "attested_enclave_v1",
          attestation_verifier: "aws-nitro-root-v1",
          enclave_measurement_hex: "ab".repeat(32),
          attestation_document_format: "opaque_b64_v1",
          attestation_document_sha256: "cd".repeat(32),
          attestation_challenge_mode: "nonce_b64_required_v1",
          observed_at: "2026-03-26T00:00:00Z",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "settings" });
    await eventually(() => {
      expect(document.body.textContent).toContain("Manifest Continuity");
      expect(document.body.textContent).toContain("Changed on this device");
      expect(document.body.textContent).toContain("Contact discovery manifest continuity changed");
    });
  });

  it("fails closed when the discovery attestation contract drifts on this device", async () => {
    const { router } = await bootApp({
      discoveryAttestationError: "Contact discovery attestation host release mismatch",
      capabilities: {
        contact_discovery_supported: true,
        contact_discovery_mode: "private_service",
        contact_discovery_service_origin: "https://cdsi.example",
        contact_discovery_manifest_issuer_ed25519_pub: "manifest-issuer-pub",
        contact_discovery_ticket_issuer_ed25519_pub: "ticket-issuer-pub",
        contact_discovery_directory_backend: "attested_enclave_directory_v1",
        contact_discovery_host_enclave_protocol_version: 1,
        contact_discovery_host_release_id: "attested-host-v1",
        contact_discovery_enclave_release_id: "attested-enclave-v1",
        contact_discovery_expected_manifest_contract_sha256: "placeholder-attestation-contract-hash",
        contact_discovery_attestation_verifier: "aws-nitro-root-v1",
        contact_discovery_expected_measurement_hex: "ab".repeat(32),
        contact_discovery_attestation_document_sha256: "cd".repeat(32),
        contact_discovery_attestation_max_age_seconds: 86_400,
      },
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "settings" });
    await eventually(() => {
      expect(document.body.textContent).toContain("Manifest");
      expect(document.body.textContent).toContain("Contact discovery attestation host release mismatch");
      expect(document.body.textContent).toContain("Unavailable");
    });
  });

  it("fails closed when discovery upload receives a mismatched ticket nonce", async () => {
    const { router } = await bootApp({
      discoveryUploadResponse: {
        ticket_nonce: "wrong-ticket-nonce",
      },
      capabilities: {
        contact_discovery_supported: true,
        contact_discovery_mode: "private_service",
        contact_discovery_service_origin: "https://cdsi.example",
        contact_discovery_manifest_issuer_ed25519_pub: "manifest-issuer-pub",
        contact_discovery_ticket_issuer_ed25519_pub: "ticket-issuer-pub",
        contact_discovery_directory_backend: "attested_enclave_directory_v1",
        contact_discovery_host_enclave_protocol_version: 1,
        contact_discovery_host_release_id: "attested-host-v1",
        contact_discovery_enclave_release_id: "attested-enclave-v1",
        contact_discovery_expected_manifest_contract_sha256: "placeholder-attestation-contract-hash",
        contact_discovery_attestation_verifier: "aws-nitro-root-v1",
        contact_discovery_expected_measurement_hex: "ab".repeat(32),
        contact_discovery_attestation_document_sha256: "cd".repeat(32),
        contact_discovery_attestation_max_age_seconds: 86_400,
      },
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "discovery" });
    await eventually(() => {
      expect(document.querySelector<HTMLButtonElement>("#disc-upload")).not.toBeNull();
    });

    const phones = document.querySelector<HTMLTextAreaElement>("#disc-phones")!;
    phones.value = "a".repeat(64);
    phones.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>("#disc-upload")!.click();

    await eventually(() => {
      expect(document.body.textContent).toContain("Upload failed: Contact discovery upload ticket mismatch");
    });
  });

  it("fails closed when discovery match receives a mismatched manifest contract", async () => {
    const { router } = await bootApp({
      discoveryMatchResponse: {
        manifest_contract_sha256: "ff".repeat(32),
      },
      capabilities: {
        contact_discovery_supported: true,
        contact_discovery_mode: "private_service",
        contact_discovery_service_origin: "https://cdsi.example",
        contact_discovery_manifest_issuer_ed25519_pub: "manifest-issuer-pub",
        contact_discovery_ticket_issuer_ed25519_pub: "ticket-issuer-pub",
        contact_discovery_directory_backend: "attested_enclave_directory_v1",
        contact_discovery_host_enclave_protocol_version: 1,
        contact_discovery_host_release_id: "attested-host-v1",
        contact_discovery_enclave_release_id: "attested-enclave-v1",
        contact_discovery_expected_manifest_contract_sha256: "placeholder-attestation-contract-hash",
        contact_discovery_attestation_verifier: "aws-nitro-root-v1",
        contact_discovery_expected_measurement_hex: "ab".repeat(32),
        contact_discovery_attestation_document_sha256: "cd".repeat(32),
        contact_discovery_attestation_max_age_seconds: 86_400,
      },
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "discovery" });
    await eventually(() => {
      expect(document.querySelector<HTMLButtonElement>("#disc-match")).not.toBeNull();
    });

    const hashes = document.querySelector<HTMLTextAreaElement>("#disc-query")!;
    hashes.value = "b".repeat(64);
    hashes.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>("#disc-match")!.click();

    await eventually(() => {
      expect(document.body.textContent).toContain("Contact discovery match contract mismatch");
    });
  });

  it("recovers from a stale transparency checkpoint by retrying without previous_tree_size", async () => {
    const { apiState, router } = await bootApp({
      transparencyCheckpointOutOfRangeUsers: ["test2"],
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "test2",
          displayName: "test1",
        });
        storage.writeTransparencyCheckpoint("http://localhost:3000", "test2", {
          epoch: 7,
          tree_size: 7,
          root_hash: "stale-root",
          signature: "stale-signature",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "chat", peerId: "test2" });
    await eventually(() => {
      expect(document.querySelector<HTMLInputElement>("#chat-input")).not.toBeNull();
    });

    const input = document.querySelector<HTMLInputElement>("#chat-input")!;
    input.value = "hello after stale checkpoint";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector<HTMLButtonElement>("#chat-send")!.click();

    await eventually(() => {
      expect(apiState.relays).toHaveLength(1);
    });
  });

  it("logs out from settings and returns to onboarding while preserving the saved server URL", async () => {
    const { storage, router } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "test2",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "settings" });
    await eventually(() => {
      expect(document.querySelector<HTMLButtonElement>("#set-logout")).not.toBeNull();
    });

    document.querySelector<HTMLButtonElement>("#set-logout")!.click();
    await flushPromises();

    expect(router.getCurrentView()).toEqual({ screen: "onboarding" });
    expect(storage.loadSetup()).toMatchObject({
      serverUrl: "http://localhost:3000",
      userId: "",
      peerUserId: "",
    });
    expect(document.body.textContent).toContain("Create Account");
  });

  it("shows private-group create and join UI while keeping calls in holdback", async () => {
    const { router } = await bootApp({
      prepare: async (storage) => {
        await storage.saveKeys("test1", "pass-1", makeKeys("test1"));
        storage.saveSetup({
          serverUrl: "http://localhost:3000",
          userId: "test1",
          deviceId: "test1-device",
          suiteLabel: "ml-kem-768",
          peerUserId: "",
          displayName: "test1",
        });
        sessionStorage.setItem("pqmsg.passphrase", "pass-1");
      },
    });

    router.navigateTo({ screen: "create-group" });
    await flushPromises();
    expect(document.body.textContent).toContain("Private groups stay client-managed");
    expect(document.body.textContent).toContain("Create Private Group");
    expect(document.body.textContent).toContain("Join Private Group");

    router.navigateTo({ screen: "call", peerId: "test2", callType: "audio" });
    await flushPromises();
    expect(document.body.textContent).toContain("Audio calling is unavailable on web");
  });
});


