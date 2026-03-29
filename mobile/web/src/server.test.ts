import { describe, it, expect, vi, beforeEach, type Mock } from "vitest";
import { PqmsgApi, PqmsgApiError } from "./server";

// Mock global fetch
const mockFetch = vi.fn() as Mock;
vi.stubGlobal("fetch", mockFetch);

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(),
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  } as unknown as Response;
}

function emptyResponse(status = 204): Response {
  return {
    ok: true,
    status,
    headers: new Headers(),
    json: () => Promise.resolve(undefined),
    text: () => Promise.resolve(""),
  } as unknown as Response;
}

function errorResponse(status: number, message: string): Response {
  return {
    ok: false,
    status,
    headers: new Headers(),
    text: () => Promise.resolve(message),
  } as unknown as Response;
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe("PqmsgApi constructor", () => {
  it("throws on empty URL", () => {
    expect(() => new PqmsgApi("")).toThrow("server URL is empty");
  });

  it("throws on whitespace-only URL", () => {
    expect(() => new PqmsgApi("   ")).toThrow("server URL is empty");
  });

  it("trims trailing slashes", () => {
    mockFetch.mockResolvedValueOnce(emptyResponse(200));
    const api = new PqmsgApi("http://localhost:8080///");
    api.pingRoot();
    expect(mockFetch).toHaveBeenCalledWith(
      "http://localhost:8080/",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("rejects insecure remote http server URLs", () => {
    expect(() => new PqmsgApi("http://chat.example")).toThrow("HTTPS server URL");
  });

  it("rejects server URLs with embedded credentials", () => {
    expect(() => new PqmsgApi("https://user:pass@chat.example")).toThrow("embedded credentials");
  });
});

describe("PqmsgApi methods", () => {
  const api = new PqmsgApi("http://localhost:8080");
  const fakeHeaders = {
    "x-pqmsg-auth-user": "alice",
    "x-pqmsg-auth-device": "d1",
    "x-pqmsg-auth-timestamp": "1700000000",
    "x-pqmsg-auth-nonce": "abc",
    "x-pqmsg-auth-signature": "sig",
  };

  it("registerUser sends POST to /v1/users/register", async () => {
    const responseData = { user_id: "alice", device_id: "d1", registered_at: "2025-01-01T00:00:00Z" };
    mockFetch.mockResolvedValueOnce(jsonResponse(responseData));
    const result = await api.registerUser({
      user_id: "alice",
      identity_x25519_pub: "pub",
      identity_sig_pub: "sig",
      identity_pq_sig_pub: "pq-sig",
      device_id: "d1",
    });
    expect(result.user_id).toBe("alice");
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/register");
    expect(opts.method).toBe("POST");
  });

  it("resetDevUserIdentity sends POST to the development reset path", async () => {
    mockFetch.mockResolvedValueOnce(emptyResponse(204));
    await api.resetDevUserIdentity("alice@example");
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/dev/users/alice%40example/reset");
    expect(opts.method).toBe("POST");
    expect(opts.headers.get("x-pqmsg-auth-user")).toBeNull();
  });

  it("getBundle sends GET with URL-encoded userId", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "bob" }));
    await api.getBundle("bob@example");
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/bob%40example/bundle");
    expect(opts.method).toBe("GET");
  });

  it("publishPrekeys sends POST with auth headers", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice" }));
    await api.publishPrekeys("alice", {
      signed_prekey_x25519_pub: "spk",
      sig_over_spk: "sig1",
      pq_signed_prekey_pub_mlkem768: "pqspk",
      sig_over_pqspk: "sig2",
      one_time_prekeys_x25519: [],
      one_time_prekeys_mlkem768: [],
    }, fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/prekeys");
    expect(opts.method).toBe("POST");
    // Verify auth headers were forwarded
    const reqHeaders = opts.headers;
    expect(reqHeaders.get("x-pqmsg-auth-user")).toBe("alice");
  });

  it("relay sends POST to /v1/relay/:recipient", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ message_id: 1, received_at: "now" }));
    await api.relay("bob", {
      sender_user_id: "alice",
      device_id: "d1",
      message_bytes_base64: "bXNn",
    }, fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/relay/bob");
  });

  it("inbox sends GET with since parameter", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice", messages: [] }));
    await api.inbox("alice", 42, fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/inbox/alice?since=42");
  });

  it("listDevices sends GET", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice", devices: [] }));
    await api.listDevices("alice", fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/devices");
  });

  it("linkDevice sends POST", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice", linked_device_id: "d2" }));
    await api.linkDevice("alice", "d2", fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/devices/link");
    expect(opts.method).toBe("POST");
  });

  it("revokeDevice sends POST to correct path", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({}));
    await api.revokeDevice("alice", "d2", fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/devices/d2/revoke");
  });

  it("retireCurrentDevice sends POST", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({}));
    await api.retireCurrentDevice("alice", fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/devices/current/retire");
  });

  it("getProfile sends GET", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice" }));
    await api.getProfile("alice", fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/profile");
  });

  it("upsertProfile sends POST", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice" }));
    await api.upsertProfile("alice", { display_name: "Alice", username: "alice.secure" }, fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/profile");
    expect(opts.method).toBe("POST");
  });

  it("resolveUsername sends unauthenticated GET", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ username: "alice.secure", user_id: "alice" }));
    const result = await api.resolveUsername("@Alice.Secure");
    const [url, opts] = mockFetch.mock.calls[0];
    expect(result.user_id).toBe("alice");
    expect(result.username).toBe("alice.secure");
    expect(url).toBe("http://localhost:8080/v1/usernames/Alice.Secure");
    expect(opts.method).toBe("GET");
    expect(opts.headers.get("x-pqmsg-auth-user")).toBeNull();
  });

  it("getUsernameBundle sends unauthenticated GET", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        user_id: "alice",
        device_id: "alice-dev-1",
        identity_x25519_pub: "ix-pub",
        identity_sig_pub: "sig-pub",
        identity_pq_sig_pub: "pq-sig-pub",
        signed_prekey_x25519_pub: "spk-pub",
        sig_over_spk: "spk-sig",
        pq_signed_prekey_pub_mlkem768: "pq-spk-pub",
        sig_over_pqspk: "pq-spk-sig",
        pq_sig_over_spk: "pq-sig-over-spk",
        pq_sig_over_pqspk: "pq-sig-over-pqspk",
        one_time_prekey_x25519: null,
        one_time_prekey_mlkem768: null,
        identity_key_version: 1,
        identity_fingerprint_sha256: "ff".repeat(32),
        bundle_generated_at: "2026-03-26T00:00:00Z",
      })
    );
    const result = await api.getUsernameBundle("@Alice.Secure");
    const [url, opts] = mockFetch.mock.calls[0];
    expect(result.user_id).toBe("alice");
    expect(url).toBe("http://localhost:8080/v1/usernames/Alice.Secure/bundle");
    expect(opts.method).toBe("GET");
    expect(opts.headers.get("x-pqmsg-auth-user")).toBeNull();
  });

  it("publishPrivateGroupState sends POST to the opaque state endpoint", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        group_id: "pg-1",
        epoch: 1,
        stored_member_count: 2,
        published_at: "2026-03-26T00:00:00Z",
      })
    );
    await api.publishPrivateGroupState({
      group_id: "pg-1",
      epoch: 1,
      state_commitment_sha256: "aa".repeat(32),
      ciphertext_nonce_base64: "bm9uY2UxMjM0NTY3",
      ciphertext_base64: "Y2lwaGVydGV4dA==",
      ciphertext_aad_base64: "YWFk",
      authorizing_membership_handle_sha256: "bb".repeat(32),
      authorizing_publish_key_base64: "cHVibGlzaC1rZXk=",
      members: [],
    });
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/private-groups/state/publish");
    expect(opts.method).toBe("POST");
    expect(opts.headers.get("x-pqmsg-auth-user")).toBeNull();
  });

  it("fetchPrivateGroupState sends POST to the opaque fetch endpoint", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        group_id: "pg-1",
        epoch: 2,
        state_commitment_sha256: "cc".repeat(32),
        ciphertext_nonce_base64: "bm9uY2UxMjM0NTY3",
        ciphertext_base64: "Y2lwaGVydGV4dA==",
        ciphertext_aad_base64: "YWFk",
        published_at: "2026-03-26T00:00:00Z",
      })
    );
    await api.fetchPrivateGroupState({
      membership_handle_sha256: "aa".repeat(32),
      fetch_key_base64: "ZmV0Y2gta2V5",
    });
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/private-groups/state/fetch");
    expect(opts.method).toBe("POST");
  });

  it("private group invite methods use the opaque invite routes", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        invite_token: "invite-1",
        group_id: "pg-1",
        epoch: 1,
        expires_at: "2026-03-30T00:00:00Z",
        created_at: "2026-03-26T00:00:00Z",
      })
    );
    await api.createPrivateGroupInvite({
      group_id: "pg-1",
      epoch: 1,
      invite_commitment_sha256: "aa".repeat(32),
      invite_ciphertext_nonce_base64: "bm9uY2UxMjM0NTY3",
      invite_ciphertext_base64: "Y2lwaGVydGV4dA==",
      invite_ciphertext_aad_base64: "YWFk",
      authorizing_membership_handle_sha256: "bb".repeat(32),
      authorizing_publish_key_base64: "cHVibGlzaC1rZXk=",
    });
    expect(mockFetch.mock.calls[0][0]).toBe("http://localhost:8080/v1/private-groups/invites");

    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        invite_token: "invite-1",
        group_id: "pg-1",
        epoch: 1,
        invite_commitment_sha256: "aa".repeat(32),
        invite_ciphertext_nonce_base64: "bm9uY2UxMjM0NTY3",
        invite_ciphertext_base64: "Y2lwaGVydGV4dA==",
        invite_ciphertext_aad_base64: "YWFk",
        created_at: "2026-03-26T00:00:00Z",
        expires_at: "2026-03-30T00:00:00Z",
      })
    );
    await api.resolvePrivateGroupInvite("invite-1");
    expect(mockFetch.mock.calls[1][0]).toBe("http://localhost:8080/v1/private-groups/invites/invite-1");

    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        invite_token: "invite-1",
        consumed: true,
        revoked_at: "2026-03-26T00:01:00Z",
      })
    );
    await api.consumePrivateGroupInvite("invite-1");
    const [url, opts] = mockFetch.mock.calls[2];
    expect(url).toBe("http://localhost:8080/v1/private-groups/invites/invite-1");
    expect(opts.method).toBe("POST");
  });

  it("private group message methods use the opaque message routes", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        message_id: 41,
        group_id: "pg-1",
        epoch: 2,
        received_at: "2026-03-26T00:00:00Z",
      })
    );
    await api.publishPrivateGroupMessage({
      group_id: "pg-1",
      epoch: 2,
      sent_at_unix_ms: 1_775_000_000_000,
      ciphertext_nonce_base64: "bm9uY2UxMjM0NTY3",
      ciphertext_base64: "Y2lwaGVydGV4dA==",
      ciphertext_aad_base64: "YWFk",
      sender_hybrid_signature_base64: "c2ln",
      authorizing_membership_handle_sha256: "aa".repeat(32),
      authorizing_fetch_key_base64: "ZmV0Y2gta2V5",
    });
    let [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/private-groups/messages/publish");
    expect(opts.method).toBe("POST");

    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        group_id: "pg-1",
        epoch: 2,
        messages: [
          {
            message_id: 41,
            group_id: "pg-1",
            epoch: 2,
            sent_at_unix_ms: 1_775_000_000_000,
            ciphertext_nonce_base64: "bm9uY2UxMjM0NTY3",
            ciphertext_base64: "Y2lwaGVydGV4dA==",
            ciphertext_aad_base64: "YWFk",
            sender_hybrid_signature_base64: "c2ln",
            received_at: "2026-03-26T00:00:00Z",
          },
        ],
        fetched_at: "2026-03-26T00:00:01Z",
      })
    );
    await api.fetchPrivateGroupMessages({
      membership_handle_sha256: "aa".repeat(32),
      fetch_key_base64: "ZmV0Y2gta2V5",
      since_message_id: 40,
    });
    [url, opts] = mockFetch.mock.calls[1];
    expect(url).toBe("http://localhost:8080/v1/private-groups/messages/fetch");
    expect(opts.method).toBe("POST");
  });

  it("getPresence sends GET", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice", status: "online" }));
    await api.getPresence("alice", fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/presence");
  });

  it("updatePresence sends POST", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice" }));
    await api.updatePresence("alice", { status: "away" }, fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/presence");
    expect(opts.method).toBe("POST");
  });

  it("getTyping sends GET", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ typing: [] }));
    await api.getTyping("alice", fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/typing/alice");
  });

  it("sendReceipt sends POST", async () => {
    mockFetch.mockResolvedValueOnce(emptyResponse());
    await api.sendReceipt("alice", { message_id: 1, receipt_type: "delivered" }, fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/receipts");
    expect(opts.method).toBe("POST");
  });

  it("getReceipts sends GET with since_id", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ receipts: [] }));
    await api.getReceipts("alice", 10, fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/receipts/poll?since_id=10");
  });

  it("createInboxWsTicket sends POST with since query", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ ticket: "ws-ticket", expires_at: "2026-03-08T00:00:30Z" }));
    await api.createInboxWsTicket("alice", 10, fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/ws/inbox/alice/ticket?since=10");
    expect(opts.method).toBe("POST");
    expect(opts.headers.get("x-pqmsg-auth-user")).toBe("alice");
  });

  it("createSealedInboxWsTicket sends POST with since query", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ ticket: "sealed-ws-ticket", expires_at: "2026-03-08T00:00:30Z" }));
    await api.createSealedInboxWsTicket("alice", 10, fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/ws/sealed-inbox/alice/ticket?since=10");
    expect(opts.method).toBe("POST");
    expect(opts.headers.get("x-pqmsg-auth-user")).toBe("alice");
  });

  it("listContacts sends GET", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ contacts: [] }));
    await api.listContacts("alice", fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/contacts");
  });

  it("createContactInvite sends authenticated POST", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        user_id: "alice",
        invite_token: "opaque-token-123",
        expires_at: "2026-03-26T00:00:00Z",
      })
    );
    const result = await api.createContactInvite("alice", fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(result.invite_token).toBe("opaque-token-123");
    expect(url).toBe("http://localhost:8080/v1/users/alice/contact-invites");
    expect(opts.method).toBe("POST");
    expect(opts.headers.get("x-pqmsg-auth-user")).toBe("alice");
  });

  it("resolveContactInvite sends unauthenticated GET", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        user_id: "alice",
        invite_token: "opaque-token-123",
        expires_at: "2026-03-26T00:00:00Z",
      })
    );
    const result = await api.resolveContactInvite("opaque-token-123");
    const [url, opts] = mockFetch.mock.calls[0];
    expect(result.user_id).toBe("alice");
    expect(url).toBe("http://localhost:8080/v1/contact-invites/opaque-token-123");
    expect(opts.method).toBe("GET");
    expect(opts.headers.get("x-pqmsg-auth-user")).toBeNull();
  });

  it("getContactInviteBundle sends unauthenticated GET", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        user_id: "alice",
        device_id: "alice-dev-1",
        identity_x25519_pub: "ix-pub",
        identity_sig_pub: "sig-pub",
        identity_pq_sig_pub: "pq-sig-pub",
        signed_prekey_x25519_pub: "spk-pub",
        sig_over_spk: "spk-sig",
        pq_signed_prekey_pub_mlkem768: "pq-spk-pub",
        sig_over_pqspk: "pq-spk-sig",
        pq_sig_over_spk: "pq-sig-over-spk",
        pq_sig_over_pqspk: "pq-sig-over-pqspk",
        one_time_prekey_x25519: null,
        one_time_prekey_mlkem768: null,
        identity_key_version: 1,
        identity_fingerprint_sha256: "ff".repeat(32),
        bundle_generated_at: "2026-03-26T00:00:00Z",
      })
    );
    const result = await api.getContactInviteBundle("opaque-token-123");
    const [url, opts] = mockFetch.mock.calls[0];
    expect(result.user_id).toBe("alice");
    expect(url).toBe("http://localhost:8080/v1/contact-invites/opaque-token-123/bundle");
    expect(opts.method).toBe("GET");
    expect(opts.headers.get("x-pqmsg-auth-user")).toBeNull();
  });

  it("createGroup sends POST to /v1/groups", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ group_id: "g1" }));
    await api.createGroup({ group_id: "g1", member_user_ids: ["alice", "bob"] }, fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/groups");
    expect(opts.method).toBe("POST");
  });

  it("listGroupMembers sends GET", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ group_id: "g1", members: [] }));
    await api.listGroupMembers("g1", fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/groups/g1/members");
  });

  it("uploadFile sends POST to /v1/files/upload", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ file_id: "f1" }));
    await api.uploadFile({
      recipient_user_id: "bob",
      device_id: "d1",
      mime_type: "image/png",
      file_bytes_base64: "abc",
    }, fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/files/upload");
  });

  it("downloadFile sends GET", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ file_id: "f1" }));
    await api.downloadFile("f1", fakeHeaders);
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/files/f1");
  });

  it("sealedRelay sends POST without auth headers", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ delivered_device_count: 1 }));
    await api.sealedRelay("bob", {
      delivery_token: "delivery-token-bob",
      message_bytes_base64: "abc",
    });
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/sealed-relay/bob");
  });

  it("anonBundle sends GET without auth", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "bob" }));
    await api.anonBundle("bob");
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/anon/users/bob/bundle");
  });

  it("getHealth sends GET to /health", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
    await api.getHealth();
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/health");
  });

  it("getCapabilities sends GET to /v1/capabilities", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ capability_schema_version: 1 }));
    await api.getCapabilities();
    const [url] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/capabilities");
  });

  it("getContactDiscoveryManifest fetches the separate discovery service manifest", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        service: "pqmsg-discovery",
        protocol_version: 1,
        attestation_mode: "attested_enclave_v1",
        attestation_verifier: "aws-nitro-root-v1",
        enclave_measurement_hex: "ab".repeat(32),
        attestation_document_format: "opaque_b64_v1",
        attestation_document_sha256: "cd".repeat(32),
        attestation_challenge_mode: "nonce_b64_required_v1",
        ticket_format: "base64(json-payload).base64(ed25519-signature)",
        ticket_issuer_ed25519_pub: "issuer-ed25519-pub",
        ticket_max_ttl_seconds: 300,
        lookup_protocol: "attested_enclave_voprf_directory_v1",
        privacy_mode: "enclave_backed_private_discovery_v1",
        directory_backend: "attested_enclave_directory_v1",
        host_enclave_protocol_version: 1,
        host_release_id: "attested-host-v1",
        enclave_release_id: "attested-enclave-v1",
        match_result_format: "contact_invite_token",
        oprf_suite: "ristretto255-sha512-v1",
        evaluation_proof_mode: "dleq_per_element_v1",
        oprf_public_key_ristretto255: "ristretto-oprf-pub",
        signed_at: "2026-03-26T12:00:00Z",
        expires_at: "2026-03-26T13:00:00Z",
        manifest_issuer_ed25519_pub: "manifest-ed25519-pub",
        manifest_signature_ed25519: "manifest-sig",
      })
    );
    const manifest = await api.getContactDiscoveryManifest("https://cdsi.example");
    const [url, opts] = mockFetch.mock.calls[0];
    expect(manifest.service).toBe("pqmsg-discovery");
    expect(url).toBe("https://cdsi.example/v1/manifest");
    expect(opts.method).toBe("GET");
  });

  it("getContactDiscoveryAttestation fetches the separate discovery service attestation", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        attestation_mode: "attested_enclave_v1",
        attestation_verifier: "aws-nitro-root-v1",
        enclave_measurement_hex: "ab".repeat(32),
        directory_backend: "attested_enclave_directory_v1",
        host_enclave_protocol_version: 1,
        host_release_id: "attested-host-v1",
        enclave_release_id: "attested-enclave-v1",
        manifest_contract_sha256: "ee".repeat(32),
        attested_oprf_public_key_ristretto255: "oprf-pub",
        document_format: "opaque_b64_v1",
        document_base64: "eyJ0ZWUiOiJzZ3gifQ==",
        document_sha256: "cd".repeat(32),
        published_at: "2026-03-26T12:00:00Z",
        challenge_nonce_base64: "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
        attestation_signature_ed25519: "attestation-sig",
      })
    );
    const attestation = await api.getContactDiscoveryAttestation(
      "https://cdsi.example",
      "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
    );
    const [url, opts] = mockFetch.mock.calls[0];
    expect(attestation.attestation_verifier).toBe("aws-nitro-root-v1");
    expect(url).toBe(
      "https://cdsi.example/v1/attestation?nonce_b64=bm9uY2UxMjM0NTY3ODkwMTIzNA%3D%3D"
    );
    expect(opts.method).toBe("GET");
  });

  it("evaluateDiscoveryElementsAtService sends POST to the blind-evaluation endpoint", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        user_id: "alice",
        device_id: "alice-dev-1",
        ticket_nonce: "ticket-nonce-1",
        manifest_contract_sha256: "ee".repeat(32),
        evaluation_proof_mode: "dleq_per_element_v1",
        evaluated_elements_base64: ["ZXZhbHVhdGVk"],
        dleq_proofs: [{
          challenge_scalar_base64: "Y2hhbGxlbmdl",
          response_scalar_base64: "cmVzcG9uc2U=",
          commitment_base_base64: "Y29tbWl0LWJhc2U=",
          commitment_blinded_base64: "Y29tbWl0LWJsaW5kZWQ=",
        }],
        evaluated_at: "2026-03-13T00:00:00Z",
      })
    );
    const result = await api.evaluateDiscoveryElementsAtService("https://cdsi.example", {
      ticket: "ticket-eval",
      blinded_elements_base64: ["YmxpbmRlZA=="],
    });
    const [url, opts] = mockFetch.mock.calls[0];
    expect(result.device_id).toBe("alice-dev-1");
    expect(result.ticket_nonce).toBe("ticket-nonce-1");
    expect(url).toBe("https://cdsi.example/v1/discovery/evaluate");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(String(opts.body))).toEqual({
      ticket: "ticket-eval",
      blinded_elements_base64: ["YmxpbmRlZA=="],
    });
  });

  it("uploadDiscoveryHandlesToService sends POST to the separate discovery service", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        user_id: "alice",
        device_id: "alice-dev-1",
        ticket_nonce: "ticket-nonce-1",
        manifest_contract_sha256: "ee".repeat(32),
        uploaded_phone_tokens: 1,
        uploaded_email_tokens: 0,
        updated_at: "2026-03-13T00:00:00Z",
      })
    );
    const result = await api.uploadDiscoveryHandlesToService("https://cdsi.example", {
      ticket: "ticket-1",
      phone_tokens_sha256: ["11".repeat(32)],
      email_tokens_sha256: [],
    });
    const [url, opts] = mockFetch.mock.calls[0];
    expect(result.user_id).toBe("alice");
    expect(result.ticket_nonce).toBe("ticket-nonce-1");
    expect(url).toBe("https://cdsi.example/v1/discovery/handles");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(String(opts.body))).toEqual({
      ticket: "ticket-1",
      phone_tokens_sha256: ["11".repeat(32)],
      email_tokens_sha256: [],
    });
  });

  it("matchDiscoveryHashesAtService sends POST to the separate discovery service", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        user_id: "alice",
        ticket_nonce: "ticket-nonce-2",
        manifest_contract_sha256: "ee".repeat(32),
        matches: [
          {
            token_sha256: "11".repeat(32),
            contact_invite_token: "opaque-bootstrap-1",
            handle_kind: "phone",
          },
        ],
        checked_at: "2026-03-13T00:00:00Z",
      })
    );
    const result = await api.matchDiscoveryHashesAtService("https://cdsi.example", {
      ticket: "ticket-2",
      tokens_sha256: ["11".repeat(32)],
    });
    const [url, opts] = mockFetch.mock.calls[0];
    expect(result.matches).toHaveLength(1);
    expect(result.ticket_nonce).toBe("ticket-nonce-2");
    expect(url).toBe("https://cdsi.example/v1/discovery/match");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(String(opts.body))).toEqual({
      ticket: "ticket-2",
      tokens_sha256: ["11".repeat(32)],
    });
  });

  it("getTransparencyProof sends GET with optional previous_tree_size", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice" }));
    await api.getTransparencyProof("alice", 7);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/transparency/users/alice/proof?previous_tree_size=7");
    expect(opts.method).toBe("GET");
  });
});

describe("PqmsgApi error handling", () => {
  const api = new PqmsgApi("http://localhost:8080");

  it("throws on HTTP 400", async () => {
    mockFetch.mockResolvedValueOnce(errorResponse(400, "bad request"));
    await expect(api.registerUser({
      user_id: "x",
      identity_x25519_pub: "p",
      identity_sig_pub: "s",
      identity_pq_sig_pub: "pq",
      device_id: "d",
    })).rejects.toThrow("HTTP 400: bad request");
  });

  it("throws on HTTP 401", async () => {
    mockFetch.mockResolvedValueOnce(errorResponse(401, "unauthorized"));
    await expect(api.getBundle("alice")).rejects.toThrow("HTTP 401");
  });

  it("throws on HTTP 500", async () => {
    mockFetch.mockResolvedValueOnce(errorResponse(500, "internal error"));
    await expect(api.getHealth()).rejects.toThrow("HTTP 500");
  });

  it("sanitizes server-controlled HTML in error messages", async () => {
    mockFetch.mockResolvedValueOnce(errorResponse(400, "<script>alert(1)</script>   bad   request"));
    await expect(api.getHealth()).rejects.toMatchObject({
      name: "PqmsgApiError",
      status: 400,
      detail: "alert(1) bad request",
      message: "HTTP 400: alert(1) bad request",
    } satisfies Partial<PqmsgApiError>);
  });
});

describe("PqmsgApi request body", () => {
  const api = new PqmsgApi("http://localhost:8080");

  it("GET requests have no body", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice" }));
    await api.getBundle("alice");
    const [, opts] = mockFetch.mock.calls[0];
    expect(opts.body).toBeUndefined();
  });

  it("POST requests include JSON body", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice" }));
    await api.registerUser({
      user_id: "alice",
      identity_x25519_pub: "pub",
      identity_sig_pub: "sig",
      identity_pq_sig_pub: "pq-sig",
      device_id: "d1",
    });
    const [, opts] = mockFetch.mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.user_id).toBe("alice");
    expect(body.device_id).toBe("d1");
  });

  it("POST requests set content-type header", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice" }));
    await api.registerUser({
      user_id: "alice",
      identity_x25519_pub: "pub",
      identity_sig_pub: "sig",
      identity_pq_sig_pub: "pq-sig",
      device_id: "d1",
    });
    const [, opts] = mockFetch.mock.calls[0];
    expect(opts.headers.get("content-type")).toBe("application/json");
  });

  it("all requests set accept header", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ user_id: "alice" }));
    await api.getBundle("alice");
    const [, opts] = mockFetch.mock.calls[0];
    expect(opts.headers.get("accept")).toBe("application/json");
  });
});

