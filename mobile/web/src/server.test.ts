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
      device_id: "d1",
    });
    expect(result.user_id).toBe("alice");
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/register");
    expect(opts.method).toBe("POST");
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
    await api.upsertProfile("alice", { display_name: "Alice" }, fakeHeaders);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/v1/users/alice/profile");
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
});

describe("PqmsgApi error handling", () => {
  const api = new PqmsgApi("http://localhost:8080");

  it("throws on HTTP 400", async () => {
    mockFetch.mockResolvedValueOnce(errorResponse(400, "bad request"));
    await expect(api.registerUser({
      user_id: "x",
      identity_x25519_pub: "p",
      identity_sig_pub: "s",
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
