import { describe, it, expect, beforeEach, vi } from "vitest";
const sessionCache = new Map<string, string>();
const metadataCache = new Map<string, string>();
const keyRecordCache = new Map<string, string>();
vi.mock("./db", () => ({
  saveSessionCache: async (userId: string, peerId: string, sealedSession: string) => {
    sessionCache.set(`${userId}:${peerId}`, sealedSession);
  },
  loadSessionCache: async (userId: string, peerId: string) =>
    sessionCache.get(`${userId}:${peerId}`) ?? null,
  clearSessionCache: async (userId: string, peerId: string) => {
    sessionCache.delete(`${userId}:${peerId}`);
  },
  clearAllSessionCache: async (userId?: string) => {
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
  saveMetadataRecord: async (id: string, rawJson: string) => {
    metadataCache.set(id, rawJson);
  },
  loadMetadataRecord: async (id: string) => metadataCache.get(id) ?? null,
  clearMetadataRecord: async (id: string) => {
    metadataCache.delete(id);
  },
  saveKeyRecord: async (id: string, sealedKeys: string) => {
    keyRecordCache.set(id, sealedKeys);
  },
  loadKeyRecord: async (id: string) => keyRecordCache.get(id) ?? null,
  listKeyRecordIds: async () => [...keyRecordCache.keys()].sort((lhs, rhs) => lhs.localeCompare(rhs)),
  clearKeyRecord: async (id: string) => {
    keyRecordCache.delete(id);
  },
}));

import { saveKeyRecord, saveMetadataRecord } from "./db";

import {
  loadSetup,
  initMetadataStorage,
  saveSetup,
  DEFAULT_SETUP,
  loadConversations,
  upsertConversation,
  markConversationRead,
  readCursor,
  writeCursor,
  readIdentityPin,
  writeIdentityPin,
  listIdentityPins,
  loadConversationMeta,
  loadConversationMetas,
  updateConversationMeta,
  readProfileDisplayName,
  writeProfileDisplayName,
  loadProfileDisplayNames,
  hasLocalKeys,
  listLocalKeyUsers,
  saveKeys,
  loadGroupConversations,
  upsertGroupConversation,
  markGroupConversationRead,
  loadPrivateGroups,
  readPrivateGroup,
  upsertPrivateGroup,
  removePrivateGroup,
  saveDirectMessageSession,
  loadDirectMessageSession,
  wipeLocalState,
  type SetupConfig,
  type IdentityPin,
} from "./storage";
import { sealJsonWithPassphrase } from "./crypto";

// Mock localStorage
const store: Record<string, string> = {};
const localStorageMock = {
  getItem: (key: string) => store[key] ?? null,
  setItem: (key: string, value: string) => { store[key] = value; },
  removeItem: (key: string) => { delete store[key]; },
  clear: () => { for (const key of Object.keys(store)) delete store[key]; },
  get length() { return Object.keys(store).length; },
  key: (index: number) => Object.keys(store)[index] ?? null,
};
vi.stubGlobal("localStorage", localStorageMock);

beforeEach(async () => {
  localStorageMock.clear();
  sessionCache.clear();
  metadataCache.clear();
  keyRecordCache.clear();
  await initMetadataStorage();
});

describe("loadSetup / saveSetup", () => {
  it("returns defaults when nothing is stored", () => {
    const setup = loadSetup();
    expect(setup).toEqual(DEFAULT_SETUP);
  });

  it("round-trips setup config", () => {
    const config: SetupConfig = {
      serverUrl: "http://example.com:8080",
      userId: "alice",
      deviceId: "d1",
      suiteLabel: "ml-kem-768",
      peerUserId: "bob",
      displayName: "Alice",
      username: "",
      usernameLookupEnabled: false,
    };
    saveSetup(config);
    expect(loadSetup()).toEqual(config);
  });

  it("falls back to defaults for missing fields", async () => {
    await saveMetadataRecord("pqmsg.web.setup.v1", JSON.stringify({ serverUrl: "http://test" }));
    await initMetadataStorage();
    const setup = loadSetup();
    expect(setup.serverUrl).toBe("http://test");
    expect(setup.suiteLabel).toBe(DEFAULT_SETUP.suiteLabel);
  });

  it("preserves explicitly cleared setup fields", async () => {
    await saveMetadataRecord(
      "pqmsg.web.setup.v1",
      JSON.stringify({
        serverUrl: "http://localhost:3000",
        userId: "",
        deviceId: "",
        suiteLabel: "ml-kem-768",
        peerUserId: "",
        displayName: "",
        username: "",
      }),
    );
    await initMetadataStorage();
    expect(loadSetup()).toEqual({
      serverUrl: "http://localhost:3000",
      userId: "",
      deviceId: "",
      suiteLabel: "ml-kem-768",
      peerUserId: "",
      displayName: "",
      username: "",
      usernameLookupEnabled: false,
    });
  });

  it("returns defaults on corrupt JSON", async () => {
    await saveMetadataRecord("pqmsg.web.setup.v1", "not-json{{{");
    await initMetadataStorage();
    expect(loadSetup()).toEqual(DEFAULT_SETUP);
  });
});

describe("conversations", () => {
  it("loadConversations returns empty for no data", () => {
    expect(loadConversations("alice")).toEqual([]);
  });

  it("upsertConversation creates new conversation", () => {
    upsertConversation("alice", "bob", "hello", false);
    const convos = loadConversations("alice");
    expect(convos).toHaveLength(1);
    expect(convos[0].peerUserId).toBe("bob");
    expect(convos[0].lastPreview).toBe("hello");
    expect(convos[0].unreadCount).toBe(0);
  });

  it("upsertConversation increments unread", () => {
    upsertConversation("alice", "bob", "msg1", true);
    upsertConversation("alice", "bob", "msg2", true);
    const convos = loadConversations("alice");
    expect(convos[0].unreadCount).toBe(2);
    expect(convos[0].lastPreview).toBe("msg2");
  });

  it("conversations are sorted by updatedAt desc", () => {
    upsertConversation("alice", "bob", "old", false);
    // Manually set a later timestamp for charlie by advancing time
    const origNow = Date.now;
    Date.now = () => origNow() + 1000;
    try {
      upsertConversation("alice", "charlie", "new", false);
      const convos = loadConversations("alice");
      expect(convos[0].peerUserId).toBe("charlie");
      expect(convos[1].peerUserId).toBe("bob");
    } finally {
      Date.now = origNow;
    }
  });

  it("conversations are scoped to userId", () => {
    upsertConversation("alice", "bob", "hi", false);
    upsertConversation("eve", "bob", "hello", false);
    expect(loadConversations("alice")).toHaveLength(1);
    expect(loadConversations("eve")).toHaveLength(1);
    expect(loadConversations("nobody")).toHaveLength(0);
  });

  it("markConversationRead resets unread count", () => {
    upsertConversation("alice", "bob", "msg", true);
    upsertConversation("alice", "bob", "msg2", true);
    expect(loadConversations("alice")[0].unreadCount).toBe(2);
    markConversationRead("alice", "bob");
    expect(loadConversations("alice")[0].unreadCount).toBe(0);
  });

  it("markConversationRead does nothing for unknown conversation", () => {
    markConversationRead("alice", "unknown");
    // Should not throw
    expect(loadConversations("alice")).toHaveLength(0);
  });

  it("preview is truncated to 160 chars", () => {
    const longText = "a".repeat(200);
    upsertConversation("alice", "bob", longText, false);
    expect(loadConversations("alice")[0].lastPreview.length).toBe(160);
  });

  it("empty preview becomes 'No content'", () => {
    upsertConversation("alice", "bob", "   ", false);
    expect(loadConversations("alice")[0].lastPreview).toBe("No content");
  });
});

describe("private groups", () => {
  it("upsertPrivateGroup stores and reads opaque local group state", () => {
    upsertPrivateGroup("alice", "pg-1", "{\"epoch\":1}", "{\"role\":\"Owner\"}", "aa".repeat(32));
    const groups = loadPrivateGroups("alice");
    expect(groups).toHaveLength(1);
    expect(groups[0].groupId).toBe("pg-1");
    expect(groups[0].stateCommitmentSha256).toBe("aa".repeat(32));
    expect(readPrivateGroup("alice", "pg-1")?.memberCredentialJson).toBe("{\"role\":\"Owner\"}");
  });

  it("removePrivateGroup deletes only the targeted opaque group state", () => {
    upsertPrivateGroup("alice", "pg-1", "{\"epoch\":1}", "{\"role\":\"Owner\"}");
    upsertPrivateGroup("alice", "pg-2", "{\"epoch\":2}", "{\"role\":\"Admin\"}");
    upsertPrivateGroup("bob", "pg-1", "{\"epoch\":1}", "{\"role\":\"Owner\"}");
    removePrivateGroup("alice", "pg-1");
    expect(loadPrivateGroups("alice").map((item) => item.groupId)).toEqual(["pg-2"]);
    expect(loadPrivateGroups("bob").map((item) => item.groupId)).toEqual(["pg-1"]);
  });
});

describe("cursors", () => {
  it("readCursor defaults to 0", () => {
    expect(readCursor("alice")).toBe(0);
  });

  it("writeCursor / readCursor round-trips", () => {
    writeCursor("alice", 42);
    expect(readCursor("alice")).toBe(42);
  });

  it("cursors support device-scoped keys", () => {
    writeCursor("alice", 10, "d1");
    writeCursor("alice", 20, "d2");
    expect(readCursor("alice", "d1")).toBe(10);
    expect(readCursor("alice", "d2")).toBe(20);
    expect(readCursor("alice")).toBe(0); // no device-less cursor
  });
});

describe("conversation meta", () => {
  it("returns defaults when no meta exists", () => {
    expect(loadConversationMeta("alice", "dm", "bob")).toEqual({
      kind: "dm",
      threadId: "bob",
      requestState: "accepted",
      pinnedAt: null,
      archivedAt: null,
      sealedSenderDefault: false,
      ephemeralTtlDefault: 0,
    });
  });

  it("updateConversationMeta persists patches", () => {
    updateConversationMeta("alice", "dm", "bob", {
      requestState: "pending",
      pinnedAt: 123,
      sealedSenderDefault: true,
      ephemeralTtlDefault: 300,
    });
    expect(loadConversationMeta("alice", "dm", "bob")).toEqual({
      kind: "dm",
      threadId: "bob",
      requestState: "pending",
      pinnedAt: 123,
      archivedAt: null,
      sealedSenderDefault: true,
      ephemeralTtlDefault: 300,
    });
  });

  it("scopes meta rows by user and thread", () => {
    updateConversationMeta("alice", "dm", "bob", { requestState: "pending" });
    updateConversationMeta("alice", "group", "g1", { pinnedAt: 10 });
    updateConversationMeta("eve", "dm", "bob", { archivedAt: 99 });
    const rows = loadConversationMetas("alice");
    expect(rows).toHaveLength(2);
    expect(rows.some((row) => row.threadId === "bob" && row.requestState === "pending")).toBe(true);
    expect(rows.some((row) => row.threadId === "g1" && row.pinnedAt === 10)).toBe(true);
    expect(loadConversationMetas("eve")).toHaveLength(1);
  });
});

describe("profile display names", () => {
  it("stores and reads cached profile display names", () => {
    writeProfileDisplayName("alice", "bob", "Bob Builder");
    expect(readProfileDisplayName("alice", "bob")).toBe("Bob Builder");
  });

  it("removes blank display names", () => {
    writeProfileDisplayName("alice", "bob", "Bob");
    writeProfileDisplayName("alice", "bob", "   ");
    expect(readProfileDisplayName("alice", "bob")).toBeNull();
  });

  it("lists cached display names scoped by user", () => {
    writeProfileDisplayName("alice", "charlie", "Charlie");
    writeProfileDisplayName("alice", "bob", "Bob");
    writeProfileDisplayName("eve", "bob", "Mallory");
    const rows = loadProfileDisplayNames("alice");
    expect(rows.map((row) => row.targetUserId)).toEqual(["bob", "charlie"]);
  });
});

describe("identity pins", () => {
  const pin: IdentityPin = {
    fingerprintSha256: "abc123",
    identityKeyVersion: 1,
    identityX25519Pub: "x25519-pub",
    identitySigPub: "pubkey",
    identityPqSigPub: "pq-pubkey",
    observedAt: "2025-01-01T00:00:00Z",
  };

  it("readIdentityPin returns null when none exists", () => {
    expect(readIdentityPin("alice", "bob")).toBeNull();
  });

  it("writeIdentityPin / readIdentityPin round-trips", () => {
    writeIdentityPin("alice", "bob", pin);
    expect(readIdentityPin("alice", "bob")).toEqual(pin);
  });

  it("writeIdentityPin overwrites existing", () => {
    writeIdentityPin("alice", "bob", pin);
    const updated = { ...pin, identityKeyVersion: 2 };
    writeIdentityPin("alice", "bob", updated);
    expect(readIdentityPin("alice", "bob")?.identityKeyVersion).toBe(2);
  });

  it("listIdentityPins returns sorted by peerUserId", () => {
    writeIdentityPin("alice", "charlie", pin);
    writeIdentityPin("alice", "bob", pin);
    const list = listIdentityPins("alice");
    expect(list).toHaveLength(2);
    expect(list[0].peerUserId).toBe("bob");
    expect(list[1].peerUserId).toBe("charlie");
  });

  it("pins are scoped to userId", () => {
    writeIdentityPin("alice", "bob", pin);
    expect(readIdentityPin("eve", "bob")).toBeNull();
    expect(listIdentityPins("eve")).toHaveLength(0);
  });

  it("defaults missing PQ identity material for legacy pins", async () => {
    metadataCache.set(
      "pqmsg.web.pins.v1",
      JSON.stringify([
        {
          userId: "alice",
          peerUserId: "bob",
          fingerprintSha256: "legacy",
          identityKeyVersion: 1,
          identityX25519Pub: "x25519-pub",
          identitySigPub: "sig-pub",
          observedAt: "2025-01-01T00:00:00Z",
        },
      ])
    );
    await initMetadataStorage();
    expect(readIdentityPin("alice", "bob")?.identityPqSigPub).toBe("");
  });
});

describe("hasLocalKeys", () => {
  it("returns false when no keys", () => {
    expect(hasLocalKeys("alice")).toBe(false);
  });

  it("returns true when keys exist", async () => {
    await saveKeyRecord("alice", "sealed-data");
    await initMetadataStorage();
    expect(hasLocalKeys("alice")).toBe(true);
  });

  it("returns false for empty/whitespace userId", () => {
    expect(hasLocalKeys("")).toBe(false);
    expect(hasLocalKeys("  ")).toBe(false);
  });
});

describe("listLocalKeyUsers", () => {
  it("returns stored key owners in sorted order", async () => {
    await saveKeyRecord("charlie", "sealed-charlie");
    await saveKeyRecord("alice", "sealed-alice");
    await saveKeyRecord("bob", "sealed-bob");
    await initMetadataStorage();

    expect(listLocalKeyUsers()).toEqual(["alice", "bob", "charlie"]);
  });

  it("ignores unrelated local storage entries", async () => {
    await saveKeyRecord("alice", "sealed-alice");
    await initMetadataStorage();
    localStorageMock.setItem("something-else", "value");

    expect(listLocalKeyUsers()).toEqual(["alice"]);
  });
});

describe("direct message sessions", () => {
  it("stores sealed sessions in IndexedDB-backed cache", async () => {
    await saveDirectMessageSession("alice", "bob", "pass-1", "session-json");

    expect(sessionCache.size).toBe(1);
    expect(localStorageMock.getItem("pqmsg.web.dmsession.v1.alice:bob")).toBeNull();
    await expect(loadDirectMessageSession("alice", "bob", "pass-1")).resolves.toBe("session-json");
  });

  it("rejects legacy localStorage sessions instead of migrating them", async () => {
    const sealed = await sealJsonWithPassphrase("legacy-session", "pass-1");
    localStorageMock.setItem("pqmsg.web.dmsession.v1.alice:bob", sealed);

    await expect(loadDirectMessageSession("alice", "bob", "pass-1")).resolves.toBeNull();
    expect(sessionCache.has("alice:bob")).toBe(false);
    expect(localStorageMock.getItem("pqmsg.web.dmsession.v1.alice:bob")).toBe(sealed);
  });
});

describe("group conversations", () => {
  it("loadGroupConversations returns empty initially", () => {
    expect(loadGroupConversations("alice")).toEqual([]);
  });

  it("upsertGroupConversation creates and updates", () => {
    upsertGroupConversation("alice", "g1", "alice", "first msg", false);
    const groups = loadGroupConversations("alice");
    expect(groups).toHaveLength(1);
    expect(groups[0].groupId).toBe("g1");
    expect(groups[0].ownerUserId).toBe("alice");
    expect(groups[0].lastPreview).toBe("first msg");
    expect(groups[0].unreadCount).toBe(0);
  });

  it("upsertGroupConversation increments unread", () => {
    upsertGroupConversation("alice", "g1", "alice", "msg1", true);
    upsertGroupConversation("alice", "g1", "alice", "msg2", true);
    const groups = loadGroupConversations("alice");
    expect(groups[0].unreadCount).toBe(2);
  });

  it("markGroupConversationRead resets unread", () => {
    upsertGroupConversation("alice", "g1", "alice", "msg", true);
    markGroupConversationRead("alice", "g1");
    expect(loadGroupConversations("alice")[0].unreadCount).toBe(0);
  });

  it("group conversations are sorted by updatedAt desc", () => {
    upsertGroupConversation("alice", "g1", "alice", "old", false);
    const origNow = Date.now;
    Date.now = () => origNow() + 1000;
    try {
      upsertGroupConversation("alice", "g2", "alice", "new", false);
      const groups = loadGroupConversations("alice");
      expect(groups[0].groupId).toBe("g2");
    } finally {
      Date.now = origNow;
    }
  });
});

describe("wipeLocalState", () => {
  it("removes keys for the user", async () => {
    await saveKeyRecord("alice", "sealed-data");
    await initMetadataStorage();
    await wipeLocalState("alice");
    expect(hasLocalKeys("alice")).toBe(false);
  });

  it("removes conversations for the user", async () => {
    upsertConversation("alice", "bob", "hi", false);
    upsertConversation("eve", "bob", "yo", false);
    await wipeLocalState("alice");
    expect(loadConversations("alice")).toHaveLength(0);
    expect(loadConversations("eve")).toHaveLength(1);
  });

  it("removes group conversations for the user", async () => {
    upsertGroupConversation("alice", "g1", "alice", "msg", false);
    upsertGroupConversation("eve", "g2", "eve", "msg", false);
    await wipeLocalState("alice");
    expect(loadGroupConversations("alice")).toHaveLength(0);
    expect(loadGroupConversations("eve")).toHaveLength(1);
  });

  it("removes cursors for the user", async () => {
    writeCursor("alice", 42);
    writeCursor("alice", 10, "d1");
    writeCursor("eve", 99);
    await wipeLocalState("alice");
    expect(readCursor("alice")).toBe(0);
    expect(readCursor("alice", "d1")).toBe(0);
    expect(readCursor("eve")).toBe(99);
  });

  it("removes identity pins for the user", async () => {
    const pin: IdentityPin = {
      fingerprintSha256: "abc",
      identityKeyVersion: 1,
      identityX25519Pub: "x25519-pub",
      identitySigPub: "pub",
      observedAt: "now",
    };
    writeIdentityPin("alice", "bob", pin);
    writeIdentityPin("eve", "bob", pin);
    await wipeLocalState("alice");
    expect(listIdentityPins("alice")).toHaveLength(0);
    expect(listIdentityPins("eve")).toHaveLength(1);
  });

  it("does nothing for empty userId", async () => {
    upsertConversation("alice", "bob", "hi", false);
    await wipeLocalState("");
    await wipeLocalState("  ");
    expect(loadConversations("alice")).toHaveLength(1);
  });

  it("removes conversation meta and profile caches for the user", async () => {
    updateConversationMeta("alice", "dm", "bob", { pinnedAt: 1 });
    updateConversationMeta("eve", "dm", "bob", { pinnedAt: 2 });
    writeProfileDisplayName("alice", "bob", "Bob");
    writeProfileDisplayName("eve", "bob", "Bob");
    await wipeLocalState("alice");
    expect(loadConversationMetas("alice")).toHaveLength(0);
    expect(loadConversationMetas("eve")).toHaveLength(1);
    expect(loadProfileDisplayNames("alice")).toHaveLength(0);
    expect(loadProfileDisplayNames("eve")).toHaveLength(1);
  });

  it("removes session cache for the user", async () => {
    await saveDirectMessageSession("alice", "bob", "pass-1", "session-json");
    await saveDirectMessageSession("eve", "bob", "pass-2", "session-json-2");

    await wipeLocalState("alice");

    await expect(loadDirectMessageSession("alice", "bob", "pass-1")).resolves.toBeNull();
    await expect(loadDirectMessageSession("eve", "bob", "pass-2")).resolves.toBe("session-json-2");
  });
});
