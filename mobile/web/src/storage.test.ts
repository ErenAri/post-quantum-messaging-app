import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  loadSetup,
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
  hasLocalKeys,
  loadGroupConversations,
  upsertGroupConversation,
  markGroupConversationRead,
  wipeLocalState,
  type SetupConfig,
  type IdentityPin,
} from "./storage";

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

beforeEach(() => {
  localStorageMock.clear();
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
      passphrase: "secret",
    };
    saveSetup(config);
    expect(loadSetup()).toEqual(config);
  });

  it("falls back to defaults for missing fields", () => {
    localStorageMock.setItem("pqmsg.web.setup.v1", JSON.stringify({ serverUrl: "http://test" }));
    const setup = loadSetup();
    expect(setup.serverUrl).toBe("http://test");
    expect(setup.suiteLabel).toBe(DEFAULT_SETUP.suiteLabel);
  });

  it("returns defaults on corrupt JSON", () => {
    localStorageMock.setItem("pqmsg.web.setup.v1", "not-json{{{");
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

describe("identity pins", () => {
  const pin: IdentityPin = {
    fingerprintSha256: "abc123",
    identityKeyVersion: 1,
    identitySigPub: "pubkey",
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
});

describe("hasLocalKeys", () => {
  it("returns false when no keys", () => {
    expect(hasLocalKeys("alice")).toBe(false);
  });

  it("returns true when keys exist", () => {
    localStorageMock.setItem("pqmsg.web.keys.v1.alice", "sealed-data");
    expect(hasLocalKeys("alice")).toBe(true);
  });

  it("returns false for empty/whitespace userId", () => {
    expect(hasLocalKeys("")).toBe(false);
    expect(hasLocalKeys("  ")).toBe(false);
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
  it("removes keys for the user", () => {
    localStorageMock.setItem("pqmsg.web.keys.v1.alice", "sealed-data");
    wipeLocalState("alice");
    expect(hasLocalKeys("alice")).toBe(false);
  });

  it("removes conversations for the user", () => {
    upsertConversation("alice", "bob", "hi", false);
    upsertConversation("eve", "bob", "yo", false);
    wipeLocalState("alice");
    expect(loadConversations("alice")).toHaveLength(0);
    expect(loadConversations("eve")).toHaveLength(1);
  });

  it("removes group conversations for the user", () => {
    upsertGroupConversation("alice", "g1", "alice", "msg", false);
    upsertGroupConversation("eve", "g2", "eve", "msg", false);
    wipeLocalState("alice");
    expect(loadGroupConversations("alice")).toHaveLength(0);
    expect(loadGroupConversations("eve")).toHaveLength(1);
  });

  it("removes cursors for the user", () => {
    writeCursor("alice", 42);
    writeCursor("alice", 10, "d1");
    writeCursor("eve", 99);
    wipeLocalState("alice");
    expect(readCursor("alice")).toBe(0);
    expect(readCursor("alice", "d1")).toBe(0);
    expect(readCursor("eve")).toBe(99);
  });

  it("removes identity pins for the user", () => {
    const pin: IdentityPin = {
      fingerprintSha256: "abc",
      identityKeyVersion: 1,
      identitySigPub: "pub",
      observedAt: "now",
    };
    writeIdentityPin("alice", "bob", pin);
    writeIdentityPin("eve", "bob", pin);
    wipeLocalState("alice");
    expect(listIdentityPins("alice")).toHaveLength(0);
    expect(listIdentityPins("eve")).toHaveLength(1);
  });

  it("does nothing for empty userId", () => {
    upsertConversation("alice", "bob", "hi", false);
    wipeLocalState("");
    wipeLocalState("  ");
    expect(loadConversations("alice")).toHaveLength(1);
  });
});
