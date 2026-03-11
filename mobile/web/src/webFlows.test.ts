import { describe, expect, it, vi } from "vitest";
import type { GeneratedKeys } from "./crypto";
import type { SetupConfig } from "./storage";
import type { OutboxMessage } from "./db";
import {
  drainSupportedOutbox,
  normalizeBrowserUserId,
  parseDirectChatTarget,
  startDirectConversationFlow,
  unlockBrowserAccount,
} from "./webFlows";

const BASE_SETUP: SetupConfig = {
  serverUrl: "http://127.0.0.1:3000",
  userId: "",
  deviceId: "",
  suiteLabel: "ml-kem-768",
  peerUserId: "bob",
  displayName: "",
};

const GENERATED_KEYS: GeneratedKeys = {
  userId: "test1",
  deviceId: "test1-web",
  suite: "ml-kem-768",
  identityX25519Pub: "ix-pub",
  identityX25519Secret: "ix-sec",
  identitySigPub: "sig-pub",
  identitySigSecret: "sig-sec",
  signedPrekeyX25519Pub: "spk-pub",
  signedPrekeyX25519Secret: "spk-sec",
  pqSignedPrekeyPubMlkem768: "pqspk-pub",
  pqSignedPrekeySecretMlkem768: "pqspk-sec",
  oneTimePrekeysX25519: [],
  oneTimePrekeysX25519Secret: [],
  oneTimePrekeysMlkem768: [],
  oneTimePrekeysMlkem768Secret: [],
};

describe("normalizeBrowserUserId", () => {
  it("trims, strips @, and lowercases", () => {
    expect(normalizeBrowserUserId("  @Test1  ")).toBe("test1");
  });
});

describe("parseDirectChatTarget", () => {
  it("extracts invite usernames from URLs", () => {
    expect(parseDirectChatTarget("https://app.test/?invite=test2")).toBe("test2");
  });

  it("returns the raw value for direct usernames", () => {
    expect(parseDirectChatTarget("@carol")).toBe("@carol");
  });
});

describe("unlockBrowserAccount", () => {
  it("unlocks a browser-local account and bootstraps identity data", async () => {
    const saveSetup = vi.fn();
    const setPassphrase = vi.fn();
    const bootstrapIdentityData = vi.fn(async () => {});

    const result = await unlockBrowserAccount(
      {
        inputUserId: "  @Test1  ",
        passphrase: "secret-pass",
        currentSetup: BASE_SETUP,
      },
      {
        ensureRuntime: async () => {},
        hasLocalKeys: () => true,
        loadKeys: async () => GENERATED_KEYS,
        saveSetup,
        setPassphrase,
        bootstrapIdentityData,
      }
    );

    expect(result.keys).toBe(GENERATED_KEYS);
    expect(result.setup).toEqual({
      ...BASE_SETUP,
      userId: "test1",
      deviceId: "test1-web",
      suiteLabel: "ml-kem-768",
      peerUserId: "",
      displayName: "test1",
    });
    expect(saveSetup).toHaveBeenCalledWith(result.setup);
    expect(setPassphrase).toHaveBeenCalledWith("secret-pass");
    expect(bootstrapIdentityData).toHaveBeenCalledOnce();
  });

  it("fails when the account does not exist in local browser storage", async () => {
    await expect(
      unlockBrowserAccount(
        {
          inputUserId: "missing-user",
          passphrase: "secret-pass",
          currentSetup: BASE_SETUP,
        },
        {
          ensureRuntime: async () => {},
          hasLocalKeys: () => false,
          loadKeys: async () => GENERATED_KEYS,
          saveSetup: () => {},
          setPassphrase: () => {},
          bootstrapIdentityData: async () => {},
        }
      )
    ).rejects.toThrow("No keys found for this User ID on this device");
  });
});

describe("startDirectConversationFlow", () => {
  it("validates and prepares a new direct conversation", async () => {
    const ensureDirectChatPeerExists = vi.fn(async () => {});
    const addContactSilent = vi.fn(async () => {});
    const markConversationAccepted = vi.fn();
    const setConversationArchived = vi.fn();
    const upsertConversation = vi.fn();
    const markConversationRead = vi.fn();

    const peerId = await startDirectConversationFlow(
      {
        rawTarget: "https://app.test/?invite=test2",
        currentUserId: "test1",
      },
      {
        ensureDirectChatPeerExists,
        addContactSilent,
        markConversationAccepted,
        setConversationArchived,
        upsertConversation,
        markConversationRead,
      }
    );

    expect(peerId).toBe("test2");
    expect(ensureDirectChatPeerExists).toHaveBeenCalledWith("test2");
    expect(addContactSilent).toHaveBeenCalledWith("test2");
    expect(markConversationAccepted).toHaveBeenCalledWith("test2");
    expect(setConversationArchived).toHaveBeenCalledWith("dm", "test2", false);
    expect(upsertConversation).toHaveBeenCalledWith("test1", "test2", "New conversation", false);
    expect(markConversationRead).toHaveBeenCalledWith("test1", "test2");
  });

  it("rejects attempts to start a self-chat", async () => {
    await expect(
      startDirectConversationFlow(
        {
          rawTarget: "@test1",
          currentUserId: "test1",
        },
        {
          ensureDirectChatPeerExists: async () => {},
          addContactSilent: async () => {},
          markConversationAccepted: () => {},
          setConversationArchived: () => {},
          upsertConversation: () => {},
          markConversationRead: () => {},
        }
      )
    ).rejects.toThrow("You can't chat with yourself");
  });
});

describe("drainSupportedOutbox", () => {
  const queued: OutboxMessage[] = [
    {
      id: "dm-1",
      userId: "test1",
      peerId: "test2",
      text: "hello",
      timestamp: 1,
      sealed: false,
      ephemeralTtl: 0,
    },
    {
      id: "group-1",
      userId: "test1",
      peerId: "unused",
      groupId: "group-a",
      text: "should fail",
      timestamp: 2,
      sealed: false,
      ephemeralTtl: 0,
    },
    {
      id: "sealed-1",
      userId: "test1",
      peerId: "test3",
      text: "secret",
      timestamp: 3,
      sealed: true,
      ephemeralTtl: 0,
    },
  ];

  it("fails closed when direct web messaging is unavailable", async () => {
    const removed: string[] = [];
    const failed: string[] = [];

    const summary = await drainSupportedOutbox(
      { keys: GENERATED_KEYS },
      {
        isDirectMessagingAllowed: async () => false,
        listOutboxMessages: async () => queued,
        removeOutboxMessage: async (id) => {
          removed.push(id);
        },
        markMessageFailed: async (id) => {
          failed.push(id);
        },
        markMessageSent: async () => {},
        encryptDirectPayload: async () => "cipher",
        sealedRelay: async () => {},
        relayEphemeral: async () => {},
        relay: async () => {},
        buildEphemeralRelayAuthHeaders: () => ({}),
        buildRelayAuthHeaders: () => ({}),
      }
    );

    expect(summary).toEqual({
      sentIds: [],
      failedIds: ["dm-1", "group-1", "sealed-1"],
      retainedIds: [],
    });
    expect(removed).toEqual(["dm-1", "group-1", "sealed-1"]);
    expect(failed).toEqual(["dm-1", "group-1", "sealed-1"]);
  });

  it("sends supported direct items, fails group items, and retains transient failures", async () => {
    const removed: string[] = [];
    const failed: string[] = [];
    const sent: string[] = [];
    const relayed: string[] = [];
    const sealed: string[] = [];

    const summary = await drainSupportedOutbox(
      { keys: GENERATED_KEYS },
      {
        isDirectMessagingAllowed: async () => true,
        listOutboxMessages: async () => queued,
        removeOutboxMessage: async (id) => {
          removed.push(id);
        },
        markMessageFailed: async (id) => {
          failed.push(id);
        },
        markMessageSent: async (id) => {
          sent.push(id);
        },
        encryptDirectPayload: async (_keys, peerId) => `cipher-for-${peerId}`,
        sealedRelay: async (peerId) => {
          sealed.push(peerId);
          throw new Error("temporary failure");
        },
        relayEphemeral: async () => {},
        relay: async (peerId) => {
          relayed.push(peerId);
        },
        buildEphemeralRelayAuthHeaders: () => ({}),
        buildRelayAuthHeaders: () => ({}),
      }
    );

    expect(summary).toEqual({
      sentIds: ["dm-1"],
      failedIds: ["group-1"],
      retainedIds: ["sealed-1"],
    });
    expect(relayed).toEqual(["test2"]);
    expect(sealed).toEqual(["test3"]);
    expect(removed).toEqual(["dm-1", "group-1"]);
    expect(sent).toEqual(["dm-1"]);
    expect(failed).toEqual(["group-1"]);
  });
});
