import type { OutboxMessage } from "./db";
import type { GeneratedKeys } from "./crypto";
import type { ConversationKind, SetupConfig } from "./storage";

export function normalizeBrowserUserId(rawValue: string): string {
  return rawValue.trim().replace(/^@/, "").toLowerCase();
}

export function parseDirectChatTarget(rawValue: string): string {
  const trimmed = rawValue.trim();
  if (!trimmed) {
    return "";
  }
  try {
    const parsed = new URL(trimmed);
    const invite = parsed.searchParams.get("invite")?.trim();
    if (invite) {
      return invite;
    }
  } catch {
    // Not a URL, treat as a direct user ID.
  }
  return trimmed;
}

export type UnlockBrowserAccountDeps = {
  ensureRuntime: () => Promise<void>;
  hasLocalKeys: (userId: string) => boolean;
  loadKeys: (userId: string, passphrase: string) => Promise<GeneratedKeys>;
  saveSetup: (setup: SetupConfig) => void;
  setPassphrase: (passphrase: string) => void;
  bootstrapIdentityData: () => Promise<void>;
};

export async function unlockBrowserAccount(
  params: {
    inputUserId: string;
    passphrase: string;
    currentSetup: SetupConfig;
  },
  deps: UnlockBrowserAccountDeps
): Promise<{ setup: SetupConfig; keys: GeneratedKeys }> {
  const userId = normalizeBrowserUserId(params.inputUserId);
  if (!userId) {
    throw new Error("User ID is required");
  }
  if (!params.passphrase) {
    throw new Error("Password is required");
  }

  await deps.ensureRuntime();
  if (!deps.hasLocalKeys(userId)) {
    throw new Error("No keys found for this User ID on this device");
  }

  const loadedKeys = await deps.loadKeys(userId, params.passphrase);
  const nextSetup: SetupConfig = {
    serverUrl: params.currentSetup.serverUrl,
    userId,
    deviceId: loadedKeys.deviceId,
    suiteLabel: loadedKeys.suite,
    peerUserId: "",
    displayName: userId,
  };
  deps.saveSetup(nextSetup);
  deps.setPassphrase(params.passphrase);
  await deps.bootstrapIdentityData();
  return {
    setup: nextSetup,
    keys: loadedKeys,
  };
}

export type StartDirectConversationDeps = {
  ensureDirectChatPeerExists: (peerId: string) => Promise<void>;
  addContactSilent: (peerId: string) => Promise<void>;
  markConversationAccepted: (peerId: string) => void;
  setConversationArchived: (
    kind: ConversationKind,
    threadId: string,
    archived: boolean
  ) => void;
  upsertConversation: (
    userId: string,
    peerId: string,
    preview: string,
    incrementUnread: boolean
  ) => void;
  markConversationRead: (userId: string, peerId: string) => void;
};

export async function startDirectConversationFlow(
  params: {
    rawTarget: string;
    currentUserId: string;
  },
  deps: StartDirectConversationDeps
): Promise<string> {
  const resolvedPeer = parseDirectChatTarget(params.rawTarget).replace(/^@/, "");
  if (!resolvedPeer) {
    throw new Error("User ID is required");
  }
  if (resolvedPeer === params.currentUserId) {
    throw new Error("You can't chat with yourself");
  }

  await deps.ensureDirectChatPeerExists(resolvedPeer);
  await deps.addContactSilent(resolvedPeer);
  deps.markConversationAccepted(resolvedPeer);
  deps.setConversationArchived("dm", resolvedPeer, false);
  deps.upsertConversation(params.currentUserId, resolvedPeer, "New conversation", false);
  deps.markConversationRead(params.currentUserId, resolvedPeer);
  return resolvedPeer;
}

type DirectRelayRequest = {
  sender_user_id: string;
  device_id: string;
  message_bytes_base64: string;
};

type EphemeralRelayRequest = DirectRelayRequest & {
  ttl_seconds: number;
};

export type DrainOutboxDeps = {
  isDirectMessagingAllowed: () => Promise<boolean>;
  listOutboxMessages: (userId: string) => Promise<OutboxMessage[]>;
  removeOutboxMessage: (id: string) => Promise<void>;
  markMessageFailed: (id: string) => Promise<void>;
  markMessageSent: (id: string) => Promise<void>;
  encryptDirectPayload: (
    keys: GeneratedKeys,
    peerId: string,
    plaintext: string
  ) => Promise<string>;
  sealedRelay: (peerId: string, request: { message_bytes_base64: string }) => Promise<void>;
  relayEphemeral: (
    peerId: string,
    request: EphemeralRelayRequest,
    headers: unknown
  ) => Promise<void>;
  relay: (peerId: string, request: DirectRelayRequest, headers: unknown) => Promise<void>;
  buildEphemeralRelayAuthHeaders: (
    keys: GeneratedKeys,
    peerId: string,
    ttlSeconds: number
  ) => unknown;
  buildRelayAuthHeaders: (
    keys: GeneratedKeys,
    peerId: string,
    messageBytesBase64: string
  ) => unknown;
};

export type DrainOutboxSummary = {
  sentIds: string[];
  failedIds: string[];
  retainedIds: string[];
};

export async function drainSupportedOutbox(
  params: {
    keys: GeneratedKeys;
  },
  deps: DrainOutboxDeps
): Promise<DrainOutboxSummary> {
  const summary: DrainOutboxSummary = {
    sentIds: [],
    failedIds: [],
    retainedIds: [],
  };
  const queued = await deps.listOutboxMessages(params.keys.userId);
  if (!(await deps.isDirectMessagingAllowed())) {
    for (const item of queued) {
      await deps.removeOutboxMessage(item.id);
      await deps.markMessageFailed(item.id);
      summary.failedIds.push(item.id);
    }
    return summary;
  }

  for (const item of queued) {
    try {
      if (item.groupId) {
        await deps.removeOutboxMessage(item.id);
        await deps.markMessageFailed(item.id);
        summary.failedIds.push(item.id);
        continue;
      }

      const messageBytesBase64 = await deps.encryptDirectPayload(
        params.keys,
        item.peerId,
        item.text
      );
      if (item.sealed) {
        await deps.sealedRelay(item.peerId, {
          sender_user_id: params.keys.userId,
          device_id: params.keys.deviceId,
          message_bytes_base64: messageBytesBase64,
        });
      } else if (item.ephemeralTtl > 0) {
        await deps.relayEphemeral(
          item.peerId,
          {
            sender_user_id: params.keys.userId,
            device_id: params.keys.deviceId,
            message_bytes_base64: messageBytesBase64,
            ttl_seconds: item.ephemeralTtl,
          },
          deps.buildEphemeralRelayAuthHeaders(
            params.keys,
            item.peerId,
            item.ephemeralTtl
          )
        );
      } else {
        await deps.relay(
          item.peerId,
          {
            sender_user_id: params.keys.userId,
            device_id: params.keys.deviceId,
            message_bytes_base64: messageBytesBase64,
          },
          deps.buildRelayAuthHeaders(params.keys, item.peerId, messageBytesBase64)
        );
      }
      await deps.removeOutboxMessage(item.id);
      await deps.markMessageSent(item.id);
      summary.sentIds.push(item.id);
    } catch {
      summary.retainedIds.push(item.id);
    }
  }

  return summary;
}
