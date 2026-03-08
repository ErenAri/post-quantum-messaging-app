import { GeneratedKeys, openJsonWithPassphrase, sealJsonWithPassphrase } from "./crypto";

export type SetupConfig = {
  serverUrl: string;
  userId: string;
  deviceId: string;
  suiteLabel: "ml-kem-768" | "kyber768";
  peerUserId: string;
  displayName: string;
  passphrase: string;
};

export type ConversationSummary = {
  peerUserId: string;
  lastPreview: string;
  unreadCount: number;
  updatedAt: number;
};

export type GroupConversationSummary = {
  groupId: string;
  ownerUserId: string;
  lastPreview: string;
  unreadCount: number;
  updatedAt: number;
};

export type ConversationKind = "dm" | "group";

export type ConversationRequestState = "accepted" | "pending" | "dismissed";

export type ConversationMeta = {
  kind: ConversationKind;
  threadId: string;
  requestState: ConversationRequestState;
  pinnedAt: number | null;
  archivedAt: number | null;
  sealedSenderDefault: boolean;
  ephemeralTtlDefault: number;
};

export type ProfileDisplayName = {
  targetUserId: string;
  displayName: string;
  updatedAt: number;
};

export type IdentityPin = {
  fingerprintSha256: string;
  identityKeyVersion: number;
  identitySigPub: string;
  observedAt: string;
};

const SETUP_KEY = "pqmsg.web.setup.v1";
const CONVERSATIONS_KEY = "pqmsg.web.conversations.v1";
const GROUP_CONVOS_KEY = "pqmsg.web.groupconvos.v1";
const CONVERSATION_META_KEY = "pqmsg.web.conversationmeta.v1";
const PROFILE_CACHE_KEY = "pqmsg.web.profilecache.v1";
const PINS_KEY = "pqmsg.web.pins.v1";
const CURSORS_KEY = "pqmsg.web.cursors.v1";
const KEYS_PREFIX = "pqmsg.web.keys.v1.";

export const DEFAULT_SETUP: SetupConfig = {
  serverUrl: "http://127.0.0.1:3000",
  userId: "",
  deviceId: "",
  suiteLabel: "ml-kem-768",
  peerUserId: "bob",
  displayName: "",
  passphrase: ""
};

export function loadSetup(): SetupConfig {
  const raw = localStorage.getItem(SETUP_KEY);
  if (!raw) {
    return DEFAULT_SETUP;
  }
  try {
    const parsed = JSON.parse(raw) as SetupConfig;
    return {
      serverUrl: parsed.serverUrl || DEFAULT_SETUP.serverUrl,
      userId: parsed.userId || DEFAULT_SETUP.userId,
      deviceId: parsed.deviceId || DEFAULT_SETUP.deviceId,
      suiteLabel: parsed.suiteLabel || DEFAULT_SETUP.suiteLabel,
      peerUserId: parsed.peerUserId || DEFAULT_SETUP.peerUserId,
      displayName: parsed.displayName || DEFAULT_SETUP.displayName,
      passphrase: parsed.passphrase || DEFAULT_SETUP.passphrase
    };
  } catch {
    return DEFAULT_SETUP;
  }
}

export function saveSetup(setup: SetupConfig): void {
  localStorage.setItem(SETUP_KEY, JSON.stringify(setup));
}

export async function saveKeys(
  userId: string,
  passphrase: string,
  keys: GeneratedKeys
): Promise<void> {
  const sealed = await sealJsonWithPassphrase(keys, passphrase);
  localStorage.setItem(`${KEYS_PREFIX}${userId}`, sealed);
}

export async function loadKeys(
  userId: string,
  passphrase: string
): Promise<GeneratedKeys> {
  const sealed = localStorage.getItem(`${KEYS_PREFIX}${userId}`);
  if (!sealed) {
    throw new Error(`missing keys for user '${userId}'`);
  }
  return openJsonWithPassphrase<GeneratedKeys>(sealed, passphrase);
}

export function hasLocalKeys(userId: string): boolean {
  const normalized = userId.trim();
  if (!normalized) {
    return false;
  }
  return localStorage.getItem(`${KEYS_PREFIX}${normalized}`) !== null;
}

type ConversationRow = ConversationSummary & { userId: string };
type ConversationMetaRow = ConversationMeta & { userId: string };
type ProfileDisplayNameRow = ProfileDisplayName & { userId: string };

export function loadConversations(userId: string): ConversationSummary[] {
  const all = parseRecord<ConversationRow[]>(CONVERSATIONS_KEY, []);
  const list = all
    .filter((item) => item.peerUserId && item.userId === userId)
    .map((item) => ({
      peerUserId: item.peerUserId,
      lastPreview: item.lastPreview,
      unreadCount: item.unreadCount,
      updatedAt: item.updatedAt
    }));
  return list.sort((lhs, rhs) => rhs.updatedAt - lhs.updatedAt);
}

export function upsertConversation(
  userId: string,
  peerUserId: string,
  preview: string,
  incrementUnread: boolean
): void {
  const all = parseRecord<ConversationRow[]>(CONVERSATIONS_KEY, []);
  const now = Date.now();
  const normalizedPreview = preview.trim().slice(0, 160) || "No content";
  const idx = all.findIndex((item) => item.userId === userId && item.peerUserId === peerUserId);
  if (idx >= 0) {
    const current = all[idx];
    current.lastPreview = normalizedPreview;
    current.updatedAt = now;
    if (incrementUnread) {
      current.unreadCount += 1;
    }
  } else {
    all.push({
      userId,
      peerUserId,
      lastPreview: normalizedPreview,
      unreadCount: incrementUnread ? 1 : 0,
      updatedAt: now
    });
  }
  localStorage.setItem(CONVERSATIONS_KEY, JSON.stringify(all));
}

export function markConversationRead(userId: string, peerUserId: string): void {
  const all = parseRecord<ConversationRow[]>(CONVERSATIONS_KEY, []);
  const idx = all.findIndex((item) => item.userId === userId && item.peerUserId === peerUserId);
  if (idx >= 0) {
    all[idx].unreadCount = 0;
    localStorage.setItem(CONVERSATIONS_KEY, JSON.stringify(all));
  }
}

export function loadConversationMeta(
  userId: string,
  kind: ConversationKind,
  threadId: string
): ConversationMeta {
  const all = parseRecord<ConversationMetaRow[]>(CONVERSATION_META_KEY, []);
  const found = all.find(
    (item) => item.userId === userId && item.kind === kind && item.threadId === threadId
  );
  return found
    ? {
        kind: found.kind,
        threadId: found.threadId,
        requestState: found.requestState,
        pinnedAt: found.pinnedAt,
        archivedAt: found.archivedAt,
        sealedSenderDefault: found.sealedSenderDefault,
        ephemeralTtlDefault: found.ephemeralTtlDefault,
      }
    : defaultConversationMeta(kind, threadId);
}

export function loadConversationMetas(userId: string): ConversationMeta[] {
  return parseRecord<ConversationMetaRow[]>(CONVERSATION_META_KEY, [])
    .filter((item) => item.userId === userId)
    .map((item) => ({
      kind: item.kind,
      threadId: item.threadId,
      requestState: item.requestState,
      pinnedAt: item.pinnedAt,
      archivedAt: item.archivedAt,
      sealedSenderDefault: item.sealedSenderDefault,
      ephemeralTtlDefault: item.ephemeralTtlDefault,
    }))
    .sort((lhs, rhs) => {
      const lhsPinned = lhs.pinnedAt ?? 0;
      const rhsPinned = rhs.pinnedAt ?? 0;
      if (lhsPinned !== rhsPinned) {
        return rhsPinned - lhsPinned;
      }
      return lhs.threadId.localeCompare(rhs.threadId);
    });
}

export function updateConversationMeta(
  userId: string,
  kind: ConversationKind,
  threadId: string,
  patch: Partial<Omit<ConversationMeta, "kind" | "threadId">>
): ConversationMeta {
  const all = parseRecord<ConversationMetaRow[]>(CONVERSATION_META_KEY, []);
  const idx = all.findIndex(
    (item) => item.userId === userId && item.kind === kind && item.threadId === threadId
  );
  const current = idx >= 0
    ? all[idx]
    : { userId, ...defaultConversationMeta(kind, threadId) };
  const next: ConversationMetaRow = {
    ...current,
    ...patch,
    userId,
    kind,
    threadId,
  };
  if (idx >= 0) {
    all[idx] = next;
  } else {
    all.push(next);
  }
  writeRecord(CONVERSATION_META_KEY, all);
  return {
    kind: next.kind,
    threadId: next.threadId,
    requestState: next.requestState,
    pinnedAt: next.pinnedAt,
    archivedAt: next.archivedAt,
    sealedSenderDefault: next.sealedSenderDefault,
    ephemeralTtlDefault: next.ephemeralTtlDefault,
  };
}

export function readProfileDisplayName(userId: string, targetUserId: string): string | null {
  const all = parseRecord<ProfileDisplayNameRow[]>(PROFILE_CACHE_KEY, []);
  const found = all.find((item) => item.userId === userId && item.targetUserId === targetUserId);
  return found?.displayName ?? null;
}

export function writeProfileDisplayName(
  userId: string,
  targetUserId: string,
  displayName: string
): void {
  const all = parseRecord<ProfileDisplayNameRow[]>(PROFILE_CACHE_KEY, []);
  const idx = all.findIndex((item) => item.userId === userId && item.targetUserId === targetUserId);
  const normalizedDisplayName = displayName.trim();
  if (!normalizedDisplayName) {
    if (idx >= 0) {
      all.splice(idx, 1);
      writeRecord(PROFILE_CACHE_KEY, all);
    }
    return;
  }
  const row: ProfileDisplayNameRow = {
    userId,
    targetUserId,
    displayName: normalizedDisplayName,
    updatedAt: Date.now(),
  };
  if (idx >= 0) {
    all[idx] = row;
  } else {
    all.push(row);
  }
  writeRecord(PROFILE_CACHE_KEY, all);
}

export function loadProfileDisplayNames(userId: string): ProfileDisplayName[] {
  return parseRecord<ProfileDisplayNameRow[]>(PROFILE_CACHE_KEY, [])
    .filter((item) => item.userId === userId)
    .map((item) => ({
      targetUserId: item.targetUserId,
      displayName: item.displayName,
      updatedAt: item.updatedAt,
    }))
    .sort((lhs, rhs) => lhs.targetUserId.localeCompare(rhs.targetUserId));
}

export function readCursor(userId: string, deviceId?: string): number {
  const cursors = parseRecord<Record<string, number>>(CURSORS_KEY, {});
  const key = deviceId ? `${userId}:${deviceId}` : userId;
  return Number(cursors[key] ?? 0);
}

export function writeCursor(userId: string, cursor: number, deviceId?: string): void {
  const cursors = parseRecord<Record<string, number>>(CURSORS_KEY, {});
  const key = deviceId ? `${userId}:${deviceId}` : userId;
  cursors[key] = cursor;
  localStorage.setItem(CURSORS_KEY, JSON.stringify(cursors));
}

type PinRow = IdentityPin & { userId: string; peerUserId: string };

export function readIdentityPin(userId: string, peerUserId: string): IdentityPin | null {
  const pins = parseRecord<PinRow[]>(PINS_KEY, []);
  const found = pins.find((item) => item.userId === userId && item.peerUserId === peerUserId);
  if (!found) {
    return null;
  }
  return {
    fingerprintSha256: found.fingerprintSha256,
    identityKeyVersion: found.identityKeyVersion,
    identitySigPub: found.identitySigPub,
    observedAt: found.observedAt
  };
}

export function writeIdentityPin(userId: string, peerUserId: string, pin: IdentityPin): void {
  const pins = parseRecord<PinRow[]>(PINS_KEY, []);
  const idx = pins.findIndex((item) => item.userId === userId && item.peerUserId === peerUserId);
  const row: PinRow = { userId, peerUserId, ...pin };
  if (idx >= 0) {
    pins[idx] = row;
  } else {
    pins.push(row);
  }
  localStorage.setItem(PINS_KEY, JSON.stringify(pins));
}

export function listIdentityPins(userId: string): Array<{ peerUserId: string; pin: IdentityPin }> {
  const pins = parseRecord<PinRow[]>(PINS_KEY, []);
  return pins
    .filter((item) => item.userId === userId)
    .map((item) => ({
      peerUserId: item.peerUserId,
      pin: {
        fingerprintSha256: item.fingerprintSha256,
        identityKeyVersion: item.identityKeyVersion,
        identitySigPub: item.identitySigPub,
        observedAt: item.observedAt
      }
    }))
    .sort((lhs, rhs) => lhs.peerUserId.localeCompare(rhs.peerUserId));
}

// --- Group conversations ---

type GroupConvoRow = GroupConversationSummary & { userId: string };

export function loadGroupConversations(userId: string): GroupConversationSummary[] {
  const all = parseRecord<GroupConvoRow[]>(GROUP_CONVOS_KEY, []);
  return all
    .filter(item => item.userId === userId)
    .map(item => ({
      groupId: item.groupId,
      ownerUserId: item.ownerUserId,
      lastPreview: item.lastPreview,
      unreadCount: item.unreadCount,
      updatedAt: item.updatedAt,
    }))
    .sort((a, b) => b.updatedAt - a.updatedAt);
}

export function upsertGroupConversation(
  userId: string,
  groupId: string,
  ownerUserId: string,
  preview: string,
  incrementUnread: boolean
): void {
  const all = parseRecord<GroupConvoRow[]>(GROUP_CONVOS_KEY, []);
  const now = Date.now();
  const normalizedPreview = preview.trim().slice(0, 160) || "No content";
  const idx = all.findIndex(item => item.userId === userId && item.groupId === groupId);
  if (idx >= 0) {
    all[idx].lastPreview = normalizedPreview;
    all[idx].updatedAt = now;
    if (incrementUnread) all[idx].unreadCount += 1;
  } else {
    all.push({ userId, groupId, ownerUserId, lastPreview: normalizedPreview, unreadCount: incrementUnread ? 1 : 0, updatedAt: now });
  }
  localStorage.setItem(GROUP_CONVOS_KEY, JSON.stringify(all));
}

export function markGroupConversationRead(userId: string, groupId: string): void {
  const all = parseRecord<GroupConvoRow[]>(GROUP_CONVOS_KEY, []);
  const idx = all.findIndex(item => item.userId === userId && item.groupId === groupId);
  if (idx >= 0) {
    all[idx].unreadCount = 0;
    localStorage.setItem(GROUP_CONVOS_KEY, JSON.stringify(all));
  }
}

export function wipeLocalState(userId: string): void {
  const normalizedUser = userId.trim();
  if (!normalizedUser) {
    return;
  }

  localStorage.removeItem(`${KEYS_PREFIX}${normalizedUser}`);

  const conversations = parseRecord<ConversationRow[]>(CONVERSATIONS_KEY, []).filter(
    (item) => item.userId !== normalizedUser
  );
  writeRecord(CONVERSATIONS_KEY, conversations);

  const groupConvos = parseRecord<GroupConvoRow[]>(GROUP_CONVOS_KEY, []).filter(
    (item) => item.userId !== normalizedUser
  );
  writeRecord(GROUP_CONVOS_KEY, groupConvos);

  const conversationMeta = parseRecord<ConversationMetaRow[]>(CONVERSATION_META_KEY, []).filter(
    (item) => item.userId !== normalizedUser
  );
  writeRecord(CONVERSATION_META_KEY, conversationMeta);

  const profileCache = parseRecord<ProfileDisplayNameRow[]>(PROFILE_CACHE_KEY, []).filter(
    (item) => item.userId !== normalizedUser
  );
  writeRecord(PROFILE_CACHE_KEY, profileCache);

  const pins = parseRecord<PinRow[]>(PINS_KEY, []).filter((item) => item.userId !== normalizedUser);
  writeRecord(PINS_KEY, pins);

  const cursors = parseRecord<Record<string, number>>(CURSORS_KEY, {});
  for (const cursorKey of Object.keys(cursors)) {
    if (cursorKey === normalizedUser || cursorKey.startsWith(`${normalizedUser}:`)) {
      delete cursors[cursorKey];
    }
  }
  writeRecord(CURSORS_KEY, cursors);
}

function parseRecord<T>(key: string, fallback: T): T {
  const raw = localStorage.getItem(key);
  if (!raw) {
    return fallback;
  }
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function writeRecord<T>(key: string, value: T): void {
  if (Array.isArray(value) && value.length === 0) {
    localStorage.removeItem(key);
    return;
  }
  if (typeof value === "object" && value !== null && !Array.isArray(value) && Object.keys(value).length === 0) {
    localStorage.removeItem(key);
    return;
  }
  localStorage.setItem(key, JSON.stringify(value));
}

function defaultConversationMeta(kind: ConversationKind, threadId: string): ConversationMeta {
  return {
    kind,
    threadId,
    requestState: "accepted",
    pinnedAt: null,
    archivedAt: null,
    sealedSenderDefault: false,
    ephemeralTtlDefault: 0,
  };
}
