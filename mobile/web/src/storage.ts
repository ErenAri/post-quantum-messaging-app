import { GeneratedKeys, openJsonWithPassphrase, sealJsonWithPassphrase } from "./crypto";

export type SetupConfig = {
  serverUrl: string;
  userId: string;
  deviceId: string;
  suiteLabel: "ml-kem-768" | "kyber768";
  peerUserId: string;
};

export type ConversationSummary = {
  peerUserId: string;
  lastPreview: string;
  unreadCount: number;
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
const PINS_KEY = "pqmsg.web.pins.v1";
const CURSORS_KEY = "pqmsg.web.cursors.v1";
const KEYS_PREFIX = "pqmsg.web.keys.v1.";

export const DEFAULT_SETUP: SetupConfig = {
  serverUrl: "http://127.0.0.1:3000",
  userId: "",
  deviceId: "",
  suiteLabel: "ml-kem-768",
  peerUserId: "bob"
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
      peerUserId: parsed.peerUserId || DEFAULT_SETUP.peerUserId
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

export function readCursor(userId: string): number {
  const cursors = parseRecord<Record<string, number>>(CURSORS_KEY, {});
  return Number(cursors[userId] ?? 0);
}

export function writeCursor(userId: string, cursor: number): void {
  const cursors = parseRecord<Record<string, number>>(CURSORS_KEY, {});
  cursors[userId] = cursor;
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

  const pins = parseRecord<PinRow[]>(PINS_KEY, []).filter((item) => item.userId !== normalizedUser);
  writeRecord(PINS_KEY, pins);

  const cursors = parseRecord<Record<string, number>>(CURSORS_KEY, {});
  if (normalizedUser in cursors) {
    delete cursors[normalizedUser];
    writeRecord(CURSORS_KEY, cursors);
  }
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
