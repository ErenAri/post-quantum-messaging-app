import { GeneratedKeys, openJsonWithPassphrase, sealJsonWithPassphrase } from "./crypto";
import {
  clearAllSessionCache,
  clearKeyRecord,
  clearMetadataRecord,
  clearSessionCache,
  listKeyRecordIds,
  loadKeyRecord,
  loadMetadataRecord,
  loadSessionCache,
  saveKeyRecord,
  saveMetadataRecord,
  saveSessionCache,
} from "./db";

export type SetupConfig = {
  serverUrl: string;
  userId: string;
  deviceId: string;
  suiteLabel: "ml-kem-768" | "kyber768";
  peerUserId: string;
  displayName: string;
  username?: string;
  usernameLookupEnabled?: boolean;
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

export type PrivateGroupLocalState = {
  groupId: string;
  stateJson: string;
  memberCredentialJson: string;
  stateCommitmentSha256: string | null;
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
  identityX25519Pub: string;
  identitySigPub: string;
  identityPqSigPub: string;
  observedAt: string;
};

export type TransparencyCheckpoint = {
  epoch: number;
  tree_size: number;
  root_hash: string;
  signature: string;
};

export type ContactDiscoveryCheckpoint = {
  service_origin: string;
  manifest_issuer_ed25519_pub: string;
  ticket_issuer_ed25519_pub: string;
  protocol_version: number;
  ticket_format: string;
  lookup_protocol: string;
  privacy_mode: string;
  directory_backend: string;
  host_enclave_protocol_version: number;
  host_release_id: string;
  enclave_release_id: string;
  match_result_format: string;
  oprf_suite: string;
  evaluation_proof_mode: string;
  oprf_public_key_ristretto255: string;
  attestation_mode: string;
  attestation_verifier: string | null;
  enclave_measurement_hex: string | null;
  attestation_pcrs_sha384: Record<string, string> | null;
  attestation_document_format: string | null;
  attestation_document_sha256: string | null;
  attestation_challenge_mode: string | null;
  observed_at: string;
};

const SETUP_KEY = "pqmsg.web.setup.v1";
const CONVERSATIONS_KEY = "pqmsg.web.conversations.v1";
const GROUP_CONVOS_KEY = "pqmsg.web.groupconvos.v1";
const PRIVATE_GROUPS_KEY = "pqmsg.web.privategroups.v1";
const CONVERSATION_META_KEY = "pqmsg.web.conversationmeta.v1";
const PROFILE_CACHE_KEY = "pqmsg.web.profilecache.v1";
const PINS_KEY = "pqmsg.web.pins.v1";
const CURSORS_KEY = "pqmsg.web.cursors.v1";
const PRIVATE_GROUP_CURSORS_KEY = "pqmsg.web.privategroupcursors.v1";
const TRANSPARENCY_KEY = "pqmsg.web.transparency.v1";
const CONTACT_DISCOVERY_KEY = "pqmsg.web.contactdiscovery.v1";
const METADATA_KEYS = [
  SETUP_KEY,
  CONVERSATIONS_KEY,
  GROUP_CONVOS_KEY,
  PRIVATE_GROUPS_KEY,
  CONVERSATION_META_KEY,
  PROFILE_CACHE_KEY,
  PINS_KEY,
  CURSORS_KEY,
  PRIVATE_GROUP_CURSORS_KEY,
  TRANSPARENCY_KEY,
  CONTACT_DISCOVERY_KEY,
] as const;
const metadataCache = new Map<string, string | null>();
const localKeyUsers = new Set<string>();

export const DEFAULT_SETUP: SetupConfig = {
  serverUrl: "http://127.0.0.1:3000",
  userId: "",
  deviceId: "",
  suiteLabel: "ml-kem-768",
  peerUserId: "bob",
  displayName: "",
  username: "",
  usernameLookupEnabled: false,
};

export async function initMetadataStorage(): Promise<void> {
  for (const key of METADATA_KEYS) {
    metadataCache.set(key, await loadMetadataRecord(key));
  }
  localKeyUsers.clear();
  for (const userId of await listKeyRecordIds()) {
    const normalized = userId.trim();
    if (normalized) {
      localKeyUsers.add(normalized);
    }
  }
}

export function loadSetup(): SetupConfig {
  const raw = readMetadataJson(SETUP_KEY);
  if (!raw) {
    return DEFAULT_SETUP;
  }
  try {
    const parsed = JSON.parse(raw) as SetupConfig;
    return {
      serverUrl: typeof parsed.serverUrl === "string" ? parsed.serverUrl : DEFAULT_SETUP.serverUrl,
      userId: typeof parsed.userId === "string" ? parsed.userId : DEFAULT_SETUP.userId,
      deviceId: typeof parsed.deviceId === "string" ? parsed.deviceId : DEFAULT_SETUP.deviceId,
      suiteLabel: parsed.suiteLabel === "kyber768" || parsed.suiteLabel === "ml-kem-768"
        ? parsed.suiteLabel
        : DEFAULT_SETUP.suiteLabel,
      peerUserId: typeof parsed.peerUserId === "string" ? parsed.peerUserId : DEFAULT_SETUP.peerUserId,
      displayName: typeof parsed.displayName === "string" ? parsed.displayName : DEFAULT_SETUP.displayName,
      username: typeof parsed.username === "string" ? parsed.username : DEFAULT_SETUP.username,
      usernameLookupEnabled: typeof parsed.usernameLookupEnabled === "boolean"
        ? parsed.usernameLookupEnabled
        : DEFAULT_SETUP.usernameLookupEnabled,
    };
  } catch {
    return DEFAULT_SETUP;
  }
}

export function saveSetup(setup: SetupConfig): void {
  writeRecord(SETUP_KEY, setup);
}

export async function saveKeys(
  userId: string,
  passphrase: string,
  keys: GeneratedKeys
): Promise<void> {
  const sealed = await sealJsonWithPassphrase(keys, passphrase);
  await saveKeyRecord(userId, sealed);
  localKeyUsers.add(userId.trim());
}

export async function loadKeys(
  userId: string,
  passphrase: string
): Promise<GeneratedKeys> {
  const sealed = await loadKeyRecord(userId);
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
  return localKeyUsers.has(normalized);
}

export function listLocalKeyUsers(): string[] {
  return [...localKeyUsers].sort((lhs, rhs) => lhs.localeCompare(rhs));
}

export async function saveDirectMessageSession(
  userId: string,
  peerUserId: string,
  passphrase: string,
  sessionJson: string
): Promise<void> {
  const sealed = await sealJsonWithPassphrase(sessionJson, passphrase);
  await saveSessionCache(userId, peerUserId, sealed);
}

export async function loadDirectMessageSession(
  userId: string,
  peerUserId: string,
  passphrase: string
): Promise<string | null> {
  const sealed = await loadSessionCache(userId, peerUserId);
  if (!sealed) {
    return null;
  }
  return openJsonWithPassphrase<string>(sealed, passphrase);
}

export async function clearDirectMessageSession(userId: string, peerUserId: string): Promise<void> {
  await clearSessionCache(userId, peerUserId);
}

export async function clearAllDirectMessageSessions(userId: string): Promise<void> {
  const normalizedUser = userId.trim();
  if (!normalizedUser) {
    return;
  }
  await clearAllSessionCache(normalizedUser);
}

type ConversationRow = ConversationSummary & { userId: string };
type ConversationMetaRow = ConversationMeta & { userId: string };
type ProfileDisplayNameRow = ProfileDisplayName & { userId: string };
type PrivateGroupCursorRow = { userId: string; groupId: string; lastMessageId: number };

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
  writeRecord(CONVERSATIONS_KEY, all);
}

export function markConversationRead(userId: string, peerUserId: string): void {
  const all = parseRecord<ConversationRow[]>(CONVERSATIONS_KEY, []);
  const idx = all.findIndex((item) => item.userId === userId && item.peerUserId === peerUserId);
  if (idx >= 0) {
    all[idx].unreadCount = 0;
    writeRecord(CONVERSATIONS_KEY, all);
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
  writeRecord(CURSORS_KEY, cursors);
}

export function readSealedCursor(userId: string, deviceId?: string): number {
  const sealedKey = deviceId ? `sealed:${deviceId}` : "sealed";
  return readCursor(userId, sealedKey);
}

export function writeSealedCursor(userId: string, cursor: number, deviceId?: string): void {
  const sealedKey = deviceId ? `sealed:${deviceId}` : "sealed";
  writeCursor(userId, cursor, sealedKey);
}

export function readTransparencyCheckpoint(
  serverUrl: string,
  userId: string,
): TransparencyCheckpoint | null {
  const checkpoints = parseRecord<Record<string, TransparencyCheckpoint>>(TRANSPARENCY_KEY, {});
  return checkpoints[`${serverUrl.trim()}::${userId.trim()}`] ?? null;
}

export function writeTransparencyCheckpoint(
  serverUrl: string,
  userId: string,
  checkpoint: TransparencyCheckpoint,
): void {
  const checkpoints = parseRecord<Record<string, TransparencyCheckpoint>>(TRANSPARENCY_KEY, {});
  checkpoints[`${serverUrl.trim()}::${userId.trim()}`] = checkpoint;
  writeRecord(TRANSPARENCY_KEY, checkpoints);
}

export function readContactDiscoveryCheckpoint(
  serverUrl: string,
  userId: string,
): ContactDiscoveryCheckpoint | null {
  const checkpoints = parseRecord<Record<string, ContactDiscoveryCheckpoint>>(CONTACT_DISCOVERY_KEY, {});
  return checkpoints[`${serverUrl.trim()}::${userId.trim()}`] ?? null;
}

export function writeContactDiscoveryCheckpoint(
  serverUrl: string,
  userId: string,
  checkpoint: ContactDiscoveryCheckpoint,
): void {
  const checkpoints = parseRecord<Record<string, ContactDiscoveryCheckpoint>>(CONTACT_DISCOVERY_KEY, {});
  checkpoints[`${serverUrl.trim()}::${userId.trim()}`] = checkpoint;
  writeRecord(CONTACT_DISCOVERY_KEY, checkpoints);
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
    identityX25519Pub: found.identityX25519Pub,
    identitySigPub: found.identitySigPub,
    identityPqSigPub: typeof found.identityPqSigPub === "string" ? found.identityPqSigPub : "",
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
  writeRecord(PINS_KEY, pins);
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
        identityX25519Pub: item.identityX25519Pub,
        identitySigPub: item.identitySigPub,
        identityPqSigPub: typeof item.identityPqSigPub === "string" ? item.identityPqSigPub : "",
        observedAt: item.observedAt
      }
    }))
    .sort((lhs, rhs) => lhs.peerUserId.localeCompare(rhs.peerUserId));
}

// --- Group conversations ---

type GroupConvoRow = GroupConversationSummary & { userId: string };
type PrivateGroupRow = PrivateGroupLocalState & { userId: string };

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
  writeRecord(GROUP_CONVOS_KEY, all);
}

export function markGroupConversationRead(userId: string, groupId: string): void {
  const all = parseRecord<GroupConvoRow[]>(GROUP_CONVOS_KEY, []);
  const idx = all.findIndex(item => item.userId === userId && item.groupId === groupId);
  if (idx >= 0) {
    all[idx].unreadCount = 0;
    writeRecord(GROUP_CONVOS_KEY, all);
  }
}

export function loadPrivateGroups(userId: string): PrivateGroupLocalState[] {
  const all = parseRecord<PrivateGroupRow[]>(PRIVATE_GROUPS_KEY, []);
  return all
    .filter((item) => item.userId === userId)
    .map((item) => ({
      groupId: item.groupId,
      stateJson: item.stateJson,
      memberCredentialJson: item.memberCredentialJson,
      stateCommitmentSha256: item.stateCommitmentSha256 ?? null,
      updatedAt: item.updatedAt,
    }))
    .sort((lhs, rhs) => rhs.updatedAt - lhs.updatedAt);
}

export function readPrivateGroup(userId: string, groupId: string): PrivateGroupLocalState | null {
  if (!userId.trim() || !groupId.trim()) {
    return null;
  }
  return loadPrivateGroups(userId).find((item) => item.groupId === groupId) ?? null;
}

export function upsertPrivateGroup(
  userId: string,
  groupId: string,
  stateJson: string,
  memberCredentialJson: string,
  stateCommitmentSha256?: string | null,
): void {
  if (!userId.trim() || !groupId.trim()) {
    return;
  }
  const all = parseRecord<PrivateGroupRow[]>(PRIVATE_GROUPS_KEY, []);
  const idx = all.findIndex((item) => item.userId === userId && item.groupId === groupId);
  const nextRow: PrivateGroupRow = {
    userId,
    groupId,
    stateJson,
    memberCredentialJson,
    stateCommitmentSha256: stateCommitmentSha256?.trim() || null,
    updatedAt: Date.now(),
  };
  if (idx >= 0) {
    all[idx] = nextRow;
  } else {
    all.push(nextRow);
  }
  writeRecord(PRIVATE_GROUPS_KEY, all);
}

export function removePrivateGroup(userId: string, groupId: string): void {
  if (!userId.trim() || !groupId.trim()) {
    return;
  }
  const all = parseRecord<PrivateGroupRow[]>(PRIVATE_GROUPS_KEY, []).filter(
    (item) => !(item.userId === userId && item.groupId === groupId)
  );
  writeRecord(PRIVATE_GROUPS_KEY, all);
  writeRecord(
    PRIVATE_GROUP_CURSORS_KEY,
    parseRecord<PrivateGroupCursorRow[]>(PRIVATE_GROUP_CURSORS_KEY, []).filter(
      (item) => !(item.userId === userId && item.groupId === groupId)
    )
  );
}

export function readPrivateGroupCursor(userId: string, groupId: string): number {
  if (!userId.trim() || !groupId.trim()) {
    return 0;
  }
  return (
    parseRecord<PrivateGroupCursorRow[]>(PRIVATE_GROUP_CURSORS_KEY, []).find(
      (item) => item.userId === userId && item.groupId === groupId
    )?.lastMessageId ?? 0
  );
}

export function writePrivateGroupCursor(userId: string, groupId: string, lastMessageId: number): void {
  if (!userId.trim() || !groupId.trim()) {
    return;
  }
  const all = parseRecord<PrivateGroupCursorRow[]>(PRIVATE_GROUP_CURSORS_KEY, []);
  const idx = all.findIndex((item) => item.userId === userId && item.groupId === groupId);
  const next = {
    userId,
    groupId,
    lastMessageId,
  } satisfies PrivateGroupCursorRow;
  if (idx >= 0) {
    all[idx] = next;
  } else {
    all.push(next);
  }
  writeRecord(PRIVATE_GROUP_CURSORS_KEY, all);
}

export async function wipeLocalState(userId: string): Promise<void> {
  const normalizedUser = userId.trim();
  if (!normalizedUser) {
    return;
  }

  await clearKeyRecord(normalizedUser);
  localKeyUsers.delete(normalizedUser);

  const conversations = parseRecord<ConversationRow[]>(CONVERSATIONS_KEY, []).filter(
    (item) => item.userId !== normalizedUser
  );
  writeRecord(CONVERSATIONS_KEY, conversations);

  const groupConvos = parseRecord<GroupConvoRow[]>(GROUP_CONVOS_KEY, []).filter(
    (item) => item.userId !== normalizedUser
  );
  writeRecord(GROUP_CONVOS_KEY, groupConvos);

  const privateGroups = parseRecord<PrivateGroupRow[]>(PRIVATE_GROUPS_KEY, []).filter(
    (item) => item.userId !== normalizedUser
  );
  writeRecord(PRIVATE_GROUPS_KEY, privateGroups);
  const privateGroupCursors = parseRecord<PrivateGroupCursorRow[]>(PRIVATE_GROUP_CURSORS_KEY, []).filter(
    (item) => item.userId !== normalizedUser
  );
  writeRecord(PRIVATE_GROUP_CURSORS_KEY, privateGroupCursors);

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

  const checkpoints = parseRecord<Record<string, TransparencyCheckpoint>>(TRANSPARENCY_KEY, {});
  for (const checkpointKey of Object.keys(checkpoints)) {
    if (checkpointKey.endsWith(`::${normalizedUser}`)) {
      delete checkpoints[checkpointKey];
    }
  }
  writeRecord(TRANSPARENCY_KEY, checkpoints);

  const discoveryCheckpoints = parseRecord<Record<string, ContactDiscoveryCheckpoint>>(
    CONTACT_DISCOVERY_KEY,
    {},
  );
  for (const checkpointKey of Object.keys(discoveryCheckpoints)) {
    if (checkpointKey.endsWith(`::${normalizedUser}`)) {
      delete discoveryCheckpoints[checkpointKey];
    }
  }
  writeRecord(CONTACT_DISCOVERY_KEY, discoveryCheckpoints);

  await clearAllDirectMessageSessions(normalizedUser);
}

function parseRecord<T>(key: string, fallback: T): T {
  const raw = readMetadataJson(key);
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
    persistMetadataJson(key, null);
    return;
  }
  if (typeof value === "object" && value !== null && !Array.isArray(value) && Object.keys(value).length === 0) {
    persistMetadataJson(key, null);
    return;
  }
  persistMetadataJson(key, JSON.stringify(value));
}

function readMetadataJson(key: string): string | null {
  if (metadataCache.has(key)) {
    return metadataCache.get(key) ?? null;
  }
  return null;
}

function persistMetadataJson(key: string, raw: string | null): void {
  metadataCache.set(key, raw);
  if (raw === null) {
    void clearMetadataRecord(key).catch(() => {
      // Best-effort cleanup only.
    });
    return;
  }
  void saveMetadataRecord(key, raw).catch(() => {
    // Metadata persistence errors surface on the next bootstrap.
  });
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
