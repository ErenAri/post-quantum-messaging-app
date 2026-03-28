import "./app.css";
import {
  buildPrekeysAuthHeaders,
  buildPublishPrekeysPayload,
  buildRetireDeviceAuthHeaders,
  buildProfileGetAuthHeaders,
  buildProfileUpsertAuthHeaders,
  buildPresenceGetAuthHeaders,
  buildPresenceUpdateAuthHeaders,
  buildTypingGetAuthHeaders,
  buildTypingUpdateAuthHeaders,
  buildSendReceiptAuthHeaders,
  buildGetReceiptsAuthHeaders,
  buildContactsListAuthHeaders,
  buildContactInviteCreateAuthHeaders,
  buildContactsUpsertAuthHeaders,
  buildContactsRemoveAuthHeaders,
  buildUserGroupsListAuthHeaders,
  buildGroupMembersListAuthHeaders,
  buildFileUploadAuthHeaders,
  buildFileDownloadAuthHeaders,
  buildInboxDeleteAuthHeaders,
  buildPrekeysStatusAuthHeaders,
  buildRotateInitAuthHeaders,
  buildRotateConfirmAuthHeaders,
  buildRotateConfirmPayload,
  buildIdentityLogAuthHeaders,
  buildSealedInboxAuthHeaders,
  buildSenderCertificateAuthHeaders,
  buildContactDiscoveryTicketAuthHeaders,
  buildContactDiscoveryAttestationChallengeNonce,
  contactDiscoveryManifestContractSha256,
  buildPushTokenAuthHeaders,
  buildListDevicesAuthHeaders,
  buildLinkDeviceAuthHeaders,
  buildRevokeDeviceAuthHeaders,
  decryptDirectMessage,
  computeSafetyNumber,
  encryptDirectMessageWithSession,
  finalizeContactDiscoveryTokens,
  generateIdentityKeys,
  identityFingerprint,
  initWasmCrypto,
  initiateDirectMessageSession,
  isPqSessionMessagingAvailable,
  openTransportEnvelopeWithSenderCert,
  prepareContactDiscoveryBlindRequest,
  regeneratePublishedPrekeys,
  sealTransportEnvelopeWithSenderCert,
  verifyContactDiscoveryManifest,
  verifyContactDiscoveryAttestationDocument,
  verifyContactDiscoveryEvaluationProofs,
  verifyTransparencyProof,
  type GeneratedKeys,
} from "./crypto";
import {
  PqmsgApi,
  type BundleResponse,
  type ContactEntry,
  type ContactDiscoveryManifestResponse,
  type GroupMembershipRecord,
  type GroupMemberRecord,
  type IdentityLogItem,
  type DeviceRecord,
  type PrivateDiscoveryMatchItem,
  type ServerCapabilitiesResponse,
  type TransparencyProofResponse,
} from "./server";
import {
  clearDirectMessageSession,
  clearAllDirectMessageSessions,
  DEFAULT_SETUP,
  initMetadataStorage,
  hasSeenThreadTips,
  loadConversationMeta,
  loadConversationMetas,
  loadDirectMessageSession,
  hasLocalKeys,
  listLocalKeyUsers,
  loadConversations,
  loadGroupConversations,
  loadPrivateGroups,
  loadProfileDisplayNames,
  readProfileDisplayName,
  readIdentityPin,
  readPrivateGroup,
  readPrivateGroupCursor,
  readThreadDraft,
  readThreadDraftUpdatedAt,
  loadKeys,
  loadSetup,
  markThreadTipsSeen,
  markConversationRead,
  markGroupConversationRead,
  setConversationUnreadCount,
  setGroupConversationUnreadCount,
  removePrivateGroup,
  updateConversationMeta,
  readCursor,
  readContactDiscoveryCheckpoint,
  readSealedCursor,
  readTransparencyCheckpoint,
  saveKeys,
  saveDirectMessageSession,
  saveSetup,
  upsertConversation,
  upsertGroupConversation,
  upsertPrivateGroup,
  wipeLocalState,
  writeProfileDisplayName,
  writeCursor,
  writeContactDiscoveryCheckpoint,
  writeSealedCursor,
  writeIdentityPin,
  writePrivateGroupCursor,
  writeThreadDraft,
  writeTransparencyCheckpoint,
  type ContactDiscoveryCheckpoint,
  type IdentityPin,
  type ConversationKind,
  type ConversationMeta,
  type ConversationRequestState,
  type ConversationSummary,
  type GroupConversationSummary,
  type PrivateGroupLocalState,
} from "./storage";
import {
  saveMessage,
  updateMessageStatus,
  getMessages,
  deleteMessages,
  clearAllMessages,
  clearOutboxMessages,
  searchMessages,
  queueOutboxMessage,
  getOutboxMessages,
  removeOutboxMessage,
  addReaction,
  editStoredMessage,
  getMessage,
  type StoredMessage,
} from "./db";
import { RealtimeInbox, type WsInboxMessage } from "./realtime";
import {
  getCurrentView,
  navigateTo,
  onViewChange,
  notify,
  onNotification,
  type AppView,
  type AppNotification,
} from "./router";
import { getWebBetaHoldback, WEB_BETA_SCOPE_SUMMARY } from "./betaScope";
import {
  extractInviteToken,
  normalizeBrowserUserId,
  parseDirectChatTarget,
  startDirectConversationFlow,
} from "./webFlows";
import {
  getLiveUnsupportedWebRuntimeReason,
  isLoopbackHostname,
  isSecureWebOrigin,
  validateWebServerUrl,
} from "./webEnvironment";
import {
  privateGroupBindingsAvailable,
  privateGroupCreateState,
  privateGroupDescribeMemberCredential,
  privateGroupEncryptSnapshot,
  privateGroupEncryptJoinPackageForShareLink,
  privateGroupEncryptMessage,
  privateGroupExportJoinPackageForMember,
  privateGroupOpenMessage,
  privateGroupOpenShareLinkInvite,
  privateGroupPrepareAddMemberTransition,
  privateGroupPrepareBootstrapMaterial,
  privateGroupPrepareRemoveMemberTransition,
  privateGroupRestoreJoinPackage,
  type PrivateGroupBootstrapMaterial,
  type PrivateGroupCredentialMaterial,
  type PrivateGroupEncryptedMessage,
  type PrivateGroupEpochTransition,
  type PrivateGroupLinkInviteEnvelope,
  type PrivateGroupMember,
  type PrivateGroupMemberCredential,
  type PrivateGroupRole,
  type PrivateGroupState,
} from "./crypto-wasm";
import { base64ToBytes, bytesToBase64, bytesToHex } from "./base64";

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const app = document.getElementById("app")!;
let setup = DEFAULT_SETUP;
let keys: GeneratedKeys | null = null;
let realtimeInbox: RealtimeInbox | null = null;
let activeChatPeer: string | null = null;
let toastTimer: ReturnType<typeof setTimeout> | null = null;
let activeToastAction: (() => void) | null = null;
let disposeMessageSelectionShortcuts: (() => void) | null = null;
let keyboardShortcutOverlay: HTMLElement | null = null;
let sharedMediaOverlay: HTMLElement | null = null;
let sharedMediaOverlayKeyHandler: ((event: KeyboardEvent) => void) | null = null;
let keyboardShortcutLauncherInstalled = false;
type ComposeField = HTMLInputElement | HTMLTextAreaElement;
type SharedMediaFilter = "all" | "media" | "files" | "audio";
type MediaEnvelope = {
  fileName: string;
  mimeType: string;
  noteText: string;
  dataBase64: string;
  byteLength: number;
};
type GroupOutboundPayload = {
  plaintext: string;
  previewText: string;
  storedText: string;
  attachment?: MediaEnvelope;
};
const MEDIA_ENVELOPE_PREFIX = "pqmsg-media-v1";

// Phase 2 state
let presenceHeartbeatTimer: ReturnType<typeof setInterval> | null = null;
let typingTimer: ReturnType<typeof setTimeout> | null = null;
let typingPollTimer: ReturnType<typeof setInterval> | null = null;
let receiptPollTimer: ReturnType<typeof setInterval> | null = null;
let receiptCursor = 0;
let cachedContacts: ContactEntry[] = [];
let cachedProfileNames: Record<string, string> = {};
let cachedSealedDeliveryTokens: Record<string, string> = {};
let cachedInviteBundles: Record<string, BundleResponse> = {};
let peerPresenceCache: Record<string, { status: string; updated: number }> = {};
let activeInboxFilter: InboxFilter = "all";

// Phase 3 state
let activeGroupId: string | null = null;
let cachedGroupMembers: Record<string, GroupMemberRecord[]> = {};
let groupSyncTimer: ReturnType<typeof setInterval> | null = null;

// Phase 4 state
let sealedSenderEnabled = false;
let sealedInboxCursor = 0;
let sealedInboxPollTimer: ReturnType<typeof setInterval> | null = null;

let cachedCapabilities: ServerCapabilitiesResponse | null = null;
let cachedCapabilitiesServerUrl: string | null = null;

type InboxFilter = "all" | "unread" | "groups" | "requests" | "archived";

type PrivateGroupInviteTarget = {
  serverUrl: string;
  inviteToken: string;
  inviteSecretBase64: string;
};

type PrivateGroupWrappedMessage = {
  kind: "pqmsg-private-group-message-v1";
  group_id: string;
  body: string;
  sent_at_unix_ms: number;
};

const PRIVATE_GROUP_MESSAGE_PREFIX = "pqmsg-private-group-message-v1:";
const GROUP_INVITE_SECRET_FRAGMENT_KEY = "group_secret";

function parsePrivateGroupStateJson(stateJson: string): PrivateGroupState | null {
  try {
    return JSON.parse(stateJson) as PrivateGroupState;
  } catch {
    return null;
  }
}

function parsePrivateGroupMemberCredentialJson(
  memberCredentialJson: string
): PrivateGroupMemberCredential | null {
  try {
    return JSON.parse(memberCredentialJson) as PrivateGroupMemberCredential;
  } catch {
    return null;
  }
}

function getPrivateGroupLocalState(groupId: string): PrivateGroupLocalState | null {
  return readPrivateGroup(setup.userId, groupId);
}

function getPrivateGroupState(groupId: string): PrivateGroupState | null {
  const local = getPrivateGroupLocalState(groupId);
  return local ? parsePrivateGroupStateJson(local.stateJson) : null;
}

function getPrivateGroupCredential(groupId: string): PrivateGroupMemberCredential | null {
  const local = getPrivateGroupLocalState(groupId);
  return local ? parsePrivateGroupMemberCredentialJson(local.memberCredentialJson) : null;
}

function findPrivateGroupCredentialForUser(
  memberCredentials: PrivateGroupMemberCredential[],
  userId: string
): PrivateGroupMemberCredential {
  const credential = memberCredentials.find((item) => item.member_user_id === userId);
  if (!credential) {
    throw new Error(`Private-group credential for @${userId} is missing from the current epoch.`);
  }
  return credential;
}

function getPrivateGroupOwnerUserId(state: PrivateGroupState): string {
  return state.members.find((member) => member.role === "Owner")?.user_id || setup.userId;
}

function getPrivateGroupTitle(groupId: string): string {
  return getPrivateGroupState(groupId)?.attributes.title?.trim() || groupId;
}

function isPrivateGroupMember(state: PrivateGroupState, userId: string): boolean {
  return state.members.some((member) => member.user_id === userId);
}

function buildPrivateGroupInviteLink(
  serverUrl: string,
  inviteToken: string,
  inviteSecretBase64: string
): string {
  const url = new URL(location.origin + "/");
  url.searchParams.set("group_invite_token", inviteToken);
  url.searchParams.set("server", serverUrl);
  url.hash = `${GROUP_INVITE_SECRET_FRAGMENT_KEY}=${encodeURIComponent(inviteSecretBase64)}`;
  return url.toString();
}

function readHashParam(name: string, value: string = location.hash): string {
  const hash = value.startsWith("#") ? value.slice(1) : value;
  const params = new URLSearchParams(hash);
  return params.get(name)?.trim() || "";
}

function hexToByteArray(value: string): number[] {
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.length % 2 !== 0) {
    throw new Error("Invalid hex value.");
  }
  const out: number[] = [];
  for (let idx = 0; idx < normalized.length; idx += 2) {
    out.push(Number.parseInt(normalized.slice(idx, idx + 2), 16));
  }
  return out;
}

function extractPrivateGroupInviteTarget(rawInput?: string | null): PrivateGroupInviteTarget | null {
  const raw = (rawInput || "").trim();
  const candidate = raw || location.href;
  let parsed: URL;
  try {
    parsed = new URL(candidate, location.origin);
  } catch {
    return null;
  }
  const inviteToken = (
    parsed.searchParams.get("group_invite_token")
    || parsed.searchParams.get("group_token")
    || parsed.searchParams.get("pg_invite_token")
    || ""
  ).trim();
  const inviteSecretBase64 = (
    readHashParam(GROUP_INVITE_SECRET_FRAGMENT_KEY, parsed.hash)
    || parsed.searchParams.get("group_secret")
    || ""
  ).trim();
  if (!inviteToken || !inviteSecretBase64) {
    return null;
  }
  const serverUrl = (parsed.searchParams.get("server") || setup.serverUrl || location.origin).trim();
  return {
    serverUrl,
    inviteToken,
    inviteSecretBase64,
  };
}

function encodePrivateGroupMessage(groupId: string, body: string): string {
  const payload: PrivateGroupWrappedMessage = {
    kind: "pqmsg-private-group-message-v1",
    group_id: groupId,
    body,
    sent_at_unix_ms: Date.now(),
  };
  return `${PRIVATE_GROUP_MESSAGE_PREFIX}${JSON.stringify(payload)}`;
}

function decodePrivateGroupMessage(
  plaintext: string,
  senderUserId: string
): { groupId: string; body: string } | null {
  if (!plaintext.startsWith(PRIVATE_GROUP_MESSAGE_PREFIX)) {
    return null;
  }
  try {
    const payload = JSON.parse(
      plaintext.slice(PRIVATE_GROUP_MESSAGE_PREFIX.length)
    ) as PrivateGroupWrappedMessage;
    if (payload.kind !== "pqmsg-private-group-message-v1") {
      return null;
    }
    if (!payload.group_id.trim() || !payload.body.trim()) {
      return null;
    }
    const state = getPrivateGroupState(payload.group_id);
    if (!state || !isPrivateGroupMember(state, senderUserId)) {
      return null;
    }
    return {
      groupId: payload.group_id,
      body: payload.body,
    };
  } catch {
    return null;
  }
}

function privateGroupCredentialRecord(
  material: PrivateGroupCredentialMaterial
): import("./server").PrivateGroupMemberCredentialRecord {
  return {
    membership_handle_sha256: material.membership_handle_sha256,
    member_commitment_sha256: material.member_commitment_sha256,
    fetch_key_sha256: material.fetch_key_sha256,
    publish_key_sha256: material.publish_key_sha256,
  };
}

async function publishPrivateGroupBootstrap(
  api: PqmsgApi,
  material: PrivateGroupBootstrapMaterial
): Promise<string> {
  const authorizingCredentialMaterial = privateGroupDescribeMemberCredential(
    material.authorizing_member_credential
  );
  if (!authorizingCredentialMaterial.publish_key_base64) {
    throw new Error("Current private group credential cannot publish state");
  }
  const stateCommitmentSha256 = bytesToHex(
    Uint8Array.from(material.snapshot.state_commitment_sha256)
  );
  await api.publishPrivateGroupState({
    group_id: material.snapshot.group_id,
    epoch: material.snapshot.epoch,
    state_commitment_sha256: stateCommitmentSha256,
    ciphertext_nonce_base64: bytesToBase64(Uint8Array.from(material.snapshot.ciphertext.nonce)),
    ciphertext_base64: bytesToBase64(Uint8Array.from(material.snapshot.ciphertext.ciphertext)),
    ciphertext_aad_base64: bytesToBase64(Uint8Array.from(material.snapshot.ciphertext.aad)),
    authorizing_membership_handle_sha256:
      authorizingCredentialMaterial.membership_handle_sha256,
    authorizing_publish_key_base64: authorizingCredentialMaterial.publish_key_base64,
    members: material.member_credentials.map((credential) =>
      privateGroupCredentialRecord(privateGroupDescribeMemberCredential(credential))
    ),
  });
  return stateCommitmentSha256;
}

async function publishPrivateGroupTransition(
  api: PqmsgApi,
  state: PrivateGroupState,
  authorizingCredential: PrivateGroupMemberCredential,
  memberCredentials: PrivateGroupMemberCredential[],
): Promise<string> {
  const authorizingCredentialMaterial = privateGroupDescribeMemberCredential(authorizingCredential);
  if (!authorizingCredentialMaterial.publish_key_base64) {
    throw new Error("Current private group credential cannot publish state");
  }
  const snapshot = privateGroupEncryptSnapshot(state);
  const stateCommitmentSha256 = bytesToHex(Uint8Array.from(snapshot.state_commitment_sha256));
  await api.publishPrivateGroupState({
    group_id: snapshot.group_id,
    epoch: snapshot.epoch,
    state_commitment_sha256: stateCommitmentSha256,
    ciphertext_nonce_base64: bytesToBase64(Uint8Array.from(snapshot.ciphertext.nonce)),
    ciphertext_base64: bytesToBase64(Uint8Array.from(snapshot.ciphertext.ciphertext)),
    ciphertext_aad_base64: bytesToBase64(Uint8Array.from(snapshot.ciphertext.aad)),
    authorizing_membership_handle_sha256:
      authorizingCredentialMaterial.membership_handle_sha256,
    authorizing_publish_key_base64: authorizingCredentialMaterial.publish_key_base64,
    members: memberCredentials.map((credential) =>
      privateGroupCredentialRecord(privateGroupDescribeMemberCredential(credential))
    ),
  });
  return stateCommitmentSha256;
}

function updateLocalPrivateGroupState(
  state: PrivateGroupState,
  memberCredential: PrivateGroupMemberCredential,
  stateCommitmentSha256: string | null,
  preview: string,
  incrementUnread: boolean,
): void {
  upsertPrivateGroup(
    setup.userId,
    state.group_id,
    JSON.stringify(state),
    JSON.stringify(memberCredential),
    stateCommitmentSha256,
  );
  upsertGroupConversation(
    setup.userId,
    state.group_id,
    getPrivateGroupOwnerUserId(state),
    preview,
    incrementUnread,
  );
}

async function createPrivateGroupInviteLinksForMembers(
  api: PqmsgApi,
  state: PrivateGroupState,
  authorizingCredential: PrivateGroupMemberCredential,
  targetMemberUserIds?: string[],
): Promise<string[]> {
  const authorizingCredentialMaterial = privateGroupDescribeMemberCredential(authorizingCredential);
  if (!authorizingCredentialMaterial.publish_key_base64) {
    throw new Error("Current private-group credential cannot issue invites.");
  }
  const targetSet = targetMemberUserIds ? new Set(targetMemberUserIds) : null;
  const links: string[] = [];
  for (const member of state.members) {
    if (member.user_id === setup.userId) {
      continue;
    }
    if (targetSet && !targetSet.has(member.user_id)) {
      continue;
    }
    const joinPackage = privateGroupExportJoinPackageForMember(state, member.user_id);
    const shareLinkMaterial = privateGroupEncryptJoinPackageForShareLink(joinPackage);
    const invite = await api.createPrivateGroupInvite({
      group_id: state.group_id,
      epoch: state.epoch,
      invite_commitment_sha256: bytesToHex(
        Uint8Array.from(shareLinkMaterial.envelope.invite_commitment_sha256),
      ),
      invite_ciphertext_nonce_base64: bytesToBase64(
        Uint8Array.from(shareLinkMaterial.envelope.ciphertext.nonce),
      ),
      invite_ciphertext_base64: bytesToBase64(
        Uint8Array.from(shareLinkMaterial.envelope.ciphertext.ciphertext),
      ),
      invite_ciphertext_aad_base64: bytesToBase64(
        Uint8Array.from(shareLinkMaterial.envelope.ciphertext.aad),
      ),
      authorizing_membership_handle_sha256:
        authorizingCredentialMaterial.membership_handle_sha256,
      authorizing_publish_key_base64:
        authorizingCredentialMaterial.publish_key_base64,
    });
    links.push(
      `${member.user_id}: ${buildPrivateGroupInviteLink(
        setup.serverUrl,
        invite.invite_token,
        bytesToBase64(Uint8Array.from(shareLinkMaterial.invite_secret)),
      )}`,
    );
  }
  return links;
}

async function createPrivateGroupInviteLinkFromJoinPackage(
  api: PqmsgApi,
  state: PrivateGroupState,
  authorizingCredential: PrivateGroupMemberCredential,
  joinPackage: PrivateGroupJoinPackage,
): Promise<string> {
  const authorizingCredentialMaterial = privateGroupDescribeMemberCredential(authorizingCredential);
  if (!authorizingCredentialMaterial.publish_key_base64) {
    throw new Error("Current private-group credential cannot issue invites.");
  }
  const shareLinkMaterial = privateGroupEncryptJoinPackageForShareLink(joinPackage);
  const invite = await api.createPrivateGroupInvite({
    group_id: state.group_id,
    epoch: state.epoch,
    invite_commitment_sha256: bytesToHex(
      Uint8Array.from(shareLinkMaterial.envelope.invite_commitment_sha256),
    ),
    invite_ciphertext_nonce_base64: bytesToBase64(
      Uint8Array.from(shareLinkMaterial.envelope.ciphertext.nonce),
    ),
    invite_ciphertext_base64: bytesToBase64(
      Uint8Array.from(shareLinkMaterial.envelope.ciphertext.ciphertext),
    ),
    invite_ciphertext_aad_base64: bytesToBase64(
      Uint8Array.from(shareLinkMaterial.envelope.ciphertext.aad),
    ),
    authorizing_membership_handle_sha256:
      authorizingCredentialMaterial.membership_handle_sha256,
    authorizing_publish_key_base64:
      authorizingCredentialMaterial.publish_key_base64,
  });
  return buildPrivateGroupInviteLink(
    setup.serverUrl,
    invite.invite_token,
    bytesToBase64(Uint8Array.from(shareLinkMaterial.invite_secret)),
  );
}

function encodeMediaEnvelope(
  fileName: string,
  mimeType: string,
  noteText: string,
  dataBase64: string,
): string {
  const encoder = new TextEncoder();
  const fileNamePart = bytesToBase64(encoder.encode(fileName));
  const mimeTypePart = bytesToBase64(encoder.encode(mimeType));
  const notePart = bytesToBase64(encoder.encode(noteText));
  return [MEDIA_ENVELOPE_PREFIX, fileNamePart, mimeTypePart, notePart, dataBase64].join("|");
}

function decodeMediaEnvelope(plaintext: string): MediaEnvelope | null {
  const parts = plaintext.split("|", 5);
  if (parts.length !== 5 || parts[0] !== MEDIA_ENVELOPE_PREFIX) {
    return null;
  }
  const decoder = new TextDecoder();
  try {
    const fileName = decoder.decode(base64ToBytes(parts[1]));
    const mimeType = decoder.decode(base64ToBytes(parts[2]));
    const noteText = decoder.decode(base64ToBytes(parts[3]));
    const dataBytes = base64ToBytes(parts[4]);
    return {
      fileName,
      mimeType,
      noteText,
      dataBase64: parts[4],
      byteLength: dataBytes.byteLength,
    };
  } catch {
    return null;
  }
}

function attachmentConversationPreview(noteText: string, mimeType: string): string {
  const trimmedNote = noteText.trim();
  const kind = describeAttachmentKind(mimeType).toLowerCase();
  return trimmedNote ? `Sent ${kind}: ${trimmedNote}` : `Sent ${kind}`;
}

function attachmentMetadataText(message: StoredMessage): string {
  if (!hasStoredAttachment(message)) {
    return "";
  }
  const kind = describeAttachmentKind(attachmentMimeType(message));
  const name = attachmentDisplayName(message);
  const size = message.attachmentByteLength ? ` (${formatFileSize(message.attachmentByteLength)})` : "";
  return `${kind}: ${name}${size}`;
}

function messageTranscriptText(message: StoredMessage): string {
  const parts = new Set<string>();
  const body = message.text.trim();
  if (body) {
    parts.add(body);
  }
  const attachmentLine = attachmentMetadataText(message);
  if (attachmentLine) {
    parts.add(attachmentLine);
  }
  const noteText = message.attachmentNoteText?.trim() || "";
  if (noteText && !body.toLowerCase().includes(noteText.toLowerCase())) {
    parts.add(noteText);
  }
  return Array.from(parts).join("\n").trim();
}

function messageSearchText(message: StoredMessage): string {
  const parts = new Set<string>();
  const transcript = messageTranscriptText(message);
  if (transcript) {
    parts.add(transcript);
  }
  const replyPreview = message.replyPreview?.trim() || "";
  if (replyPreview) {
    parts.add(replyPreview);
  }
  const fileName = message.fileName?.trim() || "";
  if (fileName) {
    parts.add(fileName);
  }
  const mimeType = message.mimeType?.trim() || "";
  if (mimeType) {
    parts.add(mimeType);
  }
  const attachmentKind = hasStoredAttachment(message) ? describeAttachmentKind(attachmentMimeType(message)) : "";
  if (attachmentKind) {
    parts.add(attachmentKind);
  }
  return Array.from(parts).join("\n");
}

function inlineMessagePreview(message: StoredMessage, maxLength = 80): string {
  return messageTranscriptText(message).replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function directConversationPreview(message: StoredMessage): string {
  const preview = inlineMessagePreview(message) || "No messages yet";
  return message.sender === setup.userId ? `You: ${preview}` : preview;
}

function groupConversationPreview(message: StoredMessage): string {
  return inlineMessagePreview(message) || "No messages yet";
}

async function buildGroupOutboundPayload(text: string, attachment: File | null): Promise<GroupOutboundPayload> {
  const trimmedText = text.trim();
  if (!attachment) {
    return {
      plaintext: trimmedText,
      previewText: `You: ${trimmedText}`,
      storedText: `You: ${trimmedText}`,
    };
  }
  const mimeType = attachment.type || "application/octet-stream";
  const dataBase64 = arrayBufferToBase64(await attachment.arrayBuffer());
  const attachmentEnvelope: MediaEnvelope = {
    fileName: attachment.name,
    mimeType,
    noteText: trimmedText,
    dataBase64,
    byteLength: attachment.size,
  };
  const preview = attachmentConversationPreview(trimmedText, mimeType);
  return {
    plaintext: encodeMediaEnvelope(
      attachmentEnvelope.fileName,
      attachmentEnvelope.mimeType,
      attachmentEnvelope.noteText,
      attachmentEnvelope.dataBase64,
    ),
    previewText: `You: ${preview}`,
    storedText: `You: ${preview}`,
    attachment: attachmentEnvelope,
  };
}

function buildInboundGroupAttachmentPreview(senderLabel: string, envelope: MediaEnvelope): string {
  return `${senderLabel}: ${attachmentConversationPreview(envelope.noteText, envelope.mimeType)}`;
}

async function sendPrivateGroupMessage(groupId: string, outbound: GroupOutboundPayload): Promise<void> {
  const state = getPrivateGroupState(groupId);
  if (!state) {
    throw new Error("Private-group state is not available on this device.");
  }
  const credential = getPrivateGroupCredential(groupId);
  if (!credential) {
    throw new Error("Private-group credential is not available on this device.");
  }
  const k = await ensureKeys();
  await ensureWebPqRuntime();
  const api = new PqmsgApi(setup.serverUrl);
  const credentialMaterial = privateGroupDescribeMemberCredential(credential);
  const encrypted = privateGroupEncryptMessage(
    state,
    setup.userId,
    k.identitySigSecret,
    k.identityPqSigSecret,
    outbound.plaintext,
    Date.now()
  );
  const response = await api.publishPrivateGroupMessage({
    group_id: encrypted.group_id,
    epoch: encrypted.epoch,
    sent_at_unix_ms: encrypted.sent_at_unix_ms,
    ciphertext_nonce_base64: bytesToBase64(Uint8Array.from(encrypted.ciphertext.nonce)),
    ciphertext_base64: bytesToBase64(Uint8Array.from(encrypted.ciphertext.ciphertext)),
    ciphertext_aad_base64: bytesToBase64(Uint8Array.from(encrypted.ciphertext.aad)),
    sender_hybrid_signature_base64: bytesToBase64(Uint8Array.from(encrypted.sender_hybrid_signature)),
    authorizing_membership_handle_sha256: credentialMaterial.membership_handle_sha256,
    authorizing_fetch_key_base64: credentialMaterial.fetch_key_base64,
  });
  writePrivateGroupCursor(setup.userId, groupId, response.message_id);
  const ownerUserId = getPrivateGroupOwnerUserId(state);
  upsertGroupConversation(setup.userId, groupId, ownerUserId, outbound.previewText, false);
  await saveMessage({
    id: `srv-group-${response.message_id}`,
    conversationId: `group:${groupId}`,
    sender: setup.userId,
    recipient: groupId,
    text: outbound.storedText,
    timestamp: encrypted.sent_at_unix_ms,
    status: "sent",
    serverMessageId: response.message_id,
    mimeType: outbound.attachment?.mimeType,
    fileName: outbound.attachment?.fileName,
    attachmentDataBase64: outbound.attachment?.dataBase64,
    attachmentByteLength: outbound.attachment?.byteLength,
    attachmentNoteText: outbound.attachment?.noteText,
  });
}

async function ensurePrivateGroupSenderPin(
  senderUserId: string,
  api: PqmsgApi,
  localKeys?: GeneratedKeys
): Promise<IdentityPin> {
  if (senderUserId === setup.userId) {
    const keysForSelf = localKeys ?? await ensureKeys();
    return {
      fingerprintSha256: identityFingerprint(
        keysForSelf.identityX25519Pub,
        keysForSelf.identityPqSigPub
      ),
      identityKeyVersion: 1,
      identityX25519Pub: keysForSelf.identityX25519Pub,
      identitySigPub: keysForSelf.identitySigPub,
      identityPqSigPub: keysForSelf.identityPqSigPub,
      observedAt: new Date().toISOString(),
    };
  }
  const pin = await ensurePeerIdentityPinForTrust(senderUserId, api);
  await ensurePeerTransparencyVerified(senderUserId, api, pin);
  return pin;
}

function privateGroupTransportMessageFromServer(
  item: import("./server").PrivateGroupMessageItem,
  senderUserId: string
): PrivateGroupEncryptedMessage {
  return {
    group_id: item.group_id,
    epoch: item.epoch,
    sender_user_id: senderUserId,
    sent_at_unix_ms: item.sent_at_unix_ms,
    ciphertext: {
      nonce: Array.from(base64ToBytes(item.ciphertext_nonce_base64)),
      ciphertext: Array.from(base64ToBytes(item.ciphertext_base64)),
      aad: Array.from(base64ToBytes(item.ciphertext_aad_base64)),
    },
    sender_hybrid_signature: Array.from(base64ToBytes(item.sender_hybrid_signature_base64)),
  };
}

async function openPrivateGroupTransportMessageWithCandidates(
  state: PrivateGroupState,
  item: import("./server").PrivateGroupMessageItem,
  api: PqmsgApi,
  localKeys: GeneratedKeys
): Promise<{ opened: PrivateGroupDecryptedMessage; senderPin: IdentityPin }> {
  const candidateUserIds = [...new Set(state.members.map((member) => member.user_id))]
    .sort((lhs, rhs) => {
      const lhsPriority = lhs === setup.userId || readIdentityPin(setup.userId, lhs) ? 0 : 1;
      const rhsPriority = rhs === setup.userId || readIdentityPin(setup.userId, rhs) ? 0 : 1;
      if (lhsPriority !== rhsPriority) {
        return lhsPriority - rhsPriority;
      }
      return lhs.localeCompare(rhs);
    });
  let lastError: unknown = null;
  for (const candidateUserId of candidateUserIds) {
    try {
      const senderPin = await ensurePrivateGroupSenderPin(candidateUserId, api, localKeys);
      const opened = privateGroupOpenMessage(
        state,
        privateGroupTransportMessageFromServer(item, candidateUserId),
        senderPin.identitySigPub,
        senderPin.identityPqSigPub
      );
      return { opened, senderPin };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error("Private-group sender could not be identified from the current group state.");
}

async function syncPrivateGroupMessagesForGroup(groupId: string): Promise<boolean> {
  const local = getPrivateGroupLocalState(groupId);
  const state = local ? parsePrivateGroupStateJson(local.stateJson) : null;
  const credential = local ? parsePrivateGroupMemberCredentialJson(local.memberCredentialJson) : null;
  if (!state || !credential) {
    return false;
  }
  const api = new PqmsgApi(setup.serverUrl);
  const credentialMaterial = privateGroupDescribeMemberCredential(credential);
  let cursor = readPrivateGroupCursor(setup.userId, groupId);
  const response = await api.fetchPrivateGroupMessages({
    membership_handle_sha256: credentialMaterial.membership_handle_sha256,
    fetch_key_base64: credentialMaterial.fetch_key_base64,
    since_message_id: cursor || undefined,
  });
  if (!response.messages.length) {
    return false;
  }

  const localKeys = await ensureKeys();
  let changed = false;
  for (const item of response.messages) {
    if (item.message_id <= cursor) {
      continue;
    }
    const { opened } = await openPrivateGroupTransportMessageWithCandidates(
      state,
      item,
      api,
      localKeys
    );
    const senderLabel = resolvePeerIdentity(opened.sender_user_id).primaryLabel;
    const attachmentEnvelope = decodeMediaEnvelope(opened.body);
    const senderPrefix = opened.sender_user_id === setup.userId ? "You" : senderLabel;
    const storedText = attachmentEnvelope
      ? buildInboundGroupAttachmentPreview(senderPrefix, attachmentEnvelope)
      : `${senderPrefix}: ${opened.body}`;
    const conversationPreview = attachmentEnvelope
      ? attachmentConversationPreview(attachmentEnvelope.noteText, attachmentEnvelope.mimeType)
      : opened.body;
    await saveMessage({
      id: `srv-group-${item.message_id}`,
      conversationId: `group:${groupId}`,
      sender: opened.sender_user_id,
      recipient: groupId,
      text: storedText,
      timestamp: item.sent_at_unix_ms,
      status: "delivered",
      serverMessageId: item.message_id,
      mimeType: attachmentEnvelope?.mimeType,
      fileName: attachmentEnvelope?.fileName,
      attachmentDataBase64: attachmentEnvelope?.dataBase64,
      attachmentByteLength: attachmentEnvelope?.byteLength,
      attachmentNoteText: attachmentEnvelope?.noteText,
    });
    noteIncomingGroupConversation(
      groupId,
      opened.sender_user_id,
      conversationPreview,
      activeGroupId !== groupId && opened.sender_user_id !== setup.userId
    );
    void loadProfileNameBackground(opened.sender_user_id);
    cursor = Math.max(cursor, item.message_id);
    changed = true;
  }
  if (cursor > 0) {
    writePrivateGroupCursor(setup.userId, groupId, cursor);
  }
  if (activeGroupId === groupId) {
    markGroupConversationRead(setup.userId, groupId);
  }
  return changed;
}

async function syncPrivateGroupMessagesBackground(): Promise<void> {
  if (!setup.userId) {
    return;
  }
  const capabilities = await loadServerCapabilitiesCached();
  if (!capabilities?.private_group_messaging_supported) {
    return;
  }
  let changed = false;
  for (const group of loadPrivateGroups(setup.userId)) {
    try {
      if (await syncPrivateGroupMessagesForGroup(group.groupId)) {
        changed = true;
      }
    } catch {
      // best effort
    }
  }
  if (changed) {
    refreshConversationsIfVisible();
  }
}

async function bootstrapApp(): Promise<void> {
  try {
    await initMetadataStorage();
    setup = loadSetup();
    ensureSupportedWebEnvironment();
    await ensureWebPqRuntime();
  } catch (error) {
    app.innerHTML = `
      <div class="empty-state">
        <h2>Secure web messaging unavailable</h2>
        <p>${escHtml(errorMsg(error))}</p>
      </div>
    `;
    return;
  }

  if (setup.userId && hasLocalKeys(setup.userId)) {
    const params = new URLSearchParams(location.search);
    const invite = params.get("invite");
    const inviteToken = params.get("invite_token") || params.get("token");
    const groupInvite = params.get("group_invite_token") || params.get("group_token") || params.get("pg_invite_token");
    if (groupInvite) {
      navigateTo({ screen: "create-group" });
    } else if ((invite && invite !== setup.userId) || inviteToken) {
      navigateTo({ screen: "new-chat" });
    } else {
      navigateTo({ screen: "conversations" });
    }
  } else {
    navigateTo({ screen: "onboarding" });
  }

  onViewChange(render);
  onNotification(showToast);
  installKeyboardShortcutLauncher();
  render(getCurrentView());
}

function hideKeyboardShortcutOverlay(): void {
  keyboardShortcutOverlay?.remove();
  keyboardShortcutOverlay = null;
}

function showKeyboardShortcutOverlay(): void {
  if (keyboardShortcutOverlay) {
    return;
  }
  const overlay = document.createElement("div");
  overlay.className = "shortcut-sheet";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-labelledby", "shortcut-sheet-title");
  overlay.innerHTML = `
    <div class="shortcut-card">
      <div class="shortcut-head">
        <div>
          <h2 id="shortcut-sheet-title">Keyboard shortcuts</h2>
          <p>Signal Desktop exposes shortcuts with <span class="mono">Ctrl /</span> or <span class="mono">Cmd /</span>. This web build now does the same for the shortcuts it currently supports.</p>
        </div>
        <button id="shortcut-sheet-close" class="icon-btn" aria-label="Close keyboard shortcuts">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M18 6L6 18M6 6l12 12"/>
          </svg>
        </button>
      </div>
      <div class="shortcut-grid">
        <section class="shortcut-section">
          <h3>General</h3>
          <div class="shortcut-row">
            <span>Show keyboard shortcuts</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>/</kbd> <span class="shortcut-sep">or</span> <kbd>Cmd</kbd><kbd>/</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Focus composer</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>T</kbd> <span class="shortcut-sep">or</span> <kbd>Cmd</kbd><kbd>Shift</kbd><kbd>T</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Insert a new line while composing</span>
            <span class="shortcut-keys"><kbd>Shift</kbd><kbd>Enter</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Expand composer</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>X</kbd> <span class="shortcut-sep">or</span> <kbd>Cmd</kbd><kbd>Shift</kbd><kbd>X</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Send from expanded composer</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>Enter</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Attach file in direct chat</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>U</kbd> <span class="shortcut-sep">or</span> <kbd>Cmd</kbd><kbd>U</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Search in conversation</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>F</kbd> <span class="shortcut-sep">or</span> <kbd>Cmd</kbd><kbd>Shift</kbd><kbd>F</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Close shortcut sheet or selection mode</span>
            <span class="shortcut-keys"><kbd>Esc</kbd></span>
          </div>
        </section>
        <section class="shortcut-section">
          <h3>Selected messages</h3>
          <div class="shortcut-row">
            <span>Share selected messages</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>S</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Delete selected messages from this device</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>D</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Reply to a single selected message</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>R</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>React to a single selected message</span>
            <span class="shortcut-keys"><kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>E</kbd></span>
          </div>
          <div class="shortcut-row">
            <span>Open selected message menu</span>
            <span class="shortcut-keys"><kbd>Shift</kbd><kbd>F10</kbd></span>
          </div>
        </section>
        <section class="shortcut-section">
          <h3>Thread navigation</h3>
          <div class="shortcut-row">
            <span>Reply to a message</span>
            <span class="shortcut-keys">Swipe right on Android <span class="shortcut-sep">or</span> right-click a bubble on web</span>
          </div>
          <div class="shortcut-row">
            <span>Jump through a reply thread</span>
            <span class="shortcut-keys">Click a quoted reply or reply count chip</span>
          </div>
        </section>
      </div>
      <p class="shortcut-footnote">To enter selection mode, right-click a message bubble and choose <strong>Select messages</strong>, then click additional bubbles.</p>
    </div>
  `;
  document.body.appendChild(overlay);
  keyboardShortcutOverlay = overlay;
  overlay.querySelector<HTMLElement>("#shortcut-sheet-close")?.addEventListener("click", hideKeyboardShortcutOverlay);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) {
      hideKeyboardShortcutOverlay();
    }
  });
}

function installKeyboardShortcutLauncher(): void {
  if (keyboardShortcutLauncherInstalled) {
    return;
  }
  keyboardShortcutLauncherInstalled = true;
  window.addEventListener("keydown", (event) => {
    const isShowShortcuts = (event.ctrlKey || event.metaKey) && !event.altKey && event.code === "Slash";
    if (isShowShortcuts) {
      event.preventDefault();
      if (keyboardShortcutOverlay) {
        hideKeyboardShortcutOverlay();
      } else {
        showKeyboardShortcutOverlay();
      }
      return;
    }
    if (event.key === "Escape" && keyboardShortcutOverlay) {
      event.preventDefault();
      hideKeyboardShortcutOverlay();
    }
  });
}

async function loadServerCapabilitiesCached(): Promise<ServerCapabilitiesResponse | null> {
  if (cachedCapabilities && cachedCapabilitiesServerUrl === setup.serverUrl) {
    return cachedCapabilities;
  }
  try {
    const caps = await new PqmsgApi(setup.serverUrl).getCapabilities();
    cachedCapabilities = caps;
    cachedCapabilitiesServerUrl = setup.serverUrl;
    return caps;
  } catch {
    cachedCapabilities = null;
    cachedCapabilitiesServerUrl = setup.serverUrl;
    return null;
  }
}

function presenceSupported(): boolean {
  return cachedCapabilities?.presence_supported ?? false;
}

function typingIndicatorsSupported(): boolean {
  return cachedCapabilities?.typing_indicators_supported ?? false;
}

function readReceiptsSupported(): boolean {
  return cachedCapabilities?.read_receipts_supported ?? false;
}

function ensureSupportedWebEnvironment(): void {
  const runtimeIssue = getLiveUnsupportedWebRuntimeReason();
  if (runtimeIssue) {
    throw new Error(runtimeIssue);
  }
}

async function ensureWebPqRuntime(): Promise<void> {
  if (isPqSessionMessagingAvailable()) {
    return;
  }
  const ready = await initWasmCrypto();
  if (!ready || !isPqSessionMessagingAvailable()) {
    throw new Error("Web post-quantum runtime unavailable in this build.");
  }
}

async function ensureMandatoryPqRatchetPolicy(): Promise<ServerCapabilitiesResponse> {
  const capabilities = await loadServerCapabilitiesCached();
  if (!capabilities) {
    throw new Error("Server capabilities could not be verified.");
  }
  if (capabilities.pq_ratchet_interval !== 1) {
    throw new Error("Server is not advertising per-message PQ ratchet support.");
  }
  if (!capabilities.sealed_sender_required) {
    throw new Error("Server is not advertising sealed-sender-only direct messaging.");
  }
  if (!capabilities.sender_certificate_supported) {
    throw new Error("Server is not advertising sender certificate support.");
  }
  if (!capabilities.key_transparency_supported) {
    throw new Error("Server is not advertising key transparency support.");
  }
  if (!capabilities.sealed_delivery_tokens_supported) {
    throw new Error("Server is not advertising sealed delivery token support.");
  }
  if (!capabilities.sender_certificate_issuer_ed25519_pub) {
    throw new Error("Server is not advertising the sender certificate issuer key.");
  }
  if (!capabilities.transparency_log_issuer_ed25519_pub) {
    throw new Error("Server is not advertising the transparency log issuer key.");
  }
  if (
    capabilities.contact_discovery_mode === "private_service" &&
    (
      !capabilities.contact_discovery_supported ||
      !capabilities.contact_discovery_ticket_supported ||
      !capabilities.contact_discovery_service_origin ||
      !capabilities.contact_discovery_ticket_issuer_ed25519_pub ||
      !capabilities.contact_discovery_manifest_issuer_ed25519_pub
    )
  ) {
    throw new Error("Server is advertising private contact discovery without a complete service contract.");
  }
  return capabilities;
}

async function persistDirectSession(peerUserId: string, sessionJson: string): Promise<void> {
  await saveDirectMessageSession(setup.userId, peerUserId, getPassphrase(), sessionJson);
}

async function loadStoredDirectSession(peerUserId: string): Promise<string | null> {
  return loadDirectMessageSession(setup.userId, peerUserId, getPassphrase());
}

function sessionRequiresRehandshake(sessionJson: string, requiredPqRatchetInterval: number): boolean {
  try {
    const parsed = JSON.parse(sessionJson) as {
      snapshot?: { pq_ratchet?: { interval?: unknown } | null };
    };
    const interval = parsed.snapshot?.pq_ratchet?.interval;
    return typeof interval !== "number" || interval !== requiredPqRatchetInterval;
  } catch {
    return true;
  }
}

async function loadCompatibleDirectSession(
  peerUserId: string,
  requiredPqRatchetInterval: number
): Promise<{ sessionJson: string | null; clearedLegacy: boolean }> {
  const existingSession = await loadStoredDirectSession(peerUserId);
  if (!existingSession) {
    return { sessionJson: null, clearedLegacy: false };
  }
  if (!sessionRequiresRehandshake(existingSession, requiredPqRatchetInterval)) {
    return { sessionJson: existingSession, clearedLegacy: false };
  }
  await clearDirectMessageSession(setup.userId, peerUserId);
  return { sessionJson: null, clearedLegacy: true };
}

async function syncUpdatedKeys(updatedKeys: GeneratedKeys): Promise<void> {
  const passphrase = getPassphrase();
  keys = updatedKeys;
  await saveKeys(updatedKeys.userId, passphrase, updatedKeys);
}

async function encryptDirectPayload(
  k: GeneratedKeys,
  peerUserId: string,
  plaintext: string
): Promise<string> {
  await ensureWebPqRuntime();
  const capabilities = await ensureMandatoryPqRatchetPolicy();
  const { sessionJson: existingSession } = await loadCompatibleDirectSession(
    peerUserId,
    capabilities.pq_ratchet_interval
  );
  const api = new PqmsgApi(setup.serverUrl);
  if (existingSession) {
    const result = encryptDirectMessageWithSession(existingSession, k.userId, peerUserId, plaintext);
    await persistDirectSession(peerUserId, result.sessionJson);
    const peerIdentityX25519Pub = await loadPeerTransportIdentityX25519(peerUserId, api);
    const senderCertificateBase64 = await issueSenderCertificate(k, api);
    return sealTransportEnvelopeWithSenderCert(
      k,
      peerUserId,
      peerIdentityX25519Pub,
      result.messageBytesBase64,
      senderCertificateBase64
    );
  }

  const bundle = cachedInviteBundles[peerUserId] ?? await api.getBundle(peerUserId);
  delete cachedInviteBundles[peerUserId];
  const fingerprint =
    bundle.identity_fingerprint_sha256
    || identityFingerprint(bundle.identity_x25519_pub, bundle.identity_pq_sig_pub);
  enforceIdentityPin(
    peerUserId,
    bundle.identity_x25519_pub,
    bundle.identity_sig_pub,
    bundle.identity_pq_sig_pub,
    fingerprint,
    bundle.identity_key_version,
    bundle.bundle_generated_at
  );
  await ensurePeerTransparencyVerified(peerUserId, api, readIdentityPin(setup.userId, peerUserId));
  const result = initiateDirectMessageSession(k, bundle, plaintext);
  await persistDirectSession(peerUserId, result.sessionJson);
  const senderCertificateBase64 = await issueSenderCertificate(k, api);
  return sealTransportEnvelopeWithSenderCert(
    k,
    peerUserId,
    bundle.identity_x25519_pub,
    result.messageBytesBase64,
    senderCertificateBase64
  );
}

type DecryptedIncomingPayload = {
  kind: "dm" | "group" | "ignored";
  senderUserId: string;
  recipient: string;
  plaintext: string;
};

async function decryptIncomingPayload(
  k: GeneratedKeys,
  messageBytesBase64: string,
  senderUserId?: string,
  senderIdentityX25519Pub?: string | null
): Promise<DecryptedIncomingPayload> {
  const activeKeys = keys ?? k;
  await ensureWebPqRuntime();
  const capabilities = await ensureMandatoryPqRatchetPolicy();
  let transportPayloadBase64 = messageBytesBase64;
  let resolvedSenderUserId = senderUserId ?? "";
  if (capabilities.sealed_sender_required) {
    const opened = openTransportEnvelopeWithSenderCert(
      activeKeys,
      senderIdentityX25519Pub,
      messageBytesBase64,
      capabilities.sender_certificate_issuer_ed25519_pub
    );
    resolvedSenderUserId = opened.senderUserId;
    transportPayloadBase64 = opened.payloadMessageBytesBase64;
  }
  if (!resolvedSenderUserId) {
    throw new Error("Missing sender identity for incoming message");
  }
  await ensurePeerTransparencyVerified(resolvedSenderUserId, new PqmsgApi(setup.serverUrl));
  const {
    sessionJson: existingSession,
    clearedLegacy,
  } = await loadCompatibleDirectSession(
    resolvedSenderUserId,
    capabilities.pq_ratchet_interval
  );
  let result: ReturnType<typeof decryptDirectMessage>;
  try {
    result = decryptDirectMessage(
      activeKeys,
      resolvedSenderUserId,
      transportPayloadBase64,
      existingSession
    );
  } catch (error) {
    if (clearedLegacy) {
      throw new Error("Stored session was reset for mandatory PQ ratchet rollout; peer must start a fresh session.");
    }
    throw error;
  }
  await syncUpdatedKeys(result.updatedKeys);
  await persistDirectSession(resolvedSenderUserId, result.sessionJson);
  if (result.plaintextUtf8.startsWith(PRIVATE_GROUP_MESSAGE_PREFIX)) {
    if (capabilities.private_group_messaging_supported) {
      return {
        kind: "ignored",
        senderUserId: resolvedSenderUserId,
        recipient: activeKeys.userId,
        plaintext: "",
      };
    }
    const privateGroupMessage = decodePrivateGroupMessage(result.plaintextUtf8, resolvedSenderUserId);
    if (!privateGroupMessage) {
      throw new Error("Private-group message could not be matched to local opaque state.");
    }
    return {
      kind: "group",
      senderUserId: resolvedSenderUserId,
      recipient: privateGroupMessage.groupId,
      plaintext: privateGroupMessage.body,
    };
  }
  return {
    kind: "dm",
    senderUserId: resolvedSenderUserId,
    recipient: activeKeys.userId,
    plaintext: result.plaintextUtf8,
  };
}

async function loadPeerTransportIdentityX25519(
  peerUserId: string,
  api: PqmsgApi
): Promise<string> {
  const pinned = readIdentityPin(setup.userId, peerUserId);
  if (pinned?.identityX25519Pub) {
    await ensurePeerTransparencyVerified(peerUserId, api, pinned);
    return pinned.identityX25519Pub;
  }
  const bundle = await api.getBundle(peerUserId);
  const fingerprint =
    bundle.identity_fingerprint_sha256
    || identityFingerprint(bundle.identity_x25519_pub, bundle.identity_pq_sig_pub);
  enforceIdentityPin(
    peerUserId,
    bundle.identity_x25519_pub,
    bundle.identity_sig_pub,
    bundle.identity_pq_sig_pub,
    fingerprint,
    bundle.identity_key_version,
    bundle.bundle_generated_at
  );
  await ensurePeerTransparencyVerified(peerUserId, api, readIdentityPin(setup.userId, peerUserId));
  return bundle.identity_x25519_pub;
}

async function issueSenderCertificate(k: GeneratedKeys, api: PqmsgApi): Promise<string> {
  const headers = buildSenderCertificateAuthHeaders(k);
  const response = await api.getSenderCertificate(k.userId, headers);
  return response.certificate_base64;
}

type PeerTransparencyAssessment = {
  leafVersion: number;
  treeSize: number;
  consistencyVerified: boolean;
};

function transparencyProofMatchesPin(
  peerUserId: string,
  proof: TransparencyProofResponse,
  pin: IdentityPin
): boolean {
  if (proof.user_id !== peerUserId || proof.leaf.user_id !== peerUserId) {
    return false;
  }
  return (
    proof.leaf.version === pin.identityKeyVersion
    && proof.leaf.identity_x25519_pub === pin.identityX25519Pub
    && proof.leaf.identity_sig_pub === pin.identitySigPub
    && (proof.leaf.identity_pq_sig_pub ?? "") === pin.identityPqSigPub
  );
}

async function ensurePeerTransparencyVerified(
  peerUserId: string,
  api: PqmsgApi,
  identityPin?: IdentityPin | null
): Promise<PeerTransparencyAssessment> {
  const capabilities = await ensureMandatoryPqRatchetPolicy();
  const pin = identityPin?.identityPqSigPub?.trim()
    ? identityPin
    : await ensurePeerIdentityPinForTrust(peerUserId, api);
  const checkpoint = readTransparencyCheckpoint(setup.serverUrl, peerUserId);
  const proof = await api.getTransparencyProof(peerUserId, checkpoint?.tree_size);
  const verification = verifyTransparencyProof(
    JSON.stringify(proof),
    capabilities.transparency_log_issuer_ed25519_pub,
    checkpoint ? JSON.stringify(checkpoint) : null,
  );
  if (!transparencyProofMatchesPin(peerUserId, proof, pin)) {
    throw new Error(`Peer transparency proof does not match the pinned hybrid identity for ${peerUserId}.`);
  }
  if (verification.leafUserId !== peerUserId || verification.leafVersion !== proof.leaf.version) {
    throw new Error(`Peer transparency proof returned an unexpected leaf for ${peerUserId}.`);
  }
  writeTransparencyCheckpoint(setup.serverUrl, peerUserId, proof.signed_tree_head);
  return {
    leafVersion: verification.leafVersion,
    treeSize: verification.treeSize,
    consistencyVerified: verification.consistencyVerified,
  };
}

async function loadPeerSealedDeliveryToken(
  k: GeneratedKeys,
  peerUserId: string,
  api: PqmsgApi
): Promise<string> {
  const cached = cachedSealedDeliveryTokens[peerUserId]?.trim();
  if (cached) {
    return cached;
  }
  const headers = buildProfileGetAuthHeaders(k, peerUserId);
  let profile = await api.getProfile(peerUserId, headers);
  let sealedDeliveryToken = profile.sealed_delivery_token?.trim() || "";
  if (!sealedDeliveryToken) {
    const contactHeaders = buildContactsUpsertAuthHeaders(k, peerUserId, peerUserId, false, "");
    await api.upsertContact(k.userId, { contact_user_id: peerUserId }, contactHeaders);
    markConversationAccepted(peerUserId);
    void loadContactsBackground();
    profile = await api.getProfile(peerUserId, headers);
    sealedDeliveryToken = profile.sealed_delivery_token?.trim() || "";
  }
  if (!sealedDeliveryToken) {
    throw new Error("Direct messaging requires adding this user as a contact first.");
  }
  cachedSealedDeliveryTokens[peerUserId] = sealedDeliveryToken;
  const displayName = profile.display_name?.trim() || "";
  if (displayName) {
    cachedProfileNames[peerUserId] = displayName;
    writeProfileDisplayName(k.userId, peerUserId, displayName);
  }
  return sealedDeliveryToken;
}

async function ensureWebMessagingAllowed(kind: "direct" | "group"): Promise<boolean> {
  const holdback = getWebBetaHoldback(await loadServerCapabilitiesCached());
  if (kind === "direct") {
    try {
      await ensureWebPqRuntime();
    } catch (e) {
      notify(errorMsg(e), "error");
      return false;
    }
    if (holdback.directMessagingAllowed) {
      return true;
    }
  } else if (holdback.groupMessagingAllowed) {
    return true;
  }
  const label = kind === "group" ? "group messaging" : "messaging";
  notify(
    `Web ${label} is disabled. ${holdback.detail}`,
    "error"
  );
  return false;
}

type UnifiedConversationRow = {
  kind: ConversationKind;
  threadId: string;
  updatedAt: number;
  unreadCount: number;
  lastPreview: string;
  draftText: string | null;
  meta: ConversationMeta;
  primaryLabel: string;
  secondaryLabel: string;
  avatarText: string;
  presenceStatus: string | null;
  isVerified: boolean;
  ownerUserId?: string;
};

const ONBOARDING_LOGO = `
  <div class="onboarding-icon">
    <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
      <rect width="64" height="64" rx="16" fill="#1a8cff"/>
      <path d="M20 22h24v20H20z" fill="#fff" opacity="0.9"/>
      <circle cx="28" cy="32" r="4" fill="#1a8cff"/>
      <rect x="36" y="28" width="14" height="3" rx="1.5" fill="#1a8cff"/>
      <rect x="36" y="34" width="10" height="3" rx="1.5" fill="#1a8cff" opacity="0.6"/>
    </svg>
  </div>
  <h1>PQMsg</h1>
  <p class="onboarding-sub">Post-quantum encrypted messaging</p>
`;

void bootstrapApp();

// Offline banner
window.addEventListener("offline", () => showOfflineBanner(true));
window.addEventListener("online", () => { showOfflineBanner(false); void drainOutbox(); });

// ---------------------------------------------------------------------------
// Render dispatcher
// ---------------------------------------------------------------------------

function render(view: AppView): void {
  disposeMessageSelectionShortcuts?.();
  disposeMessageSelectionShortcuts = null;
  switch (view.screen) {
    case "onboarding":
      renderOnboarding();
      break;
    case "create-account":
      renderCreateAccount();
      break;
    case "sign-in":
      renderSignIn();
      break;
    case "conversations":
      renderConversations();
      break;
    case "chat":
      activeChatPeer = view.peerId;
      renderChat(view.peerId);
      break;
    case "new-chat":
      renderNewChat();
      break;
    case "settings":
      renderSettings();
      break;
    case "group-chat":
      activeGroupId = view.groupId;
      renderGroupChat(view.groupId);
      break;
    case "group-info":
      renderGroupInfo(view.groupId);
      break;
    case "create-group":
      renderCreateGroup();
      break;
    case "identity-log":
      renderIdentityLog();
      break;
    case "discovery":
      renderDiscovery();
      break;
    case "server-info":
      renderServerInfo();
      break;
    case "search":
      renderSearch();
      break;
    case "devices":
      renderDevices();
      break;
    case "link-device":
      renderLinkDevice();
      break;
    case "call":
      renderCall(view.peerId, view.callType);
      break;
    case "incoming-call":
      renderIncomingCall(view.callId, view.peerId, view.callType, view.sdpOfferBase64);
      break;
  }

  // Move focus to the main heading or first focusable element for screen readers
  requestAnimationFrame(() => {
    const heading = app.querySelector("h1, h2, h3, .topbar .chat-header-name, .search-input");
    if (heading instanceof HTMLElement) heading.focus({ preventScroll: true });
  });
}

function conversationMetaKey(kind: ConversationKind, threadId: string): string {
  return `${kind}:${threadId}`;
}

function buildConversationMetaLookup(): Map<string, ConversationMeta> {
  return new Map(
    loadConversationMetas(setup.userId).map((meta) => [conversationMetaKey(meta.kind, meta.threadId), meta])
  );
}

function getConversationMetaCached(
  lookup: Map<string, ConversationMeta>,
  kind: ConversationKind,
  threadId: string
): ConversationMeta {
  return lookup.get(conversationMetaKey(kind, threadId)) ?? loadConversationMeta(setup.userId, kind, threadId);
}

function formatContactHandle(contact: Pick<ContactEntry, "contact_user_id" | "username"> | undefined): string {
  const username = contact?.username?.trim().replace(/^@+/, "") || "";
  return username ? `@${username}` : (contact?.contact_user_id || "");
}

function resolvePeerIdentity(peerId: string): {
  primaryLabel: string;
  secondaryLabel: string;
  avatarText: string;
  isVerified: boolean;
} {
  const contact = cachedContacts.find((item) => item.contact_user_id === peerId);
  const cachedName = cachedProfileNames[peerId]?.trim() || readProfileDisplayName(setup.userId, peerId)?.trim() || "";
  const contactHandle = formatContactHandle(contact);
  const primaryLabel = contact?.alias?.trim() || cachedName || contactHandle || peerId;
  const secondaryCandidate = contactHandle || (primaryLabel === peerId ? "" : peerId);
  const secondaryLabel = secondaryCandidate && primaryLabel !== secondaryCandidate ? secondaryCandidate : "";
  const avatarText = primaryLabel.slice(0, 2).toUpperCase() || peerId.slice(0, 2).toUpperCase();
  const isVerified = Boolean(contact?.verified_by_qr || readIdentityPin(setup.userId, peerId));
  return { primaryLabel, secondaryLabel, avatarText, isVerified };
}

function resolveGroupIdentity(groupId: string, ownerUserId: string): {
  primaryLabel: string;
  secondaryLabel: string;
  avatarText: string;
} {
  const title = getPrivateGroupTitle(groupId);
  return {
    primaryLabel: title,
    secondaryLabel: ownerUserId === setup.userId ? "You created this group" : `Owner @${ownerUserId}`,
    avatarText: title.slice(0, 2).toUpperCase() || groupId.slice(0, 2).toUpperCase(),
  };
}

function describePrivateGroupMemberTrust(memberUserId: string): {
  summary: string;
  detail: string;
} {
  if (memberUserId === setup.userId) {
    return {
      summary: "Local member credential",
      detail: "This device holds the current opaque state for your membership.",
    };
  }
  const contact = cachedContacts.find((item) => item.contact_user_id === memberUserId);
  const identityPin = readIdentityPin(setup.userId, memberUserId);
  const transparencyCheckpoint = readTransparencyCheckpoint(setup.serverUrl, memberUserId);
  if (isContactFingerprintVerified(contact, identityPin)) {
    return {
      summary: "Verified via safety number",
      detail: transparencyCheckpoint
        ? `Transparency auto-verified in tree #${transparencyCheckpoint.tree_size}.`
        : "This member's current fingerprint matches the saved verification.",
    };
  }
  if (transparencyCheckpoint) {
    return {
      summary: "Transparency auto-verified",
      detail: `Signed transparency checkpoint saved at tree #${transparencyCheckpoint.tree_size}.`,
    };
  }
  if (identityPin) {
    return {
      summary: "Pinned on this device",
      detail: "This member's hybrid identity is pinned locally, but not safety-number verified.",
    };
  }
  return {
    summary: "No local trust checkpoint",
    detail: "Open a direct chat and verify this member before trusting membership changes.",
  };
}

function setConversationRequestState(
  kind: ConversationKind,
  threadId: string,
  requestState: ConversationRequestState
): ConversationMeta {
  return updateConversationMeta(setup.userId, kind, threadId, { requestState });
}

function setConversationArchived(kind: ConversationKind, threadId: string, archived: boolean): ConversationMeta {
  return updateConversationMeta(setup.userId, kind, threadId, {
    archivedAt: archived ? Date.now() : null,
  });
}

function toggleConversationPinned(kind: ConversationKind, threadId: string): ConversationMeta {
  const meta = loadConversationMeta(setup.userId, kind, threadId);
  return updateConversationMeta(setup.userId, kind, threadId, {
    pinnedAt: meta.pinnedAt ? null : Date.now(),
  });
}

function notifyArchiveChange(kind: ConversationKind, threadId: string, archived: boolean): void {
  notify(
    archived ? "Chat archived" : "Chat restored",
    "success",
    {
      actionLabel: "Undo",
      action: () => {
        setConversationArchived(kind, threadId, !archived);
        refreshConversationsIfVisible();
      },
    }
  );
}

function readConversationUnreadCount(kind: ConversationKind, threadId: string): number {
  if (kind === "group") {
    return loadGroupConversations(setup.userId).find((item) => item.groupId === threadId)?.unreadCount ?? 0;
  }
  return loadConversations(setup.userId).find((item) => item.peerUserId === threadId)?.unreadCount ?? 0;
}

function setConversationUnread(kind: ConversationKind, threadId: string, unread: boolean): void {
  if (kind === "group") {
    if (unread) {
      setGroupConversationUnreadCount(setup.userId, threadId, 1);
    } else {
      markGroupConversationRead(setup.userId, threadId);
    }
    return;
  }
  if (unread) {
    setConversationUnreadCount(setup.userId, threadId, 1);
  } else {
    markConversationRead(setup.userId, threadId);
  }
}

function setConversationSendDefaults(
  threadId: string,
  defaults: Partial<Pick<ConversationMeta, "sealedSenderDefault" | "ephemeralTtlDefault">>
): ConversationMeta {
  return updateConversationMeta(setup.userId, "dm", threadId, defaults);
}

function isKnownPeer(peerId: string): boolean {
  if (cachedContacts.some((item) => item.contact_user_id === peerId)) {
    return true;
  }
  return loadConversationMeta(setup.userId, "dm", peerId).requestState === "accepted";
}

function markConversationAccepted(peerId: string): void {
  setConversationRequestState("dm", peerId, "accepted");
  setConversationArchived("dm", peerId, false);
}

function isContactFingerprintVerified(
  contact: ContactEntry | undefined,
  identityPin: IdentityPin | null
): boolean {
  if (!contact?.verified_by_qr || !identityPin) {
    return false;
  }
  const verifiedFingerprint = contact.verified_fingerprint_sha256?.trim().toLowerCase() || "";
  return verifiedFingerprint === identityPin.fingerprintSha256.trim().toLowerCase();
}

function upsertCachedContact(contact: ContactEntry): void {
  const existingIndex = cachedContacts.findIndex((item) => item.contact_user_id === contact.contact_user_id);
  if (existingIndex >= 0) {
    cachedContacts = [
      ...cachedContacts.slice(0, existingIndex),
      contact,
      ...cachedContacts.slice(existingIndex + 1),
    ];
    return;
  }
  cachedContacts = [...cachedContacts, contact].sort((lhs, rhs) => lhs.contact_user_id.localeCompare(rhs.contact_user_id));
}

function markConversationDismissed(peerId: string): void {
  updateConversationMeta(setup.userId, "dm", peerId, {
    requestState: "dismissed",
    archivedAt: Date.now(),
  });
}

function noteIncomingConversation(peerId: string, preview: string, incrementUnread: boolean): void {
  if (!isKnownPeer(peerId)) {
    setConversationRequestState("dm", peerId, "pending");
  } else {
    markConversationAccepted(peerId);
  }
  upsertConversation(setup.userId, peerId, preview, incrementUnread);
}

function ensureAcceptedContactsMeta(): void {
  for (const contact of cachedContacts) {
    updateConversationMeta(setup.userId, "dm", contact.contact_user_id, {
      requestState: "accepted",
    });
  }
}

async function loadProfileNameBackground(targetUserId: string): Promise<void> {
  if (!targetUserId) {
    return;
  }
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildProfileGetAuthHeaders(k, targetUserId);
    const profile = await api.getProfile(targetUserId, headers);
    const sealedDeliveryToken = profile.sealed_delivery_token?.trim() || "";
    if (sealedDeliveryToken) {
      cachedSealedDeliveryTokens[targetUserId] = sealedDeliveryToken;
    }
    const displayName = profile.display_name?.trim() || "";
    if (displayName) {
      cachedProfileNames[targetUserId] = displayName;
      writeProfileDisplayName(k.userId, targetUserId, displayName);
    }
    if (targetUserId === k.userId) {
      let changed = false;
      if (displayName && setup.displayName !== displayName) {
        setup.displayName = displayName;
        changed = true;
      }
      const username = profile.username?.trim() || "";
      if ((setup.username || "") !== username) {
        setup.username = username;
        changed = true;
      }
      const usernameLookupEnabled = Boolean(profile.username_lookup_enabled && username);
      if (Boolean(setup.usernameLookupEnabled) !== usernameLookupEnabled) {
        setup.usernameLookupEnabled = usernameLookupEnabled;
        changed = true;
      }
      if (changed) {
        saveSetup(setup);
      }
    }
  } catch {
    // Best-effort
  }
}

async function loadProfileNamesBackground(targetUserIds: string[]): Promise<void> {
  const uniqueTargets = [...new Set(targetUserIds)]
    .map((value) => value.trim())
    .filter((value) => value && !cachedProfileNames[value]);
  if (uniqueTargets.length === 0) {
    return;
  }
  const knownBefore = JSON.stringify(cachedProfileNames);
  await Promise.allSettled(uniqueTargets.map((targetUserId) => loadProfileNameBackground(targetUserId)));
  if (JSON.stringify(cachedProfileNames) !== knownBefore) {
    refreshConversationsIfVisible();
  }
}

async function bootstrapIdentityData(): Promise<void> {
  cachedProfileNames = Object.fromEntries(
    loadProfileDisplayNames(setup.userId).map((item) => [item.targetUserId, item.displayName])
  );
  await Promise.allSettled([
    loadContactsBackground(),
    syncGroupsBackground(),
    syncPrivateGroupMessagesBackground(),
    loadProfileNameBackground(setup.userId),
  ]);
}

function noteIncomingGroupConversation(
  groupId: string,
  senderUserId: string,
  preview: string,
  incrementUnread: boolean
): void {
  const existing = loadGroupConversations(setup.userId).find((item) => item.groupId === groupId);
  const senderLabel = resolvePeerIdentity(senderUserId).primaryLabel;
  const state = getPrivateGroupState(groupId);
  upsertGroupConversation(
    setup.userId,
    groupId,
    state ? getPrivateGroupOwnerUserId(state) : (existing?.ownerUserId || senderUserId),
    `${senderLabel}: ${preview}`,
    incrementUnread
  );
}

async function syncGroupsBackground(): Promise<void> {
  if (!setup.userId) {
    return;
  }
  const capabilities = await loadServerCapabilitiesCached();
  if (!capabilities?.group_messaging_supported) {
    return;
  }
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildUserGroupsListAuthHeaders(k, k.userId);
    const res = await api.listUserGroups(k.userId, headers);
    const existing = new Map(loadGroupConversations(k.userId).map((item) => [item.groupId, item]));
    let changed = false;
    for (const group of res.groups) {
      if (existing.has(group.group_id)) {
        continue;
      }
      upsertGroupConversation(
        k.userId,
        group.group_id,
        group.owner_user_id,
        group.owner_user_id === k.userId ? "Group created" : "You were added to a group",
        false
      );
      changed = true;
    }
    if (changed) {
      refreshConversationsIfVisible();
    }
  } catch {
    // Best-effort - use cached groups
  }
  await syncPrivateGroupMessagesBackground();
}

async function ensureDirectChatPeerExists(peerId: string): Promise<void> {
  const normalizedPeer = await resolvePeerUserIdFromTarget(peerId);
  if (!normalizedPeer) {
    throw new Error("User ID is required");
  }
  if (normalizedPeer === setup.userId) {
    throw new Error("You can't chat with yourself");
  }

  const k = await ensureKeys();
  const api = new PqmsgApi(setup.serverUrl);
  const headers = buildProfileGetAuthHeaders(k, normalizedPeer);
  try {
    const profile = await api.getProfile(normalizedPeer, headers);
    const sealedDeliveryToken = profile.sealed_delivery_token?.trim() || "";
    if (sealedDeliveryToken) {
      cachedSealedDeliveryTokens[normalizedPeer] = sealedDeliveryToken;
    }
    const displayName = profile.display_name?.trim() || "";
    if (displayName) {
      cachedProfileNames[normalizedPeer] = displayName;
      writeProfileDisplayName(k.userId, normalizedPeer, displayName);
    }
    return;
  } catch (err) {
    if (!errorMsg(err).includes("HTTP 404")) {
      throw err;
    }
  }
  await api.getBundle(normalizedPeer);
}

async function resolvePeerUserIdFromTarget(rawTarget: string, api?: PqmsgApi): Promise<string> {
  const inviteToken = extractInviteToken(rawTarget);
  if (inviteToken) {
    return loadInvitePeerFromToken(inviteToken, api);
  }
  const resolvedTarget = parseDirectChatTarget(rawTarget).trim();
  if (!resolvedTarget) {
    return "";
  }
  if (resolvedTarget.startsWith("@")) {
    return loadUsernamePeerFromHandle(resolvedTarget, api);
  }
  return resolvedTarget.replace(/^@/, "").trim();
}

function describePeerLookupError(peerId: string, err: unknown): string {
  const message = errorMsg(err);
  if (message.includes("HTTP 404")) {
    if (peerId === "private invite") {
      return "Private invite link was not found or has expired";
    }
    return `User @${peerId} was not found on this server`;
  }
  return message;
}

function rememberInviteBundle(bundle: BundleResponse): string {
  const peerUserId = bundle.user_id.trim().replace(/^@/, "");
  if (!peerUserId) {
    throw new Error("Invite bundle did not contain a user ID");
  }
  cachedInviteBundles[peerUserId] = bundle;
  const fingerprint =
    bundle.identity_fingerprint_sha256
    || identityFingerprint(bundle.identity_x25519_pub, bundle.identity_pq_sig_pub);
  enforceIdentityPin(
    peerUserId,
    bundle.identity_x25519_pub,
    bundle.identity_sig_pub,
    bundle.identity_pq_sig_pub,
    fingerprint,
    bundle.identity_key_version,
    bundle.bundle_generated_at
  );
  return peerUserId;
}

async function loadInvitePeerFromToken(inviteToken: string, api?: PqmsgApi): Promise<string> {
  const resolvedApi = api ?? new PqmsgApi(setup.serverUrl);
  const bundle = await resolvedApi.getContactInviteBundle(inviteToken);
  return rememberInviteBundle(bundle);
}

async function loadUsernamePeerFromHandle(username: string, api?: PqmsgApi): Promise<string> {
  const resolvedApi = api ?? new PqmsgApi(setup.serverUrl);
  const bundle = await resolvedApi.getUsernameBundle(username);
  return rememberInviteBundle(bundle);
}

// ---------------------------------------------------------------------------
// 1. Onboarding — Welcome / Create / Sign-In
// ---------------------------------------------------------------------------

function renderOnboarding(): void {
  app.innerHTML = `
    <div class="onboarding">
      <div class="onboarding-card">
        ${ONBOARDING_LOGO}
        <div class="onboarding-actions">
          <button id="onb-create" class="btn-primary">Create Account</button>
          <button id="onb-signin" class="btn-secondary">I Have an Account</button>
        </div>
        <details class="onb-advanced">
          <summary>Advanced</summary>
          <label class="field">
            <span>Server URL</span>
            <input id="onb-server" type="text" value="${escHtml(setup.serverUrl)}" />
          </label>
          <button id="onb-save-server" class="btn-sm">Save</button>
        </details>
        <div class="beta-banner beta-banner-warning">
          <strong>Current beta scope</strong>
          <p>${escHtml(WEB_BETA_SCOPE_SUMMARY)}</p>
        </div>
        <p class="onboarding-note">Your keys are generated locally and never leave this device.</p>
      </div>
    </div>
  `;

  q("#onb-create").addEventListener("click", () => navigateTo({ screen: "create-account" }));
  q("#onb-signin").addEventListener("click", () => navigateTo({ screen: "sign-in" }));

  q("#onb-save-server").addEventListener("click", () => {
    const server = q<HTMLInputElement>("#onb-server").value.trim();
    if (server) {
      try {
        const parsed = validateWebServerUrl(server);
        setup.serverUrl = parsed.toString().replace(/\/+$/, "");
        saveSetup(setup);
        cachedCapabilities = null;
        cachedCapabilitiesServerUrl = null;
        notify("Server URL saved", "success");
      } catch (error) {
        notify(errorMsg(error), "error");
      }
    }
  });
}

function renderCreateAccount(): void {
  app.innerHTML = `
    <div class="onboarding">
      <div class="onboarding-card">
        ${ONBOARDING_LOGO}
        <div class="onboarding-form">
          <label class="field">
            <span>Display Name</span>
            <input id="onb-name" type="text" placeholder="Your name" autocomplete="off" />
          </label>
          <label class="field">
            <span>Password</span>
            <input id="onb-pass" type="password" placeholder="Protects your keys on this device" />
            <div id="onb-strength" class="password-strength"></div>
          </label>
          <label class="field">
            <span>Confirm Password</span>
            <input id="onb-pass2" type="password" placeholder="Re-enter password" />
          </label>
          <button id="onb-go" class="btn-primary">Create Account</button>
          <button id="onb-back" class="btn-link">← Back</button>
        </div>
        <div id="onb-progress" class="progress-bar hidden"><div class="progress-fill"></div></div>
        ${
          localAccounts.length > 0
            ? `
          <div class="contacts-section">
            <h3 class="section-label">Accounts on this browser</h3>
            <div class="contacts-list">
              ${localAccounts
                .map(
                  (accountId) => `
                <button type="button" class="contact-row" data-local-account="${escHtml(accountId)}">
                  <div class="avatar avatar-sm">${escHtml(accountId.slice(0, 2).toUpperCase())}</div>
                  <div class="contact-info">
                    <span class="contact-name">${escHtml(accountId)}</span>
                    <span class="contact-id">Tap to fill account ID</span>
                  </div>
                </button>
              `
                )
                .join("")}
            </div>
          </div>
        `
            : `<p class="onboarding-note">Only accounts created in this browser can sign in here.</p>`
        }
        <p id="onb-status" class="onboarding-status"></p>
      </div>
    </div>
  `;

  const nameInput = q<HTMLInputElement>("#onb-name");
  const passInput = q<HTMLInputElement>("#onb-pass");
  const pass2Input = q<HTMLInputElement>("#onb-pass2");
  const goBtn = q<HTMLButtonElement>("#onb-go");
  const progress = q("#onb-progress");
  const status = q("#onb-status");
  const strengthEl = q("#onb-strength");

  // Password strength indicator
  passInput.addEventListener("input", () => {
    const val = passInput.value;
    let score = 0;
    if (val.length >= 8) score++;
    if (val.length >= 12) score++;
    if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score++;
    if (/\d/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;
    const labels = ["", "Weak", "Fair", "Good", "Strong", "Very strong"];
    const colors = ["", "var(--danger)", "#f59e0b", "#eab308", "#4ade80", "#22c55e"];
    if (val.length === 0) {
      strengthEl.innerHTML = "";
    } else {
      strengthEl.innerHTML = `<div class="strength-bar"><div class="strength-fill" style="width:${score * 20}%;background:${colors[score]}"></div></div><span style="color:${colors[score]}">${labels[score]}</span>`;
    }
  });

  q("#onb-back").addEventListener("click", () => navigateTo({ screen: "onboarding" }));

  goBtn.addEventListener("click", async () => {
    const name = nameInput.value.trim();
    const pass = passInput.value;
    const pass2 = pass2Input.value;
    if (!name) { nameInput.focus(); return; }
    if (!pass) { passInput.focus(); return; }
    if (pass !== pass2) {
      status.textContent = "Passwords do not match";
      status.classList.add("error-text");
      pass2Input.focus();
      return;
    }
    if (pass.length < 6) {
      status.textContent = "Password must be at least 6 characters";
      status.classList.add("error-text");
      passInput.focus();
      return;
    }

    goBtn.disabled = true;
    status.classList.remove("error-text");
    progress.classList.remove("hidden");

    try {
      status.textContent = "Loading crypto runtime...";
      setProgress(progress, 10);
      await ensureWebPqRuntime();

      status.textContent = "Generating keys…";
      setProgress(progress, 20);
      const userId = name.toLowerCase().replace(/[^a-z0-9_-]/g, "-").slice(0, 64) || `user-${Date.now()}`;
      const deviceId = `${userId}-web-1`;
      const genKeys = generateIdentityKeys(userId, deviceId, "ml-kem-768", 16);
      await saveKeys(userId, pass, genKeys);

      status.textContent = "Registering…";
      setProgress(progress, 50);
      const api = new PqmsgApi(setup.serverUrl);
      await api.registerUser({
        user_id: genKeys.userId,
        identity_x25519_pub: genKeys.identityX25519Pub,
        identity_sig_pub: genKeys.identitySigPub,
        identity_pq_sig_pub: genKeys.identityPqSigPub,
        device_id: genKeys.deviceId,
      });

      status.textContent = "Publishing prekeys…";
      setProgress(progress, 80);
      const payload = buildPublishPrekeysPayload(genKeys);
      const headers = buildPrekeysAuthHeaders(genKeys, payload);
      await api.publishPrekeys(genKeys.userId, payload, headers);

      try {
        const profileHeaders = buildProfileUpsertAuthHeaders(genKeys, name, "", false, "", "");
        await api.upsertProfile(
          genKeys.userId,
          { display_name: name, username_lookup_enabled: false },
          profileHeaders
        );
      } catch {
        notify("Account created, but profile name could not be synced yet", "info");
      }

      setup = {
        serverUrl: setup.serverUrl,
        userId: userId,
        deviceId: deviceId,
        suiteLabel: "ml-kem-768",
        peerUserId: "",
        displayName: name,
        username: "",
        usernameLookupEnabled: false,
      };
      saveSetup(setup);
      sessionStorage.setItem("pqmsg.passphrase", pass);
      keys = genKeys;
      cachedProfileNames[userId] = name;
      writeProfileDisplayName(userId, userId, name);

      setProgress(progress, 100);
      status.textContent = "Ready!";
      notify(`Your account ID is @${userId}. Claim a shareable @username in Settings.`, "info");
      setTimeout(() => navigateTo({ screen: "conversations" }), 600);
    } catch (e) {
      status.textContent = `Error: ${errorMsg(e)}`;
      status.classList.add("error-text");
      goBtn.disabled = false;
      progress.classList.add("hidden");
    }
  });
}

function renderSignIn(): void {
  const localAccounts = listLocalKeyUsers();
  app.innerHTML = `
    <div class="onboarding">
      <div class="onboarding-card">
        ${ONBOARDING_LOGO}
        <div class="onboarding-form">
          ${
            localAccounts.length > 0
              ? `
            <div class="contacts-section">
              <h3 class="section-label">Accounts on this browser</h3>
              <div class="contacts-list">
                ${localAccounts
                  .map(
                    (accountId) => `
                  <button type="button" class="contact-row" data-local-account="${escHtml(accountId)}">
                    <div class="avatar avatar-sm">${escHtml(accountId.slice(0, 2).toUpperCase())}</div>
                    <div class="contact-info">
                      <span class="contact-name">${escHtml(accountId)}</span>
                      <span class="contact-id">Tap to fill account ID</span>
                    </div>
                  </button>
                ` 
                  )
                  .join("")}
              </div>
            </div>
          `
              : `<p class="onboarding-note">Only accounts created in this browser origin (${escHtml(location.origin)}) can be unlocked here.</p>`
          }
          <label class="field">
            <span>User ID</span>
            <input id="onb-uid" type="text" placeholder="e.g. alice-smith" autocomplete="off" />
          </label>
          <label class="field">
            <span>Password</span>
            <input id="onb-pass" type="password" placeholder="Your device password" />
          </label>
          <button id="onb-go" class="btn-primary">Sign In</button>
          <button id="onb-back" class="btn-link">← Back</button>
        </div>
        <p id="onb-status" class="onboarding-status"></p>
      </div>
    </div>
  `;

  const uidInput = q<HTMLInputElement>("#onb-uid");
  const passInput = q<HTMLInputElement>("#onb-pass");
  const goBtn = q<HTMLButtonElement>("#onb-go");
  const status = q("#onb-status");

  q("#onb-back").addEventListener("click", () => navigateTo({ screen: "onboarding" }));

  for (const button of document.querySelectorAll<HTMLElement>("[data-local-account]")) {
    button.addEventListener("click", () => {
      uidInput.value = button.dataset.localAccount || "";
      passInput.focus();
      status.textContent = "";
      status.classList.remove("error-text");
    });
  }

  goBtn.addEventListener("click", async () => {
    const uid = normalizeBrowserUserId(uidInput.value);
    const pass = passInput.value;
    if (!uidInput.value.trim()) {
      status.textContent = "Enter the account ID for an account saved in this browser.";
      status.classList.add("error-text");
      uidInput.focus();
      return;
    }
    if (!passInput.value) {
      status.textContent = "Enter the password used when creating this local account.";
      status.classList.add("error-text");
      passInput.focus();
      return;
    }
    uidInput.value = uid;

    goBtn.disabled = true;
    status.classList.remove("error-text");

    try {
      status.textContent = "Loading crypto runtime...";
      await ensureWebPqRuntime();

      if (!hasLocalKeys(uid)) {
        throw new Error("No keys found for this User ID on this device");
      }

      status.textContent = "Unlocking keys…";
      const loadedKeys = await loadKeys(uid, pass);

      setup = {
        serverUrl: setup.serverUrl,
        userId: uid,
        deviceId: loadedKeys.deviceId,
        suiteLabel: loadedKeys.suite,
        peerUserId: "",
        displayName: uid,
      };
      saveSetup(setup);
      sessionStorage.setItem("pqmsg.passphrase", pass);
      keys = loadedKeys;

      status.textContent = "Loading your chats…";
      await bootstrapIdentityData();
      status.textContent = "Signed in!";
      setTimeout(() => navigateTo({ screen: "conversations" }), 400);
    } catch (e) {
      status.textContent = errorMsg(e);
      status.classList.add("error-text");
      goBtn.disabled = false;
    }
  });
}

// ---------------------------------------------------------------------------
// 2. Conversation List
// ---------------------------------------------------------------------------

function renderConversations(): void {
  cachedProfileNames = {
    ...Object.fromEntries(loadProfileDisplayNames(setup.userId).map((item) => [item.targetUserId, item.displayName])),
    ...cachedProfileNames,
  };
  const convos = setup.userId ? loadConversations(setup.userId) : [];
  const groupConvos = setup.userId ? loadGroupConversations(setup.userId) : [];

  const metaLookup = buildConversationMetaLookup();
  const rows = buildUnifiedConversationRows(convos, groupConvos, metaLookup);
  const visibleRows = filterConversationRows(rows, activeInboxFilter);
  const counts = computeInboxCounts(rows);
  const listHtml = visibleRows.length === 0
    ? renderEmptyState(activeInboxFilter)
    : visibleRows.map((row) => renderConversationRow(row)).join("");
  const archiveToggle = activeInboxFilter === "archived"
    ? `<button id="archived-toggle" class="summary-link-btn" type="button">Back to inbox</button>`
    : counts.archived > 0
      ? `<button id="archived-toggle" class="summary-link-btn" type="button">View archived</button>`
      : "";

  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <div class="topbar-copy">
          <h1 class="topbar-title">Chats</h1>
          <p class="topbar-sub">${escHtml(setup.displayName || setup.userId)} <span class="mono">@${escHtml(setup.userId)}</span></p>
        </div>
        <div class="topbar-actions">
          <button id="conv-shortcuts" class="icon-btn" title="Keyboard shortcuts" aria-label="Keyboard shortcuts">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="6" width="18" height="12" rx="2"/>
              <path d="M7 10h.01M10 10h.01M13 10h.01M16 10h.01M7 14h10"/>
            </svg>
          </button>
          <button id="conv-search" class="icon-btn" title="Search messages" aria-label="Search messages">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
            </svg>
          </button>
          <button id="conv-settings" class="icon-btn" title="Settings" aria-label="Settings">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
            </svg>
          </button>
        </div>
      </header>
      <div class="inbox-summary" role="status" aria-live="polite">
        <span class="inbox-pill">${counts.unread > 0 ? `${counts.unread} unread` : "Protected"}</span>
        <span class="inbox-caption">Post-quantum chats stay centered here while requests, groups, and archived threads stay one tap away.</span>
        ${archiveToggle}
      </div>
      <div class="filter-chip-bar" role="tablist" aria-label="Inbox filters">
        ${renderInboxFilter("all", "All", counts.all)}
        ${renderInboxFilter("unread", "Unread", counts.unread)}
        ${renderInboxFilter("groups", "Groups", counts.groups)}
        ${renderInboxFilter("requests", "Requests", counts.requests)}
        ${renderInboxFilter("archived", "Archived", counts.archived)}
      </div>
      <div class="conversation-list" id="conv-list" role="list">
        ${listHtml}
      </div>
      <button id="fab-new" class="fab" title="New chat" aria-label="New chat">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
          <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
        </svg>
      </button>
    </div>
  `;

  q("#fab-new").addEventListener("click", () => {
    const existing = document.querySelector(".fab-menu");
    if (existing) { existing.remove(); return; }
    const menu = document.createElement("div");
    menu.className = "fab-menu";
    menu.innerHTML = `
      <button class="fab-menu-item" id="fab-new-chat">New Chat</button>
      <button class="fab-menu-item" id="fab-new-group">New Group</button>
    `;
    document.body.appendChild(menu);
    q("#fab-new-chat").addEventListener("click", () => { menu.remove(); navigateTo({ screen: "new-chat" }); });
    q("#fab-new-group").addEventListener("click", () => { menu.remove(); navigateTo({ screen: "create-group" }); });
    // Close on outside click
    setTimeout(() => document.addEventListener("click", function close(e) {
      if (!(e.target as HTMLElement).closest(".fab-menu") && !(e.target as HTMLElement).closest("#fab-new")) {
        menu.remove();
        document.removeEventListener("click", close);
      }
    }), 0);
  });
  q("#conv-search").addEventListener("click", () => navigateTo({ screen: "search" }));
  q("#conv-shortcuts").addEventListener("click", () => showKeyboardShortcutOverlay());
  q("#conv-settings").addEventListener("click", () => navigateTo({ screen: "settings" }));
  document.querySelector<HTMLButtonElement>("#archived-toggle")?.addEventListener("click", () => {
    activeInboxFilter = activeInboxFilter === "archived" ? "all" : "archived";
    renderConversations();
  });
  for (const chip of document.querySelectorAll<HTMLButtonElement>("[data-inbox-filter]")) {
    chip.addEventListener("click", () => {
      const nextFilter = (chip.dataset.inboxFilter as InboxFilter) || "all";
      if (nextFilter !== activeInboxFilter) {
        activeInboxFilter = nextFilter;
        renderConversations();
      }
    });
  }

  // Bind conversation row clicks
  for (const row of document.querySelectorAll<HTMLElement>("[data-peer]")) {
    row.addEventListener("click", () => {
      const peerId = row.dataset.peer!;
      markConversationRead(setup.userId, peerId);
      navigateTo({ screen: "chat", peerId });
    });
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        row.click();
      }
    });
  }

  // Bind group conversation row clicks
  for (const row of document.querySelectorAll<HTMLElement>("[data-group]")) {
    row.addEventListener("click", () => {
      const groupId = row.dataset.group!;
      markGroupConversationRead(setup.userId, groupId);
      navigateTo({ screen: "group-chat", groupId });
    });
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        row.click();
      }
    });
  }

  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-thread-menu]")) {
    button.addEventListener("click", (e) => {
      e.stopPropagation();
      showConversationActionMenu(
        button,
        (button.dataset.threadKind as ConversationKind) || "dm",
        button.dataset.threadId || ""
      );
    });
  }

  // Start realtime delivery on the active inbox path.
  void connectRealtime();
  if (presenceSupported()) {
    void startPresenceHeartbeat();
  }
  void loadContactsBackground();
  void syncGroupsBackground();
  void loadProfileNamesBackground(rows.filter((row) => row.kind === "dm").map((row) => row.threadId));

  // Start sealed inbox polling (Phase 4)
  if (!sealedInboxPollTimer) {
    void pollSealedInbox();
    sealedInboxPollTimer = setInterval(() => void pollSealedInbox(), 10000);
  }
  if (!groupSyncTimer) {
    groupSyncTimer = setInterval(() => void syncGroupsBackground(), 10000);
  }
}

function buildUnifiedConversationRows(
  convos: ConversationSummary[],
  groupConvos: GroupConversationSummary[],
  metaLookup: Map<string, ConversationMeta>
): UnifiedConversationRow[] {
  const dmRows = convos.map((summary) => {
    const meta = getConversationMetaCached(metaLookup, "dm", summary.peerUserId);
    const label = resolvePeerIdentity(summary.peerUserId);
    const presence = peerPresenceCache[summary.peerUserId];
    const draftText = readThreadDraft(setup.userId, "dm", summary.peerUserId).trim() || null;
    const draftUpdatedAt = readThreadDraftUpdatedAt(setup.userId, "dm", summary.peerUserId);
    return {
      kind: "dm" as const,
      threadId: summary.peerUserId,
      updatedAt: Math.max(summary.updatedAt, draftUpdatedAt),
      unreadCount: summary.unreadCount,
      lastPreview: summary.lastPreview,
      draftText,
      meta,
      primaryLabel: label.primaryLabel,
      secondaryLabel: label.secondaryLabel,
      avatarText: label.avatarText,
      presenceStatus: presenceSupported() ? presence?.status ?? null : null,
      isVerified: label.isVerified,
    };
  });
  const groupRows = groupConvos.map((summary) => {
    const meta = getConversationMetaCached(metaLookup, "group", summary.groupId);
    const label = resolveGroupIdentity(summary.groupId, summary.ownerUserId);
    const draftText = readThreadDraft(setup.userId, "group", summary.groupId).trim() || null;
    const draftUpdatedAt = readThreadDraftUpdatedAt(setup.userId, "group", summary.groupId);
    return {
      kind: "group" as const,
      threadId: summary.groupId,
      updatedAt: Math.max(summary.updatedAt, draftUpdatedAt),
      unreadCount: summary.unreadCount,
      lastPreview: summary.lastPreview,
      draftText,
      meta,
      primaryLabel: label.primaryLabel,
      secondaryLabel: label.secondaryLabel,
      avatarText: label.avatarText,
      presenceStatus: null,
      isVerified: false,
      ownerUserId: summary.ownerUserId,
    };
  });
  return [...dmRows, ...groupRows]
    .filter((row) => row.kind === "group" || row.meta.requestState !== "dismissed")
    .sort((lhs, rhs) => {
      const lhsPinned = lhs.meta.pinnedAt ?? 0;
      const rhsPinned = rhs.meta.pinnedAt ?? 0;
      if (lhsPinned !== rhsPinned) {
        return rhsPinned - lhsPinned;
      }
      return rhs.updatedAt - lhs.updatedAt;
    });
}

function filterConversationRows(rows: UnifiedConversationRow[], filter: InboxFilter): UnifiedConversationRow[] {
  return rows.filter((row) => {
    const isArchived = Boolean(row.meta.archivedAt);
    const isPending = row.kind === "dm" && row.meta.requestState === "pending";
    switch (filter) {
      case "all":
        return !isArchived && !isPending;
      case "unread":
        return !isArchived && !isPending && row.unreadCount > 0;
      case "groups":
        return row.kind === "group" && !isArchived;
      case "requests":
        return row.kind === "dm" && isPending;
      case "archived":
        return isArchived;
      default:
        return true;
    }
  });
}

function computeInboxCounts(rows: UnifiedConversationRow[]): Record<InboxFilter, number> {
  return {
    all: filterConversationRows(rows, "all").length,
    unread: filterConversationRows(rows, "unread").length,
    groups: filterConversationRows(rows, "groups").length,
    requests: filterConversationRows(rows, "requests").length,
    archived: filterConversationRows(rows, "archived").length,
  };
}

function renderInboxFilter(filter: InboxFilter, label: string, count: number): string {
  const activeClass = activeInboxFilter === filter ? " active" : "";
  const badge = count > 0 ? `<span class="filter-chip-count">${count}</span>` : "";
  return `
    <button type="button" class="filter-chip${activeClass}" data-inbox-filter="${filter}" role="tab" aria-selected="${activeInboxFilter === filter}">
      <span>${label}</span>
      ${badge}
    </button>
  `;
}

function renderEmptyState(filter: InboxFilter): string {
  const copy = filter === "requests"
    ? { title: "No message requests", body: "New chats from unknown people appear here until you accept them." }
    : filter === "archived"
      ? { title: "Archive is empty", body: "Archived chats stay out of the way until you need them." }
      : filter === "groups"
        ? { title: "No groups yet", body: "Create a group from the new chat button when you are ready." }
        : { title: "No conversations yet", body: "Start a new chat to begin a secure conversation." };
  return `
    <div class="empty-state">
      <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
        <rect width="80" height="80" rx="20" fill="#1a2d3d"/>
        <path d="M25 28h30v24H25z" fill="#2a4a5f"/>
        <circle cx="35" cy="40" r="5" fill="#4a9eff"/>
        <rect x="45" y="36" width="16" height="3" rx="1.5" fill="#4a9eff" opacity="0.7"/>
        <rect x="45" y="42" width="12" height="3" rx="1.5" fill="#4a9eff" opacity="0.4"/>
      </svg>
      <h2>${copy.title}</h2>
      <p>${copy.body}</p>
    </div>
  `;
}

function renderConversationRow(row: UnifiedConversationRow): string {
  const unread = row.unreadCount > 0 ? `<span class="badge">${row.unreadCount > 99 ? "99+" : row.unreadCount}</span>` : "";
  const stateClass = [
    row.unreadCount > 0 ? " unread" : "",
    row.meta.pinnedAt ? " pinned" : "",
    row.kind === "dm" && row.meta.requestState === "pending" ? " pending-request" : "",
  ].join("");
  const time = relativeTime(row.updatedAt);
  const presenceDot = row.kind === "dm" && row.presenceStatus && row.presenceStatus !== "offline"
    ? `<span class="presence-dot presence-${escHtml(row.presenceStatus)}"></span>`
    : "";
  const handle = row.secondaryLabel ? `<span class="conv-handle">${escHtml(row.secondaryLabel)}</span>` : "";
  const draftPrefix = row.draftText ? `<span class="conv-preview-prefix">Draft</span>` : "";
  const previewText = row.draftText || row.lastPreview;
  const verified = row.isVerified ? `<span class="verified-badge" title="Trusted identity">✓</span>` : "";
  const requestBadge = row.kind === "dm" && row.meta.requestState === "pending"
    ? `<span class="conv-state-badge">Request</span>`
    : "";
  const pinBadge = row.meta.pinnedAt ? `<span class="conv-state-badge subtle">Pinned</span>` : "";
  const kindBadge = row.kind === "group" ? `<span class="conv-state-badge subtle">Group</span>` : "";
  const targetAttrs = row.kind === "dm"
    ? `data-peer="${escHtml(row.threadId)}"`
    : `data-group="${escHtml(row.threadId)}"`;
  return `
    <div class="conv-row${stateClass}" role="button" tabindex="0" ${targetAttrs}>
      <div class="avatar-wrap">
        <div class="avatar${row.kind === "group" ? " avatar-group" : ""}">${escHtml(row.avatarText)}</div>
        ${presenceDot}
      </div>
      <div class="conv-info">
        <div class="conv-top">
          <div class="conv-heading">
            <span class="conv-name">${escHtml(row.primaryLabel)}</span>
            ${verified}
            ${requestBadge}
            ${pinBadge}
            ${kindBadge}
          </div>
          <span class="conv-time">${time}</span>
        </div>
        <div class="conv-bottom">
          ${draftPrefix}
          <span class="conv-preview${row.draftText ? " conv-preview-draft" : ""}">${escHtml(previewText)}</span>
          ${handle}
        </div>
      </div>
      <div class="conv-row-side">
        ${unread}
        <button
          type="button"
          class="icon-btn conv-row-menu"
          data-thread-menu="1"
          data-thread-kind="${row.kind}"
          data-thread-id="${escHtml(row.threadId)}"
          aria-label="Conversation actions"
          title="Conversation actions"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/>
          </svg>
        </button>
      </div>
    </div>
  `;
}

function showConversationActionMenu(anchor: HTMLElement, kind: ConversationKind, threadId: string): void {
  document.querySelector(".ctx-menu")?.remove();
  const meta = loadConversationMeta(setup.userId, kind, threadId);
  const unreadCount = readConversationUnreadCount(kind, threadId);
  const items: Array<{ label: string; className?: string; action: () => void }> = [
    {
      label: unreadCount > 0 ? "Mark read" : "Mark unread",
      action: () => {
        const nextUnread = unreadCount === 0;
        setConversationUnread(kind, threadId, nextUnread);
        notify(nextUnread ? "Marked unread" : "Marked read", "success");
        refreshConversationsIfVisible();
      },
    },
    {
      label: meta.pinnedAt ? "Unpin" : "Pin",
      action: () => {
        toggleConversationPinned(kind, threadId);
        notify(meta.pinnedAt ? "Chat unpinned" : "Chat pinned", "success");
        refreshConversationsIfVisible();
      },
    },
    {
      label: meta.archivedAt ? "Unarchive" : "Archive",
      action: () => {
        const archived = !meta.archivedAt;
        setConversationArchived(kind, threadId, archived);
        notifyArchiveChange(kind, threadId, archived);
        refreshConversationsIfVisible();
      },
    },
  ];
  if (kind === "dm" && meta.requestState === "pending") {
    items.unshift(
      {
        label: "Accept",
        action: () => {
          markConversationAccepted(threadId);
          refreshConversationsIfVisible();
        },
      },
      {
        label: "Dismiss",
        className: "ctx-danger",
        action: () => {
          markConversationDismissed(threadId);
          refreshConversationsIfVisible();
        },
      }
    );
  }

  const menu = document.createElement("div");
  menu.className = "ctx-menu";
  menu.innerHTML = items
    .map(
      (item, index) =>
        `<div class="ctx-item ${item.className ?? ""}" data-conv-action="${index}">${escHtml(item.label)}</div>`
    )
    .join("");
  document.body.appendChild(menu);
  const rect = anchor.getBoundingClientRect();
  menu.style.top = `${Math.min(window.innerHeight - menu.offsetHeight - 12, rect.bottom + 4)}px`;
  menu.style.left = `${Math.max(12, rect.right - 180)}px`;

  for (const item of menu.querySelectorAll<HTMLElement>("[data-conv-action]")) {
    item.addEventListener("click", () => {
      const idx = Number(item.dataset.convAction);
      menu.remove();
      items[idx]?.action();
    });
  }

  setTimeout(() => {
    document.addEventListener("click", function closeMenu(event) {
      if (!(event.target as HTMLElement).closest(".ctx-menu")) {
        menu.remove();
        document.removeEventListener("click", closeMenu);
      }
    });
  }, 0);
}

// ---------------------------------------------------------------------------
// 3. Chat view
// ---------------------------------------------------------------------------

async function renderChat(peerId: string): Promise<void> {
  const contact = cachedContacts.find((item) => item.contact_user_id === peerId);
  const identity = resolvePeerIdentity(peerId);
  const displayName = identity.primaryLabel;
  const meta = loadConversationMeta(setup.userId, "dm", peerId);
  const identityPin = readIdentityPin(setup.userId, peerId);
  const transparencyCheckpoint = readTransparencyCheckpoint(setup.serverUrl, peerId);
  let directMessagingReady = isPqSessionMessagingAvailable();
  if (!directMessagingReady) {
    directMessagingReady = (await initWasmCrypto()) && isPqSessionMessagingAvailable();
  }
  const presence = peerPresenceCache[peerId];
  const presenceText = presenceSupported()
    ? presence?.status === "online"
      ? "online"
      : presence?.status === "away"
        ? "away"
        : "encrypted"
    : "metadata minimized";
  const presenceClass = presenceSupported()
    ? presence?.status === "online"
      ? "presence-online"
      : presence?.status === "away"
        ? "presence-away"
        : ""
    : "";
  const fingerprintSummary = identityPin?.fingerprintSha256 || "Not pinned yet";
  const verifiedBySafetyNumber = isContactFingerprintVerified(contact, identityPin);
  const trustSummary = verifiedBySafetyNumber
    ? "Verified via safety number"
    : identityPin
      ? "Trusted on this device"
      : "Unverified";
  const transparencySummary = transparencyCheckpoint
    ? `Transparency auto-verified in tree #${transparencyCheckpoint.tree_size}`
    : "Transparency auto-check runs before encrypted traffic.";
  let safetyNumber = "";
  if (identityPin?.identityPqSigPub?.trim() && directMessagingReady && hasLocalKeys(setup.userId)) {
    try {
      const localKeys = await ensureKeys();
      safetyNumber = computeSafetyNumber(
        localKeys,
        peerId,
        identityPin.identityX25519Pub,
        identityPin.identityPqSigPub
      );
    } catch {
      safetyNumber = "";
    }
  }
  const safetyNumberSummary = identityPin
    ? safetyNumber || "Unavailable until a fresh hybrid identity bundle is observed."
    : "Available after the first peer bundle is pinned.";
  const verifySafetyLabel = verifiedBySafetyNumber ? "View Safety Number" : "Verify Safety Number";
  const directMessagingBlockedReason = directMessagingReady
    ? ""
    : "Web post-quantum runtime is unavailable in this build, so direct messages cannot be sent yet.";
  const requestBanner = meta.requestState === "pending"
    ? `
      <div class="request-banner">
        <div>
          <strong>Message request</strong>
          <p>${escHtml(displayName)} is not in your trusted chats yet.</p>
        </div>
        <div class="request-banner-actions">
          <button id="request-dismiss" class="btn-secondary">Dismiss</button>
          <button id="request-accept" class="btn-sm">Accept</button>
        </div>
      </div>
    `
    : "";

  app.innerHTML = `
    <div class="chat-shell">
      <header class="chat-header">
        <button id="chat-back" class="icon-btn" aria-label="Back to conversations">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <div class="avatar-wrap">
          <div class="avatar avatar-sm">${identity.avatarText}</div>
          ${presenceClass ? `<span class="presence-dot ${presenceClass}"></span>` : ""}
        </div>
        <div class="chat-header-info">
          <span class="chat-header-name">${escHtml(displayName)}</span>
          <span class="chat-header-status ${presenceClass}" id="chat-status">${presenceText}${identity.secondaryLabel ? ` · ${escHtml(identity.secondaryLabel)}` : ""}</span>
        </div>
        <button id="chat-search" class="icon-btn" title="Search in conversation" aria-label="Search in conversation">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path>
          </svg>
        </button>
        <button id="chat-shortcuts" class="icon-btn" title="Keyboard shortcuts" aria-label="Keyboard shortcuts">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="5" width="18" height="14" rx="2"/>
            <path d="M7 9h.01M10 9h.01M13 9h.01M16 9h.01M8 13h8M7 16h4"/>
          </svg>
        </button>
        <button id="chat-details-toggle" class="icon-btn" title="Chat details" aria-label="Chat details">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>
          </svg>
        </button>
      </header>
      ${requestBanner}
      <div class="chat-context-strip" role="status" aria-live="polite">
        <span class="context-pill context-pill-secure">${escHtml(trustSummary)}</span>
        <span class="context-pill">${escHtml(transparencySummary)}</span>
        <span class="context-pill">${escHtml(presenceText)}</span>
        <button id="chat-open-details-inline" type="button" class="context-pill context-pill-link">Privacy & send defaults</button>
      </div>
      <div id="thread-search-bar" class="thread-search-bar hidden" role="search">
        <input id="thread-search-input" type="text" class="thread-search-input" placeholder="Search in conversation" autocomplete="off" aria-label="Search in conversation" />
        <span id="thread-search-count" class="thread-search-count"></span>
        <div class="thread-search-actions">
          <button id="thread-search-prev" class="icon-btn" title="Previous result" aria-label="Previous result">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="m15 18-6-6 6-6"/>
            </svg>
          </button>
          <button id="thread-search-next" class="icon-btn" title="Next result" aria-label="Next result">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="m9 18 6-6-6-6"/>
            </svg>
          </button>
          <button id="thread-search-close" class="icon-btn" title="Close search" aria-label="Close search">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
              <path d="M18 6L6 18M6 6l12 12"/>
            </svg>
          </button>
        </div>
      </div>
      ${directMessagingBlockedReason ? `
        <div class="beta-banner beta-banner-warning chat-holdback-banner">
          <strong>Direct messaging unavailable</strong>
          <p>${escHtml(directMessagingBlockedReason)}</p>
        </div>
      ` : ""}
      ${typingIndicatorsSupported() ? `
        <div id="typing-indicator" class="typing-indicator hidden">
          <span class="typing-dots"><span></span><span></span><span></span></span>
          <span class="typing-text">${escHtml(displayName)} is typing</span>
        </div>
      ` : ""}
      <div id="message-selection-bar" class="message-selection-bar hidden">
        <span id="message-selection-count" class="message-selection-count">0 selected</span>
        <div class="message-selection-actions">
          <button id="message-selection-copy" class="btn-secondary">Copy</button>
          <button id="message-selection-share" class="btn-secondary">Share</button>
          <button id="message-selection-delete" class="btn-secondary danger-lite">Delete</button>
          <button id="message-selection-close" class="btn-secondary">Close</button>
        </div>
      </div>
      <div id="chat-details-sheet" class="chat-details-sheet hidden">
        <div class="chat-details-card">
          <div class="chat-details-head">
            <div>
              <h3>${escHtml(displayName)}</h3>
              <p>${identity.secondaryLabel ? escHtml(identity.secondaryLabel) : "Direct message"}</p>
            </div>
            <button id="chat-details-close" class="icon-btn" aria-label="Close details">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18 6 6 18M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <div class="chat-details-row"><span>Trust</span><strong>${escHtml(trustSummary)}</strong></div>
          <div class="chat-details-row"><span>Transparency</span><strong>${escHtml(transparencySummary)}</strong></div>
          <div class="chat-details-row column"><span>Identity fingerprint</span><span class="mono fingerprint">${escHtml(fingerprintSummary)}</span></div>
          <div class="chat-details-row column"><span>Safety number</span><span class="mono fingerprint">${escHtml(safetyNumberSummary)}</span></div>
          <div class="chat-details-row">
            <span>Sealed sender</span>
            <strong>Required</strong>
          </div>
          <div class="chat-details-row">
            <span>Disappearing messages</span>
            <strong>Unavailable</strong>
          </div>
          <div class="chat-details-row">
            <span>Shared media</span>
            <strong id="detail-shared-media-count">0 items</strong>
          </div>
          <div class="chat-details-actions">
            <button id="detail-shared-media" class="btn-secondary">Shared media</button>
            <button id="detail-verify-safety" class="btn-secondary" ${identityPin ? "" : "disabled"}>${verifySafetyLabel}</button>
            <button id="detail-pin" class="btn-secondary">${meta.pinnedAt ? "Unpin Chat" : "Pin Chat"}</button>
            <button id="detail-archive" class="btn-secondary">${meta.archivedAt ? "Unarchive" : "Archive"}</button>
          </div>
        </div>
      </div>
      <div class="messages-container" id="messages-container">
        <div class="messages" id="messages-list" role="log" aria-live="polite"></div>
      </div>
      <div id="attachment-preview" class="attachment-preview hidden" aria-live="polite"></div>
      <div id="chat-emoji-tray" class="emoji-tray hidden" aria-label="Quick emoji"></div>
      <div id="chat-input-bar" class="chat-input-bar">
        <button id="chat-emoji" class="icon-btn attach-btn" title="Insert emoji" aria-label="Insert emoji">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="9"/>
            <path d="M8.5 15a5 5 0 0 0 7 0"/>
            <path d="M9 10h.01M15 10h.01"/>
          </svg>
        </button>
        <button id="chat-attach" class="icon-btn attach-btn" title="Attach file" aria-label="Attach file">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/>
          </svg>
        </button>
        <button id="chat-expand-compose" class="icon-btn attach-btn" title="Expand composer" aria-label="Expand composer">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>
          </svg>
        </button>
        <textarea id="chat-input" class="chat-compose-input" rows="1" placeholder="Write a message" aria-label="Message"></textarea>
        <button id="chat-send" class="send-btn" disabled aria-label="Send message">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor">
            <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
          </svg>
        </button>
        <input id="file-input" type="file" class="hidden" />
      </div>
      <div id="attachment-sheet" class="attachment-sheet hidden" aria-hidden="true">
        <div class="attachment-sheet-card" role="dialog" aria-modal="true" aria-labelledby="attachment-sheet-title">
          <div class="attachment-sheet-head">
            <div>
              <h3 id="attachment-sheet-title">Share something</h3>
              <p>Choose what to send in this chat.</p>
            </div>
            <button id="attachment-sheet-close" class="icon-btn" aria-label="Close attachment options">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
                <path d="M18 6L6 18M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <div class="attachment-sheet-grid">
            <button class="attachment-option" data-attach-kind="camera">
              <span class="attachment-option-icon camera">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M4 7h4l2-2h4l2 2h4a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2z"/>
                  <circle cx="12" cy="13" r="4"/>
                </svg>
              </span>
              <span class="attachment-option-copy">
                <strong>Camera</strong>
                <span>Capture a photo or video</span>
              </span>
            </button>
            <button class="attachment-option" data-attach-kind="media">
              <span class="attachment-option-icon media">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="4" width="18" height="16" rx="3"/>
                  <circle cx="9" cy="10" r="2"/>
                  <path d="M21 16l-4.5-4.5L7 21"/>
                </svg>
              </span>
              <span class="attachment-option-copy">
                <strong>Photos & Videos</strong>
                <span>Pick from your library</span>
              </span>
            </button>
            <button class="attachment-option" data-attach-kind="audio">
              <span class="attachment-option-icon audio">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 4a3 3 0 0 1 3 3v5a3 3 0 0 1-6 0V7a3 3 0 0 1 3-3z"/>
                  <path d="M19 11a7 7 0 0 1-14 0"/>
                  <path d="M12 18v3"/>
                </svg>
              </span>
              <span class="attachment-option-copy">
                <strong>Audio</strong>
                <span>Share a sound file</span>
              </span>
            </button>
            <button class="attachment-option" data-attach-kind="document">
              <span class="attachment-option-icon document">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7z"/>
                  <path d="M14 2v5h5"/>
                  <path d="M9 13h6M9 17h6"/>
                </svg>
              </span>
              <span class="attachment-option-copy">
                <strong>Document</strong>
                <span>Browse files and folders</span>
              </span>
            </button>
          </div>
          <div class="attachment-sheet-actions">
            <button id="attachment-sheet-cancel" class="btn-secondary">Cancel</button>
          </div>
        </div>
      </div>
      <div id="chat-expanded-compose" class="expanded-compose-sheet hidden" aria-hidden="true">
        <div class="expanded-compose-card" role="dialog" aria-modal="true" aria-labelledby="chat-expanded-title">
          <div class="expanded-compose-head">
            <div>
              <h3 id="chat-expanded-title">Expanded composer</h3>
              <p>Use Shift+Enter for a new line and Ctrl+Enter to send.</p>
            </div>
            <button id="chat-expanded-close" class="icon-btn" aria-label="Close expanded composer">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
                <path d="M18 6L6 18M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <textarea id="chat-expanded-input" class="expanded-compose-input" rows="6" placeholder="Write a message"></textarea>
          <div class="expanded-compose-actions">
            <button id="chat-expanded-send" class="btn-primary">Send</button>
          </div>
        </div>
      </div>
    </div>
  `;

  const msgList = q("#messages-list");
  const container = q("#messages-container");
  const conversationId = convId(setup.userId, peerId);
  msgList.dataset.conversationId = conversationId;
  const input = q<HTMLTextAreaElement>("#chat-input");
  const sendBtn = q<HTMLButtonElement>("#chat-send");
  const selectionBar = q<HTMLElement>("#message-selection-bar");
  const selectionCount = q<HTMLElement>("#message-selection-count");
  const selectionCopyBtn = q<HTMLButtonElement>("#message-selection-copy");
  const selectionShareBtn = q<HTMLButtonElement>("#message-selection-share");
  const selectionDeleteBtn = q<HTMLButtonElement>("#message-selection-delete");
  const selectionCloseBtn = q<HTMLButtonElement>("#message-selection-close");
  const inputBar = q<HTMLElement>("#chat-input-bar");
  const threadSearchBar = q<HTMLElement>("#thread-search-bar");
  const threadSearchInput = q<HTMLInputElement>("#thread-search-input");
  const threadSearchCount = q<HTMLElement>("#thread-search-count");
  const threadSearchPrev = q<HTMLButtonElement>("#thread-search-prev");
  const threadSearchNext = q<HTMLButtonElement>("#thread-search-next");
  const threadSearchClose = q<HTMLButtonElement>("#thread-search-close");
  const emojiBtn = q<HTMLButtonElement>("#chat-emoji");
  const attachBtn = q<HTMLButtonElement>("#chat-attach");
  const expandComposeBtn = q<HTMLButtonElement>("#chat-expand-compose");
  const fileInput = q<HTMLInputElement>("#file-input");
  const detailsSheet = q("#chat-details-sheet");
  const inlineDetailsBtn = q<HTMLButtonElement>("#chat-open-details-inline");
  const detailSharedMediaBtn = q<HTMLButtonElement>("#detail-shared-media");
  const detailSharedMediaCount = q<HTMLElement>("#detail-shared-media-count");
  const attachmentSheet = q("#attachment-sheet");
  const attachmentPreview = q("#attachment-preview");
  const emojiTray = q("#chat-emoji-tray");
  const expandedComposeSheet = q<HTMLElement>("#chat-expanded-compose");
  const expandedComposeInput = q<HTMLTextAreaElement>("#chat-expanded-input");
  const expandedComposeClose = q<HTMLButtonElement>("#chat-expanded-close");
  const expandedComposeSend = q<HTMLButtonElement>("#chat-expanded-send");
  let sendInFlight = false;
  const useSealed = true;
  let pendingAttachmentFile: File | null = null;
  let pendingAttachmentPreviewUrl: string | null = null;
  const initialDraft = readThreadDraft(setup.userId, "dm", peerId);
  if (initialDraft) {
    input.value = initialDraft;
    expandedComposeInput.value = initialDraft;
    autoResizeComposeField(input);
    autoResizeComposeField(expandedComposeInput);
  }
  const syncSelection = async (): Promise<void> => {
    await syncMessageSelectionUi(
      conversationId,
      msgList,
      selectionBar,
      selectionCount,
      inputBar,
      attachmentPreview,
    );
  };
  const syncSendAvailability = (): void => {
    const busy = sendInFlight;
    const allowEmptyEdit = Boolean(editContext?.allowEmptyText);
    sendBtn.disabled = !directMessagingReady || (!input.value.trim() && !pendingAttachmentFile && !allowEmptyEdit) || busy;
    attachBtn.disabled = busy;
    emojiBtn.disabled = busy;
    expandComposeBtn.disabled = busy;
    expandedComposeSend.disabled = sendBtn.disabled;
  };
  const syncComposeValue = (value: string, persist = true): void => {
    if (input.value !== value) {
      input.value = value;
    }
    if (expandedComposeInput.value !== value) {
      expandedComposeInput.value = value;
    }
    autoResizeComposeField(input);
    autoResizeComposeField(expandedComposeInput);
    syncSendAvailability();
    if (persist) {
      writeThreadDraft(setup.userId, "dm", peerId, value);
    }
  };
  const resetSendButton = (): void => {
    sendBtn.textContent = "";
    sendBtn.innerHTML = `<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>`;
  };
  const refreshDirectConversationAfterLocalDelete = (history: StoredMessage[]): void => {
    const latest = history.at(-1);
    const existing = loadConversations(setup.userId).find((item) => item.peerUserId === peerId);
    upsertConversation(
      setup.userId,
      peerId,
      latest ? directConversationPreview(latest) : "No messages yet",
      false,
      latest?.timestamp ?? existing?.updatedAt ?? Date.now(),
    );
    refreshConversationsIfVisible();
  };
  const deleteMessagesFromDevice = async (ids: string[]): Promise<void> => {
    if (ids.length === 0) {
      return;
    }
    await deleteMessages(ids);
    if (replyContext && ids.includes(replyContext.msgId)) {
      replyContext = null;
      document.querySelector(".reply-compose-bar")?.remove();
    }
    if (editContext && ids.includes(editContext.msgId)) {
      editContext = null;
      resetSendButton();
      syncComposeValue("");
    }
    clearMessageSelection(conversationId);
    const history = await getMessages(conversationId);
    renderMessageList(msgList, history);
    refreshDirectConversationAfterLocalDelete(history);
    syncThreadSearch(false);
    await syncSelection();
  };
  const openExpandedComposer = (): void => {
    expandedComposeSheet.classList.remove("hidden");
    expandedComposeSheet.setAttribute("aria-hidden", "false");
    syncComposeValue(input.value, false);
    expandedComposeInput.focus();
    const pos = expandedComposeInput.value.length;
    expandedComposeInput.setSelectionRange(pos, pos);
  };
  const closeExpandedComposer = (focusComposer = true): void => {
    syncComposeValue(expandedComposeInput.value);
    expandedComposeSheet.classList.add("hidden");
    expandedComposeSheet.setAttribute("aria-hidden", "true");
    if (focusComposer) {
      input.focus();
    }
  };
  let threadSearchIndex = 0;
  const syncThreadSearch = (scrollToActive = true): void => {
    if (threadSearchBar.classList.contains("hidden")) {
      msgList.dataset.threadSearchQuery = "";
      msgList.dataset.threadSearchActiveId = "";
      refreshThreadSearchDecorations(msgList);
      return;
    }
    const query = threadSearchInput.value.trim();
    msgList.dataset.threadSearchQuery = query;
    if (!query) {
      msgList.dataset.threadSearchActiveId = "";
      refreshThreadSearchDecorations(msgList);
      threadSearchCount.textContent = "Type to search this conversation";
      threadSearchPrev.disabled = true;
      threadSearchNext.disabled = true;
      return;
    }
    let matches = refreshThreadSearchDecorations(msgList);
    if (matches.length === 0) {
      threadSearchIndex = 0;
      msgList.dataset.threadSearchActiveId = "";
      refreshThreadSearchDecorations(msgList);
      threadSearchCount.textContent = "No matches";
      threadSearchPrev.disabled = true;
      threadSearchNext.disabled = true;
      return;
    }
    if (threadSearchIndex >= matches.length) {
      threadSearchIndex = 0;
    }
    const activeId = matches[threadSearchIndex];
    msgList.dataset.threadSearchActiveId = activeId;
    matches = refreshThreadSearchDecorations(msgList);
    threadSearchCount.textContent = `${threadSearchIndex + 1} of ${matches.length}`;
    threadSearchPrev.disabled = matches.length < 2;
    threadSearchNext.disabled = matches.length < 2;
    if (scrollToActive) {
      msgList.querySelector<HTMLElement>(`#msg-${CSS.escape(activeId)}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };
  const openThreadSearch = (): void => {
    if (isMessageSelectionActive(conversationId)) {
      clearMessageSelection(conversationId);
      void syncSelection();
    }
    threadSearchBar.classList.remove("hidden");
    threadSearchInput.focus();
    threadSearchInput.select();
    syncThreadSearch(false);
  };
  const closeThreadSearch = (focusComposer = true): void => {
    threadSearchIndex = 0;
    threadSearchInput.value = "";
    threadSearchBar.classList.add("hidden");
    msgList.dataset.threadSearchQuery = "";
    msgList.dataset.threadSearchActiveId = "";
    refreshThreadSearchDecorations(msgList);
    threadSearchCount.textContent = "";
    threadSearchPrev.disabled = true;
    threadSearchNext.disabled = true;
    if (focusComposer) {
      input.focus();
    }
  };
  const moveThreadSearch = (delta: number): void => {
    const query = threadSearchInput.value.trim();
    if (!query) {
      return;
    }
    const matches = refreshThreadSearchDecorations(msgList);
    if (matches.length === 0) {
      return;
    }
    threadSearchIndex = (threadSearchIndex + delta + matches.length) % matches.length;
    syncThreadSearch();
  };
  const updateInputPlaceholder = (): void => {
    input.placeholder = pendingAttachmentFile ? "Add a caption" : "Write a message";
  };
  const clearPendingAttachment = (): void => {
    if (pendingAttachmentPreviewUrl) {
      URL.revokeObjectURL(pendingAttachmentPreviewUrl);
      pendingAttachmentPreviewUrl = null;
    }
    pendingAttachmentFile = null;
    attachmentPreview.classList.add("hidden");
    attachmentPreview.innerHTML = "";
    updateInputPlaceholder();
    syncSendAvailability();
    void syncSelection();
  };
  const renderAttachmentPreview = (): void => {
    if (!pendingAttachmentFile) {
      attachmentPreview.classList.add("hidden");
      attachmentPreview.innerHTML = "";
      updateInputPlaceholder();
      syncSendAvailability();
      void syncSelection();
      return;
    }
    if (pendingAttachmentPreviewUrl) {
      URL.revokeObjectURL(pendingAttachmentPreviewUrl);
      pendingAttachmentPreviewUrl = null;
    }
    const file = pendingAttachmentFile;
    const mime = file.type || "application/octet-stream";
    const kindLabel = describeAttachmentKind(mime);
    if (mime.startsWith("image/") || mime.startsWith("video/") || mime.startsWith("audio/")) {
      pendingAttachmentPreviewUrl = URL.createObjectURL(file);
    }
    const mediaPreview = mime.startsWith("image/") && pendingAttachmentPreviewUrl
      ? `<img src="${pendingAttachmentPreviewUrl}" alt="${escHtml(file.name)}" class="attachment-preview-thumb" />`
      : mime.startsWith("video/") && pendingAttachmentPreviewUrl
        ? `<video class="attachment-preview-thumb" src="${pendingAttachmentPreviewUrl}" muted playsinline></video>`
        : mime.startsWith("audio/") && pendingAttachmentPreviewUrl
          ? `<audio class="attachment-preview-audio" controls src="${pendingAttachmentPreviewUrl}"></audio>`
          : `<div class="attachment-preview-icon">${escHtml(kindLabel.slice(0, 1))}</div>`;
    attachmentPreview.classList.remove("hidden");
    attachmentPreview.innerHTML = `
      <div class="attachment-preview-card">
        ${mediaPreview}
        <div class="attachment-preview-copy">
          <strong>${escHtml(file.name)}</strong>
          <span>${escHtml(kindLabel)} - ${formatFileSize(file.size)}</span>
        </div>
        <button id="attachment-preview-clear" class="icon-btn" type="button" aria-label="Remove attachment">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M18 6L6 18M6 6l12 12"/>
          </svg>
        </button>
      </div>
    `;
    q("#attachment-preview-clear").addEventListener("click", clearPendingAttachment);
    updateInputPlaceholder();
    syncSendAvailability();
    void syncSelection();
  };
  const insertQuickEmoji = (emoji: string): void => {
    const activeField = !expandedComposeSheet.classList.contains("hidden") ? expandedComposeInput : input;
    const start = activeField.selectionStart ?? activeField.value.length;
    const end = activeField.selectionEnd ?? start;
    const nextValue = `${activeField.value.slice(0, start)}${emoji}${activeField.value.slice(end)}`;
    syncComposeValue(nextValue);
    const nextPos = start + emoji.length;
    activeField.focus();
    activeField.setSelectionRange(nextPos, nextPos);
  };
  emojiTray.innerHTML = ["😀", "❤️", "👍", "🎉", "🔥", "😮", "😭", "🙏"]
    .map((emoji) => `<button type="button" class="emoji-chip" data-emoji="${emoji}" aria-label="Insert ${emoji}">${emoji}</button>`)
    .join("");

  q("#chat-back").addEventListener("click", () => {
    clearMessageSelection(conversationId);
    clearPendingAttachment();
    activeChatPeer = null;
    stopChatTimers();
    navigateTo({ screen: "conversations" });
  });

  q("#chat-details-toggle").addEventListener("click", () => {
    detailsSheet.classList.remove("hidden");
  });
  q("#chat-search").addEventListener("click", () => {
    openThreadSearch();
  });
  q("#chat-shortcuts").addEventListener("click", () => {
    showKeyboardShortcutOverlay();
  });
  inlineDetailsBtn.addEventListener("click", () => {
    detailsSheet.classList.remove("hidden");
  });
  q("#chat-details-close").addEventListener("click", () => {
    detailsSheet.classList.add("hidden");
  });
  detailSharedMediaBtn.addEventListener("click", () => {
    detailsSheet.classList.add("hidden");
    void showSharedMediaSheet({
      title: `${displayName} shared media`,
      conversationId,
      emptyMessage: "No shared media in this chat yet.",
    });
  });
  threadSearchInput.addEventListener("input", () => {
    threadSearchIndex = 0;
    syncThreadSearch(false);
  });
  threadSearchInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      moveThreadSearch(event.shiftKey ? -1 : 1);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      closeThreadSearch(false);
    }
  });
  threadSearchPrev.addEventListener("click", () => moveThreadSearch(-1));
  threadSearchNext.addEventListener("click", () => moveThreadSearch(1));
  threadSearchClose.addEventListener("click", () => closeThreadSearch());
  detailsSheet.addEventListener("click", (e) => {
    if (e.target === detailsSheet) {
      detailsSheet.classList.add("hidden");
    }
  });
  q("#detail-pin").addEventListener("click", () => {
    const next = toggleConversationPinned("dm", peerId);
    notify(next.pinnedAt ? "Chat pinned" : "Chat unpinned", "success");
    refreshConversationsIfVisible();
    void renderChat(peerId);
  });
  q("#detail-verify-safety").addEventListener("click", () => {
    void (async () => {
      try {
        await verifyPeerSafetyNumber(peerId);
      } catch (error) {
        notify(`Safety-number verification failed: ${errorMsg(error)}`, "error");
      }
    })();
  });
  q("#detail-archive").addEventListener("click", () => {
    const archived = !meta.archivedAt;
    setConversationArchived("dm", peerId, archived);
    notifyArchiveChange("dm", peerId, archived);
    navigateTo({ screen: "conversations" });
  });
  const requestAcceptBtn = document.getElementById("request-accept");
  requestAcceptBtn?.addEventListener("click", () => {
    markConversationAccepted(peerId);
    notify("Message request accepted", "success");
    void renderChat(peerId);
    refreshConversationsIfVisible();
  });
  const requestDismissBtn = document.getElementById("request-dismiss");
  requestDismissBtn?.addEventListener("click", () => {
    markConversationDismissed(peerId);
    notify("Message request dismissed", "info");
    navigateTo({ screen: "conversations" });
  });

  emojiBtn.addEventListener("click", () => {
    emojiTray.classList.toggle("hidden");
  });
  expandComposeBtn.addEventListener("click", () => {
    openExpandedComposer();
  });
  expandedComposeClose.addEventListener("click", () => closeExpandedComposer());
  expandedComposeSend.addEventListener("click", () => {
    syncComposeValue(expandedComposeInput.value);
    sendBtn.click();
  });
  expandedComposeSheet.addEventListener("click", (event) => {
    if (event.target === expandedComposeSheet) {
      closeExpandedComposer();
    }
  });
  for (const button of emojiTray.querySelectorAll<HTMLButtonElement>("[data-emoji]")) {
    button.addEventListener("click", () => insertQuickEmoji(button.dataset.emoji || ""));
  }

  // Enable send when input has content
  input.addEventListener("input", () => {
    syncComposeValue(input.value);
    sendTypingIndicator(peerId, true);
  });
  expandedComposeInput.addEventListener("input", () => {
    syncComposeValue(expandedComposeInput.value);
    sendTypingIndicator(peerId, true);
  });
  input.addEventListener("focus", () => {
    emojiTray.classList.add("hidden");
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.repeat && !sendBtn.disabled && !sendInFlight) {
      e.preventDefault();
      sendBtn.click();
    }
  });
  expandedComposeInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && event.ctrlKey && !expandedComposeSend.disabled && !sendInFlight) {
      event.preventDefault();
      expandedComposeSend.click();
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      closeExpandedComposer(false);
    }
  });

  syncSendAvailability();
  updateInputPlaceholder();
  autoResizeComposeField(input);
  autoResizeComposeField(expandedComposeInput);

  // Send message with optimistic UI
  sendBtn.addEventListener("click", async () => {
    const text = input.value.trim();
    const attachment = pendingAttachmentFile;
    const canSubmitEmptyEdit = Boolean(editContext?.allowEmptyText);
    if ((!text && !attachment && !canSubmitEmptyEdit) || sendInFlight) return;
    if (!(await ensureWebMessagingAllowed("direct"))) return;
    if (editContext && attachment) {
      notify("Finish editing before adding media", "info");
      return;
    }
    sendInFlight = true;
    syncSendAvailability();
    try {
      // Handle edit mode
      if (editContext) {
        const { msgId } = editContext;
        editContext = null;
        resetSendButton();
        const updated = await editStoredMessage(msgId, text);
        if (updated) {
          const history = await getMessages(conversationId);
          renderMessageList(msgList, history);
          const latest = history.at(-1);
          if (latest) {
            upsertConversation(
              setup.userId,
              peerId,
              directConversationPreview(latest),
              false,
              latest.timestamp,
            );
            refreshConversationsIfVisible();
          }
        }
        input.value = "";
        syncComposeValue("");
        return;
      }

      const replyMeta = replyContext ? { ...replyContext } : null;
      if (replyContext) {
        replyContext = null;
        document.querySelector(".reply-compose-bar")?.remove();
      }

      markConversationAccepted(peerId);
      setConversationArchived("dm", peerId, false);

      if (attachment) {
        try {
          const k = await ensureKeys();
          const api = new PqmsgApi(setup.serverUrl);
          const buf = await attachment.arrayBuffer();
          const base64 = arrayBufferToBase64(buf);
          const mimeType = attachment.type || "application/octet-stream";
          const headers = buildFileUploadAuthHeaders(k, peerId, mimeType, base64);
          const res = await api.uploadFile({
            recipient_user_id: peerId,
            device_id: k.deviceId,
            mime_type: mimeType,
            file_bytes_base64: base64,
          }, headers);
          const tempId = `local-${Date.now()}-${Math.random().toString(36).slice(2)}`;
          const msg: StoredMessage = {
            id: tempId,
            conversationId: convId(setup.userId, peerId),
            sender: setup.userId,
            recipient: peerId,
            text,
            timestamp: Date.now(),
            status: "sent",
            fileId: res.file_id,
            mimeType,
            fileName: attachment.name,
            attachmentByteLength: attachment.size,
            attachmentNoteText: text,
            replyToId: replyMeta?.msgId,
            replyPreview: replyMeta?.preview,
            contentType: replyMeta ? "reply" : "text",
          };
          await saveMessage(msg);
          appendBubble(msgList, msg, container);
          const conversationPreview = text
            ? `You: ${text}`
            : `You: Sent ${describeAttachmentKind(mimeType).toLowerCase()}`;
          upsertConversation(setup.userId, peerId, conversationPreview, false);
          markConversationRead(setup.userId, peerId);
          refreshConversationsIfVisible();
          syncComposeValue("");
          clearPendingAttachment();
        } catch (e) {
          notify(`Upload failed: ${errorMsg(e)}`, "error");
        }
        return;
      }

      const tempId = `local-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const msg: StoredMessage = {
        id: tempId,
        conversationId: convId(setup.userId, peerId),
        sender: setup.userId,
        recipient: peerId,
        text,
        timestamp: Date.now(),
        status: "sending",
        replyToId: replyMeta?.msgId,
        replyPreview: replyMeta?.preview,
        contentType: replyMeta ? "reply" : "text",
      };

      syncComposeValue("");
      await saveMessage(msg);
      upsertConversation(setup.userId, peerId, `You: ${text}`, false);
      markConversationRead(setup.userId, peerId);
      appendBubble(msgList, msg, container);

      try {
        const k = await ensureKeys();
        const api = new PqmsgApi(setup.serverUrl);
        const messageBytesBase64 = await encryptDirectPayload(k, peerId, text);
        const deliveryToken = await loadPeerSealedDeliveryToken(k, peerId, api);

        await api.sealedRelay(peerId, {
          delivery_token: deliveryToken,
          message_bytes_base64: messageBytesBase64,
        });
        await updateMessageStatus(tempId, "sent");
        upsertConversation(setup.userId, peerId, `You: ${text}`, false);
        markConversationRead(setup.userId, peerId);
        refreshConversationsIfVisible();
        updateBubbleStatus(tempId, "sent");
      } catch (e) {
        await updateMessageStatus(tempId, "failed");
        updateBubbleStatus(tempId, "failed");
        notify(`Send failed: ${errorMsg(e)}`, "error");
      }
    } finally {
      sendInFlight = false;
      syncSendAvailability();
    }
  });

  const openAttachmentSheet = () => {
    attachmentSheet.classList.remove("hidden");
    attachmentSheet.setAttribute("aria-hidden", "false");
    q<HTMLButtonElement>("[data-attach-kind='camera']").focus();
  };
  const closeAttachmentSheet = () => {
    attachmentSheet.classList.add("hidden");
    attachmentSheet.setAttribute("aria-hidden", "true");
    attachBtn.focus();
  };
  const attachmentPickerOptions: Record<string, { accept?: string; capture?: string }> = {
    camera: { accept: "image/*,video/*", capture: "environment" },
    media: { accept: "image/*,video/*" },
    audio: { accept: "audio/*" },
    document: {},
  };
  const openAttachmentPicker = (kind: string) => {
    const option = attachmentPickerOptions[kind] ?? attachmentPickerOptions.document;
    if (option.accept) {
      fileInput.setAttribute("accept", option.accept);
    } else {
      fileInput.removeAttribute("accept");
    }
    if (option.capture) {
      fileInput.setAttribute("capture", option.capture);
    } else {
      fileInput.removeAttribute("capture");
    }
    attachmentSheet.classList.add("hidden");
    attachmentSheet.setAttribute("aria-hidden", "true");
    fileInput.click();
  };

  attachBtn.addEventListener("click", () => {
    emojiTray.classList.add("hidden");
    openAttachmentSheet();
  });
  q("#attachment-sheet-close").addEventListener("click", closeAttachmentSheet);
  q("#attachment-sheet-cancel").addEventListener("click", closeAttachmentSheet);
  attachmentSheet.addEventListener("click", (e) => {
    if (e.target === attachmentSheet) {
      closeAttachmentSheet();
    }
  });
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-attach-kind]")) {
    button.addEventListener("click", () => openAttachmentPicker(button.dataset.attachKind || "document"));
  }

  // File attachment handler
  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    if (file.size > 1_000_000) {
      notify("File too large (max 1 MB)", "error");
      fileInput.removeAttribute("accept");
      fileInput.removeAttribute("capture");
      fileInput.value = "";
      return;
    }
    pendingAttachmentFile = file;
    renderAttachmentPreview();
    syncSendAvailability();
    fileInput.removeAttribute("accept");
    fileInput.removeAttribute("capture");
    fileInput.value = "";
    input.focus();
  });

  // Message context menu (right-click / long-press) — Reply, React, Edit, Delete
  msgList.addEventListener("click", (e) => {
    if (!isMessageSelectionActive(conversationId)) {
      return;
    }
    const bubble = (e.target as HTMLElement).closest(".bubble") as HTMLElement | null;
    if (!bubble) return;
    e.preventDefault();
    toggleMessageSelection(conversationId, bubble.id.replace("msg-", ""));
    void syncSelection();
  });

  msgList.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const bubble = (e.target as HTMLElement).closest(".bubble") as HTMLElement | null;
    if (!bubble) return;
    const msgId = bubble.id.replace("msg-", "");
    if (isMessageSelectionActive(conversationId)) {
      toggleMessageSelection(conversationId, msgId);
      void syncSelection();
      return;
    }
    const isMine = bubble.classList.contains("bubble-sent");
    const serverMid = bubble.getAttribute("data-server-mid");
    showBubbleContextMenu(
      e as MouseEvent,
      msgId,
      isMine,
      serverMid ? Number(serverMid) : null,
      bubble,
      input,
      sendBtn,
      peerId,
      () => { void syncSelection(); },
      {
        allowEdit: true,
        allowServerDelete: true,
        onLocalDelete: async (targetMsgId) => {
          await deleteMessagesFromDevice([targetMsgId]);
          notify("Message deleted from this device", "success");
        },
      },
    );
  });

  selectionCloseBtn.addEventListener("click", () => {
    clearMessageSelection(conversationId);
    void syncSelection();
  });
  selectionCopyBtn.addEventListener("click", async () => {
    if (!isMessageSelectionActive(conversationId)) return;
    const selected = (await getMessages(conversationId)).filter((message) =>
      messageSelectionState?.selectedIds.has(message.id),
    );
    await navigator.clipboard.writeText(selected.map((message) => messageTranscriptText(message)).join("\n\n"));
    notify("Messages copied", "success");
  });
  selectionShareBtn.addEventListener("click", async () => {
    if (!isMessageSelectionActive(conversationId)) return;
    const selected = (await getMessages(conversationId)).filter((message) =>
      messageSelectionState?.selectedIds.has(message.id),
    );
    const payload = selected.map((message) => messageTranscriptText(message)).join("\n\n");
    if (navigator.share) {
      try {
        await navigator.share({ text: payload });
      } catch {
        await navigator.clipboard.writeText(payload);
      }
    } else {
      await navigator.clipboard.writeText(payload);
    }
    notify("Selected messages ready to share", "success");
  });
  selectionDeleteBtn.addEventListener("click", async () => {
    if (!isMessageSelectionActive(conversationId)) return;
    const ids = Array.from(messageSelectionState?.selectedIds ?? []);
    if (ids.length === 0) return;
    await deleteMessagesFromDevice(ids);
    notify("Messages deleted from this device", "success");
  });

  const selectedBubble = (): HTMLElement | null => {
    if (!isMessageSelectionActive(conversationId)) {
      return null;
    }
    const firstSelectedId = Array.from(messageSelectionState?.selectedIds ?? [])[0];
    if (!firstSelectedId) {
      return null;
    }
    return msgList.querySelector<HTMLElement>(`#msg-${CSS.escape(firstSelectedId)}`);
  };
  const openSelectedContextMenu = (): void => {
    const bubble = selectedBubble();
    if (!bubble) return;
    const rect = bubble.getBoundingClientRect();
    const msgId = bubble.id.replace("msg-", "");
    showBubbleContextMenu(
      { clientX: rect.right - 12, clientY: rect.top + Math.min(rect.height / 2, 28) } as MouseEvent,
      msgId,
      bubble.classList.contains("bubble-sent"),
      bubble.getAttribute("data-server-mid") ? Number(bubble.getAttribute("data-server-mid")) : null,
      bubble,
      input,
      sendBtn,
      peerId,
      () => { void syncSelection(); },
      {
        allowEdit: true,
        allowServerDelete: true,
        onLocalDelete: async (targetMsgId) => {
          await deleteMessagesFromDevice([targetMsgId]);
          notify("Message deleted from this device", "success");
        },
      },
    );
  };
  const replyToSelectedMessage = (): void => {
    const bubble = selectedBubble();
    if (!bubble) return;
    const msgId = bubble.id.replace("msg-", "");
    clearMessageSelection(conversationId);
    void syncSelection();
    void (async () => {
      const stored = await getMessage(msgId);
      const preview = (
        stored ? messageTranscriptText(stored) : bubble.querySelector(".bubble-text")?.textContent || ""
      ).replace(/\s+/g, " ").trim();
      replyContext = { msgId, preview: preview.slice(0, 60) };
      showReplyBar(input);
      input.focus();
    })();
  };
  const reactToSelectedMessage = (): void => {
    const bubble = selectedBubble();
    if (!bubble) return;
    const rect = bubble.getBoundingClientRect();
    showReactionPicker(
      rect.right - 12,
      rect.top + Math.min(rect.height / 2, 28),
      bubble.id.replace("msg-", ""),
      bubble,
      peerId,
    );
  };
  installMessageSelectionShortcuts((event) => {
    const withModifier = event.ctrlKey || event.metaKey;
    const key = event.key.toLowerCase();
    if (withModifier && event.shiftKey && key === "f") {
      event.preventDefault();
      openThreadSearch();
      return;
    }
    if (withModifier && event.shiftKey && key === "t") {
      event.preventDefault();
      input.focus();
      return;
    }
    if (withModifier && event.shiftKey && key === "x") {
      event.preventDefault();
      if (expandedComposeSheet.classList.contains("hidden")) {
        openExpandedComposer();
      } else {
        closeExpandedComposer(false);
      }
      return;
    }
    if (withModifier && !event.shiftKey && key === "u") {
      event.preventDefault();
      attachBtn.click();
      return;
    }
    if (event.key === "Escape" && !threadSearchBar.classList.contains("hidden")) {
      event.preventDefault();
      closeThreadSearch(false);
      return;
    }
    if (event.key === "Escape" && !expandedComposeSheet.classList.contains("hidden")) {
      event.preventDefault();
      closeExpandedComposer(false);
      return;
    }
    if (!isMessageSelectionActive(conversationId)) {
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      clearMessageSelection(conversationId);
      void syncSelection();
      return;
    }
    if (withModifier && event.shiftKey && key === "s") {
      event.preventDefault();
      selectionShareBtn.click();
      return;
    }
    if (withModifier && event.shiftKey && key === "d") {
      event.preventDefault();
      selectionDeleteBtn.click();
      return;
    }
    if (withModifier && event.shiftKey && key === "r" && (messageSelectionState?.selectedIds.size ?? 0) === 1) {
      event.preventDefault();
      replyToSelectedMessage();
      return;
    }
    if (withModifier && event.shiftKey && key === "e" && (messageSelectionState?.selectedIds.size ?? 0) === 1) {
      event.preventDefault();
      reactToSelectedMessage();
      return;
    }
    if (!withModifier && event.shiftKey && event.key === "F10") {
      event.preventDefault();
      openSelectedContextMenu();
    }
  });

  // Load history from IndexedDB
  const cid = conversationId;
  const history = await getMessages(cid);
  const sharedMediaCount = history.filter((message) => hasStoredAttachment(message)).length;
  detailSharedMediaCount.textContent = sharedMediaCount === 1 ? "1 item" : `${sharedMediaCount} items`;
  detailSharedMediaBtn.textContent = sharedMediaCount > 0 ? `Shared media (${sharedMediaCount})` : "Shared media";
  renderMessageList(msgList, history);
  await syncSelection();
  syncThreadSearch(false);
  scrollToBottom(container);
  if (!hasSeenThreadTips()) {
    markThreadTipsSeen();
    showKeyboardShortcutOverlay();
  }

  // Focus input
  input.focus();

  // Poll for any missed messages
  void pollInboxSilent();

  // Start supported metadata polling for this chat
  if (typingIndicatorsSupported()) {
    startTypingPoll(peerId);
  }
  if (readReceiptsSupported()) {
    startReceiptPoll();
  }
  if (presenceSupported()) {
    void fetchPeerPresence(peerId);
  }
}

function renderMessageList(container: HTMLElement, msgs: StoredMessage[]): void {
  if (msgs[0]?.conversationId) {
    container.dataset.conversationId = msgs[0].conversationId;
  }
  container.innerHTML = "";
  let lastDate = "";
  for (const msg of msgs) {
    const date = new Date(msg.timestamp).toLocaleDateString();
    if (date !== lastDate) {
      lastDate = date;
      const sep = document.createElement("div");
      sep.className = "date-sep";
      sep.textContent = friendlyDate(msg.timestamp);
      container.appendChild(sep);
    }
    appendBubbleElement(container, msg);
  }
  refreshReplyThreadDecorations(container);
  refreshThreadSearchDecorations(container);
  refreshMessageSelectionDecorations(container);
}

function appendBubble(container: HTMLElement, msg: StoredMessage, scrollContainer: HTMLElement): void {
  // Date separator if needed
  const lastBubble = container.lastElementChild;
  const lastDate = lastBubble?.getAttribute("data-date") || "";
  const thisDate = new Date(msg.timestamp).toLocaleDateString();
  if (thisDate !== lastDate && !lastBubble?.classList.contains("date-sep")) {
    const sep = document.createElement("div");
    sep.className = "date-sep";
    sep.textContent = friendlyDate(msg.timestamp);
    container.appendChild(sep);
  }

  appendBubbleElement(container, msg);
  refreshReplyThreadDecorations(container);
  refreshThreadSearchDecorations(container);
  refreshMessageSelectionDecorations(container);
  scrollToBottom(scrollContainer);
}

// Blob URL cache for downloaded file previews
const mediaBlobCache = new Map<string, string>();

function hasStoredAttachment(msg: StoredMessage): boolean {
  return Boolean(msg.fileId || msg.attachmentDataBase64);
}

function attachmentDisplayName(msg: StoredMessage): string {
  return msg.fileName || msg.fileId || "attachment";
}

function attachmentMimeType(msg: StoredMessage): string {
  return msg.mimeType || "application/octet-stream";
}

function attachmentCaptionText(msg: StoredMessage): string {
  return msg.attachmentNoteText ?? msg.text;
}

function inlineAttachmentCacheKey(msg: StoredMessage): string {
  return `inline:${msg.id}`;
}

function buildInlineAttachmentBlob(msg: StoredMessage): Blob | null {
  const dataBase64 = msg.attachmentDataBase64?.trim();
  if (!dataBase64) {
    return null;
  }
  try {
    const bytes = Uint8Array.from(atob(dataBase64), (c) => c.charCodeAt(0));
    return new Blob([bytes], { type: attachmentMimeType(msg) });
  } catch {
    return null;
  }
}

function getStoredAttachmentUrl(msg: StoredMessage): string | null {
  if (msg.fileId) {
    return mediaBlobCache.get(msg.fileId) ?? null;
  }
  const cacheKey = inlineAttachmentCacheKey(msg);
  const cached = mediaBlobCache.get(cacheKey);
  if (cached) {
    return cached;
  }
  const blob = buildInlineAttachmentBlob(msg);
  if (!blob) {
    return null;
  }
  const url = URL.createObjectURL(blob);
  mediaBlobCache.set(cacheKey, url);
  return url;
}

function openInlineAttachment(msg: StoredMessage): void {
  const blob = buildInlineAttachmentBlob(msg);
  if (!blob) {
    notify("Attachment is not available on this device", "error");
    return;
  }
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = attachmentDisplayName(msg);
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

async function openStoredAttachment(msg: StoredMessage): Promise<void> {
  if (msg.fileId) {
    await downloadAndOpenFile(msg.fileId);
    return;
  }
  openInlineAttachment(msg);
}

function renderMediaContent(msg: StoredMessage): string {
  if (!hasStoredAttachment(msg)) {
    return `<div class="bubble-text">${escHtml(msg.text)}</div>`;
  }
  const mime = attachmentMimeType(msg);
  const name = attachmentDisplayName(msg);
  const blobUrl = getStoredAttachmentUrl(msg);
  if (mime.startsWith("image/") && blobUrl) {
    return `<img src="${blobUrl}" alt="${escHtml(name)}" class="media-img" loading="lazy" />`;
  }
  if (mime.startsWith("audio/") && blobUrl) {
    return `<audio controls src="${blobUrl}" class="media-audio"></audio>`;
  }
  if (mime.startsWith("video/") && blobUrl) {
    return `<video controls src="${blobUrl}" class="media-video"></video>`;
  }
  // Show loading placeholder or download link
  if (msg.fileId && (mime.startsWith("image/") || mime.startsWith("audio/") || mime.startsWith("video/"))) {
    return `<div class="media-loading" data-file-id="${escHtml(msg.fileId)}">Loading media…</div>`;
  }
  return `<button type="button" class="media-file-link">📎 ${escHtml(name)}</button>`;
}

function renderBubbleBody(msg: StoredMessage): string {
  if (!hasStoredAttachment(msg)) {
    return `<div class="bubble-text">${escHtml(msg.text)}</div>`;
  }
  const captionText = attachmentCaptionText(msg).trim();
  const caption = captionText
    ? `<div class="bubble-text bubble-media-caption">${escHtml(captionText)}</div>`
    : "";
  return `${renderMediaContent(msg)}${caption}`;
}

function renderReplyQuote(msg: StoredMessage): string {
  if (!msg.replyToId || !msg.replyPreview) return "";
  return `<button type="button" class="reply-quote" data-target-id="${escHtml(msg.replyToId)}">${escHtml(msg.replyPreview)}</button>`;
}

function replyCountLabel(count: number): string {
  return count === 1 ? "1 reply" : `${count} replies`;
}

function renderReactions(msg: StoredMessage): string {
  if (!msg.reactions || msg.reactions.length === 0) return "";
  const counts = new Map<string, number>();
  for (const r of msg.reactions) counts.set(r.emoji, (counts.get(r.emoji) ?? 0) + 1);
  const pills = Array.from(counts.entries())
    .map(([emoji, count]) => `<span class="reaction-pill" data-emoji="${emoji}">${emoji}${count > 1 ? ` ${count}` : ""}</span>`)
    .join("");
  return `<div class="reaction-pills">${pills}</div>`;
}

function appendBubbleElement(container: HTMLElement, msg: StoredMessage): void {
  // Skip rendering standalone reaction messages as bubbles
  if (msg.contentType === "reaction") return;

  const isMine = msg.sender === setup.userId;
  const bubble = document.createElement("div");
  bubble.className = `bubble ${isMine ? "bubble-sent" : "bubble-received"}`;
  bubble.id = `msg-${msg.id}`;
  bubble.setAttribute("role", "listitem");
  bubble.setAttribute("data-date", new Date(msg.timestamp).toLocaleDateString());
  bubble.dataset.conversationId = msg.conversationId;
  if (msg.replyToId) {
    bubble.dataset.replyToId = msg.replyToId;
  }
  if (msg.serverMessageId) {
    bubble.setAttribute("data-server-mid", String(msg.serverMessageId));
  }
  bubble.dataset.hasAttachment = hasStoredAttachment(msg) ? "1" : "";
  bubble.dataset.searchText = messageSearchText(msg).toLowerCase();

  const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const statusIcon = isMine ? statusSvg(msg.status) : "";
  const editedTag = msg.editedAt ? ' <span class="edit-indicator">(edited)</span>' : "";

  bubble.innerHTML = `
    ${renderReplyQuote(msg)}
    ${renderBubbleBody(msg)}
    <div class="bubble-meta">
      <span class="bubble-time">${time}${editedTag}</span>
      ${statusIcon}
    </div>
    ${renderReactions(msg)}
  `;

  container.appendChild(bubble);

  // Lazy-load media if fileId present and not cached
  if (msg.fileId && !mediaBlobCache.has(msg.fileId)) {
    void loadMediaBlob(msg.fileId, bubble);
  }

  // Click image for lightbox
  const img = bubble.querySelector<HTMLImageElement>(".media-img");
  if (img) img.addEventListener("click", () => showLightbox(img.src));

  // Download link for non-previewable files
  const fileLink = bubble.querySelector<HTMLButtonElement>(".media-file-link");
  if (fileLink) {
    fileLink.addEventListener("click", (e) => {
      e.preventDefault();
      void openStoredAttachment(msg);
    });
  }

  const replyQuote = bubble.querySelector<HTMLButtonElement>(".reply-quote[data-target-id]");
  if (replyQuote) {
    replyQuote.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      openReplySource(container, replyQuote.dataset.targetId || "");
    });
  }
}

function refreshReplyThreadDecorations(container: HTMLElement): void {
  const bubbles = Array.from(container.querySelectorAll<HTMLElement>(".bubble"));
  const conversationId = container.dataset.conversationId || bubbles[0]?.dataset.conversationId || "";
  const replyCounts = new Map<string, number>();
  for (const bubble of bubbles) {
    const replyToId = bubble.dataset.replyToId;
    if (!replyToId) continue;
    replyCounts.set(replyToId, (replyCounts.get(replyToId) ?? 0) + 1);
  }

  let focusedTargetId = conversationId ? replyThreadFocusByConversation.get(conversationId) ?? null : null;
  if (focusedTargetId && !bubbles.some((bubble) => bubble.id === `msg-${focusedTargetId}` || bubble.dataset.replyToId === focusedTargetId)) {
    focusedTargetId = null;
    if (conversationId) replyThreadFocusByConversation.delete(conversationId);
  }

  for (const bubble of bubbles) {
    const msgId = bubble.id.replace("msg-", "");
    const replyCount = replyCounts.get(msgId) ?? 0;
    let pill = bubble.querySelector<HTMLButtonElement>(".reply-thread-pill");
    if (replyCount > 0) {
      if (!pill) {
        pill = document.createElement("button");
        pill.type = "button";
        pill.className = "reply-thread-pill";
        const meta = bubble.querySelector(".bubble-meta");
        if (meta) {
          meta.insertAdjacentElement("beforebegin", pill);
        } else {
          bubble.appendChild(pill);
        }
      }
      pill.textContent = replyCountLabel(replyCount);
      pill.dataset.targetId = msgId;
      pill.onclick = (event) => {
        event.preventDefault();
        event.stopPropagation();
        toggleReplyThreadFocus(container, msgId);
      };
      pill.classList.toggle("reply-thread-pill-active", focusedTargetId === msgId);
    } else if (pill) {
      pill.remove();
    }

    const isReplySource = focusedTargetId === msgId;
    const isReplyChainMessage = !!focusedTargetId && bubble.dataset.replyToId === focusedTargetId;
    bubble.classList.toggle("bubble-reply-source-active", isReplySource);
    bubble.classList.toggle("bubble-reply-active", isReplyChainMessage);
    bubble.querySelector(".reply-quote")?.classList.toggle("reply-quote-active", isReplyChainMessage);
  }
}

function refreshThreadSearchDecorations(container: HTMLElement): string[] {
  const bubbles = Array.from(container.querySelectorAll<HTMLElement>(".bubble"));
  const query = (container.dataset.threadSearchQuery || "").trim().toLowerCase();
  const activeId = container.dataset.threadSearchActiveId || "";
  const matches: string[] = [];
  for (const bubble of bubbles) {
    const bubbleId = bubble.id.replace("msg-", "");
    const bubbleText = bubble.dataset.searchText || "";
    const isMatch = !!query && bubbleText.includes(query);
    if (isMatch) {
      matches.push(bubbleId);
    }
    bubble.classList.toggle("bubble-search-match", isMatch);
    bubble.classList.toggle("bubble-search-active", isMatch && bubbleId === activeId);
  }
  return matches;
}

function toggleReplyThreadFocus(container: HTMLElement, targetId: string): void {
  const conversationId = container.dataset.conversationId || "";
  if (!conversationId) return;
  const current = replyThreadFocusByConversation.get(conversationId) ?? null;
  const next = current === targetId ? null : targetId;
  setReplyThreadFocus(container, next);
  if (!next) return;
  const firstReply = Array.from(container.querySelectorAll<HTMLElement>(".bubble")).find(
    (bubble) => bubble.dataset.replyToId === next,
  );
  firstReply?.scrollIntoView({ behavior: "smooth", block: "center" });
}

function setReplyThreadFocus(container: HTMLElement, targetId: string | null): void {
  const conversationId = container.dataset.conversationId || "";
  if (!conversationId) return;
  if (targetId == null) {
    replyThreadFocusByConversation.delete(conversationId);
  } else {
    replyThreadFocusByConversation.set(conversationId, targetId);
  }
  refreshReplyThreadDecorations(container);
}

function openReplySource(container: HTMLElement, targetId: string): void {
  if (!targetId) return;
  setReplyThreadFocus(container, targetId);
  const sourceBubble = container.querySelector<HTMLElement>(`#msg-${CSS.escape(targetId)}`);
  sourceBubble?.scrollIntoView({ behavior: "smooth", block: "center" });
}

function isMessageSelectionActive(conversationId?: string): boolean {
  if (!messageSelectionState) {
    return false;
  }
  return conversationId ? messageSelectionState.conversationId === conversationId : true;
}

function enterMessageSelection(conversationId: string, msgId: string): void {
  messageSelectionState = {
    conversationId,
    selectedIds: new Set([msgId]),
  };
}

function toggleMessageSelection(conversationId: string, msgId: string): void {
  if (!isMessageSelectionActive(conversationId)) {
    enterMessageSelection(conversationId, msgId);
    return;
  }
  const selectedIds = messageSelectionState!.selectedIds;
  if (selectedIds.has(msgId)) {
    selectedIds.delete(msgId);
  } else {
    selectedIds.add(msgId);
  }
  if (selectedIds.size === 0) {
    messageSelectionState = null;
  }
}

function clearMessageSelection(conversationId?: string): void {
  if (!messageSelectionState) {
    return;
  }
  if (conversationId && messageSelectionState.conversationId !== conversationId) {
    return;
  }
  messageSelectionState = null;
}

function refreshMessageSelectionDecorations(container: HTMLElement): void {
  const conversationId = container.dataset.conversationId || "";
  const active = isMessageSelectionActive(conversationId);
  const selectedIds = active ? messageSelectionState!.selectedIds : null;
  container.classList.toggle("messages-selection-active", active);
  for (const bubble of container.querySelectorAll<HTMLElement>(".bubble")) {
    const msgId = bubble.id.replace("msg-", "");
    bubble.classList.toggle("bubble-selected", Boolean(selectedIds?.has(msgId)));
  }
}

async function syncMessageSelectionUi(
  conversationId: string,
  container: HTMLElement,
  selectionBar: HTMLElement,
  selectionCount: HTMLElement,
  inputBar: HTMLElement,
  attachmentPreview?: HTMLElement,
): Promise<void> {
  if (!isMessageSelectionActive(conversationId)) {
    selectionBar.classList.add("hidden");
    inputBar.classList.remove("hidden");
    if (attachmentPreview && attachmentPreview.innerHTML.trim()) {
      attachmentPreview.classList.remove("hidden");
    }
    refreshMessageSelectionDecorations(container);
    return;
  }
  const messages = await getMessages(conversationId);
  const validIds = new Set(messages.map((message) => message.id));
  messageSelectionState!.selectedIds.forEach((id) => {
    if (!validIds.has(id)) {
      messageSelectionState!.selectedIds.delete(id);
    }
  });
  if (messageSelectionState!.selectedIds.size === 0) {
    clearMessageSelection(conversationId);
    selectionBar.classList.add("hidden");
    inputBar.classList.remove("hidden");
    refreshMessageSelectionDecorations(container);
    return;
  }
  selectionCount.textContent = `${messageSelectionState!.selectedIds.size} selected`;
  selectionBar.classList.remove("hidden");
  inputBar.classList.add("hidden");
  attachmentPreview?.classList.add("hidden");
  refreshMessageSelectionDecorations(container);
}

function installMessageSelectionShortcuts(handler: (event: KeyboardEvent) => void): void {
  disposeMessageSelectionShortcuts?.();
  const listener = (event: KeyboardEvent) => handler(event);
  window.addEventListener("keydown", listener);
  disposeMessageSelectionShortcuts = () => {
    window.removeEventListener("keydown", listener);
  };
}

function updateBubbleStatus(msgId: string, status: StoredMessage["status"]): void {
  const bubble = document.getElementById(`msg-${msgId}`);
  if (!bubble) return;
  const meta = bubble.querySelector(".bubble-meta");
  if (!meta) return;
  const existing = meta.querySelector(".status-icon");
  if (existing) existing.remove();
  const icon = document.createElement("span");
  icon.className = "status-icon";
  icon.innerHTML = statusSvg(status);
  meta.appendChild(icon);
}

function statusSvg(status: StoredMessage["status"]): string {
  switch (status) {
    case "sending":
      return `<span class="status-icon" title="Sending"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#8899aa" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg></span>`;
    case "sent":
      return `<span class="status-icon" title="Sent"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#8899aa" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg></span>`;
    case "delivered":
      return `<span class="status-icon" title="Delivered"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#8899aa" stroke-width="2.5"><path d="M18 6L7 17l-5-5M22 6L11 17"/></svg></span>`;
    case "failed":
      return `<span class="status-icon error-icon" title="Failed — tap to retry"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ff5555" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg></span>`;
  }
}

// ---------------------------------------------------------------------------
// 4. New Chat dialog
// ---------------------------------------------------------------------------

function renderNewChat(): void {
  const contactRows = cachedContacts.map(c => {
    const identity = resolvePeerIdentity(c.contact_user_id);
    const verified = c.verified_by_qr ? `<span class="verified-badge" title="Verified">✓</span>` : "";
    return `
      <div class="contact-row" data-contact="${escHtml(c.contact_user_id)}">
        <div class="avatar avatar-sm">${escHtml(identity.avatarText)}</div>
        <div class="contact-info">
          <span class="contact-name">${escHtml(identity.primaryLabel)}${verified}</span>
          ${identity.secondaryLabel ? `<span class="contact-id">${escHtml(identity.secondaryLabel)}</span>` : ""}
        </div>
      </div>
    `;
  }).join("");

  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="nc-back" class="icon-btn" aria-label="Back">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <div class="topbar-copy">
          <h1 class="topbar-title">Start Chat</h1>
          <p class="topbar-sub">Choose a contact or enter a username.</p>
        </div>
      </header>
      <div class="new-chat-body">
        ${cachedContacts.length > 0 ? `
          <div class="contacts-section">
            <h3 class="section-label">Contacts</h3>
            <div class="contacts-list">${contactRows}</div>
          </div>
          <div class="divider-or"><span>or enter a username</span></div>
        ` : ""}
        <label class="field">
          <span>Username or invite link</span>
          <input id="nc-peer" type="text" placeholder="@username or invite link" autocomplete="off" />
        </label>
        <button id="nc-start" class="btn-primary">Start Chat</button>
        <p id="nc-status" class="onboarding-status"></p>
        <div class="invite-section">
          <button id="nc-invite" class="btn-secondary">Copy Invite Link</button>
        </div>
      </div>
    </div>
  `;

  q("#nc-back").addEventListener("click", () => navigateTo({ screen: "conversations" }));
  const peerInput = q<HTMLInputElement>("#nc-peer");
  const startBtn = q<HTMLButtonElement>("#nc-start");
  const statusEl = q("#nc-status");

  const startChat = async (peer: string) => {
    statusEl.textContent = "";
    statusEl.classList.remove("error-text");

    const originalLabel = startBtn.textContent;
    startBtn.disabled = true;
    startBtn.textContent = "Checking...";
    try {
      const inviteToken = extractInviteToken(peer);
      let resolvedPeer: string;
      if (inviteToken) {
        const api = new PqmsgApi(setup.serverUrl);
        resolvedPeer = await loadInvitePeerFromToken(inviteToken, api);
        if (resolvedPeer === setup.userId) {
          throw new Error("You can't chat with yourself");
        }
        await addContactSilent(resolvedPeer);
        markConversationAccepted(resolvedPeer);
        setConversationArchived("dm", resolvedPeer, false);
        upsertConversation(setup.userId, resolvedPeer, "New conversation", false);
        markConversationRead(setup.userId, resolvedPeer);
      } else {
        resolvedPeer = await startDirectConversationFlow(
          {
            rawTarget: peer,
            currentUserId: setup.userId,
          },
          {
            ensureDirectChatPeerExists,
            resolveInviteToken: async (token: string) => loadInvitePeerFromToken(token),
            resolvePeerTarget: async (rawTarget: string) => resolvePeerUserIdFromTarget(rawTarget),
            addContactSilent,
            markConversationAccepted,
            setConversationArchived,
            upsertConversation,
            markConversationRead,
          }
        );
      }
      navigateTo({ screen: "chat", peerId: resolvedPeer });
    } catch (e) {
      const resolvedPeer = extractInviteToken(peer)
        ? "private invite"
        : parseDirectChatTarget(peer).replace(/^@/, "");
      const message = describePeerLookupError(resolvedPeer || "unknown", e);
      statusEl.textContent = message;
      statusEl.classList.add("error-text");
      notify(message, "error");
    } finally {
      startBtn.disabled = false;
      startBtn.textContent = originalLabel;
    }
  };

  q("#nc-start").addEventListener("click", () => { void startChat(peerInput.value.trim()); });

  // Contact row clicks
  for (const row of document.querySelectorAll("[data-contact]")) {
    row.addEventListener("click", () => {
      void startChat((row as HTMLElement).dataset.contact!);
    });
  }

  // Invite link
  q("#nc-invite").addEventListener("click", () => {
    void (async () => {
      try {
        const k = await ensureKeys();
        const api = new PqmsgApi(setup.serverUrl);
        const headers = buildContactInviteCreateAuthHeaders(k);
        const invite = await api.createContactInvite(k.userId, headers);
        const link = `${location.origin}/?invite_token=${encodeURIComponent(invite.invite_token)}&server=${encodeURIComponent(setup.serverUrl)}`;
        await navigator.clipboard.writeText(link);
        notify("Private invite link copied!", "success");
      } catch {
        notify("Could not create invite link", "error");
      }
    })();
  });

  // Check for invite param in URL
  const params = new URLSearchParams(location.search);
  const inviteToken = params.get("invite_token") || params.get("token");
  const invitee = params.get("invite");
  if (inviteToken) {
    peerInput.value = location.href;
  } else if (invitee && invitee !== setup.userId) {
    peerInput.value = invitee;
  }

  peerInput.focus();
}

// ---------------------------------------------------------------------------
// Phase 3: Group Chat
// ---------------------------------------------------------------------------

async function renderGroupChat(groupId: string): Promise<void> {
  const privateGroup = getPrivateGroupState(groupId);
  if (!privateGroup) {
    app.innerHTML = `
      <div class="app-shell">
        <header class="topbar">
          <button id="gc-back" class="icon-btn" aria-label="Back to conversations">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7"/>
            </svg>
          </button>
          <h1 class="topbar-title">Private Group</h1>
        </header>
        <div class="settings-body">
          <div class="beta-banner beta-banner-warning">
            <strong>Private-group state is missing</strong>
            <p>This device does not have the opaque state needed to open this group.</p>
          </div>
        </div>
      </div>
    `;
    q("#gc-back").addEventListener("click", () => navigateTo({ screen: "conversations" }));
    return;
  }
  const localCredential = getPrivateGroupCredential(groupId);
  const canManage = Boolean(
    localCredential && privateGroupDescribeMemberCredential(localCredential).publish_key_base64,
  );
  const groupTitle = privateGroup.attributes.title || groupId;
  app.innerHTML = `
    <div class="chat-shell">
      <header class="chat-header">
        <button id="gc-back" class="icon-btn" aria-label="Back to conversations">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <div class="avatar-wrap">
          <div class="avatar avatar-sm avatar-group">${escHtml(groupTitle.slice(0, 2).toUpperCase() || groupId.slice(0, 2).toUpperCase())}</div>
        </div>
        <div class="chat-header-info">
          <span class="chat-header-name">${escHtml(groupTitle)}</span>
          <span class="chat-header-status" id="gc-member-count">group</span>
        </div>
        <button id="gc-search" class="icon-btn" title="Search in conversation" aria-label="Search in conversation">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path>
          </svg>
        </button>
        <button id="gc-shortcuts" class="icon-btn" title="Keyboard shortcuts" aria-label="Keyboard shortcuts">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="5" width="18" height="14" rx="2"/>
            <path d="M7 9h.01M10 9h.01M13 9h.01M16 9h.01M8 13h8M7 16h4"/>
          </svg>
        </button>
        <button id="gc-info" class="icon-btn" title="Group info" aria-label="Group info">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>
          </svg>
        </button>
        <div class="chat-header-shield" title="Post-quantum encrypted">🛡️</div>
      </header>
      <div class="chat-context-strip">
        <strong>Opaque private-group state</strong>
        <p>${canManage ? "This device can rotate the current epoch and issue member invites." : "This device can read and send group messages, but cannot rotate membership."}</p>
      </div>
      <div id="thread-search-bar" class="thread-search-bar hidden" role="search">
        <input id="thread-search-input" type="text" class="thread-search-input" placeholder="Search in conversation" autocomplete="off" aria-label="Search in conversation" />
        <span id="thread-search-count" class="thread-search-count"></span>
        <div class="thread-search-actions">
          <button id="thread-search-prev" class="icon-btn" title="Previous result" aria-label="Previous result">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="m15 18-6-6 6-6"/>
            </svg>
          </button>
          <button id="thread-search-next" class="icon-btn" title="Next result" aria-label="Next result">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="m9 18 6-6-6-6"/>
            </svg>
          </button>
          <button id="thread-search-close" class="icon-btn" title="Close search" aria-label="Close search">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
              <path d="M18 6L6 18M6 6l12 12"/>
            </svg>
          </button>
        </div>
      </div>
      <div id="message-selection-bar" class="message-selection-bar hidden">
        <span id="message-selection-count" class="message-selection-count">0 selected</span>
        <div class="message-selection-actions">
          <button id="message-selection-copy" class="btn-secondary">Copy</button>
          <button id="message-selection-share" class="btn-secondary">Share</button>
          <button id="message-selection-delete" class="btn-secondary danger-lite">Delete</button>
          <button id="message-selection-close" class="btn-secondary">Close</button>
        </div>
      </div>
      <div class="messages-container" id="messages-container">
        <div class="messages" id="messages-list" role="log" aria-live="polite"></div>
      </div>
      <div id="group-attachment-preview" class="attachment-preview hidden" aria-live="polite"></div>
      <div id="group-input-bar" class="chat-input-bar">
        <button id="gc-attach" class="icon-btn attach-btn" title="Attach file" aria-label="Attach file">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21.44 11.05l-8.49 8.49a5 5 0 1 1-7.07-7.07l8.49-8.49a3.5 3.5 0 1 1 4.95 4.95l-8.5 8.49a2 2 0 0 1-2.82-2.83l7.78-7.78"/>
          </svg>
        </button>
        <button id="gc-expand-compose" class="icon-btn attach-btn" title="Expand composer" aria-label="Expand composer">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>
          </svg>
        </button>
        <textarea id="gc-input" class="chat-compose-input" rows="1" placeholder="Message ${escHtml(groupTitle)}" aria-label="Group message"></textarea>
        <button id="gc-send" class="send-btn" aria-label="Send group message">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor">
            <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
          </svg>
        </button>
      </div>
      <input id="group-file-input" type="file" class="hidden" />
      <p id="gc-status" class="text-secondary"></p>
      <div id="group-attachment-sheet" class="attachment-sheet hidden" aria-hidden="true">
        <div class="attachment-sheet-card" role="dialog" aria-modal="true" aria-labelledby="group-attachment-sheet-title">
          <div class="attachment-sheet-head">
            <div>
              <h3 id="group-attachment-sheet-title">Share something</h3>
              <p>Send photos, videos, audio, or files in this private group.</p>
            </div>
            <button id="group-attachment-sheet-close" class="icon-btn" aria-label="Close attachment options">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
                <path d="M18 6L6 18M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <div class="attachment-sheet-grid">
            <button class="attachment-option" data-group-attach-kind="camera">
              <span class="attachment-option-icon camera">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M4 7h3l2-2h6l2 2h3v12H4z"/><circle cx="12" cy="13" r="4"/>
                </svg>
              </span>
              <span class="attachment-option-copy">
                <strong>Camera</strong>
                <span>Capture a photo or video</span>
              </span>
            </button>
            <button class="attachment-option" data-group-attach-kind="media">
              <span class="attachment-option-icon media">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>
                </svg>
              </span>
              <span class="attachment-option-copy">
                <strong>Media</strong>
                <span>Choose from your library</span>
              </span>
            </button>
            <button class="attachment-option" data-group-attach-kind="audio">
              <span class="attachment-option-icon audio">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>
                </svg>
              </span>
              <span class="attachment-option-copy">
                <strong>Audio</strong>
                <span>Share voice notes or audio files</span>
              </span>
            </button>
            <button class="attachment-option" data-group-attach-kind="document">
              <span class="attachment-option-icon document">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>
                </svg>
              </span>
              <span class="attachment-option-copy">
                <strong>Document</strong>
                <span>Share PDFs and other files</span>
              </span>
            </button>
          </div>
          <div class="attachment-sheet-actions">
            <button id="group-attachment-sheet-cancel" class="btn-secondary">Cancel</button>
          </div>
        </div>
      </div>
      <div id="gc-expanded-compose" class="expanded-compose-sheet hidden" aria-hidden="true">
        <div class="expanded-compose-card" role="dialog" aria-modal="true" aria-labelledby="gc-expanded-title">
          <div class="expanded-compose-head">
            <div>
              <h3 id="gc-expanded-title">Expanded composer</h3>
              <p>Use Shift+Enter for a new line and Ctrl+Enter to send.</p>
            </div>
            <button id="gc-expanded-close" class="icon-btn" aria-label="Close expanded composer">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
                <path d="M18 6L6 18M6 6l12 12"/>
              </svg>
            </button>
          </div>
          <textarea id="gc-expanded-input" class="expanded-compose-input" rows="6" placeholder="Message ${escHtml(groupTitle)}"></textarea>
          <div class="expanded-compose-actions">
            <button id="gc-expanded-send" class="btn-primary">Send</button>
          </div>
        </div>
      </div>
    </div>
  `;

  const msgList = q("#messages-list");
  const container = q("#messages-container");
  const conversationId = `group:${groupId}`;
  msgList.dataset.conversationId = conversationId;
  const input = q<HTMLTextAreaElement>("#gc-input");
  const sendButton = q<HTMLButtonElement>("#gc-send");
  const attachBtn = q<HTMLButtonElement>("#gc-attach");
  const expandComposeBtn = q<HTMLButtonElement>("#gc-expand-compose");
  const fileInput = q<HTMLInputElement>("#group-file-input");
  const statusEl = q<HTMLElement>("#gc-status");
  const attachmentPreview = q<HTMLElement>("#group-attachment-preview");
  const attachmentSheet = q<HTMLElement>("#group-attachment-sheet");
  const selectionBar = q<HTMLElement>("#message-selection-bar");
  const selectionCount = q<HTMLElement>("#message-selection-count");
  const selectionCopyBtn = q<HTMLButtonElement>("#message-selection-copy");
  const selectionShareBtn = q<HTMLButtonElement>("#message-selection-share");
  const selectionDeleteBtn = q<HTMLButtonElement>("#message-selection-delete");
  const selectionCloseBtn = q<HTMLButtonElement>("#message-selection-close");
  const inputBar = q<HTMLElement>("#group-input-bar");
  const threadSearchBar = q<HTMLElement>("#thread-search-bar");
  const threadSearchInput = q<HTMLInputElement>("#thread-search-input");
  const threadSearchCount = q<HTMLElement>("#thread-search-count");
  const threadSearchPrev = q<HTMLButtonElement>("#thread-search-prev");
  const threadSearchNext = q<HTMLButtonElement>("#thread-search-next");
  const threadSearchClose = q<HTMLButtonElement>("#thread-search-close");
  const expandedComposeSheet = q<HTMLElement>("#gc-expanded-compose");
  const expandedComposeInput = q<HTMLTextAreaElement>("#gc-expanded-input");
  const expandedComposeClose = q<HTMLButtonElement>("#gc-expanded-close");
  const expandedComposeSend = q<HTMLButtonElement>("#gc-expanded-send");
  let sendInFlight = false;
  let pendingAttachmentFile: File | null = null;
  let pendingAttachmentPreviewUrl: string | null = null;
  const initialDraft = readThreadDraft(setup.userId, "group", groupId);
  if (initialDraft) {
    input.value = initialDraft;
    expandedComposeInput.value = initialDraft;
    autoResizeComposeField(input);
    autoResizeComposeField(expandedComposeInput);
  }
  const syncSendAvailability = (): void => {
    const busy = sendInFlight;
    const hasMessage = Boolean(input.value.trim() || pendingAttachmentFile);
    sendButton.disabled = busy || !hasMessage;
    attachBtn.disabled = busy;
    expandComposeBtn.disabled = busy;
    expandedComposeSend.disabled = busy || !hasMessage;
  };
  const syncComposeValue = (value: string, persist = true): void => {
    if (input.value !== value) {
      input.value = value;
    }
    if (expandedComposeInput.value !== value) {
      expandedComposeInput.value = value;
    }
    autoResizeComposeField(input);
    autoResizeComposeField(expandedComposeInput);
    syncSendAvailability();
    if (persist) {
      writeThreadDraft(setup.userId, "group", groupId, value);
    }
  };
  const refreshGroupConversationAfterLocalDelete = (history: StoredMessage[]): void => {
    const latest = history.at(-1);
    const existing = loadGroupConversations(setup.userId).find((item) => item.groupId === groupId);
    upsertGroupConversation(
      setup.userId,
      groupId,
      existing?.ownerUserId ?? getPrivateGroupOwnerUserId(privateGroup),
      latest ? groupConversationPreview(latest) : "No messages yet",
      false,
      latest?.timestamp ?? existing?.updatedAt ?? Date.now(),
    );
    refreshConversationsIfVisible();
  };
  const deleteGroupMessagesFromDevice = async (ids: string[]): Promise<void> => {
    if (ids.length === 0) {
      return;
    }
    await deleteMessages(ids);
    if (replyContext && ids.includes(replyContext.msgId)) {
      replyContext = null;
      document.querySelector(".reply-compose-bar")?.remove();
    }
    clearMessageSelection(conversationId);
    const history = await getMessages(conversationId);
    renderMessageList(msgList, history);
    refreshGroupConversationAfterLocalDelete(history);
    syncThreadSearch(false);
    await syncSelection();
  };
  const updateInputPlaceholder = (): void => {
    input.placeholder = pendingAttachmentFile ? `Add a caption for ${groupTitle}` : `Message ${groupTitle}`;
  };
  const clearPendingAttachment = (): void => {
    if (pendingAttachmentPreviewUrl) {
      URL.revokeObjectURL(pendingAttachmentPreviewUrl);
      pendingAttachmentPreviewUrl = null;
    }
    pendingAttachmentFile = null;
    attachmentPreview.classList.add("hidden");
    attachmentPreview.innerHTML = "";
    updateInputPlaceholder();
    syncSendAvailability();
    void syncSelection();
  };
  const renderAttachmentPreview = (): void => {
    if (!pendingAttachmentFile) {
      attachmentPreview.classList.add("hidden");
      attachmentPreview.innerHTML = "";
      updateInputPlaceholder();
      syncSendAvailability();
      void syncSelection();
      return;
    }
    if (pendingAttachmentPreviewUrl) {
      URL.revokeObjectURL(pendingAttachmentPreviewUrl);
      pendingAttachmentPreviewUrl = null;
    }
    const file = pendingAttachmentFile;
    const mime = file.type || "application/octet-stream";
    const kindLabel = describeAttachmentKind(mime);
    if (mime.startsWith("image/") || mime.startsWith("video/") || mime.startsWith("audio/")) {
      pendingAttachmentPreviewUrl = URL.createObjectURL(file);
    }
    const mediaPreview = mime.startsWith("image/") && pendingAttachmentPreviewUrl
      ? `<img src="${pendingAttachmentPreviewUrl}" alt="${escHtml(file.name)}" class="attachment-preview-thumb" />`
      : mime.startsWith("video/") && pendingAttachmentPreviewUrl
        ? `<video class="attachment-preview-thumb" src="${pendingAttachmentPreviewUrl}" muted playsinline></video>`
        : mime.startsWith("audio/") && pendingAttachmentPreviewUrl
          ? `<audio class="attachment-preview-audio" controls src="${pendingAttachmentPreviewUrl}"></audio>`
          : `<div class="attachment-preview-icon">${escHtml(kindLabel.slice(0, 1))}</div>`;
    attachmentPreview.classList.remove("hidden");
    attachmentPreview.innerHTML = `
      <div class="attachment-preview-card">
        ${mediaPreview}
        <div class="attachment-preview-copy">
          <strong>${escHtml(file.name)}</strong>
          <span>${escHtml(kindLabel)} - ${formatFileSize(file.size)}</span>
        </div>
        <button id="group-attachment-preview-clear" class="icon-btn" type="button" aria-label="Remove attachment">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M18 6L6 18M6 6l12 12"/>
          </svg>
        </button>
      </div>
    `;
    q("#group-attachment-preview-clear").addEventListener("click", clearPendingAttachment);
    updateInputPlaceholder();
    syncSendAvailability();
    void syncSelection();
  };
  const openExpandedComposer = (): void => {
    expandedComposeSheet.classList.remove("hidden");
    expandedComposeSheet.setAttribute("aria-hidden", "false");
    syncComposeValue(input.value, false);
    expandedComposeInput.focus();
    const pos = expandedComposeInput.value.length;
    expandedComposeInput.setSelectionRange(pos, pos);
  };
  const closeExpandedComposer = (focusComposer = true): void => {
    syncComposeValue(expandedComposeInput.value);
    expandedComposeSheet.classList.add("hidden");
    expandedComposeSheet.setAttribute("aria-hidden", "true");
    if (focusComposer) {
      input.focus();
    }
  };
  const syncSelection = async (): Promise<void> => {
    await syncMessageSelectionUi(
      conversationId,
      msgList,
      selectionBar,
      selectionCount,
      inputBar,
      attachmentPreview,
    );
  };
  let threadSearchIndex = 0;
  const syncThreadSearch = (scrollToActive = true): void => {
    if (threadSearchBar.classList.contains("hidden")) {
      msgList.dataset.threadSearchQuery = "";
      msgList.dataset.threadSearchActiveId = "";
      refreshThreadSearchDecorations(msgList);
      return;
    }
    const query = threadSearchInput.value.trim();
    msgList.dataset.threadSearchQuery = query;
    if (!query) {
      msgList.dataset.threadSearchActiveId = "";
      refreshThreadSearchDecorations(msgList);
      threadSearchCount.textContent = "Type to search this conversation";
      threadSearchPrev.disabled = true;
      threadSearchNext.disabled = true;
      return;
    }
    let matches = refreshThreadSearchDecorations(msgList);
    if (matches.length === 0) {
      threadSearchIndex = 0;
      msgList.dataset.threadSearchActiveId = "";
      refreshThreadSearchDecorations(msgList);
      threadSearchCount.textContent = "No matches";
      threadSearchPrev.disabled = true;
      threadSearchNext.disabled = true;
      return;
    }
    if (threadSearchIndex >= matches.length) {
      threadSearchIndex = 0;
    }
    const activeId = matches[threadSearchIndex];
    msgList.dataset.threadSearchActiveId = activeId;
    matches = refreshThreadSearchDecorations(msgList);
    threadSearchCount.textContent = `${threadSearchIndex + 1} of ${matches.length}`;
    threadSearchPrev.disabled = matches.length < 2;
    threadSearchNext.disabled = matches.length < 2;
    if (scrollToActive) {
      msgList.querySelector<HTMLElement>(`#msg-${CSS.escape(activeId)}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };
  const openThreadSearch = (): void => {
    if (isMessageSelectionActive(conversationId)) {
      clearMessageSelection(conversationId);
      void syncSelection();
    }
    threadSearchBar.classList.remove("hidden");
    threadSearchInput.focus();
    threadSearchInput.select();
    syncThreadSearch(false);
  };
  const closeThreadSearch = (focusComposer = true): void => {
    threadSearchIndex = 0;
    threadSearchInput.value = "";
    threadSearchBar.classList.add("hidden");
    msgList.dataset.threadSearchQuery = "";
    msgList.dataset.threadSearchActiveId = "";
    refreshThreadSearchDecorations(msgList);
    threadSearchCount.textContent = "";
    threadSearchPrev.disabled = true;
    threadSearchNext.disabled = true;
    if (focusComposer) {
      input.focus();
    }
  };
  const moveThreadSearch = (delta: number): void => {
    const query = threadSearchInput.value.trim();
    if (!query) {
      return;
    }
    const matches = refreshThreadSearchDecorations(msgList);
    if (matches.length === 0) {
      return;
    }
    threadSearchIndex = (threadSearchIndex + delta + matches.length) % matches.length;
    syncThreadSearch();
  };

  q("#gc-back").addEventListener("click", () => {
    clearMessageSelection(conversationId);
    clearPendingAttachment();
    activeGroupId = null;
    navigateTo({ screen: "conversations" });
  });
  q("#gc-info").addEventListener("click", () => {
    clearMessageSelection(conversationId);
    navigateTo({ screen: "group-info", groupId });
  });
  q("#gc-search").addEventListener("click", () => {
    openThreadSearch();
  });
  const openAttachmentSheet = (): void => {
    attachmentSheet.classList.remove("hidden");
    attachmentSheet.setAttribute("aria-hidden", "false");
    q<HTMLButtonElement>("[data-group-attach-kind='camera']").focus();
  };
  const closeAttachmentSheet = (): void => {
    attachmentSheet.classList.add("hidden");
    attachmentSheet.setAttribute("aria-hidden", "true");
    attachBtn.focus();
  };
  const attachmentPickerOptions: Record<string, { accept?: string; capture?: string }> = {
    camera: { accept: "image/*,video/*", capture: "environment" },
    media: { accept: "image/*,video/*" },
    audio: { accept: "audio/*" },
    document: {},
  };
  const openAttachmentPicker = (kind: string): void => {
    const option = attachmentPickerOptions[kind] ?? attachmentPickerOptions.document;
    if (option.accept) {
      fileInput.setAttribute("accept", option.accept);
    } else {
      fileInput.removeAttribute("accept");
    }
    if (option.capture) {
      fileInput.setAttribute("capture", option.capture);
    } else {
      fileInput.removeAttribute("capture");
    }
    attachmentSheet.classList.add("hidden");
    attachmentSheet.setAttribute("aria-hidden", "true");
    fileInput.click();
  };
  attachBtn.addEventListener("click", () => {
    openAttachmentSheet();
  });
  q("#group-attachment-sheet-close").addEventListener("click", closeAttachmentSheet);
  q("#group-attachment-sheet-cancel").addEventListener("click", closeAttachmentSheet);
  attachmentSheet.addEventListener("click", (event) => {
    if (event.target === attachmentSheet) {
      closeAttachmentSheet();
    }
  });
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-group-attach-kind]")) {
    button.addEventListener("click", () => openAttachmentPicker(button.dataset.groupAttachKind || "document"));
  }
  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (!file) {
      return;
    }
    if (file.size > 1_000_000) {
      notify("File too large (max 1 MB)", "error");
      fileInput.removeAttribute("accept");
      fileInput.removeAttribute("capture");
      fileInput.value = "";
      return;
    }
    pendingAttachmentFile = file;
    renderAttachmentPreview();
    syncSendAvailability();
    fileInput.removeAttribute("accept");
    fileInput.removeAttribute("capture");
    fileInput.value = "";
    input.focus();
  });
  expandComposeBtn.addEventListener("click", () => {
    openExpandedComposer();
  });
  expandedComposeClose.addEventListener("click", () => closeExpandedComposer());
  expandedComposeSend.addEventListener("click", () => {
    syncComposeValue(expandedComposeInput.value);
    sendButton.click();
  });
  expandedComposeSheet.addEventListener("click", (event) => {
    if (event.target === expandedComposeSheet) {
      closeExpandedComposer();
    }
  });
  q("#gc-shortcuts").addEventListener("click", () => {
    showKeyboardShortcutOverlay();
  });
  threadSearchInput.addEventListener("input", () => {
    threadSearchIndex = 0;
    syncThreadSearch(false);
  });
  threadSearchInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      moveThreadSearch(event.shiftKey ? -1 : 1);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      closeThreadSearch(false);
    }
  });
  threadSearchPrev.addEventListener("click", () => moveThreadSearch(-1));
  threadSearchNext.addEventListener("click", () => moveThreadSearch(1));
  threadSearchClose.addEventListener("click", () => closeThreadSearch());

  // Load group message history
  await syncPrivateGroupMessagesForGroup(groupId).catch(() => {});
  const history = await getMessages(conversationId);
  renderMessageList(msgList, history);
  await syncSelection();
  syncThreadSearch(false);
  scrollToBottom(container);
  if (!hasSeenThreadTips()) {
    markThreadTipsSeen();
    showKeyboardShortcutOverlay();
  }

  // Group chat context menu
  msgList.addEventListener("click", (e) => {
    if (!isMessageSelectionActive(conversationId)) {
      return;
    }
    const bubble = (e.target as HTMLElement).closest(".bubble") as HTMLElement | null;
    if (!bubble) return;
    e.preventDefault();
    toggleMessageSelection(conversationId, bubble.id.replace("msg-", ""));
    void syncSelection();
  });

  msgList.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const bubble = (e.target as HTMLElement).closest(".bubble") as HTMLElement | null;
    if (!bubble) return;
    const msgId = bubble.id.replace("msg-", "");
    if (isMessageSelectionActive(conversationId)) {
      toggleMessageSelection(conversationId, msgId);
      void syncSelection();
      return;
    }
    const isMine = bubble.classList.contains("bubble-sent");
    const serverMid = bubble.getAttribute("data-server-mid");
    showBubbleContextMenu(
      e as MouseEvent,
      msgId,
      isMine,
      serverMid ? Number(serverMid) : null,
      bubble,
      input,
      sendButton,
      undefined,
      () => { void syncSelection(); },
      {
        allowEdit: false,
        allowServerDelete: false,
        onLocalDelete: async (targetMsgId) => {
          await deleteGroupMessagesFromDevice([targetMsgId]);
          notify("Message deleted from this device", "success");
        },
      },
    );
  });

  selectionCloseBtn.addEventListener("click", () => {
    clearMessageSelection(conversationId);
    void syncSelection();
  });
  selectionCopyBtn.addEventListener("click", async () => {
    if (!isMessageSelectionActive(conversationId)) return;
    const selected = (await getMessages(conversationId)).filter((message) =>
      messageSelectionState?.selectedIds.has(message.id),
    );
    await navigator.clipboard.writeText(selected.map((message) => messageTranscriptText(message)).join("\n\n"));
    notify("Messages copied", "success");
  });
  selectionShareBtn.addEventListener("click", async () => {
    if (!isMessageSelectionActive(conversationId)) return;
    const selected = (await getMessages(conversationId)).filter((message) =>
      messageSelectionState?.selectedIds.has(message.id),
    );
    const payload = selected.map((message) => messageTranscriptText(message)).join("\n\n");
    if (navigator.share) {
      try {
        await navigator.share({ text: payload });
      } catch {
        await navigator.clipboard.writeText(payload);
      }
    } else {
      await navigator.clipboard.writeText(payload);
    }
    notify("Selected messages ready to share", "success");
  });
  selectionDeleteBtn.addEventListener("click", async () => {
    if (!isMessageSelectionActive(conversationId)) return;
    const ids = Array.from(messageSelectionState?.selectedIds ?? []);
    if (ids.length === 0) return;
    await deleteGroupMessagesFromDevice(ids);
    notify("Messages deleted from this device", "success");
  });

  const selectedBubble = (): HTMLElement | null => {
    if (!isMessageSelectionActive(conversationId)) {
      return null;
    }
    const firstSelectedId = Array.from(messageSelectionState?.selectedIds ?? [])[0];
    if (!firstSelectedId) {
      return null;
    }
    return msgList.querySelector<HTMLElement>(`#msg-${CSS.escape(firstSelectedId)}`);
  };
  const openSelectedContextMenu = (): void => {
    const bubble = selectedBubble();
    if (!bubble) return;
    const rect = bubble.getBoundingClientRect();
    const msgId = bubble.id.replace("msg-", "");
    showBubbleContextMenu(
      { clientX: rect.right - 12, clientY: rect.top + Math.min(rect.height / 2, 28) } as MouseEvent,
      msgId,
      bubble.classList.contains("bubble-sent"),
      bubble.getAttribute("data-server-mid") ? Number(bubble.getAttribute("data-server-mid")) : null,
      bubble,
      input,
      sendButton,
      undefined,
      () => { void syncSelection(); },
      {
        allowEdit: false,
        allowServerDelete: false,
        onLocalDelete: async (targetMsgId) => {
          await deleteGroupMessagesFromDevice([targetMsgId]);
          notify("Message deleted from this device", "success");
        },
      },
    );
  };
  const replyToSelectedMessage = (): void => {
    const bubble = selectedBubble();
    if (!bubble) return;
    const msgId = bubble.id.replace("msg-", "");
    clearMessageSelection(conversationId);
    void syncSelection();
    void (async () => {
      const stored = await getMessage(msgId);
      const preview = (
        stored ? messageTranscriptText(stored) : bubble.querySelector(".bubble-text")?.textContent || ""
      ).replace(/\s+/g, " ").trim();
      replyContext = { msgId, preview: preview.slice(0, 60) };
      showReplyBar(input);
      input.focus();
    })();
  };
  const reactToSelectedMessage = (): void => {
    const bubble = selectedBubble();
    if (!bubble) return;
    const rect = bubble.getBoundingClientRect();
    showReactionPicker(
      rect.right - 12,
      rect.top + Math.min(rect.height / 2, 28),
      bubble.id.replace("msg-", ""),
      bubble,
    );
  };
  installMessageSelectionShortcuts((event) => {
    const withModifier = event.ctrlKey || event.metaKey;
    const key = event.key.toLowerCase();
    if (withModifier && event.shiftKey && key === "f") {
      event.preventDefault();
      openThreadSearch();
      return;
    }
    if (withModifier && event.shiftKey && key === "t") {
      event.preventDefault();
      input.focus();
      return;
    }
    if (withModifier && event.shiftKey && key === "x") {
      event.preventDefault();
      if (expandedComposeSheet.classList.contains("hidden")) {
        openExpandedComposer();
      } else {
        closeExpandedComposer(false);
      }
      return;
    }
    if (event.key === "Escape" && !threadSearchBar.classList.contains("hidden")) {
      event.preventDefault();
      closeThreadSearch(false);
      return;
    }
    if (event.key === "Escape" && !expandedComposeSheet.classList.contains("hidden")) {
      event.preventDefault();
      closeExpandedComposer(false);
      return;
    }
    if (!isMessageSelectionActive(conversationId)) {
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      clearMessageSelection(conversationId);
      void syncSelection();
      return;
    }
    if (withModifier && event.shiftKey && key === "s") {
      event.preventDefault();
      selectionShareBtn.click();
      return;
    }
    if (withModifier && event.shiftKey && key === "d") {
      event.preventDefault();
      selectionDeleteBtn.click();
      return;
    }
    if (withModifier && event.shiftKey && key === "r" && (messageSelectionState?.selectedIds.size ?? 0) === 1) {
      event.preventDefault();
      replyToSelectedMessage();
      return;
    }
    if (withModifier && event.shiftKey && key === "e" && (messageSelectionState?.selectedIds.size ?? 0) === 1) {
      event.preventDefault();
      reactToSelectedMessage();
      return;
    }
    if (!withModifier && event.shiftKey && event.key === "F10") {
      event.preventDefault();
      openSelectedContextMenu();
    }
  });

  // Load members count
  void loadGroupMembersCount(groupId);
  input.addEventListener("input", () => {
    syncComposeValue(input.value);
  });
  expandedComposeInput.addEventListener("input", () => {
    syncComposeValue(expandedComposeInput.value);
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !sendButton.disabled && !sendInFlight) {
      event.preventDefault();
      sendButton.click();
    }
  });
  expandedComposeInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && event.ctrlKey && !expandedComposeSend.disabled && !sendInFlight) {
      event.preventDefault();
      expandedComposeSend.click();
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      closeExpandedComposer(false);
    }
  });
  syncComposeValue(input.value, false);
  updateInputPlaceholder();
  syncSendAvailability();
  sendButton.addEventListener("click", () => {
    void (async () => {
      const text = input.value.trim();
      const attachment = pendingAttachmentFile;
      if (!text && !attachment) {
        return;
      }
      sendInFlight = true;
      syncSendAvailability();
      statusEl.classList.remove("error-text");
      statusEl.textContent = "Sending...";
      try {
        if (!(await ensureWebMessagingAllowed("group"))) {
          throw new Error("Private-group messaging is disabled for this web profile.");
        }
        const outbound = await buildGroupOutboundPayload(text, attachment);
        await sendPrivateGroupMessage(groupId, outbound);
        syncComposeValue("");
        clearPendingAttachment();
        statusEl.textContent = "Sent.";
        const updatedHistory = await getMessages(`group:${groupId}`);
        renderMessageList(msgList, updatedHistory);
        scrollToBottom(container);
        refreshConversationsIfVisible();
      } catch (error) {
        statusEl.textContent = errorMsg(error);
        statusEl.classList.add("error-text");
      } finally {
        sendInFlight = false;
        syncComposeValue(input.value, false);
      }
    })();
  });
}

async function loadGroupMembersCount(groupId: string): Promise<void> {
  const countEl = document.getElementById("gc-member-count");
  if (!countEl) {
    return;
  }
  const state = getPrivateGroupState(groupId);
  if (!state) {
    countEl.textContent = "private-group state unavailable";
    return;
  }
  const yourRole = state.members.find((member) => member.user_id === setup.userId)?.role || "member";
  countEl.textContent = `${state.members.length} members · epoch ${state.epoch} · your role ${yourRole}`;
}

// ---------------------------------------------------------------------------
// Phase 3: Group Info
// ---------------------------------------------------------------------------

async function renderGroupInfo(groupId: string): Promise<void> {
  const state = getPrivateGroupState(groupId);
  const credential = getPrivateGroupCredential(groupId);
  if (!state || !credential) {
    app.innerHTML = `
      <div class="app-shell">
        <header class="topbar">
          <button id="gi-back" class="icon-btn" aria-label="Back to conversations">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7"/>
            </svg>
          </button>
          <h1 class="topbar-title">Group Info</h1>
        </header>
        <div class="settings-body">
          <div class="settings-section">
            <h3>${escHtml(getPrivateGroupTitle(groupId))}</h3>
            <div class="beta-banner beta-banner-warning">
              <strong>Private-group state is unavailable</strong>
              <p>This device does not have the local opaque state needed to manage this group.</p>
            </div>
          </div>
        </div>
      </div>
    `;
    q("#gi-back").addEventListener("click", () => navigateTo({ screen: "conversations" }));
    return;
  }

  const credentialMaterial = privateGroupDescribeMemberCredential(credential);
  const canManage = Boolean(credentialMaterial.publish_key_base64);
  const groupTitle = state.attributes.title || groupId;
  const ownerUserId = state.members.find((member) => member.role === "Owner")?.user_id || setup.userId;
  const yourRole = state.members.find((member) => member.user_id === setup.userId)?.role || "Member";
  const groupHistory = await getMessages(`group:${groupId}`);
  const groupSharedMediaCount = groupHistory.filter((message) => hasStoredAttachment(message)).length;
  const membersHtml = state.members.map((member) => {
    const identity = resolvePeerIdentity(member.user_id);
    const trust = describePrivateGroupMemberTrust(member.user_id);
    const canRemoveMember = canManage && member.user_id !== setup.userId && member.role !== "Owner";
    return `
      <div class="contact-manage-row">
        <div>
          <span>${escHtml(identity.primaryLabel)}</span>
          <span class="text-secondary">${escHtml(member.role)}</span>
          <div class="text-secondary">${escHtml(trust.summary)}</div>
          <div class="text-secondary">${escHtml(trust.detail)}</div>
        </div>
        <div class="contact-manage-actions">
          ${member.user_id === setup.userId ? '<span class="text-secondary">you</span>' : ""}
          ${canManage && member.user_id !== setup.userId
            ? `<button class="btn-inline" data-private-group-invite="${escHtml(member.user_id)}">Copy Invite</button>`
            : ""}
          ${canRemoveMember
            ? `<button class="btn-inline" data-private-group-remove="${escHtml(member.user_id)}">Remove</button>`
            : ""}
        </div>
      </div>
    `;
  }).join("");

  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="gi-back" class="icon-btn" aria-label="Back to group chat">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">Group Info</h1>
      </header>
      <div class="settings-body">
        <div class="settings-section">
          <h3>${escHtml(groupTitle)}</h3>
          <p class="text-secondary">Epoch ${state.epoch} | ${state.members.length} members | Your role ${escHtml(yourRole)} | Owner ${escHtml(resolvePeerIdentity(ownerUserId).primaryLabel)}</p>
          <div class="beta-banner beta-banner-warning">
            <strong>Opaque private-group state</strong>
            <p>${canManage ? "This device can rotate membership and issue member invites." : "This device can read the current private-group state but cannot rotate membership."}</p>
            <p>Member trust uses the same local safety-number, identity-pin, and transparency checkpoints as direct chats.</p>
          </div>
          <div id="gi-members">${membersHtml}</div>
        </div>
        <div class="settings-section">
          <h3 class="section-label">Shared Media</h3>
          <p class="text-secondary">${groupSharedMediaCount === 1 ? "1 attachment" : `${groupSharedMediaCount} attachments`} saved in this group on this device.</p>
          <button id="gi-shared-media" class="btn-secondary">Open Shared Media</button>
        </div>
        ${canManage ? `
          <div class="settings-section">
            <h3 class="section-label">Add Member</h3>
            <label class="field">
              <span>User</span>
              <input id="gi-add-member" type="text" placeholder="@username, user ID, or invite link" autocomplete="off" />
            </label>
            <button id="gi-add-member-btn" class="btn-primary">Rotate Epoch And Create Invite</button>
          </div>
        ` : `
          <div class="settings-section">
            <p class="text-secondary">Membership changes require an owner/admin credential for the current epoch.</p>
          </div>
        `}
        <p id="gi-status" class="text-secondary"></p>
      </div>
    </div>
  `;

  q("#gi-back").addEventListener("click", () => navigateTo({ screen: "group-chat", groupId }));
  q<HTMLButtonElement>("#gi-shared-media").addEventListener("click", () => {
    void showSharedMediaSheet({
      title: `${groupTitle} shared media`,
      conversationId: `group:${groupId}`,
      emptyMessage: "No shared media in this group yet.",
    });
  });
  const statusEl = q<HTMLElement>("#gi-status");
  const setStatus = (message: string, isError = false): void => {
    statusEl.textContent = message;
    statusEl.classList.toggle("error-text", isError);
  };

  qAll<HTMLElement>("[data-private-group-invite]").forEach((button) => {
    button.addEventListener("click", () => {
      void (async () => {
        try {
          if (!(await ensureWebMessagingAllowed("group"))) {
            throw new Error("Private-group messaging is disabled for this web profile.");
          }
          const memberUserId = button.dataset.privateGroupInvite?.trim() || "";
          if (!memberUserId) {
            throw new Error("Private-group member ID is missing.");
          }
          const api = new PqmsgApi(setup.serverUrl);
          const joinPackage = privateGroupExportJoinPackageForMember(state, memberUserId);
          const inviteLink = await createPrivateGroupInviteLinkFromJoinPackage(
            api,
            state,
            credential,
            joinPackage,
          );
          await navigator.clipboard.writeText(inviteLink);
          notify(`Invite link for @${memberUserId} copied.`, "success");
          setStatus(`Invite link for @${memberUserId} copied.`);
        } catch (error) {
          setStatus(errorMsg(error), true);
        }
      })();
    });
  });

  qAll<HTMLElement>("[data-private-group-remove]").forEach((button) => {
    button.addEventListener("click", () => {
      void (async () => {
        try {
          if (!(await ensureWebMessagingAllowed("group"))) {
            throw new Error("Private-group messaging is disabled for this web profile.");
          }
          const memberUserId = button.dataset.privateGroupRemove?.trim() || "";
          if (!memberUserId) {
            throw new Error("Private-group member ID is missing.");
          }
          const api = new PqmsgApi(setup.serverUrl);
          const transition = privateGroupPrepareRemoveMemberTransition(
            state,
            memberUserId,
            Math.floor(Date.now() / 1000),
          );
          const nextCredential = findPrivateGroupCredentialForUser(
            transition.member_credentials,
            setup.userId,
          );
          const stateCommitmentSha256 = await publishPrivateGroupTransition(
            api,
            transition.next_state,
            credential,
            transition.member_credentials,
          );
          updateLocalPrivateGroupState(
            transition.next_state,
            nextCredential,
            stateCommitmentSha256,
            `Removed @${memberUserId}`,
            false,
          );
          notify(`Removed @${memberUserId} from ${groupTitle}.`, "success");
          refreshConversationsIfVisible();
          void loadGroupMembersCount(groupId);
          await renderGroupInfo(groupId);
        } catch (error) {
          setStatus(errorMsg(error), true);
        }
      })();
    });
  });

  const addMemberButton = document.getElementById("gi-add-member-btn") as HTMLButtonElement | null;
  const addMemberInput = document.getElementById("gi-add-member") as HTMLInputElement | null;
  if (addMemberButton && addMemberInput) {
    addMemberInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        addMemberButton.click();
      }
    });
    addMemberButton.addEventListener("click", () => {
      void (async () => {
        try {
          if (!(await ensureWebMessagingAllowed("group"))) {
            throw new Error("Private-group messaging is disabled for this web profile.");
          }
          const rawTarget = addMemberInput.value.trim();
          if (!rawTarget) {
            throw new Error("Member target is required.");
          }
          const api = new PqmsgApi(setup.serverUrl);
          const memberUserId = await resolvePeerUserIdFromTarget(rawTarget, api);
          if (!memberUserId) {
            throw new Error("Member target could not be resolved.");
          }
          if (memberUserId === setup.userId) {
            throw new Error("You are already in this private group.");
          }
          if (state.members.some((member) => member.user_id === memberUserId)) {
            throw new Error(`@${memberUserId} is already a member of this private group.`);
          }
          await ensureDirectChatPeerExists(rawTarget);
          const transition = privateGroupPrepareAddMemberTransition(
            state,
            memberUserId,
            "Member",
            Math.floor(Date.now() / 1000),
          );
          const nextCredential = findPrivateGroupCredentialForUser(
            transition.member_credentials,
            setup.userId,
          );
          const stateCommitmentSha256 = await publishPrivateGroupTransition(
            api,
            transition.next_state,
            credential,
            transition.member_credentials,
          );
          updateLocalPrivateGroupState(
            transition.next_state,
            nextCredential,
            stateCommitmentSha256,
            `Added @${memberUserId}`,
            false,
          );
          const joinPackage =
            transition.added_member_join_package
            || privateGroupExportJoinPackageForMember(transition.next_state, memberUserId);
          const inviteLink = await createPrivateGroupInviteLinkFromJoinPackage(
            api,
            transition.next_state,
            nextCredential,
            joinPackage,
          );
          await navigator.clipboard.writeText(inviteLink);
          await addContactSilent(memberUserId);
          notify(`Invite link for @${memberUserId} copied.`, "success");
          refreshConversationsIfVisible();
          void loadGroupMembersCount(groupId);
          await renderGroupInfo(groupId);
        } catch (error) {
          setStatus(errorMsg(error), true);
        }
      })();
    });
  }
  return;

  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="gi-back" class="icon-btn" aria-label="Back to group chat">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">Group Info</h1>
      </header>
      <div class="settings-body">
        <div class="settings-section">
          <h3>${escHtml(groupId)}</h3>
          <div class="beta-banner beta-banner-warning">
            <strong>Web group management is unavailable</strong>
            <p>Group membership changes are outside the supported web beta path.</p>
          </div>
          <div id="gi-members"><p class="text-secondary">Loading members…</p></div>
        </div>
        <div class="settings-section">
          <p class="text-secondary">Add and remove member actions stay unavailable until a private-group design is in place.</p>
        </div>
      </div>
    </div>
  `;

  q("#gi-back").addEventListener("click", () => navigateTo({ screen: "group-chat", groupId }));

  // Load members
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildGroupMembersListAuthHeaders(k, groupId);
    const res = await api.listGroupMembers(groupId, headers);
    cachedGroupMembers[groupId] = res.members;

    const membersDiv = q("#gi-members");
    membersDiv.innerHTML = res.members.map(m => `
      <div class="contact-manage-row">
        <span>${escHtml(m.user_id)}</span>
        <span class="text-secondary">${new Date(m.joined_at).toLocaleDateString()}</span>
        ${m.user_id !== setup.userId ? '<span class="text-secondary">managed on Android</span>' : '<span class="text-secondary">you</span>'}
      </div>
    `).join("");
  } catch (e) {
    q("#gi-members").innerHTML = `<p class="error-text">Failed to load: ${escHtml(errorMsg(e))}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Phase 3: Create Group
// ---------------------------------------------------------------------------

function renderCreateGroup(): void {
  const pendingInviteTarget = extractPrivateGroupInviteTarget();
  const contactRows = cachedContacts.map(c => {
    const identity = resolvePeerIdentity(c.contact_user_id);
    return `
      <label class="contact-row contact-checkbox">
        <input type="checkbox" value="${escHtml(c.contact_user_id)}" class="cg-member-cb" />
        <div class="avatar avatar-sm">${escHtml(identity.avatarText)}</div>
        <span class="contact-name">${escHtml(identity.primaryLabel)}</span>
      </label>
    `;
  }).join("");

  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="cg-back" class="icon-btn" aria-label="Back">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">New Group</h1>
      </header>
      <div class="settings-body">
        <div class="beta-banner beta-banner-warning">
          <strong>Private groups stay client-managed</strong>
          <p>Creation and join use opaque group state plus share links. The server stores encrypted state and invite ciphertext only.</p>
        </div>
        <label class="field">
          <span>Group Name</span>
          <input id="cg-name" type="text" placeholder="e.g. project-team" autocomplete="off" />
        </label>
        ${cachedContacts.length > 0 ? `
          <div class="contacts-section">
            <h3 class="section-label">Select Members</h3>
            <div class="contacts-list">${contactRows}</div>
          </div>
        ` : ""}
        <button id="cg-create" class="btn-primary">Create Private Group</button>
        <div class="settings-section">
          <h3 class="section-label">Join Group Link</h3>
          <label class="field">
            <span>Share Link</span>
            <input id="cg-join-link" type="text" placeholder="Paste a private-group link" value="${escHtml(pendingInviteTarget ? location.href : "")}" autocomplete="off" />
          </label>
          <button id="cg-join" class="btn-secondary">Join Private Group</button>
        </div>
        <p id="cg-status" class="text-secondary"></p>
      </div>
    </div>
  `;

  q("#cg-back").addEventListener("click", () => navigateTo({ screen: "conversations" }));
  const statusEl = q<HTMLElement>("#cg-status");
  const nameInput = q<HTMLInputElement>("#cg-name");
  const joinInput = q<HTMLInputElement>("#cg-join-link");
  q<HTMLButtonElement>("#cg-create").addEventListener("click", () => {
    void (async () => {
      try {
        if (!(await ensureWebMessagingAllowed("group"))) {
          throw new Error("Private-group messaging is disabled for this web profile.");
        }
        if (!privateGroupBindingsAvailable()) {
          throw new Error("Private-group bindings are unavailable in this browser.");
        }
        const groupName = nameInput.value.trim();
        if (!groupName) {
          throw new Error("Group name is required.");
        }
        const selectedMembers = [
          ...document.querySelectorAll<HTMLInputElement>(".cg-member-cb:checked"),
        ]
          .map((input) => input.value.trim())
          .filter((value) => value && value !== setup.userId);
        const initialMembers: PrivateGroupMember[] = selectedMembers.map((memberUserId) => ({
          user_id: memberUserId,
          role: "Member",
        }));
        const state = privateGroupCreateState(
          setup.userId,
          {
            title: groupName,
            description: null,
            avatar_hash_sha256: null,
            disappearing_message_timer_seconds: null,
          },
          initialMembers,
          Math.floor(Date.now() / 1000),
        );
        const bootstrap = privateGroupPrepareBootstrapMaterial(state, setup.userId);
        const api = new PqmsgApi(setup.serverUrl);
        const stateCommitmentSha256 = await publishPrivateGroupBootstrap(api, bootstrap);
        updateLocalPrivateGroupState(
          state,
          bootstrap.authorizing_member_credential,
          stateCommitmentSha256,
          "Private group created",
          false,
        );

        const inviteLinks: string[] = [];
        for (const memberJoinPackage of bootstrap.member_join_packages) {
          if (memberJoinPackage.member_user_id === setup.userId) {
            continue;
          }
          const shareLinkMaterial = privateGroupEncryptJoinPackageForShareLink(
            memberJoinPackage.join_package,
          );
          const authorizingCredentialMaterial = privateGroupDescribeMemberCredential(
            bootstrap.authorizing_member_credential,
          );
          if (!authorizingCredentialMaterial.publish_key_base64) {
            throw new Error("Current private-group credential cannot issue invites.");
          }
          const invite = await api.createPrivateGroupInvite({
            group_id: state.group_id,
            epoch: state.epoch,
            invite_commitment_sha256: bytesToHex(
              Uint8Array.from(shareLinkMaterial.envelope.invite_commitment_sha256),
            ),
            invite_ciphertext_nonce_base64: bytesToBase64(
              Uint8Array.from(shareLinkMaterial.envelope.ciphertext.nonce),
            ),
            invite_ciphertext_base64: bytesToBase64(
              Uint8Array.from(shareLinkMaterial.envelope.ciphertext.ciphertext),
            ),
            invite_ciphertext_aad_base64: bytesToBase64(
              Uint8Array.from(shareLinkMaterial.envelope.ciphertext.aad),
            ),
            authorizing_membership_handle_sha256:
              authorizingCredentialMaterial.membership_handle_sha256,
            authorizing_publish_key_base64:
              authorizingCredentialMaterial.publish_key_base64,
          });
          inviteLinks.push(
            `${memberJoinPackage.member_user_id}: ${buildPrivateGroupInviteLink(
              setup.serverUrl,
              invite.invite_token,
              bytesToBase64(Uint8Array.from(shareLinkMaterial.invite_secret)),
            )}`,
          );
        }

        if (inviteLinks.length > 0) {
          await navigator.clipboard.writeText(inviteLinks.join("\n"));
          notify("Private group created. Invite links copied.", "success");
        } else {
          notify("Private group created.", "success");
        }
        statusEl.textContent = inviteLinks.length > 0
          ? "Group created. Invite links were copied to your clipboard."
          : "Group created.";
        navigateTo({ screen: "group-chat", groupId: state.group_id });
      } catch (error) {
        statusEl.textContent = errorMsg(error);
        statusEl.classList.add("error-text");
      }
    })();
  });
  q<HTMLButtonElement>("#cg-join").addEventListener("click", () => {
    void (async () => {
      try {
        if (!(await ensureWebMessagingAllowed("group"))) {
          throw new Error("Private-group messaging is disabled for this web profile.");
        }
        if (!privateGroupBindingsAvailable()) {
          throw new Error("Private-group bindings are unavailable in this browser.");
        }
        const target = extractPrivateGroupInviteTarget(joinInput.value.trim());
        if (!target) {
          throw new Error("Private-group link is invalid or missing its secret fragment.");
        }
        const currentServer = validateWebServerUrl(setup.serverUrl).toString().replace(/\/+$/, "");
        const targetServer = validateWebServerUrl(target.serverUrl).toString().replace(/\/+$/, "");
        if (currentServer !== targetServer) {
          throw new Error("Private-group links must target the current account server.");
        }
        const api = new PqmsgApi(target.serverUrl);
        const invite = await api.resolvePrivateGroupInvite(target.inviteToken);
        const joinPackage = privateGroupOpenShareLinkInvite(
          {
            group_id: invite.group_id,
            epoch: invite.epoch,
            invite_commitment_sha256: hexToByteArray(invite.invite_commitment_sha256),
            ciphertext: {
              nonce: [...base64ToBytes(invite.invite_ciphertext_nonce_base64)],
              ciphertext: [...base64ToBytes(invite.invite_ciphertext_base64)],
              aad: [...base64ToBytes(invite.invite_ciphertext_aad_base64)],
            },
          },
          target.inviteSecretBase64,
        );
        const restored = privateGroupRestoreJoinPackage(joinPackage);
        const memberMaterial = privateGroupDescribeMemberCredential(restored.member_credential);
        const fetchedState = await api.fetchPrivateGroupState({
          membership_handle_sha256: memberMaterial.membership_handle_sha256,
          fetch_key_base64: memberMaterial.fetch_key_base64,
        });
        const expectedCommitment = bytesToHex(
          Uint8Array.from(joinPackage.invite.snapshot.state_commitment_sha256),
        );
        if (fetchedState.group_id !== restored.state.group_id || fetchedState.epoch !== restored.state.epoch) {
          throw new Error("Private-group state fetch does not match the invite package.");
        }
        if (expectedCommitment && fetchedState.state_commitment_sha256 !== expectedCommitment) {
          throw new Error("Private-group state fetch failed commitment verification.");
        }
        await api.consumePrivateGroupInvite(target.inviteToken);
        updateLocalPrivateGroupState(
          restored.state,
          restored.member_credential,
          fetchedState.state_commitment_sha256,
          "Joined private group",
          false,
        );
        notify("Joined private group.", "success");
        statusEl.textContent = "Private group joined.";
        navigateTo({ screen: "group-chat", groupId: restored.state.group_id });
      } catch (error) {
        statusEl.textContent = errorMsg(error);
        statusEl.classList.add("error-text");
      }
    })();
  });
}

// ---------------------------------------------------------------------------
// Phase 3: Message deletion confirm
// ---------------------------------------------------------------------------

function showDeleteConfirm(bubble: HTMLElement, serverMessageId: number): void {
  // Remove any existing delete popup
  document.querySelector(".delete-popup")?.remove();

  const popup = document.createElement("div");
  popup.className = "delete-popup";
  popup.innerHTML = `
    <button class="delete-popup-btn delete-popup-delete">Delete</button>
    <button class="delete-popup-btn delete-popup-cancel">Cancel</button>
  `;

  bubble.style.position = "relative";
  bubble.appendChild(popup);

  popup.querySelector(".delete-popup-cancel")!.addEventListener("click", () => popup.remove());
  popup.querySelector(".delete-popup-delete")!.addEventListener("click", async () => {
    popup.remove();
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildInboxDeleteAuthHeaders(k, [serverMessageId]);
      await api.deleteInboxMessages(k.userId, { message_ids: [serverMessageId] }, headers);
      const messageList = bubble.parentElement;
      bubble.remove();
      if (messageList instanceof HTMLElement) {
        refreshReplyThreadDecorations(messageList);
      }
      notify("Message deleted", "success");
    } catch (e) {
      notify(`Delete failed: ${errorMsg(e)}`, "error");
    }
  });
}

function buildContactDiscoveryCheckpoint(
  serviceOrigin: string,
  manifest: ContactDiscoveryManifestResponse
): ContactDiscoveryCheckpoint {
  return {
    service_origin: serviceOrigin,
    manifest_issuer_ed25519_pub: manifest.manifest_issuer_ed25519_pub,
    ticket_issuer_ed25519_pub: manifest.ticket_issuer_ed25519_pub,
    protocol_version: manifest.protocol_version,
    ticket_format: manifest.ticket_format,
    lookup_protocol: manifest.lookup_protocol,
    privacy_mode: manifest.privacy_mode,
    directory_backend: manifest.directory_backend,
    host_enclave_protocol_version: manifest.host_enclave_protocol_version,
    host_release_id: manifest.host_release_id,
    enclave_release_id: manifest.enclave_release_id,
    match_result_format: manifest.match_result_format,
    oprf_suite: manifest.oprf_suite,
    evaluation_proof_mode: manifest.evaluation_proof_mode,
    oprf_public_key_ristretto255: manifest.oprf_public_key_ristretto255,
    attestation_mode: manifest.attestation_mode,
    attestation_verifier: manifest.attestation_verifier ?? null,
    enclave_measurement_hex: manifest.enclave_measurement_hex ?? null,
    attestation_pcrs_sha384: normalizeContactDiscoveryPcrs(manifest.attestation_pcrs_sha384),
    attestation_document_format: manifest.attestation_document_format ?? null,
    attestation_document_sha256: manifest.attestation_document_sha256 ?? null,
    attestation_challenge_mode: manifest.attestation_challenge_mode ?? null,
    observed_at: new Date().toISOString(),
  };
}

function diffContactDiscoveryCheckpoint(
  previous: ContactDiscoveryCheckpoint,
  current: ContactDiscoveryCheckpoint
): string[] {
  const changed: string[] = [];
  if (previous.service_origin !== current.service_origin) changed.push("service_origin");
  if (previous.manifest_issuer_ed25519_pub !== current.manifest_issuer_ed25519_pub) {
    changed.push("manifest_issuer_ed25519_pub");
  }
  if (previous.ticket_issuer_ed25519_pub !== current.ticket_issuer_ed25519_pub) {
    changed.push("ticket_issuer_ed25519_pub");
  }
  if (previous.protocol_version !== current.protocol_version) changed.push("protocol_version");
  if (previous.ticket_format !== current.ticket_format) changed.push("ticket_format");
  if (previous.lookup_protocol !== current.lookup_protocol) changed.push("lookup_protocol");
  if (previous.privacy_mode !== current.privacy_mode) changed.push("privacy_mode");
  if (previous.directory_backend !== current.directory_backend) changed.push("directory_backend");
  if (previous.host_enclave_protocol_version !== current.host_enclave_protocol_version) {
    changed.push("host_enclave_protocol_version");
  }
  if (previous.host_release_id !== current.host_release_id) {
    changed.push("host_release_id");
  }
  if (previous.enclave_release_id !== current.enclave_release_id) {
    changed.push("enclave_release_id");
  }
  if (previous.match_result_format !== current.match_result_format) changed.push("match_result_format");
  if (previous.oprf_suite !== current.oprf_suite) changed.push("oprf_suite");
  if (previous.evaluation_proof_mode !== current.evaluation_proof_mode) {
    changed.push("evaluation_proof_mode");
  }
  if (previous.oprf_public_key_ristretto255 !== current.oprf_public_key_ristretto255) {
    changed.push("oprf_public_key_ristretto255");
  }
  if (previous.attestation_mode !== current.attestation_mode) changed.push("attestation_mode");
  if (previous.attestation_verifier !== current.attestation_verifier) {
    changed.push("attestation_verifier");
  }
  if (previous.enclave_measurement_hex !== current.enclave_measurement_hex) {
    changed.push("enclave_measurement_hex");
  }
  if (
    JSON.stringify(normalizeContactDiscoveryPcrs(previous.attestation_pcrs_sha384))
      !== JSON.stringify(normalizeContactDiscoveryPcrs(current.attestation_pcrs_sha384))
  ) {
    changed.push("attestation_pcrs_sha384");
  }
  if (previous.attestation_document_format !== current.attestation_document_format) {
    changed.push("attestation_document_format");
  }
  if (previous.attestation_document_sha256 !== current.attestation_document_sha256) {
    changed.push("attestation_document_sha256");
  }
  if (previous.attestation_challenge_mode !== current.attestation_challenge_mode) {
    changed.push("attestation_challenge_mode");
  }
  return changed;
}

async function loadVerifiedContactDiscoveryManifest(
  capabilities: ServerCapabilitiesResponse
): Promise<{ manifest: ContactDiscoveryManifestResponse; continuityStatus: string }> {
  if (
    capabilities.contact_discovery_mode !== "private_service"
    || !capabilities.contact_discovery_service_origin
  ) {
    throw new Error("Private contact discovery is not configured");
  }
  const apiClient = new PqmsgApi(setup.serverUrl);
  const serviceOrigin = validateWebServerUrl(capabilities.contact_discovery_service_origin).origin;
  const attestationContractFields = [
    capabilities.contact_discovery_attestation_verifier,
    capabilities.contact_discovery_expected_measurement_hex,
    capabilities.contact_discovery_attestation_document_sha256,
    capabilities.contact_discovery_attestation_max_age_seconds,
  ].map((value) => value !== null && value !== undefined && value !== "");
  if (attestationContractFields.some(Boolean) && !attestationContractFields.every(Boolean)) {
    throw new Error("Private contact discovery attestation contract is incomplete");
  }
  const manifest = await apiClient.getContactDiscoveryManifest(serviceOrigin);
  verifyContactDiscoveryManifest(
    manifest,
    capabilities.contact_discovery_ticket_issuer_ed25519_pub,
    capabilities.contact_discovery_manifest_issuer_ed25519_pub || "",
    capabilities.contact_discovery_attestation_verifier,
    capabilities.contact_discovery_expected_measurement_hex,
    capabilities.contact_discovery_expected_pcrs_sha384,
    capabilities.contact_discovery_attestation_document_sha256,
  );
  if (
    !capabilities.contact_discovery_directory_backend
    || !capabilities.contact_discovery_host_enclave_protocol_version
    || !capabilities.contact_discovery_host_release_id
    || !capabilities.contact_discovery_enclave_release_id
    || !capabilities.contact_discovery_expected_manifest_contract_sha256
    || !capabilities.contact_discovery_attestation_verifier
    || !capabilities.contact_discovery_expected_measurement_hex
    || !capabilities.contact_discovery_attestation_document_sha256
    || !capabilities.contact_discovery_attestation_max_age_seconds
  ) {
    throw new Error("Private contact discovery backend contract is incomplete");
  }
  const manifestContractSha256 = contactDiscoveryManifestContractSha256(manifest);
  if (
    manifest.lookup_protocol !== "attested_enclave_voprf_directory_v1"
    || manifest.privacy_mode !== "enclave_backed_private_discovery_v1"
    || manifest.directory_backend !== "attested_enclave_directory_v1"
    || manifest.host_enclave_protocol_version !== 1
    || !manifest.host_release_id
    || !manifest.enclave_release_id
    || manifest.match_result_format !== "contact_invite_token"
    || manifest.oprf_suite !== "ristretto255-sha512-v1"
    || manifest.evaluation_proof_mode !== "dleq_per_element_v1"
    || !manifest.oprf_public_key_ristretto255
    || manifest.attestation_mode !== "attested_enclave_v1"
    || !manifest.attestation_verifier
    || !manifest.enclave_measurement_hex
    || !manifest.attestation_document_format
    || !manifest.attestation_document_sha256
    || !manifest.attestation_challenge_mode
  ) {
    throw new Error("Unsupported contact discovery manifest");
  }
  if (
    manifest.attestation_challenge_mode !== "nonce_b64_required_v1"
  ) {
    throw new Error("Unsupported contact discovery attestation challenge mode");
  }
  if (
    manifest.directory_backend !== capabilities.contact_discovery_directory_backend
    || manifest.host_enclave_protocol_version
      !== capabilities.contact_discovery_host_enclave_protocol_version
    || manifest.host_release_id !== capabilities.contact_discovery_host_release_id
    || manifest.enclave_release_id !== capabilities.contact_discovery_enclave_release_id
    || manifestContractSha256
      !== capabilities.contact_discovery_expected_manifest_contract_sha256
  ) {
    throw new Error("Contact discovery backend contract mismatch");
  }
  if (manifest.attestation_document_sha256) {
    const attestationChallengeNonce = buildContactDiscoveryAttestationChallengeNonce();
    const attestation = await apiClient.getContactDiscoveryAttestation(
      serviceOrigin,
      attestationChallengeNonce,
    );
    verifyContactDiscoveryAttestationDocument(
      attestation,
      manifest.attestation_mode,
      manifest.attestation_verifier || "",
      manifest.enclave_measurement_hex || "",
      manifest.attestation_pcrs_sha384 ?? null,
      manifest.manifest_issuer_ed25519_pub,
      attestationChallengeNonce,
      manifestContractSha256,
      manifest.host_release_id,
      manifest.enclave_release_id,
      manifest.oprf_public_key_ristretto255,
      manifest.attestation_document_sha256,
      capabilities.contact_discovery_attestation_max_age_seconds || 0,
    );
  }
  let continuityStatus = "Not pinned";
  if (setup.userId.trim()) {
    const checkpoint = buildContactDiscoveryCheckpoint(serviceOrigin, manifest);
    const previousCheckpoint = readContactDiscoveryCheckpoint(setup.serverUrl, setup.userId);
    if (previousCheckpoint) {
      const changedFields = diffContactDiscoveryCheckpoint(previousCheckpoint, checkpoint);
      if (changedFields.length) {
        throw new Error(
          `Contact discovery manifest continuity changed: ${changedFields.join(", ")}`
        );
      }
      continuityStatus = "Pinned on this device";
    } else {
      continuityStatus = "Saved on this device";
    }
    writeContactDiscoveryCheckpoint(setup.serverUrl, setup.userId, checkpoint);
  }
  return { manifest, continuityStatus };
}

function normalizeContactDiscoveryPcrs(
  pcrs: Record<string, string> | null | undefined
): Record<string, string> | null {
  if (!pcrs) {
    return null;
  }
  const entries = Object.entries(pcrs).sort(([lhs], [rhs]) => lhs.localeCompare(rhs));
  if (!entries.length) {
    return null;
  }
  return Object.fromEntries(entries);
}

function formatContactDiscoveryPcrs(
  pcrs: Record<string, string> | null | undefined
): string {
  const normalized = normalizeContactDiscoveryPcrs(pcrs);
  if (!normalized) {
    return "not advertised";
  }
  return Object.entries(normalized)
    .map(([key, value]) => `${key}=${value}`)
    .join(", ");
}

function requireContactDiscoveryServiceContract(
  manifestContractSha256: string,
  observedManifestContractSha256: string,
  operationLabel: string,
): void {
  if (observedManifestContractSha256 !== manifestContractSha256) {
    throw new Error(`Contact discovery ${operationLabel} contract mismatch`);
  }
}

function requireContactDiscoveryTicketNonce(
  expectedTicketNonce: string,
  observedTicketNonce: string,
  operationLabel: string,
): void {
  if (observedTicketNonce !== expectedTicketNonce) {
    throw new Error(`Contact discovery ${operationLabel} ticket mismatch`);
  }
}

// ---------------------------------------------------------------------------
// 5. Settings screen
// ---------------------------------------------------------------------------

async function renderSettings(): Promise<void> {
  const fingerprint = keys
    ? identityFingerprint(keys.identityX25519Pub, keys.identityPqSigPub)
    : "not available";
  const capabilities = await loadServerCapabilitiesCached();
  const webHoldback = getWebBetaHoldback(capabilities);
  const contactDiscoverySupported = capabilities?.contact_discovery_supported ?? false;
  const contactDiscoveryMode = capabilities?.contact_discovery_mode ?? "manual_only";
  let contactDiscoveryManifest: ContactDiscoveryManifestResponse | null = null;
  let contactDiscoveryContinuityStatus =
    contactDiscoveryMode === "private_service" ? "Unavailable" : "N/A";
  let contactDiscoveryManifestStatus =
    contactDiscoveryMode === "private_service" ? "Manifest unavailable" : "Manual-only";
  if (
    contactDiscoveryMode === "private_service" &&
    capabilities?.contact_discovery_service_origin
  ) {
    try {
      const verifiedManifest = await loadVerifiedContactDiscoveryManifest(capabilities);
      contactDiscoveryManifest = verifiedManifest.manifest;
      contactDiscoveryManifestStatus = `Verified (${contactDiscoveryManifest.attestation_mode})`;
      contactDiscoveryContinuityStatus = verifiedManifest.continuityStatus;
    } catch (error) {
      contactDiscoveryManifestStatus =
        error instanceof Error ? error.message : "Manifest unavailable";
      contactDiscoveryContinuityStatus = contactDiscoveryManifestStatus.includes("continuity changed")
        ? "Changed on this device"
        : "Unavailable";
    }
  }
  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="set-back" class="icon-btn" aria-label="Back to conversations">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">Settings</h1>
      </header>
      <div class="settings-body">
        <div class="settings-hero">
          <div>
            <span class="settings-eyebrow">Your account</span>
            <h2>${escHtml(setup.displayName || setup.userId)}</h2>
            <p class="settings-hero-copy">${
              setup.username
                ? `Shareable username <span class="mono">@${escHtml(setup.username)}</span> ${setup.usernameLookupEnabled ? "· exact lookup on" : "· invite-only"} · Account ID <span class="mono">@${escHtml(setup.userId)}</span> on <span class="mono">${escHtml(setup.deviceId)}</span>`
                : `Account ID <span class="mono">@${escHtml(setup.userId)}</span> on <span class="mono">${escHtml(setup.deviceId)}</span>. Claim a shareable @username below.`
            }</p>
          </div>
          <button data-open-devices="1" class="btn-secondary">Manage Devices</button>
        </div>
        <div class="settings-section">
          <h3>Beta Scope</h3>
          <div class="beta-banner beta-banner-${webHoldback.tone}">
            <strong>${escHtml(webHoldback.title)}</strong>
            <p>${escHtml(webHoldback.detail)}</p>
          </div>
        </div>
        <div class="settings-section">
          <h3>Account</h3>
          <div class="profile-edit-row">
            <label class="field">
              <span>Display Name</span>
              <input id="set-name" type="text" value="${escHtml(setup.displayName || setup.userId)}" />
            </label>
            <label class="field">
              <span>Shareable Username</span>
              <input id="set-username" type="text" value="${escHtml(setup.username || "")}" placeholder="@yourname" autocomplete="off" />
            </label>
            <label class="switch-inline">
              <input id="set-username-lookup-enabled" type="checkbox" ${setup.username && setup.usernameLookupEnabled ? "checked" : ""} ${setup.username ? "" : "disabled"} />
              <span>Allow exact @username lookup</span>
            </label>
            <button id="set-save-profile" class="btn-sm">Save</button>
          </div>
          <div class="settings-row"><span>User ID</span><span class="mono">${escHtml(setup.userId)}</span></div>
          <div class="settings-row"><span>Device</span><span class="mono">${escHtml(setup.deviceId)}</span></div>
        </div>
        <div class="settings-section">
          <h3>Session</h3>
          <p class="text-secondary settings-desc">Sign out of this browser while keeping your encrypted local keys available for a later sign-in.</p>
          <button id="set-logout" class="btn-secondary">Log Out</button>
        </div>
        <div class="settings-section">
          <h3>People</h3>
          <p class="text-secondary settings-desc">${
            contactDiscoveryMode === "private_service"
              ? "Manual contacts remain the active flow here. This server is prepared for a separate private discovery service, but the blinded lookup client flow is not shipped yet."
              : "Manual contacts only. Add people by exact @username or invite link. Private discovery stays unavailable in this privacy profile."
          }</p>
          <div id="contacts-manage">
            ${cachedContacts.length === 0 ? '<p class="text-secondary">No contacts yet</p>' :
              cachedContacts.map(c => {
                const identity = resolvePeerIdentity(c.contact_user_id);
                return `
                <div class="contact-manage-row">
                  <span>${escHtml(identity.primaryLabel)}</span>
                  ${identity.secondaryLabel ? `<span class="mono text-secondary">${escHtml(identity.secondaryLabel)}</span>` : ""}
                  <button class="btn-sm btn-danger-sm" data-remove-contact="${escHtml(c.contact_user_id)}">Remove</button>
                </div>
              `;
              }).join("")
            }
          </div>
          <div class="add-contact-row">
            <input id="set-add-contact-id" type="text" placeholder="@username or invite link" class="input-sm" />
            <input id="set-add-contact-alias" type="text" placeholder="Alias (optional)" class="input-sm" />
            <button id="set-add-contact" class="btn-sm">Add</button>
          </div>
        </div>
        <div class="settings-section">
          <h3>Privacy & Trust</h3>
          <div class="settings-row"><span>Encryption</span><span>Post-quantum (ML-KEM-768)</span></div>
          <div class="settings-row"><span>Mode</span><span>Mandatory WASM PQ runtime</span></div>
          <div class="settings-row column"><span>Identity Fingerprint</span><span class="mono fingerprint">${escHtml(fingerprint)}</span></div>
          <div class="settings-row"><span>Server</span><span class="mono">${escHtml(setup.serverUrl)}</span></div>
          <div class="settings-row">
            <button id="set-rotate-key" class="btn-sm">Rotate Identity Key</button>
            <button id="set-identity-log" class="btn-sm">Identity Log</button>
          </div>
          <div id="rotate-status"></div>
        </div>
        <details class="settings-foldout">
          <summary>Privacy, devices, and advanced</summary>
          <div class="settings-foldout-body">
        <div class="settings-section">
          <h3>Key Health</h3>
          <div id="prekey-status"><p class="text-secondary">Loading…</p></div>
        </div>
        <div class="settings-section">
          <h3>Advanced Discovery</h3>
          <p class="text-secondary settings-desc">${
            contactDiscoverySupported
              ? "Let contacts find you by phone or email hash."
              : contactDiscoveryMode === "private_service"
                ? "Raw-hash contact discovery stays disabled. The discovery manifest is checked here before any future private-lookup flow is allowed."
                : "Raw-hash contact discovery is disabled. Share your @username or a private invite link and manage contacts manually."
          }</p>
          ${
            contactDiscoveryMode === "private_service"
              ? `<div class="settings-row"><span>Manifest</span><span>${escHtml(contactDiscoveryManifestStatus)}</span></div>
          <div class="settings-row"><span>Manifest Continuity</span><span>${escHtml(contactDiscoveryContinuityStatus)}</span></div>
          <div class="settings-row"><span>Service Origin</span><span class="mono">${escHtml(capabilities?.contact_discovery_service_origin || "not configured")}</span></div>
          <div class="settings-row"><span>Lookup Protocol</span><span>${escHtml(contactDiscoveryManifest?.lookup_protocol || "unknown")}</span></div>
          <div class="settings-row"><span>Evaluation Proof</span><span>${escHtml(contactDiscoveryManifest?.evaluation_proof_mode || "unknown")}</span></div>
          <div class="settings-row"><span>Attestation Verifier</span><span class="mono">${escHtml(contactDiscoveryManifest?.attestation_verifier || "not advertised")}</span></div>
          <div class="settings-row"><span>Enclave Measurement</span><span class="mono">${escHtml(contactDiscoveryManifest?.enclave_measurement_hex || "not advertised")}</span></div>
          <div class="settings-row"><span>Attestation PCRs</span><span class="mono">${escHtml(formatContactDiscoveryPcrs(contactDiscoveryManifest?.attestation_pcrs_sha384))}</span></div>
          <div class="settings-row"><span>Attestation Max Age</span><span>${escHtml(capabilities?.contact_discovery_attestation_max_age_seconds ? `${capabilities.contact_discovery_attestation_max_age_seconds}s` : "not advertised")}</span></div>`
              : ""
          }
          <div class="settings-row">
            <button id="set-discovery" class="btn-sm" ${contactDiscoverySupported ? "" : "disabled"}>${
              contactDiscoverySupported ? "Contact Discovery" : "Unavailable"
            }</button>
          </div>
        </div>
        <div class="settings-section">
          <h3>Advanced Push</h3>
          <div class="push-token-row">
            <input id="set-push-token" type="text" placeholder="FCM / APNs token" class="input-sm push-input" />
            <select id="set-push-provider" class="ephem-select">
              <option value="fcm">FCM</option>
              <option value="apns">APNs</option>
            </select>
            <button id="set-push-register" class="btn-sm">Register</button>
          </div>
          <div id="push-status"></div>
        </div>
        <div class="settings-section">
          <h3>Devices</h3>
          <p class="text-secondary settings-desc">Manage linked devices for your account.</p>
          <div class="settings-row">
            <button id="set-devices" class="btn-sm">Manage Devices</button>
          </div>
        </div>
        <div class="settings-section">
          <h3>Advanced Server</h3>
          <div class="settings-row">
            <button id="set-server-info" class="btn-sm">Server Info</button>
          </div>
        </div>
          </div>
        </details>
        <div class="settings-section">
          <h3>Danger Zone</h3>
          <button id="set-reset" class="btn-danger">Delete Account & Data</button>
        </div>
      </div>
    </div>
  `;

  q("#set-back").addEventListener("click", () => navigateTo({ screen: "conversations" }));

  // Save profile
  q<HTMLInputElement>("#set-username").addEventListener("input", () => {
    const usernameInput = q<HTMLInputElement>("#set-username");
    const usernameLookupEnabledInput = q<HTMLInputElement>("#set-username-lookup-enabled");
    const hasUsername = usernameInput.value.trim().length > 0;
    usernameLookupEnabledInput.disabled = !hasUsername;
    if (!hasUsername) {
      usernameLookupEnabledInput.checked = false;
    }
  });

  q("#set-save-profile").addEventListener("click", async () => {
    const nameInput = q<HTMLInputElement>("#set-name");
    const usernameInput = q<HTMLInputElement>("#set-username");
    const usernameLookupEnabledInput = q<HTMLInputElement>("#set-username-lookup-enabled");
    const newName = nameInput.value.trim();
    const newUsername = usernameInput.value.trim();
    const usernameLookupEnabled = Boolean(newUsername) && usernameLookupEnabledInput.checked;
    if (!newName) { nameInput.focus(); return; }
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildProfileUpsertAuthHeaders(k, newName, newUsername, usernameLookupEnabled, "", "");
      const profile = await api.upsertProfile(
        k.userId,
        {
          display_name: newName,
          username: newUsername || undefined,
          username_lookup_enabled: usernameLookupEnabled,
        },
        headers
      );
      setup.displayName = profile.display_name?.trim() || newName;
      setup.username = profile.username?.trim() || "";
      setup.usernameLookupEnabled = Boolean(profile.username_lookup_enabled && setup.username);
      saveSetup(setup);
      cachedProfileNames[k.userId] = setup.displayName;
      writeProfileDisplayName(k.userId, k.userId, setup.displayName);
      refreshConversationsIfVisible();
      void renderSettings();
      notify("Profile updated", "success");
    } catch (e) {
      notify(`Profile update failed: ${errorMsg(e)}`, "error");
    }
  });

  // Add contact
  q("#set-add-contact").addEventListener("click", async () => {
    const rawTarget = q<HTMLInputElement>("#set-add-contact-id").value.trim();
    const alias = q<HTMLInputElement>("#set-add-contact-alias").value.trim();
    if (!rawTarget) { q<HTMLInputElement>("#set-add-contact-id").focus(); return; }
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const inviteToken = extractInviteToken(rawTarget);
      const contactId = inviteToken
        ? await loadInvitePeerFromToken(inviteToken, api)
        : await resolvePeerUserIdFromTarget(rawTarget, api);
      if (!inviteToken) {
        await ensureDirectChatPeerExists(rawTarget);
      }
      const headers = buildContactsUpsertAuthHeaders(k, contactId, alias || contactId, false, "");
      await api.upsertContact(k.userId, { contact_user_id: contactId, alias: alias || undefined }, headers);
      notify("Contact added", "success");
      void loadContactsBackground();
      void loadProfileNameBackground(contactId);
      // Re-render to show updated list
      renderSettings();
    } catch (e) {
      notify(`Add contact failed: ${describePeerLookupError(rawTarget, e)}`, "error");
    }
  });

  // Remove contact buttons
  for (const btn of document.querySelectorAll("[data-remove-contact]")) {
    btn.addEventListener("click", async () => {
      const cid = (btn as HTMLElement).dataset.removeContact!;
      try {
        const k = await ensureKeys();
        const api = new PqmsgApi(setup.serverUrl);
        const headers = buildContactsRemoveAuthHeaders(k, cid);
        await api.removeContact(k.userId, { contact_user_id: cid }, headers);
        notify("Contact removed", "success");
        void loadContactsBackground();
        renderSettings();
      } catch (e) {
        notify(`Remove failed: ${errorMsg(e)}`, "error");
      }
    });
  }

  // Prekey status
  void loadPrekeyStatus();

  // Identity log navigation
  q("#set-identity-log").addEventListener("click", () => navigateTo({ screen: "identity-log" }));

  // Discovery navigation
  const discoveryButton = document.getElementById("set-discovery") as HTMLButtonElement | null;
  if (discoveryButton && !discoveryButton.disabled) {
    discoveryButton.addEventListener("click", () => navigateTo({ screen: "discovery" }));
  }

  // Server info navigation
  q("#set-server-info").addEventListener("click", () => navigateTo({ screen: "server-info" }));
  for (const button of document.querySelectorAll<HTMLElement>("[data-open-devices], #set-devices")) {
    button.addEventListener("click", () => navigateTo({ screen: "devices" }));
  }
  q("#set-logout").addEventListener("click", async () => {
    await logoutCurrentSession();
  });

  // Push token registration
  q("#set-push-register").addEventListener("click", async () => {
    const token = q<HTMLInputElement>("#set-push-token").value.trim();
    const provider = q<HTMLSelectElement>("#set-push-provider").value;
    const statusEl = document.getElementById("push-status")!;
    if (!token) { q<HTMLInputElement>("#set-push-token").focus(); return; }
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildPushTokenAuthHeaders(k, token);
      const res = await api.registerPushToken(k.userId, {
        device_id: k.deviceId,
        provider,
        token,
      }, headers);
      statusEl.innerHTML = `<span class="text-success">✓ Registered ${escHtml(res.provider)} push token</span>`;
    } catch (e) {
      statusEl.innerHTML = `<span class="text-danger">Failed: ${escHtml(errorMsg(e))}</span>`;
    }
  });

  // Key rotation
  q("#set-rotate-key").addEventListener("click", async () => {
    const statusEl = document.getElementById("rotate-status")!;
    statusEl.textContent = "Generating new identity keys…";
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      // Generate fresh identity keypair for rotation
      const newKeys = generateIdentityKeys(k.userId, k.deviceId, k.suite, 4);
      // Step 1: initiate rotation challenge
      const initHeaders = buildRotateInitAuthHeaders(
        k,
        newKeys.identityX25519Pub,
        newKeys.identitySigPub,
        newKeys.identityPqSigPub
      );
      statusEl.textContent = "Requesting rotation challenge…";
      const challenge = await api.rotateInit(k.userId, {
        new_identity_x25519_pub: newKeys.identityX25519Pub,
        new_identity_sig_pub: newKeys.identitySigPub,
        new_identity_pq_sig_pub: newKeys.identityPqSigPub,
        new_device_id: k.deviceId,
      }, initHeaders);
      // Step 2: sign the full rotation transcript with both current and new hybrid identities
      const rotateConfirmPayload = buildRotateConfirmPayload(
        k,
        newKeys,
        challenge.challenge_id,
        challenge.challenge_nonce
      );
      statusEl.textContent = "Confirming rotation…";
      const confirmHeaders = buildRotateConfirmAuthHeaders(
        k,
        rotateConfirmPayload.challenge_id,
        rotateConfirmPayload.sig_by_current_identity,
        rotateConfirmPayload.sig_by_new_identity,
        rotateConfirmPayload.pq_sig_by_current_identity,
        rotateConfirmPayload.pq_sig_by_new_identity
      );
      const result = await api.rotateConfirm(k.userId, rotateConfirmPayload, confirmHeaders);
      // Step 3: persist new keys locally
      const rotatedKeys: GeneratedKeys = { ...k, ...newKeys };
      const passphrase = getPassphrase();
      await saveKeys(k.userId, passphrase, rotatedKeys);
      await clearAllDirectMessageSessions(k.userId);
      keys = rotatedKeys;
      statusEl.innerHTML = `<span class="text-success">✓ Rotated to v${result.identity_key_version}</span>`;
      notify("Identity key rotated successfully", "success");
    } catch (e) {
      statusEl.innerHTML = `<span class="text-danger">Rotation failed: ${escHtml(errorMsg(e))}</span>`;
    }
  });

  q("#set-reset").addEventListener("click", async () => {
    if (!confirm("Delete all local data and retire your device from the server?")) return;
    try {
      if (hasLocalKeys(setup.userId)) {
        const k = await ensureKeys();
        const api = new PqmsgApi(setup.serverUrl);
        await api.retireCurrentDevice(setup.userId, buildRetireDeviceAuthHeaders(k));
      }
    } catch {
      // Best-effort server retirement
    }
    await wipeLocalState(setup.userId);
    await clearOutboxMessages(setup.userId);
    await clearAllMessages();
    keys = null;
    if (realtimeInbox) { realtimeInbox.disconnect(); realtimeInbox = null; }
    stopAllTimers();
    cachedContacts = [];
    peerPresenceCache = {};
    setup = { ...DEFAULT_SETUP, serverUrl: setup.serverUrl, suiteLabel: setup.suiteLabel, displayName: "" };
    saveSetup(setup);
    navigateTo({ screen: "onboarding" });
    notify("Account deleted", "info");
  });
}

// ---------------------------------------------------------------------------
// Device management
// ---------------------------------------------------------------------------

async function renderDevices(): Promise<void> {
  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="dev-back" class="icon-btn" aria-label="Back to settings">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">Devices</h1>
      </header>
      <div class="settings-body">
        <div id="device-list"><p class="text-secondary">Loading devices…</p></div>
        <button id="dev-link" class="btn-primary" style="margin-top:1rem;">+ Link New Device</button>
      </div>
    </div>
  `;
  q("#dev-back").addEventListener("click", () => navigateTo({ screen: "settings" }));
  q("#dev-link").addEventListener("click", () => navigateTo({ screen: "link-device" }));

  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildListDevicesAuthHeaders(k);
    const resp = await api.listDevices(k.userId, headers);
    const listEl = q("#device-list");
    if (resp.devices.length === 0) {
      listEl.innerHTML = `<p class="text-secondary">No devices found.</p>`;
      return;
    }
    listEl.innerHTML = resp.devices.map(d => {
      const isCurrent = d.device_id === setup.deviceId;
      const statusLabel = d.active ? (isCurrent ? "This device" : "Active") : "Revoked";
      const statusClass = d.active ? (isCurrent ? "text-success" : "") : "text-danger";
      const linked = new Date(d.linked_at).toLocaleDateString();
      const revokeBtn = d.active && !isCurrent
        ? `<button class="btn-sm btn-danger-sm" data-revoke-device="${escHtml(d.device_id)}">Revoke</button>`
        : "";
      return `
        <div class="device-row">
          <div class="device-info">
            <span class="mono">${escHtml(d.device_id)}</span>
            <span class="${statusClass}">${statusLabel}</span>
            <span class="text-secondary">Linked ${linked}</span>
            ${d.revoked_at ? `<span class="text-secondary">Revoked ${new Date(d.revoked_at).toLocaleDateString()}</span>` : ""}
          </div>
          ${revokeBtn}
        </div>
      `;
    }).join("");

    listEl.querySelectorAll("[data-revoke-device]").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const targetDeviceId = (e.currentTarget as HTMLElement).dataset.revokeDevice!;
        if (!confirm(`Revoke device "${targetDeviceId}"? This cannot be undone.`)) return;
        try {
          const rk = await ensureKeys();
          const rHeaders = buildRevokeDeviceAuthHeaders(rk, targetDeviceId);
          await api.revokeDevice(rk.userId, targetDeviceId, rHeaders);
          notify(`Device ${targetDeviceId} revoked`, "success");
          renderDevices();
        } catch (err) {
          notify(`Revoke failed: ${errorMsg(err)}`, "error");
        }
      });
    });
  } catch (e) {
    q("#device-list").innerHTML = `<p class="text-danger">Failed to load devices: ${escHtml(errorMsg(e))}</p>`;
  }
}

function renderLinkDevice(): void {
  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="ld-back" class="icon-btn" aria-label="Back to devices">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">Link New Device</h1>
      </header>
      <div class="settings-body">
        <p class="text-secondary">Enter a device ID for the new device. Keys will be generated and linked to your account.</p>
        <label class="field">
          <span>New Device ID</span>
          <input id="ld-device-id" type="text" placeholder="e.g. my-phone-1" />
        </label>
        <button id="ld-submit" class="btn-primary">Link Device</button>
        <div id="ld-status"></div>
      </div>
    </div>
  `;

  q("#ld-back").addEventListener("click", () => navigateTo({ screen: "devices" }));
  q("#ld-submit").addEventListener("click", async () => {
    const newDeviceId = q<HTMLInputElement>("#ld-device-id").value.trim();
    if (!newDeviceId) { q<HTMLInputElement>("#ld-device-id").focus(); return; }
    const statusEl = q("#ld-status");
    statusEl.textContent = "Linking device…";
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildLinkDeviceAuthHeaders(k, newDeviceId);
      const result = await api.linkDevice(k.userId, newDeviceId, headers);
      statusEl.innerHTML = `<p class="text-success">✓ Device "${escHtml(result.linked_device_id)}" linked at ${new Date(result.linked_at).toLocaleString()}</p>`;
      notify(`Device ${result.linked_device_id} linked`, "success");
    } catch (e) {
      statusEl.innerHTML = `<p class="text-danger">Link failed: ${escHtml(errorMsg(e))}</p>`;
    }
  });
}

// ---------------------------------------------------------------------------
// Call UI
// ---------------------------------------------------------------------------

async function renderCall(peerId: string, callType: "audio" | "video"): Promise<void> {
  const displayName = resolvePeerIdentity(peerId).primaryLabel;
  const callMode = callType === "video" ? "Video" : "Audio";

  app.innerHTML = `
    <div class="call-shell">
      <div class="call-overlay">
        <div class="call-avatar">
          <div class="avatar avatar-lg">${displayName.slice(0, 2).toUpperCase()}</div>
        </div>
        <h2 class="call-name">${escHtml(displayName)}</h2>
        <div class="beta-banner beta-banner-warning">
          <strong>${callMode} calling is unavailable on web</strong>
          <p>Use the supported messaging path instead. Web calling stays disabled in this beta.</p>
        </div>
        <div class="call-controls">
          <button id="call-back-chat" class="btn-secondary">Back to chat</button>
        </div>
      </div>
    </div>
  `;

  q("#call-back-chat").addEventListener("click", () => {
    navigateTo({ screen: "chat", peerId });
  });
  return;
  /*

  app.innerHTML = `
    <div class="call-shell">
      <div class="call-overlay">
        <div class="call-avatar">
          <div class="avatar avatar-lg">${displayName.slice(0, 2).toUpperCase()}</div>
        </div>
        <h2 class="call-name">${escHtml(displayName)}</h2>
        <p class="call-status" id="call-status">Calling…</p>
        <p class="call-timer" id="call-timer"></p>
        <div class="call-pq-badge" id="call-pq-badge" style="display:none">🛡️ PQ E2E Encrypted</div>
        <div class="call-media">
          <video id="remote-video" autoplay playsinline style="display:none"></video>
          <video id="local-video" autoplay playsinline muted style="display:none"></video>
        </div>
        <div class="call-controls">
          <button id="call-mute" class="call-btn" title="Mute">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 1a3 3 0 00-3 3v8a3 3 0 006 0V4a3 3 0 00-3-3z"/>
              <path d="M19 10v2a7 7 0 01-14 0v-2"/>
              <line x1="12" y1="19" x2="12" y2="23"/>
              <line x1="8" y1="23" x2="16" y2="23"/>
            </svg>
          </button>
          ${callType === "video" ? `
          <button id="call-cam" class="call-btn" title="Toggle camera">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polygon points="23 7 16 12 23 17 23 7"/>
              <rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>
            </svg>
          </button>
          ` : ""}
          <button id="call-hangup" class="call-btn call-btn-hangup" title="Hang up">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10.68 13.31a16 16 0 003.41 2.6l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6A19.79 19.79 0 012.12 4.18 2 2 0 014.11 2h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L8.09 9.91"/>
              <line x1="1" y1="1" x2="23" y2="23"/>
            </svg>
          </button>
        </div>
      </div>
    </div>
  `;

  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);

    callManager = new CallManager(api, k);

    let callTimerInterval: ReturnType<typeof setInterval> | null = null;

    callManager.onStateChange((info: CallInfo) => {
      currentCallInfo = info;
      const statusEl = document.getElementById("call-status");
      const timerEl = document.getElementById("call-timer");
      const pqBadge = document.getElementById("call-pq-badge");

      if (statusEl) {
        switch (info.state) {
          case "outgoing-ringing": statusEl.textContent = "Ringing…"; break;
          case "connecting": statusEl.textContent = "Connecting…"; break;
          case "active":
            statusEl.textContent = "Connected";
            if (pqBadge) pqBadge.style.display = "";
            // Start call timer
            if (!callTimerInterval && timerEl) {
              const startTime = Date.now();
              callTimerInterval = setInterval(() => {
                const elapsed = Math.floor((Date.now() - startTime) / 1000);
                const mins = Math.floor(elapsed / 60).toString().padStart(2, "0");
                const secs = (elapsed % 60).toString().padStart(2, "0");
                timerEl.textContent = `${mins}:${secs}`;
              }, 1000);
            }
            break;
          case "ended":
            statusEl.textContent = "Call ended";
            if (callTimerInterval) { clearInterval(callTimerInterval); callTimerInterval = null; }
            setTimeout(() => {
              if (setup.userId) {
                navigateTo({ screen: "chat", peerId });
              }
            }, 1500);
            break;
        }
      }

      // Show video elements when active
      if (info.state === "active" && callType === "video") {
        const remoteVideo = document.getElementById("remote-video") as HTMLVideoElement | null;
        const localVideo = document.getElementById("local-video") as HTMLVideoElement | null;
        if (remoteVideo && callManager?.getRemoteStream()) {
          remoteVideo.srcObject = callManager.getRemoteStream();
          remoteVideo.style.display = "";
        }
        if (localVideo && callManager?.getLocalStream()) {
          localVideo.srcObject = callManager.getLocalStream();
          localVideo.style.display = "";
        }
      }
    });

    // Start the outgoing call
    await callManager.startCall(peerId, callType);

    // Show local video preview immediately
    if (callType === "video") {
      const localVideo = document.getElementById("local-video") as HTMLVideoElement | null;
      if (localVideo && callManager.getLocalStream()) {
        localVideo.srcObject = callManager.getLocalStream();
        localVideo.style.display = "";
      }
    }

  } catch (e) {
    const statusEl = document.getElementById("call-status");
    if (statusEl) statusEl.textContent = `Call failed: ${errorMsg(e)}`;
    notify(`Call failed: ${errorMsg(e)}`, "error");
  }

  // Controls
  document.getElementById("call-hangup")?.addEventListener("click", () => {
    void callManager?.hangup();
  });
  document.getElementById("call-mute")?.addEventListener("click", (e) => {
    const muted = callManager?.toggleMute();
    const btn = e.currentTarget as HTMLButtonElement;
    btn.classList.toggle("call-btn-active", muted === true);
  });
  document.getElementById("call-cam")?.addEventListener("click", (e) => {
    const disabled = callManager?.toggleVideo();
    const btn = e.currentTarget as HTMLButtonElement;
    btn.classList.toggle("call-btn-active", disabled === true);
  });
  */
}

async function renderIncomingCall(
  callId: string,
  peerId: string,
  callType: "audio" | "video",
  sdpOfferBase64: string
): Promise<void> {
  const displayName = resolvePeerIdentity(peerId).primaryLabel;
  void callId;
  const callMode = callType === "video" ? "video" : "audio";
  void sdpOfferBase64;

  app.innerHTML = `
    <div class="call-shell">
      <div class="call-overlay">
        <div class="call-avatar">
          <div class="avatar avatar-lg">${displayName.slice(0, 2).toUpperCase()}</div>
        </div>
        <h2 class="call-name">${escHtml(displayName)}</h2>
        <div class="beta-banner beta-banner-warning">
          <strong>Incoming ${callMode} calls are disabled on web</strong>
          <p>Calling is out of scope for this beta. Return to conversations and continue on the messaging path.</p>
        </div>
        <div class="call-controls">
          <button id="call-back-conversations" class="btn-secondary">Back to conversations</button>
        </div>
      </div>
    </div>
  `;

  q("#call-back-conversations").addEventListener("click", () => {
    navigateTo({ screen: "conversations" });
  });
  return;
  /*

  app.innerHTML = `
    <div class="call-shell">
      <div class="call-overlay">
        <div class="call-avatar">
          <div class="avatar avatar-lg">${displayName.slice(0, 2).toUpperCase()}</div>
        </div>
        <h2 class="call-name">${escHtml(displayName)}</h2>
        <p class="call-status">Incoming ${callType} call…</p>
        <div class="call-controls">
          <button id="call-decline" class="call-btn call-btn-hangup" title="Decline">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10.68 13.31a16 16 0 003.41 2.6l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6A19.79 19.79 0 012.12 4.18 2 2 0 014.11 2h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L8.09 9.91"/>
              <line x1="1" y1="1" x2="23" y2="23"/>
            </svg>
          </button>
          <button id="call-accept" class="call-btn call-btn-accept" title="Accept">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6 19.79 19.79 0 01-3.07-8.67A2 2 0 014.11 2h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L8.09 9.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z"/>
            </svg>
          </button>
        </div>
      </div>
    </div>
  `;

  q("#call-decline").addEventListener("click", () => {
    navigateTo({ screen: "conversations" });
  });

  q("#call-accept").addEventListener("click", async () => {
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      callManager = new CallManager(api, k);

      callManager.onStateChange((info: CallInfo) => {
        currentCallInfo = info;
        if (info.state === "ended") {
          setTimeout(() => {
            if (setup.userId) {
              navigateTo({ screen: "conversations" });
            }
          }, 1500);
        }
      });

      await callManager.acceptCall(callId, peerId, callType, sdpOfferBase64);
      // Re-render to active call UI
      navigateTo({ screen: "call", peerId, callType });
    } catch (e) {
      notify(`Failed to accept call: ${errorMsg(e)}`, "error");
      navigateTo({ screen: "conversations" });
    }
  });
  */
}

// ---------------------------------------------------------------------------
// WebSocket realtime
// ---------------------------------------------------------------------------

async function connectRealtime(): Promise<void> {
  if (realtimeInbox) return;
  try {
    const capabilities = await loadServerCapabilitiesCached();
    const k = await ensureKeys();
    if (capabilities?.sealed_sender_required !== true) {
      return;
    }
    realtimeInbox = new RealtimeInbox(setup.serverUrl, k);
    realtimeInbox.onMessage(handleRealtimeMessage);
    realtimeInbox.connect();
  } catch {
    // Fall back to polling
  }
}

async function handleRealtimeMessage(wsMsg: WsInboxMessage): Promise<void> {
  try {
    const k = await ensureKeys();
    const decrypted = await decryptIncomingPayload(
      k,
      wsMsg.message_bytes_base64,
      wsMsg.sender_user_id,
      wsMsg.sender_identity_x25519_pub
    );
    if (decrypted.kind === "ignored") {
      const cursor = readSealedCursor(k.userId, k.deviceId);
      if (wsMsg.message_id > cursor) {
        writeSealedCursor(k.userId, wsMsg.message_id, k.deviceId);
      }
      return;
    }
    const plaintext = decrypted.plaintext;
    const senderId = decrypted.senderUserId;
    const isDirectMessage = decrypted.kind === "dm";
    const groupId = isDirectMessage ? null : decrypted.recipient;
    const conversationId = isDirectMessage
      ? convId(k.userId, senderId)
      : `group:${groupId}`;
    const existing = await getMessages(conversationId);
    if (existing.some((msg) => msg.serverMessageId === wsMsg.message_id)) {
      const cursor = readSealedCursor(k.userId, k.deviceId);
      if (wsMsg.message_id > cursor) {
        writeSealedCursor(k.userId, wsMsg.message_id, k.deviceId);
      }
      return;
    }
    const msg: StoredMessage = {
      id: `srv-${wsMsg.message_id}`,
      conversationId,
      sender: senderId,
      recipient: isDirectMessage ? k.userId : decrypted.recipient,
      text: isDirectMessage
        ? plaintext
        : `${resolvePeerIdentity(senderId).primaryLabel}: ${plaintext}`,
      timestamp: new Date(wsMsg.received_at).getTime() || Date.now(),
      status: "delivered",
      serverMessageId: wsMsg.message_id,
    };
    await saveMessage(msg);

    if (isDirectMessage) {
      void sendDeliveredReceipt(wsMsg.message_id);
    }

    const cursor = readSealedCursor(k.userId, k.deviceId);
    if (wsMsg.message_id > cursor) {
      writeSealedCursor(k.userId, wsMsg.message_id, k.deviceId);
    }

    if (isDirectMessage) {
      const isActivePeer = activeChatPeer === senderId;
      noteIncomingConversation(senderId, plaintext, !isActivePeer);
      if (isActivePeer) {
        markConversationRead(k.userId, senderId);
        const msgList = document.getElementById("messages-list");
        const container = document.getElementById("messages-container");
        if (msgList && container) {
          appendBubble(msgList, msg, container);
        }
      } else {
        notify(`${resolvePeerIdentity(senderId).primaryLabel}: ${plaintext.slice(0, 50)}`, "info");
      }
    } else if (groupId) {
      const groupSenderId = wsMsg.sender_user_id ?? senderId;
      const isActiveGroup = activeGroupId === groupId;
      noteIncomingGroupConversation(groupId, groupSenderId, plaintext, !isActiveGroup);
      void loadProfileNameBackground(groupSenderId);
      if (isActiveGroup) {
        markGroupConversationRead(k.userId, groupId);
        const msgList = document.getElementById("messages-list");
        const container = document.getElementById("messages-container");
        if (msgList && container) {
          appendBubble(msgList, msg, container);
        }
      } else {
        const ownerUserId =
          loadGroupConversations(k.userId).find((item) => item.groupId === groupId)?.ownerUserId ||
          groupSenderId;
        const groupLabel = resolveGroupIdentity(groupId, ownerUserId).primaryLabel;
        notify(`${groupLabel} · ${resolvePeerIdentity(groupSenderId).primaryLabel}: ${plaintext.slice(0, 50)}`, "info");
      }
    }

    refreshConversationsIfVisible();
  } catch (e) {
    console.warn("realtime message handling failed", e);
  }
}
// ---------------------------------------------------------------------------
// Inbox polling (fallback / catch-up)
// ---------------------------------------------------------------------------

async function pollInboxSilent(): Promise<void> {
  try {
    const capabilities = await loadServerCapabilitiesCached();
    if (capabilities?.sealed_sender_required !== true) {
      return;
    }
    await pollSealedInbox();
  } catch {
    // Silent failure for background polling
  }
}
// ---------------------------------------------------------------------------
// Rich interaction helpers (Reply, React, Edit)
// ---------------------------------------------------------------------------

const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🔥"];

// State for reply compose
let replyContext: { msgId: string; preview: string } | null = null;
// State for edit compose
let editContext: { msgId: string; originalText: string; allowEmptyText: boolean } | null = null;
const replyThreadFocusByConversation = new Map<string, string | null>();
let messageSelectionState: { conversationId: string; selectedIds: Set<string> } | null = null;

function showBubbleContextMenu(
  e: MouseEvent,
  msgId: string,
  isMine: boolean,
  serverMid: number | null,
  bubble: HTMLElement,
  inputEl: ComposeField,
  sendBtnEl: HTMLButtonElement,
  peerId?: string,
  onSelectionChange?: () => void,
  options?: {
    allowEdit?: boolean;
    allowServerDelete?: boolean;
    onLocalDelete?: (msgId: string) => Promise<void> | void;
  },
): void {
  // Remove any existing context menu
  document.querySelector(".ctx-menu")?.remove();

  const menu = document.createElement("div");
  menu.className = "ctx-menu";
  menu.style.top = `${e.clientY}px`;
  menu.style.left = `${e.clientX}px`;

  const allowEdit = options?.allowEdit ?? false;
  const allowServerDelete = options?.allowServerDelete ?? false;
  const hasAttachment = bubble.dataset.hasAttachment === "1";
  let items = `<div class="ctx-item" data-action="reply">↩️ Reply</div>
    <div class="ctx-item" data-action="react">😀 React</div>`;
  if (hasAttachment) {
    items += `<div class="ctx-item" data-action="open">📎 Open attachment</div>`;
  }
  items += `<div class="ctx-item" data-action="copy">Copy</div>
    <div class="ctx-item" data-action="share">Share</div>
    <div class="ctx-item ctx-danger" data-action="delete-local">Delete from this device</div>`;
  if (isMine && allowEdit) {
    items += `<div class="ctx-item" data-action="edit">✏️ Edit</div>`;
  }
  if (isMine && allowServerDelete && serverMid) {
    items += `<div class="ctx-item ctx-danger" data-action="delete">🗑️ Delete</div>`;
  }
  items += `<div class="ctx-item" data-action="select">Select messages</div>`;
  menu.innerHTML = items;
  document.body.appendChild(menu);

  const dismiss = () => menu.remove();
  setTimeout(() => document.addEventListener("click", dismiss, { once: true }), 0);

  menu.addEventListener("click", async (ev) => {
    const action = (ev.target as HTMLElement).dataset.action;
    menu.remove();
    if (!action) return;

    if (action === "reply") {
      const stored = await getMessage(msgId);
      const preview = (
        stored ? messageTranscriptText(stored) : bubble.querySelector(".bubble-text")?.textContent || ""
      ).replace(/\s+/g, " ").trim();
      replyContext = { msgId, preview: preview.slice(0, 60) };
      showReplyBar(inputEl);
      inputEl.focus();
    }

    if (action === "react") {
      showReactionPicker(e.clientX, e.clientY, msgId, bubble, peerId);
    }

    if (action === "open") {
      const stored = await getMessage(msgId);
      if (stored && hasStoredAttachment(stored)) {
        void openStoredAttachment(stored);
      }
    }

    if (action === "copy") {
      const stored = await getMessage(msgId);
      const transcript = (
        stored ? messageTranscriptText(stored) : bubble.querySelector(".bubble-text")?.textContent || ""
      ).trim();
      if (transcript) {
        await navigator.clipboard.writeText(transcript);
        notify("Message copied", "success");
      }
    }

    if (action === "share") {
      const stored = await getMessage(msgId);
      const transcript = (
        stored ? messageTranscriptText(stored) : bubble.querySelector(".bubble-text")?.textContent || ""
      ).trim();
      if (!transcript) {
        return;
      }
      if (navigator.share) {
        try {
          await navigator.share({ text: transcript });
        } catch {
          await navigator.clipboard.writeText(transcript);
        }
      } else {
        await navigator.clipboard.writeText(transcript);
      }
      notify("Message ready to share", "success");
    }

    if (action === "delete-local") {
      await options?.onLocalDelete?.(msgId);
    }

    if (action === "edit") {
      const stored = await getMessage(msgId);
      if (!stored) {
        return;
      }
      const text = hasStoredAttachment(stored)
        ? (stored.attachmentNoteText ?? stored.text).trim()
        : stored.text.trim();
      editContext = {
        msgId,
        originalText: text,
        allowEmptyText: hasStoredAttachment(stored),
      };
      inputEl.value = text;
      autoResizeComposeField(inputEl);
      sendBtnEl.disabled = false;
      sendBtnEl.textContent = "Save";
      inputEl.focus();
    }

    if (action === "delete" && serverMid) {
      showDeleteConfirm(bubble, serverMid);
    }

    if (action === "select") {
      const conversationId = bubble.dataset.conversationId || "";
      if (!conversationId) return;
      enterMessageSelection(conversationId, msgId);
      onSelectionChange?.();
    }
  });
}

function showReplyBar(inputEl: ComposeField): void {
  // Remove existing reply bar
  document.querySelector(".reply-compose-bar")?.remove();

  if (!replyContext) return;
  const bar = document.createElement("div");
  bar.className = "reply-compose-bar";
  bar.innerHTML = `<span class="reply-bar-text">↩️ ${escHtml(replyContext.preview)}</span>
    <button class="reply-bar-close icon-btn" aria-label="Cancel reply">✕</button>`;
  bar.querySelector(".reply-bar-close")!.addEventListener("click", () => {
    replyContext = null;
    bar.remove();
  });
  inputEl.parentElement!.insertBefore(bar, inputEl.parentElement!.firstChild);
}

function autoResizeComposeField(field: ComposeField): void {
  if (!(field instanceof HTMLTextAreaElement)) {
    return;
  }
  field.style.height = "0px";
  field.style.height = `${Math.min(field.scrollHeight, 144)}px`;
}

function showReactionPicker(x: number, y: number, msgId: string, bubble: HTMLElement, peerId?: string): void {
  document.querySelector(".reaction-picker")?.remove();
  const picker = document.createElement("div");
  picker.className = "reaction-picker";
  picker.style.top = `${y}px`;
  picker.style.left = `${x}px`;
  picker.innerHTML = QUICK_REACTIONS.map(e => `<span class="reaction-option" data-emoji="${e}">${e}</span>`).join("");
  document.body.appendChild(picker);

  setTimeout(() => document.addEventListener("click", () => picker.remove(), { once: true }), 0);

  picker.addEventListener("click", async (ev) => {
    const emoji = (ev.target as HTMLElement).dataset.emoji;
    if (!emoji) return;
    picker.remove();
    const updated = await addReaction(msgId, emoji, setup.userId);
    if (updated) {
      // Re-render reaction pills on the bubble
      let pills = bubble.querySelector(".reaction-pills");
      if (pills) pills.remove();
      const newHtml = renderReactions(updated);
      if (newHtml) bubble.insertAdjacentHTML("beforeend", newHtml);
      // Add click handler for toggling on newly rendered pills
      bubble.querySelectorAll(".reaction-pill").forEach(pill => {
        pill.addEventListener("click", async () => {
          const em = (pill as HTMLElement).dataset.emoji!;
          const u = await addReaction(msgId, em, setup.userId);
          if (u) {
            bubble.querySelector(".reaction-pills")?.remove();
            const h = renderReactions(u);
            if (h) bubble.insertAdjacentHTML("beforeend", h);
          }
        });
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Media helpers
// ---------------------------------------------------------------------------

async function loadMediaBlob(fileId: string, bubbleEl: HTMLElement): Promise<void> {
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildFileDownloadAuthHeaders(k, fileId);
    const res = await api.downloadFile(fileId, headers);
    const bytes = Uint8Array.from(atob(res.file_bytes_base64), c => c.charCodeAt(0));
    const blob = new Blob([bytes], { type: res.mime_type });
    const url = URL.createObjectURL(blob);
    mediaBlobCache.set(fileId, url);
    // Re-render the placeholder
    const placeholder = bubbleEl.querySelector(`[data-file-id="${fileId}"]`);
    if (placeholder) {
      if (res.mime_type.startsWith("image/")) {
        const img = document.createElement("img");
        img.src = url;
        img.className = "media-img";
        img.loading = "lazy";
        img.addEventListener("click", () => showLightbox(url));
        placeholder.replaceWith(img);
      } else if (res.mime_type.startsWith("audio/")) {
        const audio = document.createElement("audio");
        audio.controls = true;
        audio.src = url;
        audio.className = "media-audio";
        placeholder.replaceWith(audio);
      } else if (res.mime_type.startsWith("video/")) {
        const video = document.createElement("video");
        video.controls = true;
        video.src = url;
        video.className = "media-video";
        placeholder.replaceWith(video);
      }
    }
  } catch {
    // Leave placeholder as-is
  }
}

function showLightbox(src: string): void {
  const overlay = document.createElement("div");
  overlay.className = "media-lightbox";
  overlay.innerHTML = `<img src="${src}" class="lightbox-img" />`;
  overlay.addEventListener("click", () => overlay.remove());
  document.addEventListener("keydown", function handler(e) {
    if (e.key === "Escape") { overlay.remove(); document.removeEventListener("keydown", handler); }
  });
  document.body.appendChild(overlay);
}

async function downloadAndOpenFile(fileId: string): Promise<void> {
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildFileDownloadAuthHeaders(k, fileId);
    const res = await api.downloadFile(fileId, headers);
    const bytes = Uint8Array.from(atob(res.file_bytes_base64), c => c.charCodeAt(0));
    const blob = new Blob([bytes], { type: res.mime_type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileId;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (e) {
    notify(`Download failed: ${errorMsg(e)}`, "error");
  }
}

function hideSharedMediaOverlay(): void {
  sharedMediaOverlay?.remove();
  sharedMediaOverlay = null;
  if (sharedMediaOverlayKeyHandler) {
    document.removeEventListener("keydown", sharedMediaOverlayKeyHandler);
    sharedMediaOverlayKeyHandler = null;
  }
}

function classifySharedMediaFilter(message: StoredMessage): SharedMediaFilter | null {
  if (!hasStoredAttachment(message)) {
    return null;
  }
  const mimeType = attachmentMimeType(message);
  if (mimeType.startsWith("image/") || mimeType.startsWith("video/")) {
    return "media";
  }
  if (mimeType.startsWith("audio/")) {
    return "audio";
  }
  return "files";
}

function sharedMediaFilterLabel(filter: SharedMediaFilter): string {
  switch (filter) {
    case "media":
      return "Media";
    case "files":
      return "Files";
    case "audio":
      return "Audio";
    default:
      return "All";
  }
}

function renderSharedMediaPreview(message: StoredMessage): string {
  if (!hasStoredAttachment(message)) {
    return `<div class="shared-media-empty">No preview available</div>`;
  }
  const fileId = message.fileId;
  const mimeType = attachmentMimeType(message);
  const fileName = attachmentDisplayName(message);
  const blobUrl = getStoredAttachmentUrl(message);
  if (mimeType.startsWith("image/") && blobUrl) {
    return `<img src="${blobUrl}" alt="${escHtml(fileName)}" class="media-img" loading="lazy" />`;
  }
  if (mimeType.startsWith("audio/") && blobUrl) {
    return `<audio controls src="${blobUrl}" class="media-audio"></audio>`;
  }
  if (mimeType.startsWith("video/") && blobUrl) {
    return `<video controls src="${blobUrl}" class="media-video"></video>`;
  }
  if (fileId && (mimeType.startsWith("image/") || mimeType.startsWith("audio/") || mimeType.startsWith("video/"))) {
    return `<div class="shared-media-loading" data-file-id="${escHtml(fileId)}">Loading preview…</div>`;
  }
  const kindLabel = describeAttachmentKind(mimeType);
  return `
    <div class="shared-media-file-tile">
      <span class="shared-media-file-glyph">${escHtml(kindLabel.slice(0, 1))}</span>
      <span class="shared-media-file-name">${escHtml(fileName)}</span>
    </div>
  `;
}

function formatSharedMediaSubtitle(message: StoredMessage): string {
  const parts = [describeAttachmentKind(attachmentMimeType(message))];
  if (message.conversationId.startsWith("group:")) {
    parts.push(message.sender === setup.userId ? "You" : resolvePeerIdentity(message.sender).primaryLabel);
  }
  parts.push(new Date(message.timestamp).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }));
  return parts.join(" · ");
}

async function showSharedMediaSheet(options: {
  title: string;
  conversationId: string;
  emptyMessage: string;
}): Promise<void> {
  const messages = (await getMessages(options.conversationId))
    .filter((message) => hasStoredAttachment(message))
    .sort((left, right) => right.timestamp - left.timestamp);
  if (messages.length === 0) {
    notify(options.emptyMessage, "info");
    return;
  }

  hideSharedMediaOverlay();
  let activeFilter: SharedMediaFilter = "all";
  const counts: Record<SharedMediaFilter, number> = {
    all: messages.length,
    media: messages.filter((message) => classifySharedMediaFilter(message) === "media").length,
    files: messages.filter((message) => classifySharedMediaFilter(message) === "files").length,
    audio: messages.filter((message) => classifySharedMediaFilter(message) === "audio").length,
  };

  const overlay = document.createElement("div");
  overlay.className = "shared-media-sheet";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-labelledby", "shared-media-title");
  overlay.innerHTML = `
    <div class="shared-media-card">
      <div class="shared-media-head">
        <div>
          <h3 id="shared-media-title">${escHtml(options.title)}</h3>
          <p>Browse the attachments saved in this conversation on this device.</p>
        </div>
        <button id="shared-media-close" class="icon-btn" aria-label="Close shared media">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
            <path d="M18 6L6 18M6 6l12 12"/>
          </svg>
        </button>
      </div>
      <div class="shared-media-tabs">
        ${(["all", "media", "files", "audio"] as SharedMediaFilter[])
          .map((filter) => `
            <button type="button" class="shared-media-tab" data-shared-media-filter="${filter}">
              ${sharedMediaFilterLabel(filter)} <span>${counts[filter]}</span>
            </button>
          `)
          .join("")}
      </div>
      <div id="shared-media-grid" class="shared-media-grid"></div>
    </div>
  `;
  document.body.appendChild(overlay);
  sharedMediaOverlay = overlay;

  const grid = overlay.querySelector<HTMLElement>("#shared-media-grid")!;
  const tabButtons = Array.from(overlay.querySelectorAll<HTMLButtonElement>("[data-shared-media-filter]"));
  const render = (): void => {
    tabButtons.forEach((button) => {
      button.classList.toggle("active", button.dataset.sharedMediaFilter === activeFilter);
    });
    const filtered = messages.filter((message) => activeFilter === "all" || classifySharedMediaFilter(message) === activeFilter);
    if (filtered.length === 0) {
      grid.innerHTML = `<div class="shared-media-empty">No ${sharedMediaFilterLabel(activeFilter).toLowerCase()} in this conversation yet.</div>`;
      return;
    }
    grid.innerHTML = filtered
      .map((message) => `
        <article class="shared-media-item">
          <div class="shared-media-preview">
            ${renderSharedMediaPreview(message)}
          </div>
          <div class="shared-media-copy">
            <div class="shared-media-item-title">${escHtml(attachmentDisplayName(message))}</div>
            <div class="shared-media-item-meta">${escHtml(formatSharedMediaSubtitle(message))}</div>
            ${attachmentCaptionText(message).trim() ? `<div class="shared-media-item-note">${escHtml(attachmentCaptionText(message).trim())}</div>` : ""}
          </div>
          <div class="shared-media-actions">
            <button type="button" class="btn-secondary shared-media-open" data-message-id="${escHtml(message.id)}">Open</button>
          </div>
        </article>
      `)
      .join("");

    grid.querySelectorAll<HTMLButtonElement>(".shared-media-open").forEach((button) => {
      button.addEventListener("click", () => {
        const messageId = button.dataset.messageId;
        const targetMessage = filtered.find((message) => message.id === messageId);
        if (targetMessage) {
          void openStoredAttachment(targetMessage);
        }
      });
    });
    grid.querySelectorAll<HTMLImageElement>(".shared-media-preview .media-img").forEach((img) => {
      img.addEventListener("click", () => showLightbox(img.src));
    });
    filtered.forEach((message) => {
      if (!message.fileId) {
        return;
      }
      const previewHost = grid.querySelector<HTMLElement>(`.shared-media-item .shared-media-preview [data-file-id="${CSS.escape(message.fileId)}"]`)?.closest(".shared-media-preview") as HTMLElement | null;
      if (previewHost && !mediaBlobCache.has(message.fileId) && classifySharedMediaFilter(message) !== "files") {
        void loadMediaBlob(message.fileId, previewHost);
      }
    });
  };

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      activeFilter = (button.dataset.sharedMediaFilter as SharedMediaFilter) || "all";
      render();
    });
  });
  overlay.querySelector<HTMLElement>("#shared-media-close")?.addEventListener("click", hideSharedMediaOverlay);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) {
      hideSharedMediaOverlay();
    }
  });
  sharedMediaOverlayKeyHandler = (event: KeyboardEvent) => {
    if (event.key === "Escape" && sharedMediaOverlay) {
      event.preventDefault();
      hideSharedMediaOverlay();
    }
  };
  document.addEventListener("keydown", sharedMediaOverlayKeyHandler);
  render();
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

let searchDebounce: ReturnType<typeof setTimeout> | null = null;

function renderSearch(): void {
  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="search-back" class="icon-btn" aria-label="Back to conversations">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <input id="search-input" type="text" class="search-input" placeholder="Search messages…" autocomplete="off" aria-label="Search messages" />
      </header>
      <div class="search-results" id="search-results" role="list">
        <p class="empty-state">Type to search your messages</p>
      </div>
    </div>
  `;

  const input = q<HTMLInputElement>("#search-input");
  const results = q("#search-results");

  q("#search-back").addEventListener("click", () => navigateTo({ screen: "conversations" }));

  input.addEventListener("input", () => {
    if (searchDebounce) clearTimeout(searchDebounce);
    const query = input.value.trim();
    if (!query) {
      results.innerHTML = `<p class="empty-state">Type to search your messages</p>`;
      return;
    }
    searchDebounce = setTimeout(async () => {
      const msgs = await searchMessages(query);
      if (msgs.length === 0) {
        results.innerHTML = `<p class="empty-state">No results for "${escHtml(query)}"</p>`;
        return;
      }
      results.innerHTML = msgs.slice(0, 50).map(m => {
        const isGroup = m.conversationId.startsWith("group:");
        const peer = isGroup ? m.conversationId.replace("group:", "") : (m.sender === setup.userId ? m.recipient : m.sender);
        const time = new Date(m.timestamp).toLocaleDateString([], { month: "short", day: "numeric" });
        const transcript = messageTranscriptText(m);
        const preview = transcript.length > 80 ? transcript.slice(0, 80) + "…" : transcript;
        return `<div class="search-result-item" role="listitem" data-search-peer="${escHtml(peer)}" data-search-group="${isGroup ? "1" : ""}">
          <div class="avatar avatar-sm">${peer.slice(0, 2).toUpperCase()}</div>
          <div class="search-result-body">
            <div class="search-result-header">
              <span class="search-result-name">${escHtml(peer)}</span>
              <span class="search-result-time">${time}</span>
            </div>
            <div class="search-result-preview">${escHtml(preview)}</div>
          </div>
        </div>`;
      }).join("");

      for (const row of results.querySelectorAll(".search-result-item")) {
        row.addEventListener("click", () => {
          const peer = (row as HTMLElement).dataset.searchPeer!;
          const isGroup = (row as HTMLElement).dataset.searchGroup === "1";
          if (isGroup) {
            navigateTo({ screen: "group-chat", groupId: peer });
          } else {
            navigateTo({ screen: "chat", peerId: peer });
          }
        });
      }
    }, 300);
  });

  input.focus();
}

// ---------------------------------------------------------------------------
// Offline banner & outbox
// ---------------------------------------------------------------------------

function showOfflineBanner(offline: boolean): void {
  let banner = document.getElementById("offline-banner");
  if (offline) {
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "offline-banner";
      banner.className = "offline-banner";
      banner.setAttribute("role", "status");
      banner.textContent = "No internet connection";
      document.body.appendChild(banner);
    }
  } else {
    banner?.remove();
  }
}

async function drainOutbox(): Promise<void> {
  try {
    const k = await ensureKeys();
    if (!(await ensureWebMessagingAllowed("direct"))) {
      const queued = await getOutboxMessages(k.userId);
      for (const item of queued) {
        await removeOutboxMessage(item.id);
        await updateMessageStatus(item.id, "failed");
        updateBubbleStatus(item.id, "failed");
      }
      return;
    }
    const api = new PqmsgApi(setup.serverUrl);
    const queued = await getOutboxMessages(k.userId);
    for (const item of queued) {
      try {
        if (item.groupId) {
          await removeOutboxMessage(item.id);
          await updateMessageStatus(item.id, "failed");
          updateBubbleStatus(item.id, "failed");
          continue;
        } else {
          const messageBytesBase64 = await encryptDirectPayload(k, item.peerId, item.text);
          const deliveryToken = await loadPeerSealedDeliveryToken(k, item.peerId, api);
          await api.sealedRelay(item.peerId, {
            delivery_token: deliveryToken,
            message_bytes_base64: messageBytesBase64,
          });
        }
        await removeOutboxMessage(item.id);
        await updateMessageStatus(item.id, "sent");
        updateBubbleStatus(item.id, "sent");
      } catch {
        // Leave in outbox for next retry
      }
    }
  } catch {
    // Keys not available or no passphrase — skip drain
  }
}

// ---------------------------------------------------------------------------
// Toast notifications
// ---------------------------------------------------------------------------

function showToast(n: AppNotification): void {
  let toast = document.getElementById("toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    toast.setAttribute("role", "alert");
    toast.setAttribute("aria-live", "assertive");
    document.body.appendChild(toast);
  }
  activeToastAction = n.action ?? null;
  toast.innerHTML = "";
  const text = document.createElement("span");
  text.className = "toast-text";
  text.textContent = n.text;
  toast.appendChild(text);
  if (n.actionLabel && n.action) {
    const actionButton = document.createElement("button");
    actionButton.type = "button";
    actionButton.className = "toast-action";
    actionButton.textContent = n.actionLabel;
    actionButton.addEventListener("click", () => {
      const action = activeToastAction;
      activeToastAction = null;
      toast!.classList.remove("toast-show");
      if (toastTimer) {
        clearTimeout(toastTimer);
        toastTimer = null;
      }
      action?.();
    });
    toast.appendChild(actionButton);
  }
  toast.className = `toast toast-${n.type} toast-show`;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    activeToastAction = null;
    toast!.classList.remove("toast-show");
  }, 3500);
}

// ---------------------------------------------------------------------------
// Phase 2: Presence heartbeat
// ---------------------------------------------------------------------------

function startPresenceHeartbeat(): void {
  if (!presenceSupported()) return;
  if (presenceHeartbeatTimer) return;
  void sendPresenceUpdate("online");
  presenceHeartbeatTimer = setInterval(() => {
    void sendPresenceUpdate("online");
  }, 120_000); // Re-send every 2 minutes (TTL is 180s)
}

async function sendPresenceUpdate(status: "online" | "away" | "offline"): Promise<void> {
  if (!presenceSupported()) return;
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildPresenceUpdateAuthHeaders(k, status);
    await api.updatePresence(k.userId, { status }, headers);
  } catch {
    // Best-effort
  }
}

async function fetchPeerPresence(peerId: string): Promise<void> {
  if (!presenceSupported()) return;
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildPresenceGetAuthHeaders(k);
    const res = await api.getPresence(peerId, headers);
    peerPresenceCache[peerId] = { status: res.status, updated: Date.now() };
    // Update UI if in chat
    const statusEl = document.getElementById("chat-status");
    if (statusEl && activeChatPeer === peerId) {
      statusEl.textContent = res.status === "online" ? "online" : res.status === "away" ? "away" : "encrypted";
      statusEl.className = `chat-header-status ${res.status === "offline" ? "" : `presence-${res.status}`}`;
    }
  } catch {
    // Best-effort
  }
}

// ---------------------------------------------------------------------------
// Phase 2: Typing indicators
// ---------------------------------------------------------------------------

function sendTypingIndicator(peerId: string, isTyping: boolean): void {
  if (!typingIndicatorsSupported()) return;
  if (typingTimer) clearTimeout(typingTimer);
  if (isTyping) {
    typingTimer = setTimeout(() => {
      void sendTypingUpdate(peerId, false);
    }, 10_000); // Stop typing after 10s of no input
  }
  void sendTypingUpdate(peerId, isTyping);
}

async function sendTypingUpdate(peerId: string, isTyping: boolean): Promise<void> {
  if (!typingIndicatorsSupported()) return;
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildTypingUpdateAuthHeaders(k, peerId, isTyping);
    await api.updateTyping(peerId, { is_typing: isTyping }, headers);
  } catch {
    // Best-effort
  }
}

function startTypingPoll(peerId: string): void {
  if (!typingIndicatorsSupported()) return;
  stopChatTimers();
  const poll = async () => {
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildTypingGetAuthHeaders(k);
      const res = await api.getTyping(k.userId, headers);
      const indicator = document.getElementById("typing-indicator");
      if (!indicator) return;
      const peerTyping = res.typing.some(t => t.user_id === peerId && t.is_typing);
      indicator.classList.toggle("hidden", !peerTyping);
    } catch {
      // Best-effort
    }
  };
  void poll();
  typingPollTimer = setInterval(poll, 3000);
}

// ---------------------------------------------------------------------------
// Phase 2: Read receipts
// ---------------------------------------------------------------------------

function startReceiptPoll(): void {
  if (!readReceiptsSupported()) return;
  if (receiptPollTimer) return;
  const poll = async () => {
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildGetReceiptsAuthHeaders(k, receiptCursor);
      const res = await api.getReceipts(k.userId, receiptCursor, headers);
      for (const r of res.receipts) {
        receiptCursor = Math.max(receiptCursor, r.receipt_id);
        // Update bubble status for sent messages
        const newStatus = r.receipt_type === "read" ? "delivered" : "delivered"; // both show as delivered tick
        const bubbleEl = document.querySelector(`[data-server-mid="${r.message_id}"]`);
        if (bubbleEl) {
          const statusText = r.receipt_type === "read" ? "read" : "delivered";
          updateBubbleStatus(bubbleEl.id.replace("msg-", ""), statusText as StoredMessage["status"]);
        }
      }
    } catch {
      // Best-effort
    }
  };
  void poll();
  receiptPollTimer = setInterval(poll, 5000);
}

async function sendDeliveredReceipt(messageId: number): Promise<void> {
  if (!readReceiptsSupported()) return;
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildSendReceiptAuthHeaders(k, messageId, "delivered");
    await api.sendReceipt(k.userId, { message_id: messageId, receipt_type: "delivered" }, headers);
  } catch {
    // Best-effort
  }
}

// ---------------------------------------------------------------------------
// Phase 2: Contacts
// ---------------------------------------------------------------------------

async function loadContactsBackground(): Promise<void> {
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildContactsListAuthHeaders(k);
    const res = await api.listContacts(k.userId, headers);
    const changed = JSON.stringify(cachedContacts) !== JSON.stringify(res.contacts);
    cachedContacts = res.contacts;
    ensureAcceptedContactsMeta();
    if (changed) {
      refreshConversationsIfVisible();
    }
  } catch {
    // Best-effort — use cached
  }
}

// ---------------------------------------------------------------------------
// Phase 4: Identity Log
// ---------------------------------------------------------------------------

async function renderIdentityLog(): Promise<void> {
  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="idlog-back" class="icon-btn" aria-label="Back to settings">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">Identity Log</h1>
      </header>
      <div class="settings-body" id="idlog-body">
        <p class="text-secondary">Loading identity events…</p>
      </div>
    </div>
  `;

  q("#idlog-back").addEventListener("click", () => navigateTo({ screen: "settings" }));

  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildIdentityLogAuthHeaders(k);
    const res = await api.getIdentityLog(k.userId, headers);
    const capabilities = await loadServerCapabilitiesCached();
    const body = document.getElementById("idlog-body")!;
    let transparencySummary = "";
    if (capabilities?.key_transparency_supported && capabilities.transparency_log_issuer_ed25519_pub) {
      try {
        const checkpoint = readTransparencyCheckpoint(setup.serverUrl, k.userId);
        const proof = await api.getTransparencyProof(k.userId, checkpoint?.tree_size);
        const verification = verifyTransparencyProof(
          JSON.stringify(proof),
          capabilities.transparency_log_issuer_ed25519_pub,
          checkpoint ? JSON.stringify(checkpoint) : null,
        );
        writeTransparencyCheckpoint(setup.serverUrl, k.userId, proof.signed_tree_head);
        const fingerprintMatches = res.events[0]
          ? identityFingerprint(
              proof.leaf.identity_x25519_pub,
              proof.leaf.identity_pq_sig_pub ?? undefined,
            ).toLowerCase() === res.events[0].identity_fingerprint_sha256.toLowerCase()
          : true;
        const versionMatches = res.events[0] ? res.events[0].version === verification.leafVersion : true;
        const consistencyLine = checkpoint
          ? verification.consistencyVerified
            ? "Append-only growth verified against the last saved checkpoint."
            : "Proof verified, but append-only growth was not checked."
          : "First verified transparency checkpoint saved on this device.";
        transparencySummary = `
          <div class="settings-section">
            <h3>Transparency</h3>
            <p class="text-secondary settings-desc">
              <strong>Verified.</strong> Current identity version v${verification.leafVersion} is included in signed tree #${verification.treeSize}.
            </p>
            <p class="text-secondary settings-desc">${escHtml(consistencyLine)}</p>
            <p class="text-secondary settings-desc">${fingerprintMatches && versionMatches ? "Identity log matches the signed transparency leaf." : "Warning: identity log and transparency leaf do not match exactly on this device."}</p>
          </div>
        `;
      } catch (error) {
        transparencySummary = `
          <div class="settings-section">
            <h3>Transparency</h3>
            <p class="text-danger">Verification failed: ${escHtml(errorMsg(error))}</p>
          </div>
        `;
      }
    }
    if (res.events.length === 0) {
      body.innerHTML = `${transparencySummary}<p class="text-secondary">No identity events recorded.</p>`;
      return;
    }
    body.innerHTML = `
      ${transparencySummary}
      <table class="idlog-table">
        <thead>
          <tr><th>Ver</th><th>Event</th><th>Device</th><th>Date</th><th>Fingerprint</th></tr>
        </thead>
        <tbody>
          ${res.events.map((ev: IdentityLogItem) => `
            <tr>
              <td>${ev.version}</td>
              <td><span class="badge badge-${ev.event_type === "rotation" ? "warn" : "info"}">${escHtml(ev.event_type)}</span></td>
              <td class="mono">${escHtml(ev.device_id)}</td>
              <td>${new Date(ev.changed_at).toLocaleString()}</td>
              <td class="mono fingerprint">${escHtml(ev.identity_fingerprint_sha256)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  } catch (e) {
    document.getElementById("idlog-body")!.innerHTML =
      `<p class="text-danger">Failed to load identity log: ${escHtml(errorMsg(e))}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Phase 4: Sealed Inbox Polling
// ---------------------------------------------------------------------------

async function pollSealedInbox(): Promise<void> {
  if (!keys) return;
  try {
    const k = await ensureKeys();
    const storedCursor = readSealedCursor(k.userId, k.deviceId);
    if (storedCursor > sealedInboxCursor) {
      sealedInboxCursor = storedCursor;
    }
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildSealedInboxAuthHeaders(k, sealedInboxCursor);
    const res = await api.sealedInbox(k.userId, sealedInboxCursor, headers);
    let nextCursor = sealedInboxCursor;
    let conversationListChanged = false;
    for (const item of res.messages) {
      try {
        const decrypted = await decryptIncomingPayload(
          k,
          item.message_bytes_base64,
          undefined,
          item.sender_identity_x25519_pub
        );
        if (decrypted.kind === "ignored") {
          nextCursor = Math.max(nextCursor, item.message_id);
          continue;
        }
        const senderId = decrypted.senderUserId;
        const plaintext = decrypted.plaintext;
        const isDirectMessage = decrypted.kind === "dm";
        const groupId = isDirectMessage ? null : decrypted.recipient;
        const conversationId = isDirectMessage
          ? convId(k.userId, senderId)
          : `group:${groupId}`;
        const existing = await getMessages(conversationId);
        if (existing.some((msg) => msg.serverMessageId === item.message_id)) {
          nextCursor = Math.max(nextCursor, item.message_id);
          continue;
        }
        const msg: StoredMessage = {
          id: `sealed-${item.message_id}`,
          conversationId,
          sender: senderId,
          recipient: isDirectMessage ? k.userId : decrypted.recipient,
          text: isDirectMessage
            ? plaintext
            : `${resolvePeerIdentity(senderId).primaryLabel}: ${plaintext}`,
          timestamp: new Date(item.received_at).getTime(),
          status: "delivered",
          serverMessageId: item.message_id,
        };
        await saveMessage(msg);
        void loadProfileNameBackground(senderId);
        if (isDirectMessage) {
          const isActivePeer = activeChatPeer === senderId;
          noteIncomingConversation(senderId, plaintext, !isActivePeer);
          if (isActivePeer) {
            markConversationRead(k.userId, senderId);
            const msgList = document.getElementById("messages-list");
            const container = document.getElementById("messages-container");
            if (msgList && container) {
              appendBubble(msgList, msg, container);
            }
          }
        } else if (groupId) {
          const isActiveGroup = activeGroupId === groupId;
          noteIncomingGroupConversation(groupId, senderId, plaintext, !isActiveGroup);
          if (isActiveGroup) {
            markGroupConversationRead(k.userId, groupId);
            const msgList = document.getElementById("messages-list");
            const container = document.getElementById("messages-container");
            if (msgList && container) {
              appendBubble(msgList, msg, container);
            }
          }
        }
        conversationListChanged = true;
        nextCursor = Math.max(nextCursor, item.message_id);
      } catch {
        // Skip malformed sealed messages
      }
    }
    if (nextCursor > sealedInboxCursor) {
      sealedInboxCursor = nextCursor;
      writeSealedCursor(k.userId, sealedInboxCursor, k.deviceId);
    }
    if (conversationListChanged) {
      refreshConversationsIfVisible();
    }
  } catch {
    // Best-effort polling
  }
}

async function addContactSilent(contactUserId: string): Promise<void> {
  if (cachedContacts.some(c => c.contact_user_id === contactUserId)) return;
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildContactsUpsertAuthHeaders(k, contactUserId, contactUserId, false, "");
    await api.upsertContact(k.userId, { contact_user_id: contactUserId }, headers);
    markConversationAccepted(contactUserId);
    void loadContactsBackground();
    void loadProfileNameBackground(contactUserId);
  } catch {
    // Best-effort
  }
}

// ---------------------------------------------------------------------------
// Phase 5: Discovery
// ---------------------------------------------------------------------------

async function renderDiscovery(): Promise<void> {
  const capabilities = await loadServerCapabilitiesCached();
  const contactDiscoveryMode = capabilities?.contact_discovery_mode ?? "manual_only";
  const contactDiscoveryServiceOrigin =
    capabilities?.contact_discovery_service_origin?.trim() ?? "";
  if (!capabilities?.contact_discovery_supported) {
    app.innerHTML = `
      <div class="app-shell">
        <header class="topbar">
          <button id="disc-back" class="icon-btn" aria-label="Back to settings">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7"/>
            </svg>
          </button>
          <h1 class="topbar-title">Contact Discovery</h1>
        </header>
        <div class="settings-body">
          <div class="settings-section">
            <h3>Unavailable</h3>
            <p class="text-secondary settings-desc">Raw-hash contact discovery is disabled pending a private discovery design.</p>
            <p class="text-secondary settings-desc">Share your @username or a private invite link and add contacts from Settings instead.</p>
          </div>
        </div>
      </div>
    `;
    q("#disc-back").addEventListener("click", () => navigateTo({ screen: "settings" }));
    return;
  }

  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="disc-back" class="icon-btn" aria-label="Back to settings">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">Contact Discovery</h1>
      </header>
      <div class="settings-body">
        <div class="settings-section">
          <h3>Upload Your Handles</h3>
          <p class="text-secondary settings-desc">${
            contactDiscoveryMode === "private_service"
              ? "Upload SHA-256 handle hashes to the separate discovery service using a short-lived ticket from the app server. This is a service-boundary-only development privacy mode, not full private contact discovery. Matches return opaque invite bootstraps, not stable account IDs."
              : "Share hashed phone/email so contacts can find you."
          }</p>
          <label class="field">
            <span>Phone hashes (one per line, SHA-256 hex)</span>
            <textarea id="disc-phones" rows="3" class="input-sm disc-textarea" placeholder="e.g. a1b2c3d4…"></textarea>
          </label>
          <label class="field">
            <span>Email hashes (one per line, SHA-256 hex)</span>
            <textarea id="disc-emails" rows="3" class="input-sm disc-textarea" placeholder="e.g. f5e6d7c8…"></textarea>
          </label>
          <button id="disc-upload" class="btn-sm">Upload Handles</button>
          <div id="disc-upload-status"></div>
        </div>
        <div class="settings-section">
          <h3>Find Contacts</h3>
          <p class="text-secondary settings-desc">${
            contactDiscoveryMode === "private_service"
              ? "Blind-evaluate local handle hashes against the separate discovery service with a short-lived ticket. Matches only return opaque bootstrap invites for the same finalized tokens."
              : "Enter hashes to check who's registered."
          }</p>
          <label class="field">
            <span>Query hashes (one per line, SHA-256 hex)</span>
            <textarea id="disc-query" rows="3" class="input-sm disc-textarea" placeholder="e.g. a1b2c3d4…"></textarea>
          </label>
          <button id="disc-match" class="btn-sm">🔍 Search</button>
          <div id="disc-results"></div>
        </div>
      </div>
    </div>
  `;

  q("#disc-back").addEventListener("click", () => navigateTo({ screen: "settings" }));

  async function issueDiscoveryTicket(
    api: PqmsgApi,
    keys: GeneratedKeys,
    purpose: "upload" | "match"
  ): Promise<{
    serviceOrigin: string;
    ticket: string;
    ticketNonce: string;
    manifest: ContactDiscoveryManifestResponse;
  }> {
    const headers = buildContactDiscoveryTicketAuthHeaders(keys, purpose);
    const response = await api.issueContactDiscoveryTicket(keys.userId, headers, { purpose });
    const configuredOrigin = contactDiscoveryServiceOrigin
      ? validateWebServerUrl(contactDiscoveryServiceOrigin).origin
      : null;
    const ticketOrigin = validateWebServerUrl(response.service_origin).origin;
    if (configuredOrigin && configuredOrigin !== ticketOrigin) {
      throw new Error("Contact discovery service origin mismatch");
    }
    const verifiedManifest = await loadVerifiedContactDiscoveryManifest(capabilities);
    return {
      serviceOrigin: ticketOrigin,
      ticket: response.ticket,
      ticketNonce: response.ticket_nonce,
      manifest: verifiedManifest.manifest,
    };
  }

  q("#disc-upload").addEventListener("click", async () => {
    const statusEl = document.getElementById("disc-upload-status")!;
    const phones = q<HTMLTextAreaElement>("#disc-phones").value.split("\n").map(l => l.trim()).filter(Boolean);
    const emails = q<HTMLTextAreaElement>("#disc-emails").value.split("\n").map(l => l.trim()).filter(Boolean);
    if (phones.length === 0 && emails.length === 0) { notify("Enter at least one hash", "error"); return; }
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const { serviceOrigin, ticket, ticketNonce, manifest } = await issueDiscoveryTicket(api, k, "upload");
      const manifestContractSha256 = contactDiscoveryManifestContractSha256(manifest);
      const phonePrepared = prepareContactDiscoveryBlindRequest(phones);
      const emailPrepared = prepareContactDiscoveryBlindRequest(emails);
      const phoneEvaluated = phonePrepared.blindedElementsBase64.length === 0
        ? {
          ticket_nonce: ticketNonce,
          manifest_contract_sha256: manifestContractSha256,
          evaluation_proof_mode: manifest.evaluation_proof_mode,
          evaluated_elements_base64: [],
          dleq_proofs: []
        }
        : await api.evaluateDiscoveryElementsAtService(serviceOrigin, {
          ticket,
          blinded_elements_base64: phonePrepared.blindedElementsBase64,
        });
      const emailEvaluated = emailPrepared.blindedElementsBase64.length === 0
        ? {
          ticket_nonce: ticketNonce,
          manifest_contract_sha256: manifestContractSha256,
          evaluation_proof_mode: manifest.evaluation_proof_mode,
          evaluated_elements_base64: [],
          dleq_proofs: []
        }
        : await api.evaluateDiscoveryElementsAtService(serviceOrigin, {
          ticket,
          blinded_elements_base64: emailPrepared.blindedElementsBase64,
        });
      requireContactDiscoveryServiceContract(
        manifestContractSha256,
        phoneEvaluated.manifest_contract_sha256,
        "evaluate",
      );
      requireContactDiscoveryTicketNonce(ticketNonce, phoneEvaluated.ticket_nonce, "evaluate");
      requireContactDiscoveryServiceContract(
        manifestContractSha256,
        emailEvaluated.manifest_contract_sha256,
        "evaluate",
      );
      requireContactDiscoveryTicketNonce(ticketNonce, emailEvaluated.ticket_nonce, "evaluate");
      verifyContactDiscoveryEvaluationProofs(
        phonePrepared.blindedElementsBase64,
        phoneEvaluated,
        manifest.oprf_public_key_ristretto255,
      );
      verifyContactDiscoveryEvaluationProofs(
        emailPrepared.blindedElementsBase64,
        emailEvaluated,
        manifest.oprf_public_key_ristretto255,
      );
      const phoneTokens = finalizeContactDiscoveryTokens(
        phonePrepared.blindingScalarsBase64,
        phoneEvaluated.evaluated_elements_base64,
      );
      const emailTokens = finalizeContactDiscoveryTokens(
        emailPrepared.blindingScalarsBase64,
        emailEvaluated.evaluated_elements_base64,
      );
      const res = await api.uploadDiscoveryHandlesToService(serviceOrigin, {
        ticket,
        phone_tokens_sha256: phoneTokens,
        email_tokens_sha256: emailTokens,
      });
      requireContactDiscoveryServiceContract(
        manifestContractSha256,
        res.manifest_contract_sha256,
        "upload",
      );
      requireContactDiscoveryTicketNonce(ticketNonce, res.ticket_nonce, "upload");
      statusEl.innerHTML = `<span class="text-success">Blind-evaluated and uploaded ${res.uploaded_phone_tokens} phone + ${res.uploaded_email_tokens} email tokens</span>`;
    } catch (e) {
      statusEl.innerHTML = `<span class="text-danger">Upload failed: ${escHtml(errorMsg(e))}</span>`;
    }
  });

  q("#disc-match").addEventListener("click", async () => {
    const resultsEl = document.getElementById("disc-results")!;
    const hashes = q<HTMLTextAreaElement>("#disc-query").value.split("\n").map(l => l.trim()).filter(Boolean);
    if (hashes.length === 0) { notify("Enter at least one hash", "error"); return; }
    resultsEl.innerHTML = '<p class="text-secondary">Searching…</p>';
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const { serviceOrigin, ticket, ticketNonce, manifest } = await issueDiscoveryTicket(api, k, "match");
      const manifestContractSha256 = contactDiscoveryManifestContractSha256(manifest);
      const prepared = prepareContactDiscoveryBlindRequest(hashes);
      const evaluated = await api.evaluateDiscoveryElementsAtService(serviceOrigin, {
        ticket,
        blinded_elements_base64: prepared.blindedElementsBase64,
      });
      requireContactDiscoveryServiceContract(
        manifestContractSha256,
        evaluated.manifest_contract_sha256,
        "evaluate",
      );
      requireContactDiscoveryTicketNonce(ticketNonce, evaluated.ticket_nonce, "evaluate");
      verifyContactDiscoveryEvaluationProofs(
        prepared.blindedElementsBase64,
        evaluated,
        manifest.oprf_public_key_ristretto255,
      );
      const tokens = finalizeContactDiscoveryTokens(
        prepared.blindingScalarsBase64,
        evaluated.evaluated_elements_base64,
      );
      const hashByToken = new Map<string, string>();
      tokens.forEach((token, index) => {
        hashByToken.set(token, hashes[index]);
      });
      const res = await api.matchDiscoveryHashesAtService(serviceOrigin, {
        ticket,
        tokens_sha256: tokens,
      });
      requireContactDiscoveryServiceContract(
        manifestContractSha256,
        res.manifest_contract_sha256,
        "match",
      );
      requireContactDiscoveryTicketNonce(ticketNonce, res.ticket_nonce, "match");
      if (res.matches.length === 0) {
        resultsEl.innerHTML = '<p class="text-secondary">No matches found.</p>';
        return;
      }
      resultsEl.innerHTML = `
        <table class="idlog-table">
          <thead><tr><th>Hash</th><th>Bootstrap</th><th>Type</th><th></th></tr></thead>
          <tbody>
            ${res.matches.map((m: PrivateDiscoveryMatchItem) => `
              <tr>
                <td class="mono fingerprint">${escHtml(hashByToken.get(m.token_sha256) || m.token_sha256)}</td>
                <td class="mono">invite:${escHtml(m.contact_invite_token.slice(-8))}</td>
                <td><span class="badge-info">${escHtml(m.handle_kind)}</span></td>
                <td><button class="btn-sm" data-add-discovered="${escHtml(m.contact_invite_token)}">Add</button></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
      for (const btn of document.querySelectorAll("[data-add-discovered]")) {
        btn.addEventListener("click", async () => {
          const inviteToken = (btn as HTMLElement).dataset.addDiscovered!;
          try {
            const bundle = await api.getContactInviteBundle(inviteToken);
            const userId = bundle.user_id.trim();
            await addContactSilent(userId);
            notify(`Added ${userId} as contact`, "success");
            (btn as HTMLButtonElement).disabled = true;
            (btn as HTMLButtonElement).textContent = "Added";
          } catch (error) {
            notify(`Could not resolve match bootstrap: ${errorMsg(error)}`, "error");
          }
        });
      }
    } catch (e) {
      resultsEl.innerHTML = `<span class="text-danger">Search failed: ${escHtml(errorMsg(e))}</span>`;
    }
  });
}

// ---------------------------------------------------------------------------
// Phase 5: Server Info
// ---------------------------------------------------------------------------

async function renderServerInfo(): Promise<void> {
  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <button id="sinfo-back" class="icon-btn" aria-label="Back to settings">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">Server Info</h1>
      </header>
      <div class="settings-body" id="sinfo-body">
        <p class="text-secondary">Loading server status…</p>
      </div>
    </div>
  `;

  q("#sinfo-back").addEventListener("click", () => navigateTo({ screen: "settings" }));

  const body = document.getElementById("sinfo-body")!;
  try {
    const api = new PqmsgApi(setup.serverUrl);
    const [health, caps] = await Promise.all([
      api.getHealth().catch(() => null),
      api.getCapabilities().catch(() => null),
    ]);

    let html = "";

    if (health) {
      const statusClass = health.status === "ok" ? "text-success" : "text-danger";
      html += `
        <div class="settings-section">
          <h3>Health</h3>
          <div class="settings-row"><span>Status</span><span class="${statusClass}">${escHtml(health.status)}</span></div>
          <div class="settings-row"><span>DB Backend</span><span class="mono">${escHtml(health.db_backend)}</span></div>
          <div class="settings-row"><span>DB Ready</span><span>${health.db_ready ? "✓" : "✗"}</span></div>
          <div class="settings-row"><span>Pool</span><span>${health.db_pool_idle} idle / ${health.db_pool_size} total</span></div>
          <div class="settings-row"><span>Push</span><span>${health.push_enabled ? health.push_providers.join(", ") : "disabled"}</span></div>
          <div class="settings-row"><span>TLS</span><span>${health.tls_enabled ? "enabled" : "disabled"}</span></div>
          <div class="settings-row"><span>Rate Limiter</span><span class="mono">${escHtml(health.rate_limiter_mode)}</span></div>
          <div class="settings-row"><span>Replay Cache</span><span class="mono">${escHtml(health.replay_cache_mode)}</span></div>
          <div class="settings-row"><span>Realtime</span><span class="mono">${escHtml(health.realtime_mode)}</span></div>
          <div class="settings-row"><span>Security Profile</span><span class="mono">${escHtml(health.security_profile)}</span></div>
          <div class="settings-row"><span>Deployment</span><span class="mono">${escHtml(health.deployment_mode)}</span></div>
          <div class="settings-row"><span>PoW Bits</span><span>${health.registration_pow_bits}</span></div>
        </div>
      `;
    }

    if (caps) {
      const cp = caps.runtime_crypto_profile;
      html += `
        <div class="settings-section">
          <h3>Capabilities</h3>
          <div class="settings-row"><span>Schema</span><span>v${caps.capability_schema_version}</span></div>
          <div class="settings-row"><span>Suites</span><span class="mono">${caps.supported_suite_ids.join(", ")}</span></div>
          <div class="settings-row"><span>Supported Beta Clients</span><span class="mono">${escHtml(caps.supported_beta_clients.join(", ") || "none")}</span></div>
          <div class="settings-row"><span>Web Policy</span><span class="mono">${escHtml(caps.web_client_policy)}</span></div>
          <div class="settings-row"><span>PQ Ratchet</span><span>${caps.pq_ratchet_interval === 1 ? "every message" : `every ${caps.pq_ratchet_interval} msgs`}</span></div>
          <div class="settings-row"><span>Presence</span><span>${caps.presence_supported ? "Enabled" : "Disabled"}</span></div>
          <div class="settings-row"><span>Typing</span><span>${caps.typing_indicators_supported ? "Enabled" : "Disabled"}</span></div>
          <div class="settings-row"><span>Read Receipts</span><span>${caps.read_receipts_supported ? "Enabled" : "Disabled"}</span></div>
          <div class="settings-row"><span>Calling</span><span>${caps.calling_supported ? "Enabled" : "Disabled"}</span></div>
          <div class="settings-row"><span>Stories</span><span>${caps.stories_supported ? "Enabled" : "Disabled"}</span></div>
          <div class="settings-row"><span>Channels</span><span>${caps.channels_supported ? "Enabled" : "Disabled"}</span></div>
          <div class="settings-row"><span>Group Messaging</span><span>${caps.group_messaging_supported ? "Enabled" : "Disabled"}</span></div>
          <div class="settings-row"><span>Private Groups</span><span>${caps.private_group_messaging_supported ? "Enabled" : "Disabled"}</span></div>
          <div class="settings-row"><span>Sealed Sender</span><span>${caps.sealed_sender_required ? "Required" : "Optional"}</span></div>
          <div class="settings-row"><span>Sender Certs</span><span>${caps.sender_certificate_supported ? "Required" : "Disabled"}</span></div>
          <div class="settings-row"><span>Ephemeral DM</span><span>${caps.ephemeral_messaging_supported ? "Enabled" : "Disabled"}</span></div>
          <div class="settings-row"><span>Contact Discovery</span><span>${caps.contact_discovery_mode === "private_service" ? "Private service" : (caps.contact_discovery_supported ? "Enabled" : "Manual only")}</span></div>
          <div class="settings-row"><span>Discovery Tickets</span><span>${caps.contact_discovery_ticket_supported ? "Available" : "Unavailable"}</span></div>
          <div class="settings-row"><span>Discovery Ticket Issuer</span><span class="mono">${escHtml(caps.contact_discovery_ticket_issuer_ed25519_pub)}</span></div>
          <div class="settings-row"><span>Discovery Manifest Issuer</span><span class="mono">${escHtml(caps.contact_discovery_manifest_issuer_ed25519_pub || "not advertised")}</span></div>
          <div class="settings-row"><span>Discovery Backend</span><span>${escHtml(caps.contact_discovery_directory_backend || "not advertised")}</span></div>
          <div class="settings-row"><span>Host/Enclave Protocol</span><span>${escHtml(caps.contact_discovery_host_enclave_protocol_version ? `${caps.contact_discovery_host_enclave_protocol_version}` : "not advertised")}</span></div>
          <div class="settings-row"><span>Host Release</span><span class="mono">${escHtml(caps.contact_discovery_host_release_id || "not advertised")}</span></div>
          <div class="settings-row"><span>Enclave Release</span><span class="mono">${escHtml(caps.contact_discovery_enclave_release_id || "not advertised")}</span></div>
          <div class="settings-row"><span>Manifest Contract</span><span class="mono">${escHtml(caps.contact_discovery_expected_manifest_contract_sha256 || "not advertised")}</span></div>
          <div class="settings-row"><span>Discovery Attestation Verifier</span><span class="mono">${escHtml(caps.contact_discovery_attestation_verifier || "not advertised")}</span></div>
          <div class="settings-row"><span>Discovery Enclave Measurement</span><span class="mono">${escHtml(caps.contact_discovery_expected_measurement_hex || "not advertised")}</span></div>
          <div class="settings-row"><span>Discovery Attestation PCRs</span><span class="mono">${escHtml(formatContactDiscoveryPcrs(caps.contact_discovery_expected_pcrs_sha384))}</span></div>
          <div class="settings-row"><span>Discovery Attestation Max Age</span><span>${escHtml(caps.contact_discovery_attestation_max_age_seconds ? `${caps.contact_discovery_attestation_max_age_seconds}s` : "not advertised")}</span></div>
          <div class="settings-row"><span>Prod Baseline</span><span>${caps.production_baseline_met ? "✓ Met" : "✗ Not met"}</span></div>
        </div>
        <div class="settings-section">
          <h3>Crypto Profile</h3>
          <div class="settings-row"><span>KEM</span><span class="mono">${escHtml(cp.kem)}</span></div>
          <div class="settings-row"><span>DH</span><span class="mono">${escHtml(cp.dh)}</span></div>
          <div class="settings-row"><span>KDF</span><span class="mono">${escHtml(cp.kdf)}</span></div>
          <div class="settings-row"><span>AEAD</span><span class="mono">${escHtml(cp.aead)}</span></div>
          <div class="settings-row"><span>Signature</span><span class="mono">${escHtml(cp.signature)}</span></div>
          <div class="settings-row"><span>FIPS Mode</span><span>${cp.fips_mode ? "Yes" : "No"}</span></div>
          <div class="settings-row"><span>PQ OQS</span><span>${cp.pq_oqs_enabled ? "Yes" : "No"}</span></div>
        </div>
      `;
    }

    if (!health && !caps) {
      html = '<p class="text-danger">Could not reach server.</p>';
    }

    body.innerHTML = html;
  } catch (e) {
    body.innerHTML = `<p class="text-danger">Error: ${escHtml(errorMsg(e))}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Phase 2: Timer cleanup
// ---------------------------------------------------------------------------

function stopChatTimers(): void {
  if (typingTimer) { clearTimeout(typingTimer); typingTimer = null; }
  if (typingPollTimer) { clearInterval(typingPollTimer); typingPollTimer = null; }
  if (receiptPollTimer) { clearInterval(receiptPollTimer); receiptPollTimer = null; }
}

function stopAllTimers(): void {
  stopChatTimers();
  if (presenceHeartbeatTimer) { clearInterval(presenceHeartbeatTimer); presenceHeartbeatTimer = null; }
  if (sealedInboxPollTimer) { clearInterval(sealedInboxPollTimer); sealedInboxPollTimer = null; }
  if (groupSyncTimer) { clearInterval(groupSyncTimer); groupSyncTimer = null; }
}

function refreshConversationsIfVisible(): void {
  if (getCurrentView().screen === "conversations") {
    renderConversations();
  }
}

async function logoutCurrentSession(): Promise<void> {
  const previousServerUrl = setup.serverUrl;
  const previousSuiteLabel = setup.suiteLabel;

  if (realtimeInbox) {
    realtimeInbox.disconnect();
    realtimeInbox = null;
  }

  stopAllTimers();
  keys = null;
  activeChatPeer = null;
  activeGroupId = null;
  cachedContacts = [];
  cachedProfileNames = {};
  cachedSealedDeliveryTokens = {};
  cachedInviteBundles = {};
  cachedGroupMembers = {};
  peerPresenceCache = {};
  receiptCursor = 0;
  sealedInboxCursor = 0;
  cachedCapabilities = null;
  cachedCapabilitiesServerUrl = null;
  activeInboxFilter = "all";
  sessionStorage.removeItem("pqmsg.passphrase");
  setup = {
    ...DEFAULT_SETUP,
    serverUrl: previousServerUrl,
    suiteLabel: previousSuiteLabel,
    peerUserId: "",
  };
  saveSetup(setup);
  navigateTo({ screen: "onboarding" });
  notify("Logged out", "info");
}

// ---------------------------------------------------------------------------
// Phase 3: Prekey status
// ---------------------------------------------------------------------------

async function loadPrekeyStatus(): Promise<void> {
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildPrekeysStatusAuthHeaders(k);
    const res = await api.getPrekeysStatus(k.userId, headers);
    const el = document.getElementById("prekey-status");
    if (!el) return;
    const lowClass = res.low_one_time_prekeys ? "prekey-low" : "prekey-ok";
    el.innerHTML = `
      <div class="settings-row"><span>X25519 OTPs</span><span class="${lowClass}">${res.remaining_one_time_prekeys_x25519}</span></div>
      <div class="settings-row"><span>ML-KEM-768 OTPs</span><span class="${lowClass}">${res.remaining_one_time_prekeys_mlkem768}</span></div>
      <div class="settings-row"><span>Status</span><span class="${lowClass}">${res.low_one_time_prekeys ? "⚠️ Low — publish more" : "✓ Healthy"}</span></div>
    `;
  } catch (e) {
    const el = document.getElementById("prekey-status");
    if (el) el.innerHTML = `<p class="error-text">Failed: ${escHtml(errorMsg(e))}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function enforceIdentityPin(
  peerUserId: string,
  identityX25519Pub: string,
  identitySigPub: string,
  identityPqSigPub: string,
  fingerprint: string,
  identityVersion: number,
  observedAt: string
): void {
  const existing = readIdentityPin(setup.userId, peerUserId);
  if (!existing) {
    writeIdentityPin(setup.userId, peerUserId, {
      fingerprintSha256: fingerprint,
      identityKeyVersion: identityVersion,
      identityX25519Pub,
      identitySigPub,
      identityPqSigPub,
      observedAt,
    });
    return;
  }
  if (existing.fingerprintSha256 === fingerprint) return;
  const accepted = confirm(
    `⚠️ Security Alert\n\n${peerUserId}'s security key has changed.\n\nThis could mean they reinstalled the app, or someone may be intercepting your messages.\n\nDo you trust the new key?`
  );
  if (!accepted) throw new Error(`identity changed for ${peerUserId}; action blocked`);
  writeIdentityPin(setup.userId, peerUserId, {
    fingerprintSha256: fingerprint,
    identityKeyVersion: identityVersion,
    identityX25519Pub,
    identitySigPub,
    identityPqSigPub,
    observedAt,
  });
}

async function ensurePeerIdentityPinForTrust(peerUserId: string, api: PqmsgApi): Promise<IdentityPin> {
  const existing = readIdentityPin(setup.userId, peerUserId);
  if (existing?.identityPqSigPub?.trim()) {
    return existing;
  }
  const bundle = cachedInviteBundles[peerUserId] ?? await api.getBundle(peerUserId);
  const fingerprint =
    bundle.identity_fingerprint_sha256
    || identityFingerprint(bundle.identity_x25519_pub, bundle.identity_pq_sig_pub);
  enforceIdentityPin(
    peerUserId,
    bundle.identity_x25519_pub,
    bundle.identity_sig_pub,
    bundle.identity_pq_sig_pub,
    fingerprint,
    bundle.identity_key_version,
    bundle.bundle_generated_at
  );
  const refreshed = readIdentityPin(setup.userId, peerUserId);
  if (!refreshed) {
    throw new Error(`Unable to pin identity for ${peerUserId}`);
  }
  return refreshed;
}

async function verifyPeerSafetyNumber(peerUserId: string): Promise<void> {
  await ensureWebPqRuntime();
  const k = await ensureKeys();
  const api = new PqmsgApi(setup.serverUrl);
  const identityPin = await ensurePeerIdentityPinForTrust(peerUserId, api);
  if (!identityPin.identityPqSigPub.trim()) {
    throw new Error("Peer PQ identity key is unavailable for safety-number verification.");
  }
  const safetyNumber = computeSafetyNumber(
    k,
    peerUserId,
    identityPin.identityX25519Pub,
    identityPin.identityPqSigPub
  );
  const contact = cachedContacts.find((item) => item.contact_user_id === peerUserId);
  const alias = contact?.alias?.trim() || cachedProfileNames[peerUserId]?.trim() || peerUserId;
  const alreadyVerified = isContactFingerprintVerified(contact, identityPin);
  const accepted = alreadyVerified || confirm(
    `Safety number for ${alias}\n\n${safetyNumber}\n\nMark this contact as verified against the current fingerprint?`
  );
  if (!accepted) {
    notify("Safety-number verification canceled", "info");
    return;
  }
  if (!alreadyVerified) {
    const headers = buildContactsUpsertAuthHeaders(
      k,
      peerUserId,
      alias,
      true,
      identityPin.fingerprintSha256
    );
    await api.upsertContact(
      k.userId,
      {
        contact_user_id: peerUserId,
        alias: contact?.alias || undefined,
        verified_by_qr: true,
        verified_fingerprint_sha256: identityPin.fingerprintSha256,
      },
      headers
    );
    const now = new Date().toISOString();
    upsertCachedContact({
      contact_user_id: peerUserId,
      username: contact?.username || null,
      alias: contact?.alias || null,
      verified_by_qr: true,
      verified_fingerprint_sha256: identityPin.fingerprintSha256,
      created_at: contact?.created_at || now,
      updated_at: now,
    });
    markConversationAccepted(peerUserId);
    void loadContactsBackground();
  }
  notify(
    alreadyVerified ? "Safety number matches the saved verification" : "Contact verified via safety number",
    "success"
  );
  const view = getCurrentView();
  if (view.screen === "chat" && view.peerId === peerUserId) {
    void renderChat(peerUserId);
  }
}

async function ensureKeys(): Promise<GeneratedKeys> {
  if (keys) return keys;
  const passphrase = getPassphrase();
  keys = await loadKeys(setup.userId, passphrase);
  return keys;
}

function getPassphrase(): string {
  const stored = sessionStorage.getItem("pqmsg.passphrase");
  if (stored) return stored;
  const entered = prompt("Enter your passphrase to unlock your keys:");
  if (!entered) throw new Error("Passphrase required");
  sessionStorage.setItem("pqmsg.passphrase", entered);
  return entered;
}

function convId(userId: string, peerId: string): string {
  return [userId, peerId].sort().join(":");
}

function scrollToBottom(container: HTMLElement): void {
  requestAnimationFrame(() => {
    container.scrollTop = container.scrollHeight;
  });
}

function setProgress(bar: HTMLElement, pct: number): void {
  const fill = bar.querySelector(".progress-fill") as HTMLElement;
  if (fill) fill.style.width = `${pct}%`;
}

function relativeTime(ts: number): string {
  const diff = Date.now() - ts;
  if (diff < 60_000) return "now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m`;
  if (diff < 86_400_000) return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (diff < 172_800_000) return "yesterday";
  if (diff < 604_800_000) return new Date(ts).toLocaleDateString([], { weekday: "short" });
  return new Date(ts).toLocaleDateString([], { month: "short", day: "numeric" });
}

function friendlyDate(ts: number): string {
  const today = new Date().toLocaleDateString();
  const yesterday = new Date(Date.now() - 86_400_000).toLocaleDateString();
  const d = new Date(ts).toLocaleDateString();
  if (d === today) return "Today";
  if (d === yesterday) return "Yesterday";
  return new Date(ts).toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" });
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function describeAttachmentKind(mimeType: string): string {
  if (mimeType.startsWith("image/")) return "Photo";
  if (mimeType.startsWith("video/")) return "Video";
  if (mimeType.startsWith("audio/")) return "Audio";
  if (mimeType === "application/pdf") return "PDF";
  return "Document";
}

function q<T extends HTMLElement>(selector: string): T {
  const el = document.querySelector(selector);
  if (!el) throw new Error(`missing element: ${selector}`);
  return el as T;
}

function qAll<T extends HTMLElement>(selector: string): T[] {
  return Array.from(document.querySelectorAll(selector)) as T[];
}

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function errorMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Service worker
if ("serviceWorker" in navigator) {
  const runtimeIssue = getLiveUnsupportedWebRuntimeReason();
  const isSupportedSecureOrigin = isSecureWebOrigin(location);
  const isLocalDevOrigin = location.protocol === "http:" && isLoopbackHostname(location.hostname);

  if (!isSupportedSecureOrigin || runtimeIssue) {
    // Unsupported or fail-closed web environments never register a service worker.
  } else if (isLocalDevOrigin) {
    void navigator.serviceWorker.getRegistrations()
      .then((registrations) => Promise.all(registrations.map((registration) => registration.unregister())))
      .catch(() => {
        // Best-effort cleanup for stale local dev registrations.
      });
  } else {
    void navigator.serviceWorker.register("/sw.js").catch(() => {
      // Best-effort in production-like environments.
    });
  }
}
