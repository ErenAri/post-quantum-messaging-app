import "./app.css";
import {
  buildInboxAuthHeaders,
  buildPrekeysAuthHeaders,
  buildPublishPrekeysPayload,
  buildRelayAuthHeaders,
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
  buildContactsUpsertAuthHeaders,
  buildContactsRemoveAuthHeaders,
  buildGroupCreateAuthHeaders,
  buildUserGroupsListAuthHeaders,
  buildGroupMembersListAuthHeaders,
  buildGroupMembersAddAuthHeaders,
  buildGroupMembersRemoveAuthHeaders,
  buildGroupRelayAuthHeaders,
  buildFileUploadAuthHeaders,
  buildFileDownloadAuthHeaders,
  buildInboxDeleteAuthHeaders,
  buildPrekeysStatusAuthHeaders,
  buildRotateInitAuthHeaders,
  buildRotateConfirmAuthHeaders,
  buildIdentityLogAuthHeaders,
  buildSealedInboxAuthHeaders,
  buildEphemeralRelayAuthHeaders,
  buildDiscoveryHandlesAuthHeaders,
  buildDiscoveryMatchAuthHeaders,
  buildPushTokenAuthHeaders,
  buildListDevicesAuthHeaders,
  buildLinkDeviceAuthHeaders,
  buildRevokeDeviceAuthHeaders,
  decodeWireEnvelopeBase64,
  decryptFallbackMessage,
  encryptFallbackMessage,
  encodeWireEnvelopeBase64,
  generateIdentityKeys,
  identityFingerprint,
  type GeneratedKeys,
} from "./crypto";
import { base64ToBytes, bytesToBase64 } from "./base64";
import { ed25519 } from "@noble/curves/ed25519";
import {
  PqmsgApi,
  type ContactEntry,
  type GroupMembershipRecord,
  type GroupMemberRecord,
  type IdentityLogItem,
  type DiscoveryMatchItem,
  type DeviceRecord,
  type ServerCapabilitiesResponse,
} from "./server";
import {
  DEFAULT_SETUP,
  loadConversationMeta,
  loadConversationMetas,
  hasLocalKeys,
  loadConversations,
  loadGroupConversations,
  loadProfileDisplayNames,
  readProfileDisplayName,
  readIdentityPin,
  loadKeys,
  loadSetup,
  markConversationRead,
  markGroupConversationRead,
  updateConversationMeta,
  readCursor,
  saveKeys,
  saveSetup,
  upsertConversation,
  upsertGroupConversation,
  wipeLocalState,
  writeProfileDisplayName,
  writeCursor,
  writeIdentityPin,
  type ConversationKind,
  type ConversationMeta,
  type ConversationRequestState,
  type ConversationSummary,
  type GroupConversationSummary,
} from "./storage";
import {
  saveMessage,
  updateMessageStatus,
  getMessages,
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
  type OutboxMessage,
} from "./db";
import { RealtimeInbox, type WsInboxMessage } from "./realtime";
import { CallManager, type CallInfo } from "./call";
import {
  getCurrentView,
  navigateTo,
  onViewChange,
  notify,
  onNotification,
  type AppView,
  type AppNotification,
} from "./router";

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const app = document.getElementById("app")!;
let setup = loadSetup();
let keys: GeneratedKeys | null = null;
let realtimeInbox: RealtimeInbox | null = null;
let activeChatPeer: string | null = null;
let toastTimer: ReturnType<typeof setTimeout> | null = null;

// Phase 2 state
let presenceHeartbeatTimer: ReturnType<typeof setInterval> | null = null;
let typingTimer: ReturnType<typeof setTimeout> | null = null;
let typingPollTimer: ReturnType<typeof setInterval> | null = null;
let receiptPollTimer: ReturnType<typeof setInterval> | null = null;
let receiptCursor = 0;
let cachedContacts: ContactEntry[] = [];
let cachedProfileNames: Record<string, string> = {};
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

// Call state
let callManager: CallManager | null = null;
let currentCallInfo: CallInfo | null = null;
let cachedCapabilities: ServerCapabilitiesResponse | null = null;
let cachedCapabilitiesServerUrl: string | null = null;

type InboxFilter = "all" | "unread" | "groups" | "requests" | "archived";

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

async function ensureWebMessagingAllowed(kind: "direct" | "group"): Promise<boolean> {
  const caps = await loadServerCapabilitiesCached();
  if (caps && caps.web_client_policy !== "demo_only") {
    return true;
  }
  const label = kind === "group" ? "group messaging" : "messaging";
  const detail = caps ? "server policy is demo_only" : "server capabilities could not be verified";
  notify(
    `Web ${label} is disabled because ${detail}. Use Android, iOS, or CLI for interoperable chat.`,
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

// Determine initial screen
if (setup.userId && hasLocalKeys(setup.userId)) {
  const params = new URLSearchParams(location.search);
  const invite = params.get("invite");
  if (invite && invite !== setup.userId) {
    navigateTo({ screen: "new-chat" });
  } else {
    navigateTo({ screen: "conversations" });
  }
} else {
  navigateTo({ screen: "onboarding" });
}

onViewChange(render);
onNotification(showToast);
render(getCurrentView());

// Offline banner
window.addEventListener("offline", () => showOfflineBanner(true));
window.addEventListener("online", () => { showOfflineBanner(false); void drainOutbox(); });

// ---------------------------------------------------------------------------
// Render dispatcher
// ---------------------------------------------------------------------------

function render(view: AppView): void {
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

function resolvePeerIdentity(peerId: string): {
  primaryLabel: string;
  secondaryLabel: string;
  avatarText: string;
  isVerified: boolean;
} {
  const contact = cachedContacts.find((item) => item.contact_user_id === peerId);
  const cachedName = cachedProfileNames[peerId]?.trim() || readProfileDisplayName(setup.userId, peerId)?.trim() || "";
  const primaryLabel = contact?.alias?.trim() || cachedName || peerId;
  const secondaryLabel = primaryLabel === peerId ? "" : `@${peerId}`;
  const avatarText = primaryLabel.slice(0, 2).toUpperCase() || peerId.slice(0, 2).toUpperCase();
  const isVerified = Boolean(contact?.verified_by_qr || readIdentityPin(setup.userId, peerId));
  return { primaryLabel, secondaryLabel, avatarText, isVerified };
}

function resolveGroupIdentity(groupId: string, ownerUserId: string): {
  primaryLabel: string;
  secondaryLabel: string;
  avatarText: string;
} {
  return {
    primaryLabel: groupId,
    secondaryLabel: ownerUserId === setup.userId ? "You created this group" : `Owner @${ownerUserId}`,
    avatarText: groupId.slice(0, 2).toUpperCase(),
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
    const displayName = profile.display_name?.trim() || "";
    if (!displayName) {
      return;
    }
    cachedProfileNames[targetUserId] = displayName;
    writeProfileDisplayName(k.userId, targetUserId, displayName);
    if (targetUserId === k.userId && setup.displayName !== displayName) {
      setup.displayName = displayName;
      saveSetup(setup);
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
  upsertGroupConversation(
    setup.userId,
    groupId,
    existing?.ownerUserId || senderUserId,
    `${senderLabel}: ${preview}`,
    incrementUnread
  );
}

async function syncGroupsBackground(): Promise<void> {
  if (!setup.userId) {
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
}

function parseChatTarget(rawValue: string): string {
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
        <p class="onboarding-note">🔒 Your keys are generated locally and never leave this device.</p>
      </div>
    </div>
  `;

  q("#onb-create").addEventListener("click", () => navigateTo({ screen: "create-account" }));
  q("#onb-signin").addEventListener("click", () => navigateTo({ screen: "sign-in" }));

  q("#onb-save-server").addEventListener("click", () => {
    const server = q<HTMLInputElement>("#onb-server").value.trim();
    if (server) {
      setup.serverUrl = server;
      saveSetup(setup);
      notify("Server URL saved", "success");
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
        device_id: genKeys.deviceId,
      });

      status.textContent = "Publishing prekeys…";
      setProgress(progress, 80);
      const payload = buildPublishPrekeysPayload(genKeys);
      const headers = buildPrekeysAuthHeaders(genKeys, payload);
      await api.publishPrekeys(genKeys.userId, payload, headers);

      try {
        const profileHeaders = buildProfileUpsertAuthHeaders(genKeys, name, "", "");
        await api.upsertProfile(genKeys.userId, { display_name: name }, profileHeaders);
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
        passphrase: "",
      };
      saveSetup(setup);
      sessionStorage.setItem("pqmsg.passphrase", pass);
      keys = genKeys;
      cachedProfileNames[userId] = name;
      writeProfileDisplayName(userId, userId, name);

      setProgress(progress, 100);
      status.textContent = "Ready!";
      notify(`Your username is @${userId} — share it with contacts`, "info");
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
  app.innerHTML = `
    <div class="onboarding">
      <div class="onboarding-card">
        ${ONBOARDING_LOGO}
        <div class="onboarding-form">
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

  goBtn.addEventListener("click", async () => {
    const uid = uidInput.value.trim();
    const pass = passInput.value;
    if (!uid) { uidInput.focus(); return; }
    if (!pass) { passInput.focus(); return; }

    goBtn.disabled = true;
    status.classList.remove("error-text");

    try {
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
        passphrase: "",
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

  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <div class="topbar-copy">
          <h1 class="topbar-title">Chats</h1>
          <p class="topbar-sub">${escHtml(setup.displayName || setup.userId)} <span class="mono">@${escHtml(setup.userId)}</span></p>
        </div>
        <div class="topbar-actions">
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
      <div class="shield-banner" id="shield-banner">
        <span class="shield-icon">🛡️</span>
        <span>Post-quantum encrypted — protected against future quantum computers</span>
        <button id="dismiss-banner" class="dismiss-btn" aria-label="Dismiss banner">×</button>
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

  // Check if banner was previously dismissed
  if (localStorage.getItem("pqmsg.banner.dismissed") === "1") {
    q("#shield-banner").classList.add("hidden");
  }

  q("#dismiss-banner").addEventListener("click", () => {
    q("#shield-banner").classList.add("hidden");
    localStorage.setItem("pqmsg.banner.dismissed", "1");
  });

  q("#fab-new").addEventListener("click", () => {
    // Show a simple menu: New Chat or New Group
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
  q("#conv-settings").addEventListener("click", () => navigateTo({ screen: "settings" }));
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

  // Start realtime connection & presence heartbeat
  void connectRealtime();
  void startPresenceHeartbeat();
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
    return {
      kind: "dm" as const,
      threadId: summary.peerUserId,
      updatedAt: summary.updatedAt,
      unreadCount: summary.unreadCount,
      lastPreview: summary.lastPreview,
      meta,
      primaryLabel: label.primaryLabel,
      secondaryLabel: label.secondaryLabel,
      avatarText: label.avatarText,
      presenceStatus: presence?.status ?? null,
      isVerified: label.isVerified,
    };
  });
  const groupRows = groupConvos.map((summary) => {
    const meta = getConversationMetaCached(metaLookup, "group", summary.groupId);
    const label = resolveGroupIdentity(summary.groupId, summary.ownerUserId);
    return {
      kind: "group" as const,
      threadId: summary.groupId,
      updatedAt: summary.updatedAt,
      unreadCount: summary.unreadCount,
      lastPreview: summary.lastPreview,
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
          <span class="conv-preview">${escHtml(row.lastPreview)}</span>
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
  const items: Array<{ label: string; className?: string; action: () => void }> = [
    {
      label: meta.pinnedAt ? "Unpin" : "Pin",
      action: () => {
        toggleConversationPinned(kind, threadId);
        refreshConversationsIfVisible();
      },
    },
    {
      label: meta.archivedAt ? "Unarchive" : "Archive",
      action: () => {
        setConversationArchived(kind, threadId, !meta.archivedAt);
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
  const identity = resolvePeerIdentity(peerId);
  const displayName = identity.primaryLabel;
  const meta = loadConversationMeta(setup.userId, "dm", peerId);
  const identityPin = readIdentityPin(setup.userId, peerId);
  const presence = peerPresenceCache[peerId];
  const presenceText = presence?.status === "online" ? "online" : presence?.status === "away" ? "away" : "encrypted";
  const presenceClass = presence?.status === "online" ? "presence-online" : presence?.status === "away" ? "presence-away" : "";
  const fingerprintSummary = identityPin?.fingerprintSha256 || "Not pinned yet";
  const trustSummary = identityPin ? "Trusted on this device" : "Unverified";
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
        <button id="chat-details-toggle" class="icon-btn" title="Chat details" aria-label="Chat details">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>
          </svg>
        </button>
        <button id="call-audio" class="icon-btn" title="Voice call" aria-label="Voice call">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6 19.79 19.79 0 01-3.07-8.67A2 2 0 014.11 2h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L8.09 9.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z"/>
          </svg>
        </button>
        <button id="call-video" class="icon-btn" title="Video call" aria-label="Video call">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="23 7 16 12 23 17 23 7"/>
            <rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>
          </svg>
        </button>
      </header>
      ${requestBanner}
      <div id="typing-indicator" class="typing-indicator hidden">
        <span class="typing-dots"><span></span><span></span><span></span></span>
        <span class="typing-text">${escHtml(displayName)} is typing</span>
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
          <div class="chat-details-row column"><span>Identity fingerprint</span><span class="mono fingerprint">${escHtml(fingerprintSummary)}</span></div>
          <div class="chat-details-row">
            <span>Sealed sender by default</span>
            <label class="switch-inline"><input id="detail-sealed" type="checkbox" ${meta.sealedSenderDefault ? "checked" : ""} /><span>${meta.sealedSenderDefault ? "On" : "Off"}</span></label>
          </div>
          <div class="chat-details-row">
            <span>Disappearing messages</span>
            <select id="detail-ttl" class="ephem-select">
              <option value="0">Off</option>
              <option value="30" ${meta.ephemeralTtlDefault === 30 ? "selected" : ""}>30s</option>
              <option value="300" ${meta.ephemeralTtlDefault === 300 ? "selected" : ""}>5m</option>
              <option value="3600" ${meta.ephemeralTtlDefault === 3600 ? "selected" : ""}>1h</option>
              <option value="86400" ${meta.ephemeralTtlDefault === 86400 ? "selected" : ""}>24h</option>
              <option value="604800" ${meta.ephemeralTtlDefault === 604800 ? "selected" : ""}>7d</option>
            </select>
          </div>
          <div class="chat-details-actions">
            <button id="detail-pin" class="btn-secondary">${meta.pinnedAt ? "Unpin Chat" : "Pin Chat"}</button>
            <button id="detail-archive" class="btn-secondary">${meta.archivedAt ? "Unarchive" : "Archive"}</button>
          </div>
        </div>
      </div>
      <div class="messages-container" id="messages-container">
        <div class="messages" id="messages-list" role="log" aria-live="polite"></div>
      </div>
      <div class="chat-options-bar hidden" aria-hidden="true">
        <label class="chat-option" title="Sealed sender hides your identity from the server">
          <input type="checkbox" id="opt-sealed" />
          <span class="chat-option-label">🕶️ Sealed</span>
        </label>
        <label class="chat-option" title="Message auto-deletes after TTL">
          <select id="opt-ephemeral" class="ephem-select">
            <option value="0">💬 Normal</option>
            <option value="30">⏱️ 30s</option>
            <option value="300">⏱️ 5m</option>
            <option value="3600">⏱️ 1h</option>
            <option value="86400">⏱️ 24h</option>
            <option value="604800">⏱️ 7d</option>
          </select>
        </label>
      </div>
      <div class="chat-input-bar">
        <button id="chat-attach" class="icon-btn attach-btn" title="Attach file" aria-label="Attach file">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/>
          </svg>
        </button>
        <input id="chat-input" type="text" placeholder="Message" autocomplete="off" aria-label="Message" />
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
    </div>
  `;

  const msgList = q("#messages-list");
  const container = q("#messages-container");
  const input = q<HTMLInputElement>("#chat-input");
  const sendBtn = q<HTMLButtonElement>("#chat-send");
  const attachBtn = q<HTMLButtonElement>("#chat-attach");
  const fileInput = q<HTMLInputElement>("#file-input");
  const detailsSheet = q("#chat-details-sheet");
  const attachmentSheet = q("#attachment-sheet");
  let sendInFlight = false;
  let useSealed = meta.sealedSenderDefault;
  let ephTtl = meta.ephemeralTtlDefault;

  q("#chat-back").addEventListener("click", () => {
    activeChatPeer = null;
    stopChatTimers();
    navigateTo({ screen: "conversations" });
  });

  // Call buttons
  q("#call-audio").addEventListener("click", () => {
    navigateTo({ screen: "call", peerId, callType: "audio" });
  });
  q("#call-video").addEventListener("click", () => {
    navigateTo({ screen: "call", peerId, callType: "video" });
  });
  q("#chat-details-toggle").addEventListener("click", () => {
    detailsSheet.classList.remove("hidden");
  });
  q("#chat-details-close").addEventListener("click", () => {
    detailsSheet.classList.add("hidden");
  });
  detailsSheet.addEventListener("click", (e) => {
    if (e.target === detailsSheet) {
      detailsSheet.classList.add("hidden");
    }
  });
  q<HTMLInputElement>("#detail-sealed").addEventListener("change", (e) => {
    useSealed = (e.currentTarget as HTMLInputElement).checked;
    setConversationSendDefaults(peerId, { sealedSenderDefault: useSealed });
  });
  q<HTMLSelectElement>("#detail-ttl").addEventListener("change", (e) => {
    ephTtl = Number((e.currentTarget as HTMLSelectElement).value || 0);
    setConversationSendDefaults(peerId, { ephemeralTtlDefault: ephTtl });
  });
  q("#detail-pin").addEventListener("click", () => {
    const next = toggleConversationPinned("dm", peerId);
    notify(next.pinnedAt ? "Chat pinned" : "Chat unpinned", "success");
    refreshConversationsIfVisible();
    void renderChat(peerId);
  });
  q("#detail-archive").addEventListener("click", () => {
    const archived = !meta.archivedAt;
    setConversationArchived("dm", peerId, archived);
    notify(archived ? "Chat archived" : "Chat restored", "success");
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

  // Enable send when input has content
  input.addEventListener("input", () => {
    sendBtn.disabled = !input.value.trim();
    sendTypingIndicator(peerId, true);
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.repeat && !sendBtn.disabled && !sendInFlight) {
      e.preventDefault();
      sendBtn.click();
    }
  });

  // Send message with optimistic UI
  sendBtn.addEventListener("click", async () => {
    const text = input.value.trim();
    if (!text || sendInFlight) return;
    if (!(await ensureWebMessagingAllowed("direct"))) return;
    sendInFlight = true;
    input.value = "";
    sendBtn.disabled = true;
    try {

    // Handle edit mode
    if (editContext) {
      const { msgId } = editContext;
      editContext = null;
      sendBtn.textContent = "";
      sendBtn.innerHTML = `<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>`;
      const updated = await editStoredMessage(msgId, text);
      if (updated) {
        const bubble = document.getElementById(`msg-${msgId}`);
        if (bubble) {
          const btEl = bubble.querySelector(".bubble-text");
          if (btEl) btEl.textContent = text;
          const timeEl = bubble.querySelector(".bubble-time");
          if (timeEl && !timeEl.querySelector(".edit-indicator")) {
            timeEl.insertAdjacentHTML("beforeend", ' <span class="edit-indicator">(edited)</span>');
          }
        }
      }
      return;
    }

    const tempId = `local-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const labelPrefix = useSealed ? "🕶️ " : ephTtl > 0 ? "⏱️ " : "";
    const msg: StoredMessage = {
      id: tempId,
      conversationId: convId(setup.userId, peerId),
      sender: setup.userId,
      recipient: peerId,
      text: labelPrefix + text,
      timestamp: Date.now(),
      status: "sending",
      replyToId: replyContext?.msgId,
      replyPreview: replyContext?.preview,
      contentType: replyContext ? "reply" : "text",
    };

    // Clear reply bar
    if (replyContext) {
      replyContext = null;
      document.querySelector(".reply-compose-bar")?.remove();
    }

    markConversationAccepted(peerId);
    setConversationArchived("dm", peerId, false);

    // Optimistic: show immediately
    await saveMessage(msg);
    upsertConversation(setup.userId, peerId, `You: ${text}`, false);
    markConversationRead(setup.userId, peerId);
    appendBubble(msgList, msg, container);

    // Async send
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const passphrase = getPassphrase();
      const envelope = await encryptFallbackMessage(passphrase, k.userId, peerId, text);
      const messageBytesBase64 = encodeWireEnvelopeBase64(envelope);

      if (useSealed) {
        // Sealed sender: unauthenticated relay, hides sender from server
        await api.sealedRelay(peerId, { message_bytes_base64: messageBytesBase64 });
      } else if (ephTtl > 0) {
        // Ephemeral: message auto-deletes on server after TTL
        const headers = buildEphemeralRelayAuthHeaders(k, peerId, ephTtl);
        await api.relayEphemeral(peerId, {
          sender_user_id: k.userId,
          device_id: k.deviceId,
          message_bytes_base64: messageBytesBase64,
          ttl_seconds: ephTtl,
        }, headers);
      } else {
        // Normal relay
        const bundle = await api.getBundle(peerId);
        const fingerprint = bundle.identity_fingerprint_sha256 || identityFingerprint(bundle.identity_x25519_pub);
        enforceIdentityPin(peerId, bundle.identity_sig_pub, fingerprint, bundle.identity_key_version, bundle.bundle_generated_at);
        const headers = buildRelayAuthHeaders(k, peerId, messageBytesBase64);
        const relay = await api.relay(peerId, {
          sender_user_id: k.userId,
          device_id: k.deviceId,
          message_bytes_base64: messageBytesBase64,
        }, headers);
        await updateMessageStatus(tempId, "sent", relay.message_id);
      }

      if (useSealed || ephTtl > 0) {
        await updateMessageStatus(tempId, "sent");
      }
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
      sendBtn.disabled = !input.value.trim();
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
    } else if (groupId) {
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

  attachBtn.addEventListener("click", openAttachmentSheet);
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
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    if (file.size > 1_000_000) {
      notify("File too large (max 1 MB)", "error");
      fileInput.removeAttribute("accept");
      fileInput.removeAttribute("capture");
      fileInput.value = "";
      return;
    }
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const buf = await file.arrayBuffer();
      const base64 = arrayBufferToBase64(buf);
      const headers = buildFileUploadAuthHeaders(k, peerId, file.type || "application/octet-stream", base64);
      const res = await api.uploadFile({
        recipient_user_id: peerId,
        device_id: k.deviceId,
        mime_type: file.type || "application/octet-stream",
        file_bytes_base64: base64,
      }, headers);
      // Send a message referencing the file
      const fileText = `📎 File: ${escHtml(file.name)} (${res.file_id})`;
      const tempId = `local-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const msg: StoredMessage = {
        id: tempId,
        conversationId: convId(setup.userId, peerId),
        sender: setup.userId,
        recipient: peerId,
        text: fileText,
        timestamp: Date.now(),
        status: "sent",
        fileId: res.file_id,
        mimeType: file.type || "application/octet-stream",
        fileName: file.name,
      };
      await saveMessage(msg);
      appendBubble(msgList, msg, container);
      markConversationAccepted(peerId);
      setConversationArchived("dm", peerId, false);
      upsertConversation(setup.userId, peerId, `You: ${file.name}`, false);
      markConversationRead(setup.userId, peerId);
      refreshConversationsIfVisible();
      notify("File uploaded", "success");
    } catch (e) {
      notify(`Upload failed: ${errorMsg(e)}`, "error");
    } finally {
      fileInput.removeAttribute("accept");
      fileInput.removeAttribute("capture");
      fileInput.value = "";
    }
  });

  // Message context menu (right-click / long-press) — Reply, React, Edit, Delete
  msgList.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const bubble = (e.target as HTMLElement).closest(".bubble") as HTMLElement | null;
    if (!bubble) return;
    const msgId = bubble.id.replace("msg-", "");
    const isMine = bubble.classList.contains("bubble-sent");
    const serverMid = bubble.getAttribute("data-server-mid");
    showBubbleContextMenu(e as MouseEvent, msgId, isMine, serverMid ? Number(serverMid) : null, bubble, input, sendBtn, peerId);
  });

  // Load history from IndexedDB
  const cid = convId(setup.userId, peerId);
  const history = await getMessages(cid);
  renderMessageList(msgList, history);
  scrollToBottom(container);

  // Focus input
  input.focus();

  // Poll for any missed messages
  void pollInboxSilent();

  // Start typing + receipt polling for this chat
  startTypingPoll(peerId);
  startReceiptPoll();
  fetchPeerPresence(peerId);
}

function renderMessageList(container: HTMLElement, msgs: StoredMessage[]): void {
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
  scrollToBottom(scrollContainer);
}

// Blob URL cache for downloaded file previews
const mediaBlobCache = new Map<string, string>();

function renderMediaContent(msg: StoredMessage): string {
  if (!msg.fileId) return `<div class="bubble-text">${escHtml(msg.text)}</div>`;
  const mime = msg.mimeType || "application/octet-stream";
  const name = msg.fileName || msg.fileId;
  const blobUrl = mediaBlobCache.get(msg.fileId);
  if (mime.startsWith("image/") && blobUrl) {
    return `<img src="${blobUrl}" alt="${escHtml(name)}" class="media-img" loading="lazy" data-file-id="${escHtml(msg.fileId)}" />`;
  }
  if (mime.startsWith("audio/") && blobUrl) {
    return `<audio controls src="${blobUrl}" class="media-audio"></audio>`;
  }
  if (mime.startsWith("video/") && blobUrl) {
    return `<video controls src="${blobUrl}" class="media-video"></video>`;
  }
  // Show loading placeholder or download link
  if (mime.startsWith("image/") || mime.startsWith("audio/") || mime.startsWith("video/")) {
    return `<div class="media-loading" data-file-id="${escHtml(msg.fileId)}">Loading media…</div>`;
  }
  return `<a class="media-file-link" href="#" data-file-id="${escHtml(msg.fileId)}">📎 ${escHtml(name)}</a>`;
}

function renderReplyQuote(msg: StoredMessage): string {
  if (!msg.replyToId || !msg.replyPreview) return "";
  return `<div class="reply-quote">${escHtml(msg.replyPreview)}</div>`;
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
  if (msg.serverMessageId) {
    bubble.setAttribute("data-server-mid", String(msg.serverMessageId));
  }

  const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const statusIcon = isMine ? statusSvg(msg.status) : "";
  const editedTag = msg.editedAt ? ' <span class="edit-indicator">(edited)</span>' : "";

  bubble.innerHTML = `
    ${renderReplyQuote(msg)}
    ${msg.fileId ? renderMediaContent(msg) : `<div class="bubble-text">${escHtml(msg.text)}</div>`}
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
  const fileLink = bubble.querySelector<HTMLAnchorElement>(".media-file-link");
  if (fileLink) {
    fileLink.addEventListener("click", (e) => {
      e.preventDefault();
      void downloadAndOpenFile(fileLink.dataset.fileId!);
    });
  }
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
    const name = c.alias || cachedProfileNames[c.contact_user_id] || c.contact_user_id;
    const initials = name.slice(0, 2).toUpperCase();
    const verified = c.verified_by_qr ? `<span class="verified-badge" title="Verified">✓</span>` : "";
    return `
      <div class="contact-row" data-contact="${escHtml(c.contact_user_id)}">
        <div class="avatar avatar-sm">${initials}</div>
        <div class="contact-info">
          <span class="contact-name">${escHtml(name)}${verified}</span>
          <span class="contact-id">${escHtml(c.contact_user_id)}</span>
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
        <div class="invite-section">
          <button id="nc-invite" class="btn-secondary">Copy Invite Link</button>
        </div>
      </div>
    </div>
  `;

  q("#nc-back").addEventListener("click", () => navigateTo({ screen: "conversations" }));
  const peerInput = q<HTMLInputElement>("#nc-peer");

  const startChat = (peer: string) => {
    const resolvedPeer = parseChatTarget(peer).replace(/^@/, "");
    if (!resolvedPeer) { peerInput.focus(); return; }
    if (resolvedPeer === setup.userId) {
      notify("You can't chat with yourself", "error");
      return;
    }
    void addContactSilent(resolvedPeer);
    markConversationAccepted(resolvedPeer);
    setConversationArchived("dm", resolvedPeer, false);
    upsertConversation(setup.userId, resolvedPeer, "New conversation", false);
    markConversationRead(setup.userId, resolvedPeer);
    navigateTo({ screen: "chat", peerId: resolvedPeer });
  };

  q("#nc-start").addEventListener("click", () => startChat(peerInput.value.trim()));

  // Contact row clicks
  for (const row of document.querySelectorAll("[data-contact]")) {
    row.addEventListener("click", () => {
      startChat((row as HTMLElement).dataset.contact!);
    });
  }

  // Invite link
  q("#nc-invite").addEventListener("click", () => {
    const link = `${location.origin}/?invite=${encodeURIComponent(setup.userId)}`;
    void navigator.clipboard.writeText(link).then(() => {
      notify("Invite link copied!", "success");
    }).catch(() => {
      notify("Could not copy link", "error");
    });
  });

  // Check for invite param in URL
  const params = new URLSearchParams(location.search);
  const invitee = params.get("invite");
  if (invitee && invitee !== setup.userId) {
    peerInput.value = invitee;
  }

  peerInput.focus();
}

// ---------------------------------------------------------------------------
// Phase 3: Group Chat
// ---------------------------------------------------------------------------

async function renderGroupChat(groupId: string): Promise<void> {
  app.innerHTML = `
    <div class="chat-shell">
      <header class="chat-header">
        <button id="gc-back" class="icon-btn" aria-label="Back to conversations">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <div class="avatar-wrap">
          <div class="avatar avatar-sm avatar-group">${groupId.slice(0, 2).toUpperCase()}</div>
        </div>
        <div class="chat-header-info">
          <span class="chat-header-name">${escHtml(groupId)}</span>
          <span class="chat-header-status" id="gc-member-count">group</span>
        </div>
        <button id="gc-info" class="icon-btn" title="Group info" aria-label="Group info">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>
          </svg>
        </button>
        <div class="chat-header-shield" title="Post-quantum encrypted">🛡️</div>
      </header>
      <div class="messages-container" id="messages-container">
        <div class="messages" id="messages-list" role="log" aria-live="polite"></div>
      </div>
      <div class="chat-input-bar">
        <input id="gc-input" type="text" placeholder="Message to group" autocomplete="off" aria-label="Message to group" />
        <button id="gc-send" class="send-btn" disabled aria-label="Send message">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor">
            <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
          </svg>
        </button>
      </div>
    </div>
  `;

  const msgList = q("#messages-list");
  const container = q("#messages-container");
  const input = q<HTMLInputElement>("#gc-input");
  const sendBtn = q<HTMLButtonElement>("#gc-send");
  let sendInFlight = false;

  q("#gc-back").addEventListener("click", () => {
    activeGroupId = null;
    navigateTo({ screen: "conversations" });
  });
  q("#gc-info").addEventListener("click", () => navigateTo({ screen: "group-info", groupId }));

  input.addEventListener("input", () => { sendBtn.disabled = !input.value.trim(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.repeat && !sendBtn.disabled && !sendInFlight) {
      e.preventDefault();
      sendBtn.click();
    }
  });

  sendBtn.addEventListener("click", async () => {
    const text = input.value.trim();
    if (!text || sendInFlight) return;
    if (!(await ensureWebMessagingAllowed("group"))) return;
    sendInFlight = true;
    input.value = "";
    sendBtn.disabled = true;
    try {

    // Handle edit mode
    if (editContext) {
      const { msgId } = editContext;
      editContext = null;
      sendBtn.textContent = "";
      sendBtn.innerHTML = `<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>`;
      const updated = await editStoredMessage(msgId, text);
      if (updated) {
        const bubble = document.getElementById(`msg-${msgId}`);
        if (bubble) {
          const btEl = bubble.querySelector(".bubble-text");
          if (btEl) btEl.textContent = text;
          const timeEl = bubble.querySelector(".bubble-time");
          if (timeEl && !timeEl.querySelector(".edit-indicator")) {
            timeEl.insertAdjacentHTML("beforeend", ' <span class="edit-indicator">(edited)</span>');
          }
        }
      }
      return;
    }

    const tempId = `local-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const msg: StoredMessage = {
      id: tempId,
      conversationId: `group:${groupId}`,
      sender: setup.userId,
      recipient: groupId,
      text,
      timestamp: Date.now(),
      status: "sending",
      replyToId: replyContext?.msgId,
      replyPreview: replyContext?.preview,
      contentType: replyContext ? "reply" : "text",
    };

    // Clear reply bar
    if (replyContext) {
      replyContext = null;
      document.querySelector(".reply-compose-bar")?.remove();
    }

    await saveMessage(msg);
    appendBubble(msgList, msg, container);

    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const passphrase = getPassphrase();
      const envelope = await encryptFallbackMessage(passphrase, k.userId, groupId, text);
      const messageBytesBase64 = encodeWireEnvelopeBase64(envelope);
      const headers = buildGroupRelayAuthHeaders(k, groupId, messageBytesBase64);
      await api.relayGroupMessage(groupId, {
        sender_user_id: k.userId,
        device_id: k.deviceId,
        message_bytes_base64: messageBytesBase64,
      }, headers);

      await updateMessageStatus(tempId, "sent");
      upsertGroupConversation(setup.userId, groupId, setup.userId, `You: ${text}`, false);
      markGroupConversationRead(setup.userId, groupId);
      updateBubbleStatus(tempId, "sent");
    } catch (e) {
      await updateMessageStatus(tempId, "failed");
      updateBubbleStatus(tempId, "failed");
      notify(`Send failed: ${errorMsg(e)}`, "error");
    }
    } finally {
      sendInFlight = false;
      sendBtn.disabled = !input.value.trim();
    }
  });

  // Load group message history
  const history = await getMessages(`group:${groupId}`);
  renderMessageList(msgList, history);
  scrollToBottom(container);
  input.focus();

  // Group chat context menu
  msgList.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const bubble = (e.target as HTMLElement).closest(".bubble") as HTMLElement | null;
    if (!bubble) return;
    const msgId = bubble.id.replace("msg-", "");
    const isMine = bubble.classList.contains("bubble-sent");
    const serverMid = bubble.getAttribute("data-server-mid");
    showBubbleContextMenu(e as MouseEvent, msgId, isMine, serverMid ? Number(serverMid) : null, bubble, input, sendBtn);
  });

  // Load members count
  void loadGroupMembersCount(groupId);
}

async function loadGroupMembersCount(groupId: string): Promise<void> {
  try {
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildGroupMembersListAuthHeaders(k, groupId);
    const res = await api.listGroupMembers(groupId, headers);
    cachedGroupMembers[groupId] = res.members;
    const countEl = document.getElementById("gc-member-count");
    if (countEl) countEl.textContent = `${res.members.length} members`;
  } catch {
    // Best-effort
  }
}

// ---------------------------------------------------------------------------
// Phase 3: Group Info
// ---------------------------------------------------------------------------

async function renderGroupInfo(groupId: string): Promise<void> {
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
          <div id="gi-members"><p class="text-secondary">Loading members…</p></div>
        </div>
        <div class="settings-section">
          <h3>Add Member</h3>
          <div class="add-contact-row">
            <input id="gi-add-id" type="text" placeholder="User ID" class="input-sm" />
            <button id="gi-add-btn" class="btn-sm">Add</button>
          </div>
        </div>
      </div>
    </div>
  `;

  q("#gi-back").addEventListener("click", () => navigateTo({ screen: "group-chat", groupId }));

  // Add member
  q("#gi-add-btn").addEventListener("click", async () => {
    const userId = q<HTMLInputElement>("#gi-add-id").value.trim();
    if (!userId) return;
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildGroupMembersAddAuthHeaders(k, groupId, userId);
      await api.addGroupMember(groupId, { member_user_id: userId }, headers);
      notify("Member added", "success");
      renderGroupInfo(groupId);
    } catch (e) {
      notify(`Add failed: ${errorMsg(e)}`, "error");
    }
  });

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
        ${m.user_id !== setup.userId ? `<button class="btn-sm btn-danger-sm" data-remove-member="${escHtml(m.user_id)}">Remove</button>` : '<span class="text-secondary">you</span>'}
      </div>
    `).join("");

    // Remove member handlers
    for (const btn of document.querySelectorAll("[data-remove-member]")) {
      btn.addEventListener("click", async () => {
        const memberId = (btn as HTMLElement).dataset.removeMember!;
        try {
          const kk = await ensureKeys();
          const api2 = new PqmsgApi(setup.serverUrl);
          const h = buildGroupMembersRemoveAuthHeaders(kk, groupId, memberId);
          await api2.removeGroupMember(groupId, { member_user_id: memberId }, h);
          notify("Member removed", "success");
          renderGroupInfo(groupId);
        } catch (e2) {
          notify(`Remove failed: ${errorMsg(e2)}`, "error");
        }
      });
    }
  } catch (e) {
    q("#gi-members").innerHTML = `<p class="error-text">Failed to load: ${errorMsg(e)}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Phase 3: Create Group
// ---------------------------------------------------------------------------

function renderCreateGroup(): void {
  const contactRows = cachedContacts.map(c => {
    const name = c.alias || c.contact_user_id;
    const initials = name.slice(0, 2).toUpperCase();
    return `
      <label class="contact-row contact-checkbox">
        <input type="checkbox" value="${escHtml(c.contact_user_id)}" class="cg-member-cb" />
        <div class="avatar avatar-sm">${initials}</div>
        <span class="contact-name">${escHtml(name)}</span>
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
        <button id="cg-create" class="btn-primary">Create Group</button>
      </div>
    </div>
  `;

  q("#cg-back").addEventListener("click", () => navigateTo({ screen: "conversations" }));

  q("#cg-create").addEventListener("click", async () => {
    const name = q<HTMLInputElement>("#cg-name").value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "-");
    if (!name) { q<HTMLInputElement>("#cg-name").focus(); return; }

    const checkboxes = document.querySelectorAll<HTMLInputElement>(".cg-member-cb:checked");
    const memberIds = Array.from(checkboxes).map(cb => cb.value);
    // Always include self
    if (!memberIds.includes(setup.userId)) memberIds.push(setup.userId);

    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildGroupCreateAuthHeaders(k, name, memberIds);
      const res = await api.createGroup({ group_id: name, member_user_ids: memberIds }, headers);
      upsertGroupConversation(setup.userId, res.group_id, res.owner_user_id, "Group created", false);
      notify("Group created!", "success");
      navigateTo({ screen: "group-chat", groupId: res.group_id });
    } catch (e) {
      notify(`Create group failed: ${errorMsg(e)}`, "error");
    }
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
      bubble.remove();
      notify("Message deleted", "success");
    } catch (e) {
      notify(`Delete failed: ${errorMsg(e)}`, "error");
    }
  });
}

// ---------------------------------------------------------------------------
// 5. Settings screen
// ---------------------------------------------------------------------------

function renderSettings(): void {
  const fingerprint = keys ? identityFingerprint(keys.identityX25519Pub) : "not available";
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
        <div class="settings-section">
          <h3>Account</h3>
          <div class="profile-edit-row">
            <label class="field">
              <span>Display Name</span>
              <input id="set-name" type="text" value="${escHtml(setup.displayName || setup.userId)}" />
            </label>
            <button id="set-save-profile" class="btn-sm">Save</button>
          </div>
          <div class="settings-row"><span>User ID</span><span class="mono">${escHtml(setup.userId)}</span></div>
          <div class="settings-row"><span>Device</span><span class="mono">${escHtml(setup.deviceId)}</span></div>
        </div>
        <div class="settings-section">
          <h3>People</h3>
          <div id="contacts-manage">
            ${cachedContacts.length === 0 ? '<p class="text-secondary">No contacts yet</p>' :
              cachedContacts.map(c => `
                <div class="contact-manage-row">
                  <span>${escHtml(c.alias || c.contact_user_id)}</span>
                  <span class="mono text-secondary">${escHtml(c.contact_user_id)}</span>
                  <button class="btn-sm btn-danger-sm" data-remove-contact="${escHtml(c.contact_user_id)}">Remove</button>
                </div>
              `).join("")
            }
          </div>
          <div class="add-contact-row">
            <input id="set-add-contact-id" type="text" placeholder="User ID" class="input-sm" />
            <input id="set-add-contact-alias" type="text" placeholder="Alias (optional)" class="input-sm" />
            <button id="set-add-contact" class="btn-sm">Add</button>
          </div>
        </div>
        <div class="settings-section">
          <h3>Privacy & Trust</h3>
          <div class="settings-row"><span>Encryption</span><span>Post-quantum (ML-KEM-768)</span></div>
          <div class="settings-row"><span>Mode</span><span>WebCrypto fallback</span></div>
          <div class="settings-row column"><span>Identity Fingerprint</span><span class="mono fingerprint">${escHtml(fingerprint)}</span></div>
          <div class="settings-row"><span>Server</span><span class="mono">${escHtml(setup.serverUrl)}</span></div>
          <div class="settings-row">
            <button id="set-rotate-key" class="btn-sm">🔄 Rotate Identity Key</button>
            <button id="set-identity-log" class="btn-sm">📋 Identity Log</button>
          </div>
          <div id="rotate-status"></div>
        </div>
        <div class="settings-section">
          <h3>Key Health</h3>
          <div id="prekey-status"><p class="text-secondary">Loading…</p></div>
        </div>
        <div class="settings-section">
          <h3>Advanced Discovery</h3>
          <p class="text-secondary settings-desc">Let contacts find you by phone or email hash.</p>
          <div class="settings-row">
            <button id="set-discovery" class="btn-sm">🔍 Contact Discovery</button>
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
            <button id="set-devices" class="btn-sm">📱 Manage Devices</button>
          </div>
        </div>
        <div class="settings-section">
          <h3>Advanced Server</h3>
          <div class="settings-row">
            <button id="set-server-info" class="btn-sm">📊 Server Info</button>
          </div>
        </div>
        <div class="settings-section">
          <h3>Session</h3>
          <button id="set-logout" class="btn-secondary">Log Out</button>
        </div>
        <div class="settings-section">
          <button id="set-reset" class="btn-danger">Delete Account & Data</button>
        </div>
      </div>
    </div>
  `;

  q("#set-back").addEventListener("click", () => navigateTo({ screen: "conversations" }));

  // Save profile
  q("#set-save-profile").addEventListener("click", async () => {
    const nameInput = q<HTMLInputElement>("#set-name");
    const newName = nameInput.value.trim();
    if (!newName) { nameInput.focus(); return; }
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildProfileUpsertAuthHeaders(k, newName, "", "");
      await api.upsertProfile(k.userId, { display_name: newName }, headers);
      setup.displayName = newName;
      saveSetup(setup);
      cachedProfileNames[k.userId] = newName;
      writeProfileDisplayName(k.userId, k.userId, newName);
      refreshConversationsIfVisible();
      notify("Profile updated", "success");
    } catch (e) {
      notify(`Profile update failed: ${errorMsg(e)}`, "error");
    }
  });

  // Add contact
  q("#set-add-contact").addEventListener("click", async () => {
    const contactId = q<HTMLInputElement>("#set-add-contact-id").value.trim();
    const alias = q<HTMLInputElement>("#set-add-contact-alias").value.trim();
    if (!contactId) { q<HTMLInputElement>("#set-add-contact-id").focus(); return; }
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildContactsUpsertAuthHeaders(k, contactId, alias || contactId, false, "");
      await api.upsertContact(k.userId, { contact_user_id: contactId, alias: alias || undefined }, headers);
      notify("Contact added", "success");
      void loadContactsBackground();
      void loadProfileNameBackground(contactId);
      // Re-render to show updated list
      renderSettings();
    } catch (e) {
      notify(`Add contact failed: ${errorMsg(e)}`, "error");
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
  q("#set-discovery").addEventListener("click", () => navigateTo({ screen: "discovery" }));

  // Server info navigation
  q("#set-server-info").addEventListener("click", () => navigateTo({ screen: "server-info" }));
  q("#set-devices").addEventListener("click", () => navigateTo({ screen: "devices" }));
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
      const initHeaders = buildRotateInitAuthHeaders(k, newKeys.identityX25519Pub, newKeys.identitySigPub);
      statusEl.textContent = "Requesting rotation challenge…";
      const challenge = await api.rotateInit(k.userId, {
        new_identity_x25519_pub: newKeys.identityX25519Pub,
        new_identity_sig_pub: newKeys.identitySigPub,
        new_device_id: k.deviceId,
      }, initHeaders);
      // Step 2: sign challenge nonce with both current and new identity keys
      const nonceBytes = new TextEncoder().encode(challenge.challenge_nonce);
      const sigCurrent = bytesToBase64(ed25519.sign(nonceBytes, base64ToBytes(k.identitySigSecret)));
      const sigNew = bytesToBase64(ed25519.sign(nonceBytes, base64ToBytes(newKeys.identitySigSecret)));
      statusEl.textContent = "Confirming rotation…";
      const confirmHeaders = buildRotateConfirmAuthHeaders(k, challenge.challenge_id, sigCurrent, sigNew);
      const result = await api.rotateConfirm(k.userId, {
        challenge_id: challenge.challenge_id,
        sig_by_current_identity: sigCurrent,
        sig_by_new_identity: sigNew,
      }, confirmHeaders);
      // Step 3: persist new keys locally
      const rotatedKeys: GeneratedKeys = { ...k, ...newKeys };
      const passphrase = getPassphrase();
      await saveKeys(k.userId, passphrase, rotatedKeys);
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
    wipeLocalState(setup.userId);
    await clearOutboxMessages(setup.userId);
    await clearAllMessages();
    keys = null;
    if (realtimeInbox) { realtimeInbox.disconnect(); realtimeInbox = null; }
    stopAllTimers();
    cachedContacts = [];
    peerPresenceCache = {};
    setup = { ...DEFAULT_SETUP, serverUrl: setup.serverUrl, suiteLabel: setup.suiteLabel, displayName: "", passphrase: "" };
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
  const contact = cachedContacts.find(ct => ct.contact_user_id === peerId);
  const displayName = contact?.alias || peerId;

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
}

async function renderIncomingCall(
  callId: string,
  peerId: string,
  callType: "audio" | "video",
  sdpOfferBase64: string
): Promise<void> {
  const contact = cachedContacts.find(ct => ct.contact_user_id === peerId);
  const displayName = contact?.alias || peerId;

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
}

// ---------------------------------------------------------------------------
// WebSocket realtime
// ---------------------------------------------------------------------------

async function connectRealtime(): Promise<void> {
  if (realtimeInbox) return;
  try {
    const k = await ensureKeys();
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
    const envelope = decodeWireEnvelopeBase64(wsMsg.message_bytes_base64);
    const passphrase = getPassphrase();
    const plaintext = await decryptFallbackMessage(passphrase, envelope);
    const isDirectMessage = envelope.recipient === k.userId;
    const groupId = isDirectMessage ? null : envelope.recipient;
    const conversationId = isDirectMessage
      ? convId(k.userId, wsMsg.sender_user_id)
      : `group:${groupId}`;
    const msg: StoredMessage = {
      id: `srv-${wsMsg.message_id}`,
      conversationId,
      sender: wsMsg.sender_user_id,
      recipient: isDirectMessage ? k.userId : envelope.recipient,
      text: isDirectMessage
        ? plaintext
        : `${resolvePeerIdentity(wsMsg.sender_user_id).primaryLabel}: ${plaintext}`,
      timestamp: new Date(wsMsg.received_at).getTime() || Date.now(),
      status: "delivered",
      serverMessageId: wsMsg.message_id,
    };
    await saveMessage(msg);

    if (isDirectMessage) {
      void sendDeliveredReceipt(wsMsg.message_id);
    }

    const cursor = readCursor(k.userId);
    if (wsMsg.message_id > cursor) {
      writeCursor(k.userId, wsMsg.message_id);
    }

    if (isDirectMessage) {
      const isActivePeer = activeChatPeer === wsMsg.sender_user_id;
      noteIncomingConversation(wsMsg.sender_user_id, plaintext, !isActivePeer);
      if (isActivePeer) {
        markConversationRead(k.userId, wsMsg.sender_user_id);
        const msgList = document.getElementById("messages-list");
        const container = document.getElementById("messages-container");
        if (msgList && container) {
          appendBubble(msgList, msg, container);
        }
      } else {
        notify(`${resolvePeerIdentity(wsMsg.sender_user_id).primaryLabel}: ${plaintext.slice(0, 50)}`, "info");
      }
    } else if (groupId) {
      const isActiveGroup = activeGroupId === groupId;
      noteIncomingGroupConversation(groupId, wsMsg.sender_user_id, plaintext, !isActiveGroup);
      void loadProfileNameBackground(wsMsg.sender_user_id);
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
          wsMsg.sender_user_id;
        const groupLabel = resolveGroupIdentity(groupId, ownerUserId).primaryLabel;
        notify(`${groupLabel} · ${resolvePeerIdentity(wsMsg.sender_user_id).primaryLabel}: ${plaintext.slice(0, 50)}`, "info");
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
    const k = await ensureKeys();
    const api = new PqmsgApi(setup.serverUrl);
    const since = readCursor(k.userId);
    const headers = buildInboxAuthHeaders(k, since);
    const inbox = await api.inbox(k.userId, since, headers);
    if (inbox.messages.length === 0) return;

    let cursor = since;
    const passphrase = getPassphrase();
    let conversationListChanged = false;
    for (const message of inbox.messages) {
      cursor = Math.max(cursor, message.message_id);
      try {
        const envelope = decodeWireEnvelopeBase64(message.message_bytes_base64);
        const plaintext = await decryptFallbackMessage(passphrase, envelope);
        const isDirectMessage = envelope.recipient === k.userId;
        const groupId = isDirectMessage ? null : envelope.recipient;
        const conversationId = isDirectMessage
          ? convId(k.userId, message.sender_user_id)
          : `group:${groupId}`;
        const existing = await getMessages(conversationId);
        const alreadyStored = existing.some((m) => m.serverMessageId === message.message_id);
        if (alreadyStored) continue;

        const msg: StoredMessage = {
          id: `srv-${message.message_id}`,
          conversationId,
          sender: message.sender_user_id,
          recipient: isDirectMessage ? k.userId : envelope.recipient,
          text: isDirectMessage
            ? plaintext
            : `${resolvePeerIdentity(message.sender_user_id).primaryLabel}: ${plaintext}`,
          timestamp: new Date(message.received_at).getTime() || Date.now(),
          status: "delivered",
          serverMessageId: message.message_id,
        };
        await saveMessage(msg);

        if (isDirectMessage) {
          const isActivePeer = activeChatPeer === message.sender_user_id;
          noteIncomingConversation(message.sender_user_id, plaintext, !isActivePeer);
          if (isActivePeer) {
            markConversationRead(k.userId, message.sender_user_id);
            const msgList = document.getElementById("messages-list");
            const container = document.getElementById("messages-container");
            if (msgList && container) {
              appendBubble(msgList, msg, container);
            }
          }
        } else if (groupId) {
          const isActiveGroup = activeGroupId === groupId;
          noteIncomingGroupConversation(groupId, message.sender_user_id, plaintext, !isActiveGroup);
          void loadProfileNameBackground(message.sender_user_id);
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
      } catch {
        // Skip un-decryptable messages
      }
    }
    writeCursor(k.userId, cursor);
    if (conversationListChanged) {
      refreshConversationsIfVisible();
    }
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
let editContext: { msgId: string; originalText: string } | null = null;

function showBubbleContextMenu(
  e: MouseEvent,
  msgId: string,
  isMine: boolean,
  serverMid: number | null,
  bubble: HTMLElement,
  inputEl: HTMLInputElement,
  sendBtnEl: HTMLButtonElement,
  peerId?: string,
): void {
  // Remove any existing context menu
  document.querySelector(".ctx-menu")?.remove();

  const menu = document.createElement("div");
  menu.className = "ctx-menu";
  menu.style.top = `${e.clientY}px`;
  menu.style.left = `${e.clientX}px`;

  let items = `<div class="ctx-item" data-action="reply">↩️ Reply</div>
    <div class="ctx-item" data-action="react">😀 React</div>`;
  if (isMine) {
    items += `<div class="ctx-item" data-action="edit">✏️ Edit</div>`;
    if (serverMid) items += `<div class="ctx-item ctx-danger" data-action="delete">🗑️ Delete</div>`;
  }
  menu.innerHTML = items;
  document.body.appendChild(menu);

  const dismiss = () => menu.remove();
  setTimeout(() => document.addEventListener("click", dismiss, { once: true }), 0);

  menu.addEventListener("click", async (ev) => {
    const action = (ev.target as HTMLElement).dataset.action;
    menu.remove();
    if (!action) return;

    if (action === "reply") {
      const text = bubble.querySelector(".bubble-text")?.textContent || "";
      replyContext = { msgId, preview: text.slice(0, 60) };
      showReplyBar(inputEl);
      inputEl.focus();
    }

    if (action === "react") {
      showReactionPicker(e.clientX, e.clientY, msgId, bubble, peerId);
    }

    if (action === "edit") {
      const text = bubble.querySelector(".bubble-text")?.textContent || "";
      editContext = { msgId, originalText: text };
      inputEl.value = text;
      sendBtnEl.disabled = false;
      sendBtnEl.textContent = "Save";
      inputEl.focus();
    }

    if (action === "delete" && serverMid) {
      showDeleteConfirm(bubble, serverMid);
    }
  });
}

function showReplyBar(inputEl: HTMLInputElement): void {
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
        const preview = m.text.length > 80 ? m.text.slice(0, 80) + "…" : m.text;
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
    const passphrase = getPassphrase();
    const queued = await getOutboxMessages(k.userId);
    for (const item of queued) {
      try {
        if (item.groupId) {
          const envelope = await encryptFallbackMessage(passphrase, k.userId, item.groupId, item.text);
          const messageBytesBase64 = encodeWireEnvelopeBase64(envelope);
          const headers = buildGroupRelayAuthHeaders(k, item.groupId, messageBytesBase64);
          await api.relayGroupMessage(item.groupId, {
            sender_user_id: k.userId, device_id: k.deviceId, message_bytes_base64: messageBytesBase64,
          }, headers);
        } else if (item.sealed) {
          const envelope = await encryptFallbackMessage(passphrase, k.userId, item.peerId, item.text);
          const messageBytesBase64 = encodeWireEnvelopeBase64(envelope);
          await api.sealedRelay(item.peerId, { message_bytes_base64: messageBytesBase64 });
        } else if (item.ephemeralTtl > 0) {
          const envelope = await encryptFallbackMessage(passphrase, k.userId, item.peerId, item.text);
          const messageBytesBase64 = encodeWireEnvelopeBase64(envelope);
          const headers = buildEphemeralRelayAuthHeaders(k, item.peerId, item.ephemeralTtl);
          await api.relayEphemeral(item.peerId, {
            sender_user_id: k.userId, device_id: k.deviceId,
            message_bytes_base64: messageBytesBase64, ttl_seconds: item.ephemeralTtl,
          }, headers);
        } else {
          const envelope = await encryptFallbackMessage(passphrase, k.userId, item.peerId, item.text);
          const messageBytesBase64 = encodeWireEnvelopeBase64(envelope);
          const headers = buildRelayAuthHeaders(k, item.peerId, messageBytesBase64);
          await api.relay(item.peerId, {
            sender_user_id: k.userId, device_id: k.deviceId, message_bytes_base64: messageBytesBase64,
          }, headers);
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
  toast.textContent = n.text;
  toast.className = `toast toast-${n.type} toast-show`;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast!.classList.remove("toast-show");
  }, 3500);
}

// ---------------------------------------------------------------------------
// Phase 2: Presence heartbeat
// ---------------------------------------------------------------------------

function startPresenceHeartbeat(): void {
  if (presenceHeartbeatTimer) return;
  void sendPresenceUpdate("online");
  presenceHeartbeatTimer = setInterval(() => {
    void sendPresenceUpdate("online");
  }, 120_000); // Re-send every 2 minutes (TTL is 180s)
}

async function sendPresenceUpdate(status: "online" | "away" | "offline"): Promise<void> {
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
  if (typingTimer) clearTimeout(typingTimer);
  if (isTyping) {
    typingTimer = setTimeout(() => {
      void sendTypingUpdate(peerId, false);
    }, 10_000); // Stop typing after 10s of no input
  }
  void sendTypingUpdate(peerId, isTyping);
}

async function sendTypingUpdate(peerId: string, isTyping: boolean): Promise<void> {
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
    const body = document.getElementById("idlog-body")!;
    if (res.events.length === 0) {
      body.innerHTML = '<p class="text-secondary">No identity events recorded.</p>';
      return;
    }
    body.innerHTML = `
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
    const api = new PqmsgApi(setup.serverUrl);
    const headers = buildSealedInboxAuthHeaders(k, sealedInboxCursor);
    const res = await api.sealedInbox(k.userId, sealedInboxCursor, headers);
    const passphrase = getPassphrase();
    let conversationListChanged = false;
    for (const item of res.messages) {
      try {
        const envelope = decodeWireEnvelopeBase64(item.message_bytes_base64);
        const plaintext = await decryptFallbackMessage(passphrase, envelope);
        const senderId = envelope.sender;
        const msgId = String(item.message_id);
        const msg: StoredMessage = {
          id: msgId,
          conversationId: convId(k.userId, senderId),
          sender: senderId,
          recipient: k.userId,
          text: "🕶️ " + plaintext,
          timestamp: new Date(item.received_at).getTime(),
          status: "delivered",
        };
        await saveMessage(msg);
        noteIncomingConversation(senderId, plaintext, true);
        conversationListChanged = true;
        sealedInboxCursor = Math.max(sealedInboxCursor, Number(msgId) || sealedInboxCursor + 1);
      } catch {
        // Skip malformed sealed messages
      }
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
          <p class="text-secondary settings-desc">Share hashed phone/email so contacts can find you.</p>
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
          <p class="text-secondary settings-desc">Enter hashes to check who's registered.</p>
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

  q("#disc-upload").addEventListener("click", async () => {
    const statusEl = document.getElementById("disc-upload-status")!;
    const phones = q<HTMLTextAreaElement>("#disc-phones").value.split("\n").map(l => l.trim()).filter(Boolean);
    const emails = q<HTMLTextAreaElement>("#disc-emails").value.split("\n").map(l => l.trim()).filter(Boolean);
    if (phones.length === 0 && emails.length === 0) { notify("Enter at least one hash", "error"); return; }
    try {
      const k = await ensureKeys();
      const api = new PqmsgApi(setup.serverUrl);
      const headers = buildDiscoveryHandlesAuthHeaders(k, phones, emails);
      const res = await api.uploadDiscoveryHandles(k.userId, {
        phone_hashes_sha256: phones,
        email_hashes_sha256: emails,
      }, headers);
      statusEl.innerHTML = `<span class="text-success">✓ Uploaded ${res.uploaded_phone_hashes} phone + ${res.uploaded_email_hashes} email hashes</span>`;
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
      const headers = buildDiscoveryMatchAuthHeaders(k, hashes);
      const res = await api.discoveryMatch(k.userId, { hashes_sha256: hashes }, headers);
      if (res.matches.length === 0) {
        resultsEl.innerHTML = '<p class="text-secondary">No matches found.</p>';
        return;
      }
      resultsEl.innerHTML = `
        <table class="idlog-table">
          <thead><tr><th>Hash</th><th>User</th><th>Type</th><th></th></tr></thead>
          <tbody>
            ${res.matches.map((m: DiscoveryMatchItem) => `
              <tr>
                <td class="mono fingerprint">${escHtml(m.hash_sha256)}</td>
                <td class="mono">${escHtml(m.matched_user_id)}</td>
                <td><span class="badge-info">${escHtml(m.handle_kind)}</span></td>
                <td><button class="btn-sm" data-add-discovered="${escHtml(m.matched_user_id)}">Add</button></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
      for (const btn of document.querySelectorAll("[data-add-discovered]")) {
        btn.addEventListener("click", async () => {
          const userId = (btn as HTMLElement).dataset.addDiscovered!;
          await addContactSilent(userId);
          notify(`Added ${userId} as contact`, "success");
          (btn as HTMLButtonElement).disabled = true;
          (btn as HTMLButtonElement).textContent = "Added";
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
          <div class="settings-row"><span>Web Policy</span><span class="mono">${escHtml(caps.web_client_policy)}</span></div>
          <div class="settings-row"><span>PQ Ratchet</span><span>every ${caps.pq_ratchet_interval} msgs</span></div>
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
  try {
    await callManager?.hangup("sign-out");
  } catch {
    // Best-effort call cleanup
  }

  if (realtimeInbox) {
    realtimeInbox.disconnect();
    realtimeInbox = null;
  }

  stopAllTimers();
  keys = null;
  callManager = null;
  currentCallInfo = null;
  activeChatPeer = null;
  activeGroupId = null;
  cachedContacts = [];
  cachedProfileNames = {};
  cachedGroupMembers = {};
  peerPresenceCache = {};
  receiptCursor = 0;
  sealedInboxCursor = 0;
  sessionStorage.removeItem("pqmsg.passphrase");
  setup = {
    ...DEFAULT_SETUP,
    serverUrl: setup.serverUrl,
    suiteLabel: setup.suiteLabel,
  };
  saveSetup(setup);
  navigateTo({ screen: "sign-in" });
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
    if (el) el.innerHTML = `<p class="error-text">Failed: ${errorMsg(e)}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function enforceIdentityPin(
  peerUserId: string,
  identitySigPub: string,
  fingerprint: string,
  identityVersion: number,
  observedAt: string
): void {
  const existing = readIdentityPin(setup.userId, peerUserId);
  if (!existing) {
    writeIdentityPin(setup.userId, peerUserId, {
      fingerprintSha256: fingerprint,
      identityKeyVersion: identityVersion,
      identitySigPub,
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
    identitySigPub,
    observedAt,
  });
}

async function ensureKeys(): Promise<GeneratedKeys> {
  if (keys) return keys;
  const passphrase = getPassphrase();
  keys = await loadKeys(setup.userId, passphrase);
  return keys;
}

function getPassphrase(): string {
  // Try setup passphrase or prompt
  if (setup.passphrase) return setup.passphrase;
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

function q<T extends HTMLElement>(selector: string): T {
  const el = document.querySelector(selector);
  if (!el) throw new Error(`missing element: ${selector}`);
  return el as T;
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
  void navigator.serviceWorker.register("/sw.js");
}
