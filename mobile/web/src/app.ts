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
  type GroupMemberRecord,
  type IdentityLogItem,
  type DiscoveryMatchItem,
} from "./server";
import {
  DEFAULT_SETUP,
  hasLocalKeys,
  loadConversations,
  loadGroupConversations,
  readIdentityPin,
  loadKeys,
  loadSetup,
  markConversationRead,
  markGroupConversationRead,
  readCursor,
  saveKeys,
  saveSetup,
  upsertConversation,
  upsertGroupConversation,
  wipeLocalState,
  writeCursor,
  writeIdentityPin,
  type ConversationSummary,
  type GroupConversationSummary,
} from "./storage";
import {
  saveMessage,
  updateMessageStatus,
  getMessages,
  clearAllMessages,
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
let peerPresenceCache: Record<string, { status: string; updated: number }> = {};

// Phase 3 state
let activeGroupId: string | null = null;
let cachedGroupMembers: Record<string, GroupMemberRecord[]> = {};

// Phase 4 state
let sealedSenderEnabled = false;
let sealedInboxCursor = 0;
let sealedInboxPollTimer: ReturnType<typeof setInterval> | null = null;

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
  }
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
      keys = genKeys;

      setProgress(progress, 100);
      status.textContent = "Ready!";
      notify(`Your User ID: ${userId} — share it with contacts`, "info");
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
      keys = loadedKeys;

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
  const convos = setup.userId ? loadConversations(setup.userId) : [];
  const groupConvos = setup.userId ? loadGroupConversations(setup.userId) : [];

  // Merge 1:1 and group conversations into a unified sorted list
  type UnifiedConvo = { type: "dm"; data: ConversationSummary } | { type: "group"; data: GroupConversationSummary };
  const unified: UnifiedConvo[] = [
    ...convos.map(c => ({ type: "dm" as const, data: c })),
    ...groupConvos.map(g => ({ type: "group" as const, data: g })),
  ].sort((a, b) => b.data.updatedAt - a.data.updatedAt);

  const listHtml = unified.length === 0
    ? renderEmptyState()
    : unified.map(u => u.type === "dm" ? renderConvoRow(u.data) : renderGroupConvoRow(u.data)).join("");

  app.innerHTML = `
    <div class="app-shell">
      <header class="topbar">
        <h1 class="topbar-title">PQMsg</h1>
        <div class="topbar-actions">
          <button id="conv-settings" class="icon-btn" title="Settings">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
            </svg>
          </button>
        </div>
      </header>
      <div class="shield-banner" id="shield-banner">
        <span class="shield-icon">🛡️</span>
        <span>Post-quantum encrypted — protected against future quantum computers</span>
        <button id="dismiss-banner" class="dismiss-btn">×</button>
      </div>
      <div class="conversation-list" id="conv-list">
        ${listHtml}
      </div>
      <button id="fab-new" class="fab" title="New chat">
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
  q("#conv-settings").addEventListener("click", () => navigateTo({ screen: "settings" }));

  // Bind conversation row clicks
  for (const row of document.querySelectorAll("[data-peer]")) {
    row.addEventListener("click", () => {
      const peerId = (row as HTMLElement).dataset.peer!;
      markConversationRead(setup.userId, peerId);
      navigateTo({ screen: "chat", peerId });
    });
  }

  // Bind group conversation row clicks
  for (const row of document.querySelectorAll("[data-group]")) {
    row.addEventListener("click", () => {
      const groupId = (row as HTMLElement).dataset.group!;
      markGroupConversationRead(setup.userId, groupId);
      navigateTo({ screen: "group-chat", groupId });
    });
  }

  // Start realtime connection & presence heartbeat
  connectRealtime();
  startPresenceHeartbeat();
  loadContactsBackground();

  // Start sealed inbox polling (Phase 4)
  if (!sealedInboxPollTimer) {
    void pollSealedInbox();
    sealedInboxPollTimer = setInterval(() => void pollSealedInbox(), 10000);
  }
}

function renderEmptyState(): string {
  return `
    <div class="empty-state">
      <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
        <rect width="80" height="80" rx="20" fill="#1a2d3d"/>
        <path d="M25 28h30v24H25z" fill="#2a4a5f"/>
        <circle cx="35" cy="40" r="5" fill="#4a9eff"/>
        <rect x="45" y="36" width="16" height="3" rx="1.5" fill="#4a9eff" opacity="0.7"/>
        <rect x="45" y="42" width="12" height="3" rx="1.5" fill="#4a9eff" opacity="0.4"/>
      </svg>
      <h2>No conversations yet</h2>
      <p>Tap the button below to start a new chat</p>
    </div>
  `;
}

function renderConvoRow(c: ConversationSummary): string {
  const contact = cachedContacts.find(ct => ct.contact_user_id === c.peerUserId);
  const displayName = contact?.alias || c.peerUserId;
  const initials = displayName.slice(0, 2).toUpperCase();
  const unread = c.unreadCount > 0 ? `<span class="badge">${c.unreadCount > 99 ? "99+" : c.unreadCount}</span>` : "";
  const boldClass = c.unreadCount > 0 ? " unread" : "";
  const time = relativeTime(c.updatedAt);
  const presence = peerPresenceCache[c.peerUserId];
  const presenceDot = presence && presence.status !== "offline"
    ? `<span class="presence-dot presence-${escHtml(presence.status)}"></span>` : "";
  return `
    <div class="conv-row${boldClass}" data-peer="${escHtml(c.peerUserId)}">
      <div class="avatar-wrap">
        <div class="avatar">${initials}</div>
        ${presenceDot}
      </div>
      <div class="conv-info">
        <div class="conv-top">
          <span class="conv-name">${escHtml(displayName)}</span>
          <span class="conv-time">${time}</span>
        </div>
        <div class="conv-bottom">
          <span class="conv-preview">${escHtml(c.lastPreview)}</span>
          ${unread}
        </div>
      </div>
    </div>
  `;
}

function renderGroupConvoRow(g: GroupConversationSummary): string {
  const initials = g.groupId.slice(0, 2).toUpperCase();
  const unread = g.unreadCount > 0 ? `<span class="badge">${g.unreadCount > 99 ? "99+" : g.unreadCount}</span>` : "";
  const boldClass = g.unreadCount > 0 ? " unread" : "";
  const time = relativeTime(g.updatedAt);
  return `
    <div class="conv-row${boldClass}" data-group="${escHtml(g.groupId)}">
      <div class="avatar-wrap">
        <div class="avatar avatar-group">${initials}</div>
      </div>
      <div class="conv-info">
        <div class="conv-top">
          <span class="conv-name">${escHtml(g.groupId)}</span>
          <span class="conv-time">${time}</span>
        </div>
        <div class="conv-bottom">
          <span class="conv-preview">${escHtml(g.lastPreview)}</span>
          ${unread}
        </div>
      </div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// 3. Chat view
// ---------------------------------------------------------------------------

async function renderChat(peerId: string): Promise<void> {
  const contact = cachedContacts.find(ct => ct.contact_user_id === peerId);
  const displayName = contact?.alias || peerId;
  const presence = peerPresenceCache[peerId];
  const presenceText = presence?.status === "online" ? "online" : presence?.status === "away" ? "away" : "encrypted";
  const presenceClass = presence?.status === "online" ? "presence-online" : presence?.status === "away" ? "presence-away" : "";

  app.innerHTML = `
    <div class="chat-shell">
      <header class="chat-header">
        <button id="chat-back" class="icon-btn">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <div class="avatar-wrap">
          <div class="avatar avatar-sm">${displayName.slice(0, 2).toUpperCase()}</div>
          ${presenceClass ? `<span class="presence-dot ${presenceClass}"></span>` : ""}
        </div>
        <div class="chat-header-info">
          <span class="chat-header-name">${escHtml(displayName)}</span>
          <span class="chat-header-status ${presenceClass}" id="chat-status">${presenceText}</span>
        </div>
        <div class="chat-header-shield" title="Post-quantum encrypted">🛡️</div>
      </header>
      <div id="typing-indicator" class="typing-indicator hidden">
        <span class="typing-dots"><span></span><span></span><span></span></span>
        <span class="typing-text">${escHtml(displayName)} is typing</span>
      </div>
      <div class="messages-container" id="messages-container">
        <div class="messages" id="messages-list"></div>
      </div>
      <div class="chat-options-bar">
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
        <button id="chat-attach" class="icon-btn attach-btn" title="Attach file">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48"/>
          </svg>
        </button>
        <input id="chat-input" type="text" placeholder="Message" autocomplete="off" />
        <button id="chat-send" class="send-btn" disabled>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor">
            <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
          </svg>
        </button>
        <input id="file-input" type="file" class="hidden" />
      </div>
    </div>
  `;

  const msgList = q("#messages-list");
  const container = q("#messages-container");
  const input = q<HTMLInputElement>("#chat-input");
  const sendBtn = q<HTMLButtonElement>("#chat-send");

  q("#chat-back").addEventListener("click", () => {
    activeChatPeer = null;
    stopChatTimers();
    navigateTo({ screen: "conversations" });
  });

  // Enable send when input has content
  input.addEventListener("input", () => {
    sendBtn.disabled = !input.value.trim();
    sendTypingIndicator(peerId, true);
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !sendBtn.disabled) {
      sendBtn.click();
    }
  });

  // Send message with optimistic UI
  sendBtn.addEventListener("click", async () => {
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    sendBtn.disabled = true;

    const useSealed = (document.getElementById("opt-sealed") as HTMLInputElement)?.checked ?? false;
    const ephTtl = Number((document.getElementById("opt-ephemeral") as HTMLSelectElement)?.value ?? 0);

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
    };

    // Optimistic: show immediately
    await saveMessage(msg);
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
      updateBubbleStatus(tempId, "sent");
    } catch (e) {
      await updateMessageStatus(tempId, "failed");
      updateBubbleStatus(tempId, "failed");
      notify(`Send failed: ${errorMsg(e)}`, "error");
    }
  });

  // File attachment handler
  const fileInput = q<HTMLInputElement>("#file-input");
  q("#chat-attach").addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    if (file.size > 1_000_000) {
      notify("File too large (max 1 MB)", "error");
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
      };
      await saveMessage(msg);
      appendBubble(msgList, msg, container);
      upsertConversation(setup.userId, peerId, `You: ${file.name}`, false);
      notify("File uploaded", "success");
    } catch (e) {
      notify(`Upload failed: ${errorMsg(e)}`, "error");
    }
    fileInput.value = "";
  });

  // Message deletion via context menu (right-click / long-press)
  msgList.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const bubble = (e.target as HTMLElement).closest(".bubble-sent") as HTMLElement | null;
    if (!bubble) return;
    const serverMid = bubble.getAttribute("data-server-mid");
    if (!serverMid) return;
    showDeleteConfirm(bubble, Number(serverMid));
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

function appendBubbleElement(container: HTMLElement, msg: StoredMessage): void {
  const isMine = msg.sender === setup.userId;
  const bubble = document.createElement("div");
  bubble.className = `bubble ${isMine ? "bubble-sent" : "bubble-received"}`;
  bubble.id = `msg-${msg.id}`;
  bubble.setAttribute("data-date", new Date(msg.timestamp).toLocaleDateString());
  if (msg.serverMessageId) {
    bubble.setAttribute("data-server-mid", String(msg.serverMessageId));
  }

  const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const statusIcon = isMine ? statusSvg(msg.status) : "";

  bubble.innerHTML = `
    <div class="bubble-text">${escHtml(msg.text)}</div>
    <div class="bubble-meta">
      <span class="bubble-time">${time}</span>
      ${statusIcon}
    </div>
  `;

  container.appendChild(bubble);
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
    const name = c.alias || c.contact_user_id;
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
        <button id="nc-back" class="icon-btn">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">New Chat</h1>
      </header>
      <div class="new-chat-body">
        ${cachedContacts.length > 0 ? `
          <div class="contacts-section">
            <h3 class="section-label">Contacts</h3>
            <div class="contacts-list">${contactRows}</div>
          </div>
          <div class="divider-or"><span>or enter user ID</span></div>
        ` : ""}
        <label class="field">
          <span>User ID</span>
          <input id="nc-peer" type="text" placeholder="Enter user ID to chat with" autocomplete="off" />
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
    if (!peer) { peerInput.focus(); return; }
    if (peer === setup.userId) {
      notify("You can't chat with yourself", "error");
      return;
    }
    // Auto-add as contact if not in list
    void addContactSilent(peer);
    upsertConversation(setup.userId, peer, "New conversation", false);
    markConversationRead(setup.userId, peer);
    navigateTo({ screen: "chat", peerId: peer });
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
        <button id="gc-back" class="icon-btn">
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
        <button id="gc-info" class="icon-btn" title="Group info">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>
          </svg>
        </button>
        <div class="chat-header-shield" title="Post-quantum encrypted">🛡️</div>
      </header>
      <div class="messages-container" id="messages-container">
        <div class="messages" id="messages-list"></div>
      </div>
      <div class="chat-input-bar">
        <input id="gc-input" type="text" placeholder="Message to group" autocomplete="off" />
        <button id="gc-send" class="send-btn" disabled>
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

  q("#gc-back").addEventListener("click", () => {
    activeGroupId = null;
    navigateTo({ screen: "conversations" });
  });
  q("#gc-info").addEventListener("click", () => navigateTo({ screen: "group-info", groupId }));

  input.addEventListener("input", () => { sendBtn.disabled = !input.value.trim(); });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !sendBtn.disabled) sendBtn.click(); });

  sendBtn.addEventListener("click", async () => {
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    sendBtn.disabled = true;

    const tempId = `local-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const msg: StoredMessage = {
      id: tempId,
      conversationId: `group:${groupId}`,
      sender: setup.userId,
      recipient: groupId,
      text,
      timestamp: Date.now(),
      status: "sending",
    };

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
  });

  // Load group message history
  const history = await getMessages(`group:${groupId}`);
  renderMessageList(msgList, history);
  scrollToBottom(container);
  input.focus();

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
        <button id="gi-back" class="icon-btn">
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
        <button id="cg-back" class="icon-btn">
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
        <button id="set-back" class="icon-btn">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M19 12H5M12 19l-7-7 7-7"/>
          </svg>
        </button>
        <h1 class="topbar-title">Settings</h1>
      </header>
      <div class="settings-body">
        <div class="settings-section">
          <h3>Profile</h3>
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
          <h3>Contacts</h3>
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
          <h3>Security</h3>
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
          <h3>Prekey Health</h3>
          <div id="prekey-status"><p class="text-secondary">Loading…</p></div>
        </div>
        <div class="settings-section">
          <h3>Discovery</h3>
          <p class="text-secondary settings-desc">Let contacts find you by phone or email hash.</p>
          <div class="settings-row">
            <button id="set-discovery" class="btn-sm">🔍 Contact Discovery</button>
          </div>
        </div>
        <div class="settings-section">
          <h3>Push Notifications</h3>
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
          <h3>Server</h3>
          <div class="settings-row">
            <button id="set-server-info" class="btn-sm">📊 Server Info</button>
          </div>
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
    if (envelope.recipient !== k.userId) return;

    const passphrase = getPassphrase();
    const plaintext = await decryptFallbackMessage(passphrase, envelope);

    const cid = convId(k.userId, wsMsg.sender_user_id);
    const msg: StoredMessage = {
      id: `srv-${wsMsg.message_id}`,
      conversationId: cid,
      sender: wsMsg.sender_user_id,
      recipient: k.userId,
      text: plaintext,
      timestamp: new Date(wsMsg.received_at).getTime() || Date.now(),
      status: "delivered",
      serverMessageId: wsMsg.message_id,
    };
    await saveMessage(msg);

    // Send delivered receipt
    void sendDeliveredReceipt(wsMsg.message_id);

    const isActivePeer = activeChatPeer === wsMsg.sender_user_id;
    upsertConversation(k.userId, wsMsg.sender_user_id, `${wsMsg.sender_user_id}: ${plaintext}`, !isActivePeer);

    // Update cursor
    const cursor = readCursor(k.userId);
    if (wsMsg.message_id > cursor) {
      writeCursor(k.userId, wsMsg.message_id);
    }

    // If in chat with this sender, append bubble live
    if (isActivePeer) {
      markConversationRead(k.userId, wsMsg.sender_user_id);
      const msgList = document.getElementById("messages-list");
      const container = document.getElementById("messages-container");
      if (msgList && container) {
        appendBubble(msgList, msg, container);
      }
    } else {
      // Not in this chat — show notification
      notify(`${wsMsg.sender_user_id}: ${plaintext.slice(0, 50)}`, "info");
    }
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
    for (const message of inbox.messages) {
      cursor = Math.max(cursor, message.message_id);
      try {
        const envelope = decodeWireEnvelopeBase64(message.message_bytes_base64);
        if (envelope.recipient !== k.userId) continue;
        const plaintext = await decryptFallbackMessage(passphrase, envelope);

        const cid = convId(k.userId, message.sender_user_id);
        const existing = await getMessages(cid);
        const alreadyStored = existing.some(m => m.serverMessageId === message.message_id);
        if (alreadyStored) continue;

        const msg: StoredMessage = {
          id: `srv-${message.message_id}`,
          conversationId: cid,
          sender: message.sender_user_id,
          recipient: k.userId,
          text: plaintext,
          timestamp: new Date(message.received_at).getTime() || Date.now(),
          status: "delivered",
          serverMessageId: message.message_id,
        };
        await saveMessage(msg);

        const isActivePeer = activeChatPeer === message.sender_user_id;
        upsertConversation(k.userId, message.sender_user_id, `${message.sender_user_id}: ${plaintext}`, !isActivePeer);

        if (isActivePeer) {
          markConversationRead(k.userId, message.sender_user_id);
          const msgList = document.getElementById("messages-list");
          const container = document.getElementById("messages-container");
          if (msgList && container) {
            appendBubble(msgList, msg, container);
          }
        }
      } catch {
        // Skip un-decryptable messages
      }
    }
    writeCursor(k.userId, cursor);
  } catch {
    // Silent failure for background polling
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
    cachedContacts = res.contacts;
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
        <button id="idlog-back" class="icon-btn">
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
        upsertConversation(k.userId, senderId, plaintext, true);
        sealedInboxCursor = Math.max(sealedInboxCursor, Number(msgId) || sealedInboxCursor + 1);
      } catch {
        // Skip malformed sealed messages
      }
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
    void loadContactsBackground();
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
        <button id="disc-back" class="icon-btn">
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
        <button id="sinfo-back" class="icon-btn">
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
