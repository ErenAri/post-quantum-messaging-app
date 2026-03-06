import "./styles.css";
import {
  buildLinkDeviceAuthHeaders,
  buildListDevicesAuthHeaders,
  buildRevokeDeviceAuthHeaders,
  buildRetireDeviceAuthHeaders,
  buildInboxAuthHeaders,
  buildPrekeysAuthHeaders,
  buildPublishPrekeysPayload,
  buildRelayAuthHeaders,
  decodeWireEnvelopeBase64,
  decryptFallbackMessage,
  encryptFallbackMessage,
  encodeWireEnvelopeBase64,
  generateIdentityKeys,
  identityFingerprint
} from "./crypto";
import {
  PqmsgApi,
  type DeviceListResponse,
  type ServerCapabilitiesResponse
} from "./server";
import {
  DEFAULT_SETUP,
  hasLocalKeys,
  listIdentityPins,
  loadConversations,
  readIdentityPin,
  loadKeys,
  loadSetup,
  markConversationRead,
  readCursor,
  saveKeys,
  saveSetup,
  upsertConversation,
  wipeLocalState,
  writeCursor,
  writeIdentityPin,
  type SetupConfig
} from "./storage";

const appRoot = document.getElementById("app");
if (!appRoot) {
  throw new Error("missing #app element");
}

appRoot.innerHTML = `
<main class="layout">
  <header class="hero">
    <h1>PQMsg Web Demo</h1>
    <p>Progressive Web App shell with WebCrypto fallback mode and authenticated server relay.</p>
  </header>
  <section class="grid">
    <article class="card">
      <h2>Setup</h2>
      <div class="row">
        <button id="presetAlice">Preset Alice</button>
        <button id="presetBob">Preset Bob</button>
      </div>
      <label>Server URL<input id="serverUrl" type="text" /></label>
      <label>User ID<input id="userId" type="text" /></label>
      <label>Device ID<input id="deviceId" type="text" /></label>
      <label>Suite
        <select id="suiteLabel">
          <option value="ml-kem-768">ml-kem-768</option>
          <option value="kyber768">kyber768</option>
        </select>
      </label>
      <label>Peer User ID<input id="peerUserId" type="text" /></label>
      <label>Passphrase<input id="passphrase" type="password" /></label>
      <div class="row">
        <button id="keygen">Generate Keys</button>
        <button id="registerUser">Register User</button>
      </div>
      <div class="row">
        <button id="publishPrekeys">Publish Prekeys</button>
        <button id="fetchBundle">Fetch Bundle</button>
      </div>
      <label>Managed Device ID<input id="managedDeviceId" type="text" placeholder="alice-web-2" /></label>
      <div class="row">
        <button id="listDevices">List Devices</button>
        <button id="linkDevice">Link Device</button>
        <button id="revokeDevice">Revoke Device</button>
      </div>
      <div class="row">
        <button id="resetLocalState">Reset Local State</button>
      </div>
    </article>
    <article class="card">
      <h2>Chat</h2>
      <label>Message<input id="messageInput" type="text" /></label>
      <div class="row">
        <button id="sendMessage">Send Encrypted</button>
        <button id="pollInbox">Poll Inbox</button>
      </div>
      <h3>Conversations</h3>
      <div id="conversationList" class="list"></div>
      <h3>Log</h3>
      <pre id="chatLog" class="log"></pre>
    </article>
    <article class="card">
      <h2>Security Snapshot</h2>
      <div id="securitySnapshot" class="snapshot"></div>
      <h3>Status</h3>
      <p id="statusLine"></p>
      <p id="errorLine" class="error"></p>
    </article>
  </section>
</main>
`;

let setup = loadSetup();
let lastFetchedBundle: {
  userId: string;
  identitySigPub: string;
  fingerprint: string;
  observedAt: string;
  identityVersion: number;
} | null = null;
let lastCapabilities: ServerCapabilitiesResponse | null = null;
let lastDeviceList: DeviceListResponse | null = null;

const elements = {
  serverUrl: byId<HTMLInputElement>("serverUrl"),
  userId: byId<HTMLInputElement>("userId"),
  deviceId: byId<HTMLInputElement>("deviceId"),
  managedDeviceId: byId<HTMLInputElement>("managedDeviceId"),
  suiteLabel: byId<HTMLSelectElement>("suiteLabel"),
  peerUserId: byId<HTMLInputElement>("peerUserId"),
  passphrase: byId<HTMLInputElement>("passphrase"),
  messageInput: byId<HTMLInputElement>("messageInput"),
  statusLine: byId<HTMLElement>("statusLine"),
  errorLine: byId<HTMLElement>("errorLine"),
  chatLog: byId<HTMLElement>("chatLog"),
  conversationList: byId<HTMLElement>("conversationList"),
  securitySnapshot: byId<HTMLElement>("securitySnapshot")
};

bindSetupInputs();
bindActions();
renderAll();
registerServiceWorker();

function bindSetupInputs(): void {
  elements.serverUrl.value = setup.serverUrl;
  elements.userId.value = setup.userId;
  elements.deviceId.value = setup.deviceId;
  elements.suiteLabel.value = setup.suiteLabel;
  elements.peerUserId.value = setup.peerUserId;

  const onInput = (): void => {
    setup = {
      serverUrl: elements.serverUrl.value.trim() || DEFAULT_SETUP.serverUrl,
      userId: elements.userId.value.trim(),
      deviceId: elements.deviceId.value.trim(),
      suiteLabel: normalizeSuite(elements.suiteLabel.value),
      peerUserId: elements.peerUserId.value.trim() || DEFAULT_SETUP.peerUserId
    };
    lastCapabilities = null;
    lastDeviceList = null;
    saveSetup(setup);
    renderSecuritySnapshot();
  };

  elements.serverUrl.addEventListener("input", onInput);
  elements.userId.addEventListener("input", onInput);
  elements.deviceId.addEventListener("input", onInput);
  elements.suiteLabel.addEventListener("change", onInput);
  elements.peerUserId.addEventListener("input", onInput);
}

function bindActions(): void {
  byId<HTMLButtonElement>("presetAlice").addEventListener("click", () => {
    applyPreset("alice", "bob");
  });
  byId<HTMLButtonElement>("presetBob").addEventListener("click", () => {
    applyPreset("bob", "alice");
  });
  byId<HTMLButtonElement>("keygen").addEventListener("click", () => {
    runAction("Generate keys", actionGenerateKeys);
  });
  byId<HTMLButtonElement>("registerUser").addEventListener("click", () => {
    runAction("Register user", actionRegisterUser);
  });
  byId<HTMLButtonElement>("publishPrekeys").addEventListener("click", () => {
    runAction("Publish prekeys", actionPublishPrekeys);
  });
  byId<HTMLButtonElement>("fetchBundle").addEventListener("click", () => {
    runAction("Fetch bundle", actionFetchBundle);
  });
  byId<HTMLButtonElement>("listDevices").addEventListener("click", () => {
    runAction("List devices", actionListDevices);
  });
  byId<HTMLButtonElement>("linkDevice").addEventListener("click", () => {
    runAction("Link device", actionLinkDevice);
  });
  byId<HTMLButtonElement>("revokeDevice").addEventListener("click", () => {
    runAction("Revoke device", actionRevokeDevice);
  });
  byId<HTMLButtonElement>("sendMessage").addEventListener("click", () => {
    runAction("Send message", actionSendMessage);
  });
  byId<HTMLButtonElement>("pollInbox").addEventListener("click", () => {
    runAction("Poll inbox", actionPollInbox);
  });
  byId<HTMLButtonElement>("resetLocalState").addEventListener("click", () => {
    runAction("Reset local state", actionResetLocalState);
  });
}

async function actionGenerateKeys(): Promise<void> {
  requireNonEmpty(setup.userId, "user id is empty");
  const deviceId = setup.deviceId || `${setup.userId}-web-1`;
  const keys = generateIdentityKeys(setup.userId, deviceId, setup.suiteLabel, 16);
  const passphrase = requirePassphrase();
  await saveKeys(setup.userId, passphrase, keys);
  setup.deviceId = deviceId;
  saveSetup(setup);
  setStatus(`Generated keys for ${setup.userId} (${deviceId})`);
  renderSecuritySnapshot();
}

async function actionRegisterUser(): Promise<void> {
  const keys = await readKeys();
  const api = new PqmsgApi(setup.serverUrl);
  await ensureServerCompatibleForWeb(api);
  await api.registerUser({
    user_id: keys.userId,
    identity_x25519_pub: keys.identityX25519Pub,
    identity_sig_pub: keys.identitySigPub,
    device_id: keys.deviceId
  });
  setStatus(`Registered ${keys.userId}`);
}

async function actionPublishPrekeys(): Promise<void> {
  const keys = await readKeys();
  const api = new PqmsgApi(setup.serverUrl);
  await ensureServerCompatibleForWeb(api);
  const payload = buildPublishPrekeysPayload(keys);
  const headers = buildPrekeysAuthHeaders(keys, payload);
  await api.publishPrekeys(keys.userId, payload, headers);
  setStatus(`Published prekeys for ${keys.userId}`);
}

async function actionFetchBundle(): Promise<void> {
  requireNonEmpty(setup.peerUserId, "peer user id is empty");
  const api = new PqmsgApi(setup.serverUrl);
  await ensureServerCompatibleForWeb(api);
  const bundle = await api.getBundle(setup.peerUserId);
  const fingerprint = bundle.identity_fingerprint_sha256 || identityFingerprint(bundle.identity_x25519_pub);
  lastFetchedBundle = {
    userId: bundle.user_id,
    identitySigPub: bundle.identity_sig_pub,
    fingerprint,
    observedAt: bundle.bundle_generated_at,
    identityVersion: bundle.identity_key_version
  };
  enforceIdentityPin(bundle.user_id, bundle.identity_sig_pub, fingerprint, bundle.identity_key_version, bundle.bundle_generated_at);
  upsertConversation(setup.userId, setup.peerUserId, `Bundle fetched for ${setup.peerUserId}`, false);
  renderConversations();
  setStatus(`Fetched bundle for ${setup.peerUserId}`);
}

async function actionSendMessage(): Promise<void> {
  const message = elements.messageInput.value.trim();
  requireNonEmpty(message, "message is empty");
  const keys = await readKeys();
  const api = new PqmsgApi(setup.serverUrl);
  await ensureServerCompatibleForWeb(api);
  if (!lastFetchedBundle || lastFetchedBundle.userId !== setup.peerUserId) {
    await actionFetchBundle();
  }
  const passphrase = requirePassphrase();
  const envelope = await encryptFallbackMessage(passphrase, keys.userId, setup.peerUserId, message);
  const messageBytesBase64 = encodeWireEnvelopeBase64(envelope);
  const headers = buildRelayAuthHeaders(keys, setup.peerUserId, messageBytesBase64);
  const relay = await api.relay(
    setup.peerUserId,
    {
      sender_user_id: keys.userId,
      device_id: keys.deviceId,
      message_bytes_base64: messageBytesBase64
    },
    headers
  );
  appendLog(`me->${setup.peerUserId}: ${message} [message_id=${relay.message_id}]`);
  upsertConversation(setup.userId, setup.peerUserId, `You: ${message}`, false);
  markConversationRead(setup.userId, setup.peerUserId);
  renderConversations();
  elements.messageInput.value = "";
  setStatus("Encrypted message sent");
}

async function actionPollInbox(): Promise<void> {
  const keys = await readKeys();
  const api = new PqmsgApi(setup.serverUrl);
  await ensureServerCompatibleForWeb(api);
  const since = readCursor(keys.userId);
  const headers = buildInboxAuthHeaders(keys, since);
  const inbox = await api.inbox(keys.userId, since, headers);
  if (inbox.messages.length === 0) {
    appendLog("inbox empty");
    setStatus("Inbox polling completed");
    return;
  }
  let cursor = since;
  const passphrase = requirePassphrase();
  for (const message of inbox.messages) {
    cursor = Math.max(cursor, message.message_id);
    try {
      const envelope = decodeWireEnvelopeBase64(message.message_bytes_base64);
      if (envelope.recipient !== keys.userId) {
        appendLog(`ignored message for recipient ${envelope.recipient}`);
        continue;
      }
      const plaintext = await decryptFallbackMessage(passphrase, envelope);
      appendLog(`${message.sender_user_id}: ${plaintext}`);
      const incrementUnread = message.sender_user_id !== setup.peerUserId;
      upsertConversation(
        keys.userId,
        message.sender_user_id,
        `${message.sender_user_id}: ${plaintext}`,
        incrementUnread
      );
      if (!incrementUnread) {
        markConversationRead(keys.userId, message.sender_user_id);
      }
    } catch (error) {
      appendLog(`decrypt failed for ${message.sender_user_id}: ${toError(error)}`);
    }
  }
  writeCursor(keys.userId, cursor);
  renderConversations();
  setStatus("Inbox polling completed");
}

async function actionListDevices(): Promise<void> {
  const api = new PqmsgApi(setup.serverUrl);
  await ensureServerCompatibleForWeb(api);
  const keys = await readKeys();
  const response = await api.listDevices(keys.userId, buildListDevicesAuthHeaders(keys));
  lastDeviceList = response;
  renderSecuritySnapshot();
  setStatus(`Loaded ${response.devices.length} device record(s) for ${response.user_id}`);
}

async function actionLinkDevice(): Promise<void> {
  const newDeviceId = requireNonEmpty(elements.managedDeviceId.value, "managed device id is empty");
  const api = new PqmsgApi(setup.serverUrl);
  await ensureServerCompatibleForWeb(api);
  const keys = await readKeys();
  if (newDeviceId === keys.deviceId) {
    throw new Error("managed device id must differ from the authenticated device id");
  }
  const response = await api.linkDevice(
    keys.userId,
    newDeviceId,
    buildLinkDeviceAuthHeaders(keys, newDeviceId)
  );
  await actionListDevices();
  setStatus(`Linked device ${response.linked_device_id} for ${response.user_id}`);
}

async function actionRevokeDevice(): Promise<void> {
  const targetDeviceId = requireNonEmpty(
    elements.managedDeviceId.value,
    "managed device id is empty"
  );
  const api = new PqmsgApi(setup.serverUrl);
  await ensureServerCompatibleForWeb(api);
  const keys = await readKeys();
  if (targetDeviceId === keys.deviceId) {
    throw new Error("managed device id matches the current device; use Reset Local State for self-retirement");
  }
  const response = await api.revokeDevice(
    keys.userId,
    targetDeviceId,
    buildRevokeDeviceAuthHeaders(keys, targetDeviceId)
  );
  await actionListDevices();
  setStatus(`Revoked device ${response.revoked_device_id} for ${response.user_id}`);
}

async function actionResetLocalState(): Promise<void> {
  const userId = requireNonEmpty(setup.userId, "user id is empty");
  const accepted = window.confirm(
    `Retire the current device on the server when possible, then delete local keys, pins, cursors, and conversation metadata for ${userId} in this browser?`
  );
  if (!accepted) {
    setStatus("Local reset cancelled");
    return;
  }

  let retiredDeviceId: string | null = null;
  if (hasLocalKeys(userId)) {
    const api = new PqmsgApi(setup.serverUrl);
    await ensureServerCompatibleForWeb(api);
    const keys = await readKeys();
    if (keys.userId !== userId) {
      throw new Error(`user mismatch: current input '${userId}' vs stored keys '${keys.userId}'`);
    }
    const response = await api.retireCurrentDevice(userId, buildRetireDeviceAuthHeaders(keys));
    if (response.user_id !== userId) {
      throw new Error(`retire response user mismatch: expected '${userId}' got '${response.user_id}'`);
    }
    if (response.retired_device_id !== keys.deviceId) {
      throw new Error(
        `retire response device mismatch: expected '${keys.deviceId}' got '${response.retired_device_id}'`
      );
    }
    retiredDeviceId = response.retired_device_id;
  }

  wipeLocalState(userId);
  setup = {
    ...DEFAULT_SETUP,
    serverUrl: setup.serverUrl,
    suiteLabel: setup.suiteLabel
  };
  saveSetup(setup);
  elements.serverUrl.value = setup.serverUrl;
  elements.userId.value = setup.userId;
  elements.deviceId.value = setup.deviceId;
  elements.suiteLabel.value = setup.suiteLabel;
  elements.peerUserId.value = setup.peerUserId;
  elements.passphrase.value = "";
  elements.messageInput.value = "";
  lastFetchedBundle = null;
  lastCapabilities = null;
  lastDeviceList = null;
  elements.chatLog.textContent = "No messages yet";
  renderAll();
  if (retiredDeviceId) {
    setStatus(`Retired ${retiredDeviceId} and cleared local state for ${userId}`);
  } else {
    setStatus(`Cleared local state for ${userId}`);
  }
}

function applyPreset(userId: string, peerUserId: string): void {
  setup.userId = userId;
  setup.peerUserId = peerUserId;
  setup.deviceId = `${userId}-web-1`;
  elements.managedDeviceId.value = `${userId}-web-2`;
  elements.userId.value = setup.userId;
  elements.peerUserId.value = setup.peerUserId;
  elements.deviceId.value = setup.deviceId;
  saveSetup(setup);
  renderAll();
}

async function readKeys() {
  requireNonEmpty(setup.userId, "user id is empty");
  const passphrase = requirePassphrase();
  return loadKeys(setup.userId, passphrase);
}

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
      observedAt
    });
    return;
  }
  if (existing.fingerprintSha256 === fingerprint) {
    return;
  }
  const accepted = window.confirm(
    `Identity changed for ${peerUserId}\n\nOld: ${existing.fingerprintSha256}\nNew: ${fingerprint}\n\nTrust new key?`
  );
  if (!accepted) {
    throw new Error(`identity changed for ${peerUserId}; action blocked`);
  }
  writeIdentityPin(setup.userId, peerUserId, {
    fingerprintSha256: fingerprint,
    identityKeyVersion: identityVersion,
    identitySigPub,
    observedAt
  });
}

function renderAll(): void {
  renderConversations();
  renderSecuritySnapshot();
  if (!elements.chatLog.textContent) {
    elements.chatLog.textContent = "No messages yet";
  }
  setStatus("Ready");
}

function renderConversations(): void {
  if (!setup.userId) {
    elements.conversationList.innerHTML = "<p>No conversations</p>";
    return;
  }
  const list = loadConversations(setup.userId);
  if (list.length === 0) {
    elements.conversationList.innerHTML = "<p>No conversations</p>";
    return;
  }
  const rows = list.map((item) => {
    const unread = item.unreadCount > 0 ? ` <strong>[${item.unreadCount}]</strong>` : "";
    return `<div class="conversation"><span>${escapeHtml(item.peerUserId)}</span><small>${escapeHtml(item.lastPreview)}${unread}</small></div>`;
  });
  elements.conversationList.innerHTML = rows.join("");
}

function renderSecuritySnapshot(): void {
  const pins = setup.userId ? listIdentityPins(setup.userId) : [];
  const pinRows = pins.length
    ? pins
        .map(
          (item) =>
            `<li><code>${escapeHtml(item.peerUserId)}</code> ${escapeHtml(item.pin.fingerprintSha256)}</li>`
        )
        .join("")
    : "<li>none</li>";
  const payload = {
    client_mode: "webcrypto-fallback-v1",
    request_auth: "ed25519",
    transport: "http/local-dev or https",
    key_storage: "sealed localStorage via WebCrypto AES-256-GCM",
    suite_label: setup.suiteLabel,
    interoperability: "web fallback mode is intended for web-to-web demo flows",
    server_capabilities: lastCapabilities
      ? {
          profile: lastCapabilities.security_profile,
          deployment_mode: lastCapabilities.deployment_mode,
          suite_id: lastCapabilities.runtime_crypto_profile.suite_id,
          web_client_policy: lastCapabilities.web_client_policy,
          production_baseline_met: lastCapabilities.production_baseline_met
        }
      : "not checked"
  };
  const deviceRows = lastDeviceList
    ? lastDeviceList.devices
        .map((item) => {
          const status = item.active ? "active" : `revoked at ${item.revoked_at ?? "unknown"}`;
          return `<li><code>${escapeHtml(item.device_id)}</code> ${escapeHtml(status)} (linked ${escapeHtml(item.linked_at)})</li>`;
        })
        .join("")
    : "<li>not checked</li>";
  elements.securitySnapshot.innerHTML = `
<pre>${escapeHtml(JSON.stringify(payload, null, 2))}</pre>
<h4>Pinned identities</h4>
<ul>${pinRows}</ul>
<h4>Linked devices</h4>
<ul>${deviceRows}</ul>`;
}

function appendLog(line: string): void {
  const current = elements.chatLog.textContent?.trim();
  if (!current || current === "No messages yet") {
    elements.chatLog.textContent = line;
    return;
  }
  elements.chatLog.textContent = `${current}\n${line}`;
}

function setStatus(line: string): void {
  elements.statusLine.textContent = line;
  elements.errorLine.textContent = "";
}

function setError(line: string): void {
  elements.errorLine.textContent = line;
}

function requireNonEmpty(value: string, message: string): string {
  if (!value.trim()) {
    throw new Error(message);
  }
  return value.trim();
}

function requirePassphrase(): string {
  return requireNonEmpty(elements.passphrase.value, "passphrase is empty");
}

function normalizeSuite(value: string): "ml-kem-768" | "kyber768" {
  return value === "kyber768" ? "kyber768" : "ml-kem-768";
}

function suiteIdForSetup(): number {
  return setup.suiteLabel === "kyber768" ? 2 : 1;
}

async function ensureServerCompatibleForWeb(
  api: PqmsgApi
): Promise<ServerCapabilitiesResponse> {
  const capabilities = await api.getCapabilities();
  lastCapabilities = capabilities;
  if (capabilities.capability_schema_version !== 1) {
    throw new Error(`Unsupported server capability schema ${capabilities.capability_schema_version}`);
  }
  if (!capabilities.supported_suite_ids.includes(suiteIdForSetup())) {
    throw new Error(`Server does not support suite '${setup.suiteLabel}'`);
  }
  if (capabilities.security_profile !== "research" && !capabilities.runtime_crypto_profile.pq_oqs_enabled) {
    throw new Error("Server is not running a PQ-enabled crypto backend");
  }
  if (capabilities.deployment_mode !== "development" && !capabilities.production_baseline_met) {
    throw new Error(
      `Server '${capabilities.deployment_mode}' deployment is missing its production baseline`
    );
  }
  if (
    capabilities.web_client_policy === "demo_only" &&
    capabilities.deployment_mode !== "development"
  ) {
    throw new Error("Web demo client is blocked against pilot/production servers");
  }
  renderSecuritySnapshot();
  return capabilities;
}

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`missing element #${id}`);
  }
  return element as T;
}

function runAction(label: string, action: () => Promise<void>): void {
  void action().catch((error: unknown) => {
    const message = `${label} failed: ${toError(error)}`;
    setError(message);
    appendLog(message);
  });
}

function toError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function registerServiceWorker(): void {
  if (!("serviceWorker" in navigator)) {
    return;
  }
  void navigator.serviceWorker.register("/sw.js");
}
