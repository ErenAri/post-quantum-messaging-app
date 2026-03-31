import fs from "node:fs/promises";
import { execFileSync } from "node:child_process";
import playwrightCore from "./playwright/node_modules/playwright-core/index.js";

const { chromium } = playwrightCore;

const BASE_URL = "http://127.0.0.1:4173/";
const CHROME_CANDIDATES = [
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
];
const PASS = "Passphrase123!";
const stamp = Date.now().toString().slice(-6);
const alice = `trace-alice-${stamp}`;
const bob = `trace-bob-${stamp}`;

function log(...args) {
  console.log("[trace]", ...args);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function loadLatestSealedMessageForUser(userId) {
  const python = [
    "import sqlite3,base64,json,sys",
    "user_id = sys.argv[1]",
    "conn = sqlite3.connect('pqmsg-server.db')",
    "cur = conn.cursor()",
    "cur.execute(\"select message_id, message_blob from sealed_relay_messages where recipient_user_id = ? order by message_id desc limit 1\", (user_id,))",
    "row = cur.fetchone()",
    "if row is None:",
    "    print(json.dumps(None))",
    "else:",
    "    mid, blob = row",
    "    print(json.dumps({'message_id': mid, 'message_b64': base64.b64encode(blob).decode('ascii')}))",
  ].join("\n");
  const stdout = execFileSync("python", ["-c", python, userId], {
    cwd: process.cwd(),
    encoding: "utf8",
  }).trim();
  return JSON.parse(stdout);
}

async function probeDirectOpen(page, label, userId, messageB64) {
  const result = await page.evaluate(async ({ userId, passphrase, messageB64 }) => {
    try {
      const [{ loadKeys }, { openTransportEnvelopeWithSenderCert }, { PqmsgApi }] = await Promise.all([
        import("/src/storage.ts"),
        import("/src/crypto.ts"),
        import("/src/server.ts"),
      ]);
      const keys = await loadKeys(userId, passphrase);
      const api = new PqmsgApi("http://127.0.0.1:3000");
      const capabilities = await api.getCapabilities();
      const opened = openTransportEnvelopeWithSenderCert(
        keys,
        null,
        messageB64,
        capabilities.sender_certificate_issuer_ed25519_pub,
      );
      return { ok: true, opened };
    } catch (error) {
      return {
        ok: false,
        name: error?.name || "",
        message: error?.message || String(error),
        stack: error?.stack || "",
      };
    }
  }, { userId, passphrase: PASS, messageB64 });
  console.log(`[${label}:probe] ${JSON.stringify(result)}`);
}

async function firstExistingPath(paths) {
  for (const candidate of paths) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {}
  }
  throw new Error(`No browser executable found. Checked: ${paths.join(", ")}`);
}

async function waitForAppReady(page, selector, timeout = 30000) {
  await page.waitForSelector(selector, { timeout });
  await sleep(300);
}

function attachNetworkLogging(page, label) {
  page.on("console", (msg) => console.log(`[${label}:console:${msg.type()}] ${msg.text()}`));
  page.on("pageerror", (error) => console.log(`[${label}:pageerror] ${error.message}`));
  page.on("response", async (response) => {
    if (response.status() < 400) return;
    const request = response.request();
    let body = "";
    try {
      body = await response.text();
    } catch {}
    console.log(
      `[${label}:http${response.status()}] ${request.method()} ${response.url()}\n` +
      `request-body=${request.postData() || ""}\nresponse-body=${body}\n`
    );
  });
}

async function dismissShortcutSheet(page) {
  const close = page.locator("#shortcut-sheet-close");
  if (await close.count()) {
    await close.click().catch(() => {});
    await sleep(200);
  }
  await page.keyboard.press("Escape").catch(() => {});
}

async function createAccount(page, userId, displayName) {
  await page.goto(BASE_URL, { waitUntil: "networkidle" });
  await waitForAppReady(page, "#onb-create");
  await page.click("#onb-create");
  await waitForAppReady(page, "#onb-user");
  await page.fill("#onb-user", userId);
  await page.fill("#onb-name", displayName);
  await page.fill("#onb-pass", PASS);
  await page.fill("#onb-pass2", PASS);
  await page.click("#onb-go");
  await waitForAppReady(page, "#workspace-settings", 90000);
  log(`created @${userId}`);
}

async function startDirectChat(page, peerUserId) {
  await page.click("#workspace-new-chat");
  await waitForAppReady(page, "#nc-peer");
  await page.fill("#nc-peer", peerUserId);
  await page.click("#nc-start");
  await waitForAppReady(page, "#chat-input", 90000);
  await dismissShortcutSheet(page);
}

async function sendMessage(page, text) {
  await page.fill("#chat-input", text);
  await page.click("#chat-send");
  await sleep(3500);
}

async function main() {
  const executablePath = await firstExistingPath(CHROME_CANDIDATES);
  const browser = await chromium.launch({ headless: true, executablePath });
  const contextA = await browser.newContext({ viewport: { width: 1440, height: 960 } });
  const contextB = await browser.newContext({ viewport: { width: 1440, height: 960 } });
  const pageA = await contextA.newPage();
  const pageB = await contextB.newPage();
  attachNetworkLogging(pageA, "alice");
  attachNetworkLogging(pageB, "bob");
  pageA.on("dialog", (dialog) => dialog.accept());
  pageB.on("dialog", (dialog) => dialog.accept());

  await createAccount(pageA, alice, "Alice");
  await createAccount(pageB, bob, "Bob");

  await startDirectChat(pageA, bob);
  await sendMessage(pageA, "hello from alice");
  const latestForBob = loadLatestSealedMessageForUser(bob);
  if (latestForBob?.message_b64) {
    await probeDirectOpen(pageB, "bob", bob, latestForBob.message_b64);
  }

  await startDirectChat(pageB, alice);
  await sendMessage(pageB, "hello from bob");
  const latestForAlice = loadLatestSealedMessageForUser(alice);
  if (latestForAlice?.message_b64) {
    await probeDirectOpen(pageA, "alice", alice, latestForAlice.message_b64);
  }

  await sleep(6000);
  await browser.close();
  console.log(JSON.stringify({ alice, bob }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
