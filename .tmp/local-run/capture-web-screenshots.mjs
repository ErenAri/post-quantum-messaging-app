import fs from "node:fs/promises";
import playwrightCore from "./playwright/node_modules/playwright-core/index.js";

const { chromium } = playwrightCore;

const BASE_URL = "http://127.0.0.1:4173/";
const SCREENSHOTS_DIR = "C:/projects/post-quantum-messaging-app/Screenshots";
const PASS = "Passphrase123!";
const CHROME_CANDIDATES = [
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function log(step) {
  console.log(`[capture] ${step}`);
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

async function waitForVisible(page, selector, timeout = 30000) {
  await page.waitForSelector(selector, { state: "visible", timeout });
  await sleep(250);
}

async function ensureServerUrl(page) {
  const advanced = page.locator(".onb-advanced");
  if (await advanced.count()) {
    await advanced.evaluate((node) => {
      if (node instanceof HTMLDetailsElement) {
        node.open = true;
      }
    });
  }
  await waitForVisible(page, "#onb-server");
  await page.fill("#onb-server", "http://127.0.0.1:3000");
  await page.click("#onb-save-server");
  await sleep(250);
}

async function dismissShortcutSheet(page) {
  const close = page.locator("#shortcut-sheet-close");
  if (await close.count()) {
    await close.click().catch(() => {});
    await sleep(150);
  }
  await page.keyboard.press("Escape").catch(() => {});
  await sleep(100);
}

async function createAccount(page, userId, displayName) {
  log(`create account ${userId}`);
  await page.goto(BASE_URL, { waitUntil: "networkidle" });
  await ensureServerUrl(page);
  await page.click("#onb-create");
  await waitForVisible(page, "#onb-user");
  await page.fill("#onb-user", userId);
  await page.fill("#onb-name", displayName);
  await page.fill("#onb-pass", PASS);
  await page.fill("#onb-pass2", PASS);
  await page.click("#onb-go");
  await waitForVisible(page, "#workspace-settings", 90000);
  await dismissShortcutSheet(page);
}

async function startDirectChat(page, peerUserId) {
  log(`start direct chat ${peerUserId}`);
  await page.click("#workspace-new-chat");
  await waitForVisible(page, "#nc-peer");
  await page.fill("#nc-peer", peerUserId);
  await page.click("#nc-start");
  await waitForVisible(page, "#chat-input", 90000);
  await dismissShortcutSheet(page);
}

async function sendDirectMessage(page, text) {
  log(`send direct: ${text}`);
  await page.fill("#chat-input", text);
  await page.click("#chat-send");
  await sleep(1800);
}

async function createPrivateGroup(page, name) {
  log(`create group ${name}`);
  await page.click("#workspace-new-group");
  await waitForVisible(page, "#cg-name");
  await page.fill("#cg-name", name);
  await page.click("#cg-create");
  await waitForVisible(page, "#gc-input", 90000);
  await dismissShortcutSheet(page);
}

async function sendGroupMessage(page, text) {
  log(`send group: ${text}`);
  await page.fill("#gc-input", text);
  await page.click("#gc-send");
  await sleep(1800);
}

async function screenshot(page, filename) {
  log(`screenshot ${filename}`);
  await sleep(500);
  await page.screenshot({
    path: `${SCREENSHOTS_DIR}/${filename}`,
    fullPage: false,
  });
}

async function navigateView(page, view) {
  log(`navigate ${view.screen}`);
  await page.evaluate(async (nextView) => {
    const { navigateTo } = await import("/src/router.ts");
    navigateTo(nextView);
  }, view);
  await sleep(350);
}

async function main() {
  const executablePath = await firstExistingPath(CHROME_CANDIDATES);
  const stamp = Date.now().toString().slice(-6);
  const alice = `shots-alice-${stamp}`;
  const bob = `shots-bob-${stamp}`;

  const browser = await chromium.launch({
    headless: true,
    executablePath,
  });

  const onboardingContext = await browser.newContext({ viewport: { width: 1440, height: 960 } });
  const contextA = await browser.newContext({ viewport: { width: 1440, height: 960 } });
  const contextB = await browser.newContext({ viewport: { width: 1440, height: 960 } });

  const onboardingPage = await onboardingContext.newPage();
  const pageA = await contextA.newPage();
  const pageB = await contextB.newPage();

  await onboardingPage.goto(BASE_URL, { waitUntil: "networkidle" });
  await waitForVisible(onboardingPage, "#onb-create");
  await screenshot(onboardingPage, "01-onboarding.png");

  await createAccount(pageA, alice, "Alice");
  await createAccount(pageB, bob, "Bob");

  await startDirectChat(pageA, bob);
  await sendDirectMessage(pageA, "Hey Bob, the desktop shell is looking much calmer now.");
  await sendDirectMessage(pageA, "Take a look at the new thread spacing when you can.");

  await startDirectChat(pageB, alice);
  await sendDirectMessage(pageB, "Looks cleaner already. The header feels lighter too.");

  await pageA.waitForFunction(() => document.querySelectorAll(".bubble").length >= 3, { timeout: 20000 }).catch(() => {});
  await dismissShortcutSheet(pageA);
  await screenshot(pageA, "03-direct-chat.png");

  log("return to conversations");
  await pageA.goto(BASE_URL, { waitUntil: "networkidle" });
  await waitForVisible(pageA, "#workspace-new-group");
  await createPrivateGroup(pageA, "Research Crew");
  await sendGroupMessage(pageA, "Welcome to the private group.");
  await sendGroupMessage(pageA, "This thread should feel denser and less airy now.");
  await screenshot(pageA, "04-group-chat.png");

  log("return to conversations");
  await pageA.goto(BASE_URL, { waitUntil: "networkidle" });
  await waitForVisible(pageA, "#workspace-settings");
  await screenshot(pageA, "02-inbox.png");

  await pageA.click("#workspace-settings");
  await waitForVisible(pageA, "#set-name");
  await screenshot(pageA, "05-settings.png");

  await navigateView(pageA, { screen: "discovery" });
  await waitForVisible(pageA, "#disc-back", 30000);
  await screenshot(pageA, "06-discovery.png");

  await navigateView(pageA, { screen: "devices" });
  await waitForVisible(pageA, "#device-list", 30000);
  await sleep(1200);
  await screenshot(pageA, "07-devices.png");

  await navigateView(pageA, { screen: "server-info" });
  await waitForVisible(pageA, "#sinfo-body", 30000);
  await sleep(1500);
  await screenshot(pageA, "08-server-info.png");

  console.log(JSON.stringify({ alice, bob }, null, 2));
  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
