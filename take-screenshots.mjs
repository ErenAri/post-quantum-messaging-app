import { chromium } from "playwright";

const BASE = "http://localhost:5173";
const DIR = "Screenshots";

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
const page = await context.newPage();

// Suppress shortcut overlay globally
await page.addInitScript(() => {
  new MutationObserver(() => {
    document.querySelectorAll('.shortcut-sheet').forEach(el => el.remove());
  }).observe(document.documentElement, { childList: true, subtree: true });
});

async function dismissShortcuts() {
  await page.evaluate(() => document.querySelectorAll('.shortcut-sheet').forEach(el => el.remove()));
}

async function shot(name) {
  await page.waitForTimeout(1500);
  await dismissShortcuts();
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${DIR}/${name}.png`, fullPage: false });
  console.log(`  ✓ ${name}`);
}

// 1. Onboarding
console.log("Taking screenshots...");
await page.goto(BASE);
await page.waitForTimeout(2000);
await shot("01-onboarding");

// Set server URL via Advanced
await page.click("summary:has-text('Advanced')");
await page.waitForTimeout(300);
await page.fill("details input[type='text']", "http://127.0.0.1:9090");
await page.click("details button:has-text('Save')");
await page.waitForTimeout(500);

// Create account
await page.click("button:has-text('Create Account')");
await page.waitForTimeout(500);
await page.fill("input[type='text']", `ss-${Date.now()}`);
const pwInputs = await page.locator("input[type='password']").all();
await pwInputs[0].fill("testpass123");
await pwInputs[1].fill("testpass123");
await page.click("button:has-text('Create Account')");
await page.waitForTimeout(8000);
await dismissShortcuts();

// 2. Inbox
await shot("02-inbox");

// 3. Direct chat - create a peer with prekeys and start chat
const peerId = `peer-${Date.now()}`;
await page.evaluate(async (userId) => {
  const crypto = await import('/src/crypto.ts');
  const { PqmsgApi } = await import('/src/server.ts');
  const keys = crypto.generateIdentityKeys(userId, `${userId}-dev`, 'ml-kem-768', 5);
  const api = new PqmsgApi('http://127.0.0.1:9090');
  await api.registerUser({
    user_id: userId,
    device_id: `${userId}-dev`,
    identity_x25519_pub: keys.identityX25519Pub,
    identity_sig_pub: keys.identitySigPub,
    identity_pq_sig_pub: keys.identityPqSigPub,
    display_name: 'Dave',
    suite_label: 'ml-kem-768',
  });
  const payload = crypto.buildPublishPrekeysPayload(keys);
  const authHeaders = crypto.buildPrekeysAuthHeaders(keys, payload);
  await api.publishPrekeys(userId, payload, authHeaders);
}, peerId);

await page.click("button:has-text('New chat')");
await page.waitForTimeout(1000);
await dismissShortcuts();
await page.fill("input[type='text']", peerId);
await page.click("button:has-text('Start Chat')");
await page.waitForTimeout(3000);
await dismissShortcuts();

// Send a direct message
try {
  const ta = page.locator("textarea").first();
  if (await ta.isVisible({ timeout: 2000 })) {
    await ta.fill("Hello Dave! This is a post-quantum encrypted message.");
    await page.waitForTimeout(500);
    await dismissShortcuts();
    await page.click("button[aria-label='Send message']", { timeout: 5000 });
    await page.waitForTimeout(3000);
  }
} catch { /* ignore */ }
await shot("03-direct-chat");

// 4. Group chat
await page.click("button:has-text('New group')");
await page.waitForTimeout(1000);
await dismissShortcuts();
await page.fill("input[type='text']", "PQ Research Group");
await page.click("button:has-text('Create Private Group')");
await page.waitForTimeout(5000);
await dismissShortcuts();

try {
  const ta = page.locator("textarea").first();
  if (await ta.isVisible({ timeout: 3000 })) {
    await ta.fill("Welcome to the post-quantum research group!");
    await page.waitForTimeout(500);
    await dismissShortcuts();
    await page.click("button[aria-label='Send message']", { timeout: 5000 });
    await page.waitForTimeout(2000);
  }
} catch { /* ignore */ }
await shot("04-group-chat");

// 5. Settings
await page.evaluate(() => {
  const btn = document.querySelector('#workspace-settings') ||
    document.querySelector('button[aria-label="Settings"]');
  if (btn) btn.click();
});
await page.waitForTimeout(2000);
await dismissShortcuts();
await shot("05-settings");

// 6. Discovery — scroll the .settings-body to show the discovery section
await page.evaluate(() => {
  const sb = document.querySelector('.settings-body');
  const el = document.querySelector('#set-discovery-top') ||
    [...document.querySelectorAll('h3')].find(h => h.textContent?.includes('People'));
  if (sb && el) {
    el.scrollIntoView({ behavior: 'instant', block: 'start' });
  }
});
await page.waitForTimeout(1500);
await dismissShortcuts();
await shot("06-discovery");

// 7. Devices — call navigateTo directly via dynamic import
await page.evaluate(async () => {
  const { navigateTo } = await import('/src/router.ts');
  navigateTo({ screen: "devices" });
});
await page.waitForTimeout(3000);
await dismissShortcuts();
await shot("07-devices");

// Navigate back to settings
await page.evaluate(async () => {
  const { navigateTo } = await import('/src/router.ts');
  navigateTo({ screen: "settings" });
});
await page.waitForTimeout(2000);
await dismissShortcuts();

// 8. Server Info — call navigateTo directly via dynamic import
await page.evaluate(async () => {
  const { navigateTo } = await import('/src/router.ts');
  navigateTo({ screen: "server-info" });
});
await page.waitForTimeout(3000);
await dismissShortcuts();
await shot("08-server-info");

await browser.close();
console.log("Done! Screenshots saved to Screenshots/");
