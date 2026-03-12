import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { WEB_RESPONSE_SECURITY_HEADERS } from "../vite.config";

const here = dirname(fileURLToPath(import.meta.url));

describe("browser policy", () => {
  it("ships hardened response headers for dev and preview", () => {
    expect(WEB_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]).toContain(
      "script-src 'self' 'wasm-unsafe-eval'"
    );
    expect(WEB_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]).toContain(
      "connect-src 'self' https: wss:"
    );
    expect(WEB_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]).toContain(
      "worker-src 'self'"
    );
    expect(WEB_RESPONSE_SECURITY_HEADERS["Cross-Origin-Opener-Policy"]).toBe("same-origin");
    expect(WEB_RESPONSE_SECURITY_HEADERS["X-Frame-Options"]).toBe("DENY");
    expect(WEB_RESPONSE_SECURITY_HEADERS["X-Content-Type-Options"]).toBe("nosniff");
  });

  it("embeds a CSP meta policy in the SPA shell", () => {
    const html = readFileSync(resolve(here, "../index.html"), "utf8");
    expect(html).toContain('http-equiv="Content-Security-Policy"');
    expect(html).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(html).toContain("connect-src 'self' https: wss:");
    expect(html).toContain("worker-src 'self'");
    expect(html).toContain('<meta name="referrer" content="no-referrer"');
  });
});
