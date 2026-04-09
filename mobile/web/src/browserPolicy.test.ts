import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS,
  WEB_PRODUCTION_RESPONSE_SECURITY_HEADERS,
} from "../securityHeaders";

const here = dirname(fileURLToPath(import.meta.url));

describe("browser policy", () => {
  it("ships hardened response headers for dev and preview", () => {
    expect(
      WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]
    ).toContain(
      "script-src 'self' 'wasm-unsafe-eval'"
    );
    expect(
      WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]
    ).toContain(
      "frame-src 'none'"
    );
    expect(
      WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]
    ).toContain(
      "script-src-attr 'none'"
    );
    expect(
      WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]
    ).toContain(
      "connect-src 'self' https: wss:"
    );
    expect(
      WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]
    ).toContain(
      "worker-src 'self'"
    );
    expect(WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]).toContain(
      "http://127.0.0.1:*"
    );
    expect(WEB_PRODUCTION_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"]).not.toContain(
      "http://127.0.0.1:*"
    );
    expect(WEB_PRODUCTION_RESPONSE_SECURITY_HEADERS["Strict-Transport-Security"]).toContain(
      "max-age=31536000"
    );
    expect(WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Cross-Origin-Embedder-Policy"]).toBe(
      "require-corp"
    );
    expect(WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Cross-Origin-Opener-Policy"]).toBe(
      "same-origin"
    );
    expect(WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["X-Frame-Options"]).toBe("DENY");
    expect(WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["X-Content-Type-Options"]).toBe("nosniff");
  });

  it("keeps environment-specific CSP out of the SPA shell", () => {
    const html = readFileSync(resolve(here, "../index.html"), "utf8");
    expect(html).not.toContain('http-equiv="Content-Security-Policy"');
    expect(html).toContain('name="description"');
    expect(html).toContain("<title>PQmsg</title>");
    expect(html).toContain('<meta name="referrer" content="no-referrer"');
  });

  it("keeps the service worker cache scoped to same-origin shell assets", () => {
    const sw = readFileSync(resolve(here, "../public/sw.js"), "utf8");
    expect(sw).toContain("url.origin !== self.location.origin");
    expect(sw).toContain("url.pathname.startsWith(\"/v1/\")");
    expect(sw).toContain("request.mode === \"navigate\"");
  });
});
