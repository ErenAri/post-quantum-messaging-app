import { describe, expect, it } from "vitest";
import {
  WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS,
  WEB_PRODUCTION_RESPONSE_SECURITY_HEADERS,
} from "../securityHeaders";

describe("securityHeaders", () => {
  it("allows loopback-only exceptions in development headers", () => {
    const csp = WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"];
    expect(csp).toContain("http://127.0.0.1:*");
    expect(csp).toContain("ws://localhost:*");
  });

  it("keeps production headers restricted to secure transports", () => {
    const csp = WEB_PRODUCTION_RESPONSE_SECURITY_HEADERS["Content-Security-Policy"];
    expect(csp).toContain("connect-src 'self' https: wss:");
    expect(csp).not.toContain("http://127.0.0.1:*");
    expect(csp).not.toContain("http://localhost:*");
    expect(csp).not.toContain("ws://");
  });

  it("adds HSTS only for hosted production mode", () => {
    expect(
      WEB_PRODUCTION_RESPONSE_SECURITY_HEADERS["Strict-Transport-Security"]
    ).toContain("max-age=31536000");
    expect(
      WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS["Strict-Transport-Security"]
    ).toBeUndefined();
  });
});
