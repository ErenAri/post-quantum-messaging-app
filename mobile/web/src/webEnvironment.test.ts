import { describe, expect, it } from "vitest";
import {
  getUnsupportedWebRuntimeReason,
  isLoopbackHostname,
  isSecureWebOrigin,
  validateWebServerUrl,
} from "./webEnvironment";

describe("webEnvironment", () => {
  it("accepts secure https page origins", () => {
    expect(
      getUnsupportedWebRuntimeReason({
        pageUrl: { protocol: "https:", hostname: "app.example" },
        hasSecureContext: true,
        hasCrossOriginIsolation: true,
        hasIndexedDb: true,
        hasCryptoSubtle: true,
        hasWebAssembly: true,
        hasTextEncoding: true,
      })
    ).toBeNull();
  });

  it("accepts localhost development origins", () => {
    expect(
      getUnsupportedWebRuntimeReason({
        pageUrl: { protocol: "http:", hostname: "localhost" },
        hasSecureContext: true,
        hasCrossOriginIsolation: false,
        hasIndexedDb: true,
        hasCryptoSubtle: true,
        hasWebAssembly: true,
        hasTextEncoding: true,
      })
    ).toBeNull();
    expect(isLoopbackHostname("127.0.0.1")).toBe(true);
    expect(isSecureWebOrigin({ protocol: "http:", hostname: "127.0.0.1" })).toBe(true);
  });

  it("rejects insecure remote origins", () => {
    expect(
      getUnsupportedWebRuntimeReason({
        pageUrl: { protocol: "http:", hostname: "chat.example" },
        hasSecureContext: false,
        hasCrossOriginIsolation: false,
        hasIndexedDb: true,
        hasCryptoSubtle: true,
        hasWebAssembly: true,
        hasTextEncoding: true,
      })
    ).toContain("HTTPS");
  });

  it("rejects missing encrypted-storage support", () => {
    expect(
      getUnsupportedWebRuntimeReason({
        pageUrl: { protocol: "https:", hostname: "app.example" },
        hasSecureContext: true,
        hasCrossOriginIsolation: true,
        hasIndexedDb: false,
        hasCryptoSubtle: true,
        hasWebAssembly: true,
        hasTextEncoding: true,
      })
    ).toContain("IndexedDB");
  });

  it("rejects insecure browser contexts even on https", () => {
    expect(
      getUnsupportedWebRuntimeReason({
        pageUrl: { protocol: "https:", hostname: "app.example" },
        hasSecureContext: false,
        hasCrossOriginIsolation: true,
        hasIndexedDb: true,
        hasCryptoSubtle: true,
        hasWebAssembly: true,
        hasTextEncoding: true,
      })
    ).toContain("secure browser context");
  });

  it("rejects hosted web origins without cross-origin isolation", () => {
    expect(
      getUnsupportedWebRuntimeReason({
        pageUrl: { protocol: "https:", hostname: "app.example" },
        hasSecureContext: true,
        hasCrossOriginIsolation: false,
        hasIndexedDb: true,
        hasCryptoSubtle: true,
        hasWebAssembly: true,
        hasTextEncoding: true,
      })
    ).toContain("cross-origin isolation");
  });

  it("validates server URLs for secure web messaging", () => {
    expect(validateWebServerUrl("https://chat.example")).toBeInstanceOf(URL);
    expect(validateWebServerUrl("http://localhost:3000")).toBeInstanceOf(URL);
    expect(() => validateWebServerUrl("http://chat.example")).toThrow("HTTPS server URL");
    expect(() => validateWebServerUrl("https://user:pass@chat.example")).toThrow("embedded credentials");
  });
});
