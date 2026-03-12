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
        hasIndexedDb: false,
        hasCryptoSubtle: true,
        hasWebAssembly: true,
        hasTextEncoding: true,
      })
    ).toContain("IndexedDB");
  });

  it("validates server URLs for secure web messaging", () => {
    expect(validateWebServerUrl("https://chat.example")).toBeInstanceOf(URL);
    expect(validateWebServerUrl("http://localhost:3000")).toBeInstanceOf(URL);
    expect(() => validateWebServerUrl("http://chat.example")).toThrow("HTTPS server URL");
    expect(() => validateWebServerUrl("https://user:pass@chat.example")).toThrow("embedded credentials");
  });
});
