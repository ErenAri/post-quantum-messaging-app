type UrlShape = {
  protocol: string;
  hostname: string;
};

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

export function isLoopbackHostname(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.trim().toLowerCase());
}

export function isSecureWebOrigin(url: UrlShape): boolean {
  return url.protocol === "https:" || isLoopbackHostname(url.hostname);
}

type WebRuntimeCapabilities = {
  pageUrl: UrlShape;
  hasIndexedDb: boolean;
  hasCryptoSubtle: boolean;
  hasWebAssembly: boolean;
  hasTextEncoding: boolean;
};

export function getUnsupportedWebRuntimeReason(
  capabilities: WebRuntimeCapabilities
): string | null {
  if (!isSecureWebOrigin(capabilities.pageUrl)) {
    return "Secure web messaging requires HTTPS or localhost during development.";
  }
  if (!capabilities.hasIndexedDb) {
    return "Secure web messaging requires IndexedDB for encrypted local storage.";
  }
  if (!capabilities.hasCryptoSubtle) {
    return "Secure web messaging requires SubtleCrypto support.";
  }
  if (!capabilities.hasWebAssembly) {
    return "Secure web messaging requires WebAssembly support.";
  }
  if (!capabilities.hasTextEncoding) {
    return "Secure web messaging requires TextEncoder/TextDecoder support.";
  }
  return null;
}

export function getLiveUnsupportedWebRuntimeReason(): string | null {
  return getUnsupportedWebRuntimeReason({
    pageUrl: window.location,
    hasIndexedDb: typeof window.indexedDB !== "undefined" && window.indexedDB !== null,
    hasCryptoSubtle: typeof window.crypto !== "undefined" && !!window.crypto?.subtle,
    hasWebAssembly: typeof WebAssembly !== "undefined",
    hasTextEncoding: typeof TextEncoder !== "undefined" && typeof TextDecoder !== "undefined",
  });
}

export function validateWebServerUrl(serverUrl: string): URL {
  const normalized = serverUrl.trim();
  if (!normalized) {
    throw new Error("Server URL is empty.");
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("Server URL must be a valid absolute URL.");
  }

  if (parsed.username || parsed.password) {
    throw new Error("Server URL must not include embedded credentials.");
  }

  if (parsed.protocol === "https:") {
    return parsed;
  }

  if (parsed.protocol === "http:" && isLoopbackHostname(parsed.hostname)) {
    return parsed;
  }

  throw new Error("Secure web messaging requires an HTTPS server URL or loopback HTTP during development.");
}
