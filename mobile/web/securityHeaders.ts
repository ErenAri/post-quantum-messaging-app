export type WebResponseSecurityHeaderMode = "development" | "production";

const COMMON_CSP_DIRECTIVES = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "form-action 'none'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "script-src-attr 'none'",
  "manifest-src 'self'",
  "media-src 'self' data: blob:",
  "worker-src 'self'",
] as const;

const DEVELOPMENT_CONNECT_SRC = [
  "'self'",
  "https:",
  "wss:",
  "http://127.0.0.1:*",
  "ws://127.0.0.1:*",
  "http://localhost:*",
  "ws://localhost:*",
] as const;

const PRODUCTION_CONNECT_SRC = ["'self'", "https:", "wss:"] as const;

function buildContentSecurityPolicy(mode: WebResponseSecurityHeaderMode): string {
  const connectSrc =
    mode === "production" ? PRODUCTION_CONNECT_SRC : DEVELOPMENT_CONNECT_SRC;
  return [...COMMON_CSP_DIRECTIVES, `connect-src ${connectSrc.join(" ")}`].join("; ");
}

export function buildWebResponseSecurityHeaders(
  mode: WebResponseSecurityHeaderMode
): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Security-Policy": buildContentSecurityPolicy(mode),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Origin-Agent-Cluster": "?1",
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), display-capture=(), fullscreen=(self)",
  };
  if (mode === "production") {
    headers["Strict-Transport-Security"] =
      "max-age=31536000; includeSubDomains; preload";
  }
  return headers;
}

export const WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS =
  buildWebResponseSecurityHeaders("development");

export const WEB_PRODUCTION_RESPONSE_SECURITY_HEADERS =
  buildWebResponseSecurityHeaders("production");
