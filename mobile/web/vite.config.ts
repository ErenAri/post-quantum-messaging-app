import { defineConfig } from "vite";

export const WEB_RESPONSE_SECURITY_HEADERS = {
  "Content-Security-Policy": [
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'none'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "style-src 'self' 'unsafe-inline'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "connect-src 'self' https: wss: http://127.0.0.1:* ws://127.0.0.1:* http://localhost:* ws://localhost:*",
    "manifest-src 'self'",
    "media-src 'self' data: blob:",
    "worker-src 'self'",
  ].join("; "),
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Origin-Agent-Cluster": "?1",
  "Permissions-Policy":
    "camera=(), microphone=(), geolocation=(), display-capture=(), fullscreen=(self)",
} as const;

export default defineConfig({
  server: {
    port: 5173,
    headers: WEB_RESPONSE_SECURITY_HEADERS,
  },
  preview: {
    headers: WEB_RESPONSE_SECURITY_HEADERS,
  },
  optimizeDeps: {
    exclude: ["pqmsg_core"],
  },
});
