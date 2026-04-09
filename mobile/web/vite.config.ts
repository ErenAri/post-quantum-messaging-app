import { defineConfig } from "vite";
import { WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS } from "./securityHeaders";

export default defineConfig({
  build: {
    sourcemap: false,
  },
  server: {
    port: 5173,
    headers: WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS,
  },
  preview: {
    headers: WEB_DEVELOPMENT_RESPONSE_SECURITY_HEADERS,
  },
  optimizeDeps: {
    exclude: ["pqmsg_core"],
  },
});
