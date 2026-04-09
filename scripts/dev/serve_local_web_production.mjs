import { createServer, request as httpRequest } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { resolve, normalize, extname, join } from "node:path";
import { pipeline } from "node:stream";

const HOST = process.env.PQMSG_WEB_HOST ?? "127.0.0.1";
const PORT = Number(process.env.PQMSG_WEB_PORT ?? "8081");
const BACKEND_HOST = process.env.PQMSG_BACKEND_HOST ?? "127.0.0.1";
const BACKEND_PORT = Number(process.env.PQMSG_BACKEND_PORT ?? "3000");
const DIST_ROOT = resolve(process.cwd(), "mobile/web/dist");
const BACKEND_ORIGIN = `http://${BACKEND_HOST}:${BACKEND_PORT}`;
const EXPOSE_METRICS = process.env.PQMSG_WEB_EXPOSE_METRICS === "true";

const CONTENT_SECURITY_POLICY = [
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
  "connect-src 'self' https: wss:",
].join("; ");

const STATIC_EXTENSIONS = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "application/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".webmanifest", "application/manifest+json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".webp", "image/webp"],
  [".ico", "image/x-icon"],
  [".txt", "text/plain; charset=utf-8"],
  [".wasm", "application/wasm"],
]);

function setSecurityHeaders(res) {
  res.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Origin-Agent-Cluster", "?1");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), display-capture=(), fullscreen=(self)"
  );
}

function setCacheHeaders(res, pathname) {
  if (pathname === "/manifest.webmanifest") {
    res.setHeader("Cache-Control", "no-cache");
    return;
  }
  if (pathname === "/sw.js") {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    return;
  }
  if (pathname.startsWith("/assets/") || pathname.endsWith(".wasm")) {
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    return;
  }
  res.setHeader("Cache-Control", "no-store");
}

function sanitizePath(pathname) {
  try {
    const decoded = decodeURIComponent(pathname);
    const candidate = normalize(decoded).replace(/^(\.\.[/\\])+/, "");
    return candidate.startsWith("/") ? candidate : `/${candidate}`;
  } catch {
    return null;
  }
}

function shouldServeExactOnly(pathname) {
  return (
    pathname === "/manifest.webmanifest" ||
    pathname === "/sw.js" ||
    pathname.startsWith("/assets/") ||
    pathname.endsWith(".wasm") ||
    extname(pathname) !== ""
  );
}

function resolveStaticPath(pathname) {
  const safePath = sanitizePath(pathname);
  if (!safePath) {
    return null;
  }
  const localPath = resolve(DIST_ROOT, `.${safePath}`);
  if (!localPath.startsWith(DIST_ROOT)) {
    return null;
  }
  if (existsSync(localPath) && statSync(localPath).isFile()) {
    return localPath;
  }
  if (shouldServeExactOnly(safePath)) {
    return null;
  }
  return resolve(DIST_ROOT, "index.html");
}

function serveStatic(req, res) {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  const filePath = resolveStaticPath(url.pathname);
  if (!filePath || !existsSync(filePath)) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("not found");
    return;
  }

  const exactPath = resolve(DIST_ROOT, `.${sanitizePath(url.pathname) ?? "/"}`);
  const requestedPath =
    existsSync(exactPath) && statSync(exactPath).isFile() ? url.pathname : "/index.html";
  setSecurityHeaders(res);
  setCacheHeaders(res, requestedPath);
  res.setHeader("Content-Type", STATIC_EXTENSIONS.get(extname(filePath)) ?? "application/octet-stream");
  if (requestedPath === "/index.html") {
    res.statusCode = 200;
  }
  pipeline(createReadStream(filePath), res, (error) => {
    if (error) {
      console.error("[web] static pipeline failed", error);
    }
  });
}

function proxyHttp(req, res) {
  const proxyReq = httpRequest(
    {
      host: BACKEND_HOST,
      port: BACKEND_PORT,
      method: req.method,
      path: req.url,
      headers: {
        ...req.headers,
        host: `${BACKEND_HOST}:${BACKEND_PORT}`,
      },
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
      pipeline(proxyRes, res, (error) => {
        if (error) {
          console.error("[web] backend response pipeline failed", error);
        }
      });
    }
  );

  proxyReq.on("error", (error) => {
    console.error("[web] backend proxy failed", error);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
    }
    res.end(`backend unavailable: ${error.message}`);
  });

  pipeline(req, proxyReq, (error) => {
    if (error) {
      console.error("[web] backend request pipeline failed", error);
    }
  });
}

function proxyUpgrade(req, socket, head) {
  const proxyReq = httpRequest({
    host: BACKEND_HOST,
    port: BACKEND_PORT,
    path: req.url,
    headers: {
      ...req.headers,
      host: `${BACKEND_HOST}:${BACKEND_PORT}`,
      connection: "Upgrade",
    },
  });

  proxyReq.on("upgrade", (proxyRes, proxySocket, proxyHead) => {
    socket.write(
      `HTTP/1.1 ${proxyRes.statusCode ?? 101} ${proxyRes.statusMessage ?? "Switching Protocols"}\r\n`
    );
    for (const [key, value] of Object.entries(proxyRes.headers)) {
      if (Array.isArray(value)) {
        for (const entry of value) {
          socket.write(`${key}: ${entry}\r\n`);
        }
      } else if (value !== undefined) {
        socket.write(`${key}: ${value}\r\n`);
      }
    }
    socket.write("\r\n");
    if (proxyHead.length > 0) {
      socket.write(proxyHead);
    }
    if (head.length > 0) {
      proxySocket.write(head);
    }
    proxySocket.pipe(socket);
    socket.pipe(proxySocket);
  });

  proxyReq.on("error", (error) => {
    console.error("[web] backend ws proxy failed", error);
    socket.destroy();
  });

  proxyReq.end();
}

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  if (url.pathname === "/health" || url.pathname.startsWith("/v1/")) {
    proxyHttp(req, res);
    return;
  }
  if (url.pathname === "/metrics") {
    if (!EXPOSE_METRICS) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("not found");
      return;
    }
    proxyHttp(req, res);
    return;
  }
  serveStatic(req, res);
});

server.on("upgrade", (req, socket, head) => {
  if (req.url?.startsWith("/v1/ws/")) {
    proxyUpgrade(req, socket, head);
    return;
  }
  socket.destroy();
});

server.listen(PORT, HOST, () => {
  console.log(`[web] serving ${DIST_ROOT}`);
  console.log(`[web] local origin http://${HOST}:${PORT}`);
  console.log(`[web] proxying relay traffic to ${BACKEND_ORIGIN}`);
  console.log(`[web] metrics proxy ${EXPOSE_METRICS ? "enabled" : "disabled"}`);
});
