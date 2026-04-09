# WEB DEPLOYMENT

## Objective

This document covers the hosted production deployment shape for the PQmsg web shell.

It does **not** change the rollout contract in [SUPPORT_MATRIX](SUPPORT_MATRIX.json). The current machine-readable support posture still leaves web in `demo_only` mode until the server and release process deliberately promote it.

## Hosting model

The web client is a static Vite build with WASM assets, service worker support, and strict browser header requirements.

Production hosting requirements:

- HTTPS only
- real browser secure context
- cross-origin isolation on hosted origins
- explicit CSP, COOP, COEP, and CORP headers
- immutable caching for hashed assets
- no-cache policy for `index.html`, `sw.js`, and `manifest.webmanifest`

## Build

```bash
cd mobile/web
npm ci
npm run build
```

The production output is written to `mobile/web/dist`.

## Release Package

Create a versioned deployment bundle from the built web shell:

```bash
python scripts/release/package_web_release.py --release-id 20260409-001
```

This writes:

- `dist/web-release/pqmsg-web-<release-id>.tar.gz`
- `dist/web-release/pqmsg-web-<release-id>.manifest.json`

The bundle contains:

- `site/` - static web assets from `mobile/web/dist`
- `nginx/pqmsg-web.conf` - hardened Nginx site template
- `manifest.json` - release metadata and SHA-256 hashes
- `VERSION` - release identifier

For Cloudflare Pages, the repo also ships:

- `mobile/web/public/_headers`

That file mirrors the hardened hosted-header contract for static Pages deployments.

## Nginx reference config

Use the hardened example in:

- `deploy/web/nginx/pqmsg-web.conf`

For VPS rollouts, the repo also provides:

- `deploy/web/vps/deploy_pqmsg_web_release.sh`

The config assumes:

- site root at `/var/www/pqmsg-web/current`
- TLS already provisioned
- a public hostname such as `pqmsg.example.com`

## Recommended deployment layout

```text
/var/www/pqmsg-web/
  releases/
    2026-04-09-001/
  current -> /var/www/pqmsg-web/releases/2026-04-09-001
```

Deploy by copying the built `dist/` contents into a new release directory and switching the `current` symlink.

## VPS Rollout

1. Build and package the release locally:

```bash
npm --prefix mobile/web test
npm --prefix mobile/web run build
python scripts/security/validate_web_production_contract.py
python scripts/release/package_web_release.py --release-id 20260409-001
```

2. Copy the bundle to the VPS:

```bash
scp dist/web-release/pqmsg-web-20260409-001.tar.gz user@your-host:/tmp/
```

3. Run the VPS rollout script on the server:

```bash
sudo bash deploy/web/vps/deploy_pqmsg_web_release.sh \
  /tmp/pqmsg-web-20260409-001.tar.gz \
  20260409-001 \
  pqmsg.example.com
```

The rollout script:

- extracts the bundle
- creates `/var/www/pqmsg-web/releases/<release-id>`
- updates `/var/www/pqmsg-web/current`
- renders and installs the hardened Nginx site config
- runs `nginx -t`
- reloads Nginx

Optional environment overrides for the rollout script:

- `WEB_ROOT`
- `NGINX_AVAILABLE_DIR`
- `NGINX_ENABLED_DIR`
- `NGINX_CONF_NAME`
- `INSTALL_NGINX_CONFIG=0`
- `RELOAD_NGINX=0`

## Cloudflare Pages Rollout

Use Cloudflare Pages for the static web shell only.

Recommended settings:

- Repository: `ErenAri/post-quantum-messaging-app`
- Production branch: the branch that contains the latest web deployment changes
- Framework preset: `Vite`
- Root directory: `mobile/web`
- Build command: `npm ci && npm run build`
- Build output directory: `dist`

The repo does not require a `_redirects` file for Pages because the current web shell does not use pathname-based SPA routing. Deep state lives in in-memory view state plus query/hash fragments.

The hardened response headers should come from:

- `mobile/web/public/_headers`

## Local PC Backend via Cloudflare Tunnel

If you want to keep the hosted web shell on Cloudflare Pages but run the relay on your own PC, use the repo scripts below.

Start the local relay with the hosted-web policy and CORS for the Pages origin:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev/start_local_hosted_web_backend.ps1
```

That script:

- binds the relay to `127.0.0.1:3000`
- uses a local SQLite database under `.tmp/local-run/hosted-web-backend`
- enables encrypted SQLite pages by default
- sets `PQMSG_WEB_CLIENT_POLICY=interop_candidate`
- sets `PQMSG_CORS_ALLOWED_ORIGINS=https://pqmsg-web.pages.dev`

If you need to test a specific Pages deployment URL as well as the stable project URL, pass it as an additional origin:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev/start_local_hosted_web_backend.ps1 `
  -AdditionalWebOrigins https://<deployment-id>.pqmsg-web.pages.dev
```

Then open a public HTTPS tunnel to the loopback relay:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev/start_cloudflare_quick_tunnel.ps1
```

When `cloudflared` prints a `https://*.trycloudflare.com` URL:

1. keep both terminal windows open
2. open the hosted web shell on Pages
3. go to `Advanced`
4. paste the `https://*.trycloudflare.com` URL as the relay URL
5. save and create or unlock the web profile

This path is suitable for personal testing and small trusted cohorts. It is not a production hosting model. The relay only stays reachable while:

- your PC is powered on
- the local relay process is running
- the Cloudflare quick tunnel process is running

## Post-deploy checks

Verify:

1. `https://<host>/` loads over HTTPS
2. `window.isSecureContext === true`
3. `window.crossOriginIsolated === true`
4. hashed `/assets/*` files return immutable caching headers
5. `index.html`, `sw.js`, and `manifest.webmanifest` return no-cache headers
6. CSP on the hosted origin allows only `'self'`, `https:`, and `wss:` for outbound connections

Use the remote validator from the repo:

```bash
python scripts/security/validate_hosted_web_headers.py --base-url https://pqmsg.example.com
```

For local loopback verification only:

```bash
python scripts/security/validate_hosted_web_headers.py --base-url http://127.0.0.1:8081 --allow-http-loopback
```

## Validation

Run the repo-side contract validator before rollout:

```bash
python scripts/security/validate_web_production_contract.py
```

Then run the web build and tests:

```bash
cd mobile/web
npm test
npm run build
```

## Rollout note

A hosted production shell is not the same thing as a supported production messaging client.

Before changing rollout policy, the server capability contract, support matrix, and launch validation need to move together:

- `docs/SUPPORT_MATRIX.json`
- `docs/WEB.md`
- `/v1/capabilities`
- operational launch checks
