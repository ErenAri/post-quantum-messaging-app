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
