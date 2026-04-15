# AWS EC2 Backend Runbook

## 1. Scope

This runbook deploys the non-frontend services for PQmsg on a single AWS EC2 host while keeping the web shell on Cloudflare Pages.

- Frontend stays on `https://pqmsg-web.pages.dev`.
- Backend (API relay), Postgres, and Redis run on one EC2 instance via Docker Compose.
- TLS for the API endpoint is handled by Caddy + Let's Encrypt on that same instance.

This path is optimized for low-cost dev/testing and small trusted cohorts.

## 2. Files Added

- `deploy/aws/ec2/docker-compose.ec2.yml`
- `deploy/aws/ec2/Caddyfile`
- `deploy/aws/ec2/.env.example`
- `deploy/aws/ec2/pqmsg-server.aws.env.example`
- `deploy/aws/ec2/systemd/pqmsg-backend-compose.service`
- `scripts/dev/aws/provision_ec2_backend.ps1`
- `scripts/dev/aws/deploy_ec2_backend_stack.ps1`
- `scripts/dev/aws/configure_and_start_ec2_backend.ps1`

## 3. Prerequisites

1. AWS CLI authenticated (`aws sts get-caller-identity` succeeds).
2. An existing EC2 key pair in your target region.
3. A DNS name for the API (example: `api.example.com`) that you can point to the EC2 public IP.
4. OpenSSH client (`ssh`, `scp`) available on your machine.

## 4. Provision EC2 (AWS CLI)

From repository root on Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev/aws/provision_ec2_backend.ps1 `
  -Region us-east-1 `
  -NamePrefix pqmsg `
  -InstanceType t2.micro `
  -KeyName your-ec2-keypair-name
```

What the script does:

1. Resolves Ubuntu AMI from AWS SSM.
2. Uses your default VPC/subnet unless overridden.
3. Creates or reuses a security group.
4. Adds inbound rules for 80/443 (and 22 from your current public IP when detected).
5. Launches EC2 with Docker Engine + Docker Compose preinstalled.

The script prints instance ID, public IP, and DNS when ready.

## 5. Point DNS

Create an A record so your API domain points to the instance public IP:

- `api.example.com -> <ec2-public-ip>`

Wait for DNS to propagate before starting Caddy, otherwise certificate issuance may fail.

## 6. Push Stack to EC2

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev/aws/deploy_ec2_backend_stack.ps1 `
  -InstanceHost <ec2-public-dns-or-ip> `
  -KeyFile C:\path\to\your-key.pem
```

This copies `deploy/aws/ec2` to `/opt/pqmsg/deploy/aws/ec2` and installs the systemd unit file.

## 7. Configure and Start on EC2

SSH to the instance and edit runtime config:

```bash
ssh -i /path/to/your-key.pem ubuntu@<ec2-host>
nano /opt/pqmsg/deploy/aws/ec2/.env
nano /opt/pqmsg/deploy/aws/ec2/pqmsg-server.aws.env
```

Minimum required values:

- `/opt/pqmsg/deploy/aws/ec2/.env`
  - `API_DOMAIN=api.example.com`
  - `ACME_EMAIL=ops@example.com`
  - `POSTGRES_PASSWORD=<strong-random-password>`
- `/opt/pqmsg/deploy/aws/ec2/pqmsg-server.aws.env`
  - `PQMSG_CORS_ALLOWED_ORIGINS=https://pqmsg-web.pages.dev`

Optional one-shot helper from your local machine:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev/aws/configure_and_start_ec2_backend.ps1 `
  -InstanceHost <ec2-public-dns-or-ip> `
  -ApiDomain <public-api-domain> `
  -KeyFile C:\path\to\your-key.pem
```

That helper uploads rendered env files, sets a generated database password and sender-cert signing seed, and starts `pqmsg-backend-compose.service`.

Start services:

```bash
sudo systemctl enable --now pqmsg-backend-compose.service
sudo systemctl status pqmsg-backend-compose.service --no-pager
```

Tail logs:

```bash
sudo docker compose --env-file /opt/pqmsg/deploy/aws/ec2/.env \
  -f /opt/pqmsg/deploy/aws/ec2/docker-compose.ec2.yml logs -f
```

## 8. Hosted Web Cutover Checklist

1. Confirm API HTTPS endpoint is reachable:
   - `https://api.example.com/health`
2. Confirm the hosted web origin is allowlisted:
   - `PQMSG_CORS_ALLOWED_ORIGINS=https://pqmsg-web.pages.dev`
3. Open hosted client and set relay URL to your API endpoint.
4. Verify account setup, registration, and send/receive on web.
5. Keep the previous backend available until end-to-end smoke passes.

Hosted frontend wiring options:

1. Permanent (build-time default): set `VITE_PQMSG_HOSTED_RELAY_URL` for web builds.
  - This repository now includes `mobile/web/.env.production` with a hosted relay default.
2. Immediate (no rebuild): share a bootstrap link that pins relay via query parameter.
  - Example: `https://pqmsg-web.pages.dev/?relay=https%3A%2F%2F54-157-172-51.sslip.io`

## 9. Security and Contract Notes

The default EC2 compose profile is a low-cost dev/testing baseline (`development` + `research`).

For hardened `pilot` or `production` modes, `pqmsg-server` enforces extra requirements, including:

1. PostgreSQL backend
2. Explicit Postgres storage/backup encryption declarations
3. TLS cert/key configuration via `PQMSG_TLS_CERT_PATH` and `PQMSG_TLS_KEY_PATH`
4. Audit log path
5. Redis-backed distributed controls
6. Structured JSON logs
7. Non-wildcard CORS
8. PQ-capable runtime

See deployment contract logic in:

- `crates/pqmsg-server/src/main.rs`
- `docs/DEPLOYMENT.md`

## 10. Cost Notes

- `t2.micro` can work for low-traffic dev/testing.
- Full pilot/production traffic and durability expectations typically require larger instances and managed data services.
- Watch EC2, EBS, data transfer, and public IPv4 charges.
