# Deployment

## 1. Scope

This document defines container and Kubernetes deployment procedures for `pqmsg-server`.

Profiles:

- `research`: local and integration environments.
- `high_assurance`: production baseline; TLS required.
- `nss_aligned`: strict profile variant with TLS required.

This deployment guide assumes `high_assurance`.

## 2. Container Image

The repository root includes a production multi-stage `Dockerfile`:

- builder stage compiles `pqmsg-server` in release mode,
- runtime stage executes as non-root (`uid=10001`) with `tini`.

Build:

```bash
docker build -t pqmsg-server:0.1.0 .
```

Run (example):

```bash
docker run --rm -p 8080:8080 \
  -e PQMSG_BIND=0.0.0.0:8080 \
  -e PQMSG_SECURITY_PROFILE=high_assurance \
  -e PQMSG_DATABASE_URL='postgres://pqmsg:change-me@postgres:5432/pqmsg' \
  -e PQMSG_TLS_CERT_PATH=/etc/pqmsg/tls/tls.crt \
  -e PQMSG_TLS_KEY_PATH=/etc/pqmsg/tls/tls.key \
  -v $(pwd)/certs:/etc/pqmsg/tls:ro \
  pqmsg-server:0.1.0
```

## 3. Kubernetes Manifests

Raw manifests are provided under `deploy/k8s`:

- `namespace.yaml`
- `configmap.yaml`
- `secret.example.yaml`
- `deployment.yaml`
- `service.yaml`
- `hpa.yaml`
- `ingress.yaml`
- `kustomization.yaml`

Deployment:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl create secret generic pqmsg-server-secrets \
  --namespace pqmsg \
  --from-literal=PQMSG_DATABASE_URL='postgres://pqmsg:change-me@postgres.pqmsg.svc.cluster.local:5432/pqmsg' \
  --from-literal=PQMSG_RATE_LIMIT_REDIS_URL='redis://redis.pqmsg.svc.cluster.local:6379/' \
  --from-literal=PQMSG_FCM_SERVER_KEY='replace-with-fcm-server-key' \
  --from-literal=PQMSG_APNS_BEARER_TOKEN='replace-with-apns-bearer-token' \
  --from-literal=PQMSG_APNS_TOPIC='com.example.pqmsgdemo' \
  --from-literal=PQMSG_SENTRY_DSN='https://public@example.ingest.sentry.io/project-id'
kubectl create secret tls pqmsg-server-tls \
  --namespace pqmsg \
  --cert=server.crt \
  --key=server.key
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/hpa.yaml
kubectl apply -f deploy/k8s/ingress.yaml
```

Kustomize deployment:

```bash
kubectl create secret generic pqmsg-server-secrets \
  --namespace pqmsg \
  --from-literal=PQMSG_DATABASE_URL='postgres://pqmsg:change-me@postgres.pqmsg.svc.cluster.local:5432/pqmsg' \
  --from-literal=PQMSG_RATE_LIMIT_REDIS_URL='redis://redis.pqmsg.svc.cluster.local:6379/' \
  --from-literal=PQMSG_APNS_BEARER_TOKEN='replace-with-apns-bearer-token' \
  --from-literal=PQMSG_APNS_TOPIC='com.example.pqmsgdemo' \
  --from-literal=PQMSG_SENTRY_DSN='https://public@example.ingest.sentry.io/project-id'
kubectl create secret tls pqmsg-server-tls --namespace pqmsg --cert=server.crt --key=server.key
kubectl apply -k deploy/k8s
```

## 4. Helm Chart

Helm chart path:

- `deploy/helm/pqmsg-server`

Install:

```bash
helm upgrade --install pqmsg-server deploy/helm/pqmsg-server \
  --namespace pqmsg \
  --create-namespace
```

Override example:

```bash
helm upgrade --install pqmsg-server deploy/helm/pqmsg-server \
  --namespace pqmsg \
  --set image.repository=ghcr.io/your-org/pqmsg-server \
  --set image.tag=0.1.0 \
  --set secretEnv.PQMSG_DATABASE_URL='postgres://pqmsg:change-me@postgres.pqmsg.svc.cluster.local:5432/pqmsg'
```

## 5. Autoscaling

Autoscaling is configured via Kubernetes HPA (`autoscaling/v2`):

- minimum replicas: `2`,
- maximum replicas: `10`,
- CPU target: `70%`,
- memory target: `75%`.

Requirements:

- cluster metrics server installed and healthy,
- resource requests and limits set on deployment containers.

## 6. Operational Checklist

1. Use TLS certificates and set `PQMSG_TLS_CERT_PATH` and `PQMSG_TLS_KEY_PATH`.
2. Use PostgreSQL for production (`PQMSG_DATABASE_URL=postgres://...`).
3. Configure distributed rate limiting (`PQMSG_RATE_LIMIT_REDIS_URL=redis://...`).
4. Set `PQMSG_LOG_FORMAT=json` and `PQMSG_AUDIT_LOG_PATH` for audit retention.
5. Keep `PQMSG_SECURITY_PROFILE=high_assurance` or `nss_aligned`.
6. Configure push provider credentials:
   - FCM: `PQMSG_FCM_SERVER_KEY` (and optional `PQMSG_FCM_ENDPOINT`),
   - APNs: `PQMSG_APNS_BEARER_TOKEN`, `PQMSG_APNS_TOPIC` (and optional `PQMSG_APNS_ENDPOINT`).
7. Configure Sentry (`PQMSG_SENTRY_DSN`, `PQMSG_SENTRY_TRACES_SAMPLE_RATE`) for production error telemetry.

## 7. Observability Stack

Local observability stack assets are provided under `observability/` and can be launched with:

```bash
docker compose -f docker-compose.observability.yml up -d --build
```

This stack includes:

- Prometheus scrape of `pqmsg-server:/metrics`,
- Alertmanager routing for severity-based escalation paths,
- local Mailpit SMTP sink for escalation drill validation,
- Grafana with pre-provisioned PQMSG dashboard,
- Loki + Promtail aggregation for application logs and audit JSONL streams.

See `docs/OBSERVABILITY.md` for operational details and dashboard coverage.

## 8. Alertmanager Email Escalation Inputs

Configure Alertmanager SMTP and recipient routing environment variables in production:

1. `ALERT_EMAIL_SMARTHOST` (example: `smtp.example.com:587`),
2. `ALERT_EMAIL_FROM` (example: `pqmsg-alerts@example.com`),
3. `ALERT_EMAIL_USERNAME`,
4. `ALERT_EMAIL_PASSWORD`,
5. `ALERT_EMAIL_REQUIRE_TLS` (`true` for production SMTP),
6. `ALERT_EMAIL_CRITICAL_TO`,
7. `ALERT_EMAIL_HIGH_TO`,
8. `ALERT_EMAIL_STANDARD_TO`.

For local compose:

1. `.env.alerting` is prefilled with Mailpit-safe defaults.
2. Copy `.env.alerting.example` over `.env.alerting` and set real SMTP credentials for production-like drills.

Local observability compose defaults route email to Mailpit (`mailpit:1025`) for drill validation.
