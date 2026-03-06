# OBSERVABILITY

## 1. Scope

This document defines the default observability stack for `pqmsg-server`:

- metrics: Prometheus scraping `/metrics`,
- dashboards: Grafana with provisioned PQMSG dashboard,
- logs: Loki with Promtail ingestion,
- error tracking: Sentry via runtime DSN configuration,
- alert evaluation: Prometheus rule groups for availability and security anomalies,
- escalation routing: Alertmanager severity-based receiver fan-out.

## 2. Runtime Signals

`pqmsg-server` exposes:

1. HTTP request counters and durations:
   - `pqmsg_http_requests_total`
   - `pqmsg_http_request_duration_seconds_sum`
   - `pqmsg_http_request_duration_seconds_count`
   - `pqmsg_http_in_flight_requests`
2. Security event counter:
   - `pqmsg_security_events_total{event=...}`
3. Structured JSON logs with `request_id`.
4. Optional audit JSONL stream when `PQMSG_AUDIT_LOG_PATH` is set.

## 3. Local Stack with Docker Compose

Use the dedicated compose file:

```bash
docker compose -f docker-compose.observability.yml up -d --build
```

Endpoints:

- server: `http://localhost:3000/health`
- prometheus: `http://localhost:9090`
- alertmanager: `http://localhost:9093`
- mailpit UI (local email sink): `http://localhost:8025`
- grafana: `http://localhost:3001` (default credentials: `admin` / `pqmsg`)
- loki: `http://localhost:3100`

Teardown:

```bash
docker compose -f docker-compose.observability.yml down -v
```

## 4. Grafana Dashboard

Provisioned dashboard:

- `observability/grafana/dashboards/pqmsg-overview.json`

Default views include:

1. request rate and 5xx rate,
2. average request latency,
3. in-flight requests,
4. security event rate by event class,
5. application log stream,
6. audit security-event stream.

## 5. Alert Rules

Prometheus rule groups:

- `observability/prometheus/alert-rules.yml`
- `observability/alertmanager/alertmanager.yml`

The default rules cover:

1. sustained 5xx ratio breach (`PQMSGHighServerErrorRate`, critical),
2. authentication reject spikes (`PQMSGAuthRejectSpike`, high),
3. rate-limit reject spikes (`PQMSGRatelimitRejectSpike`, high),
4. sustained high in-flight request load (`PQMSGHighInflightRequests`, medium),
5. push circuit breaker open (`PQMSGPushCircuitBreakerOpen`, critical) — fires on `fcm_circuit_open` or `apns_circuit_open` security events,
6. signed prekey staleness (`PQMSGSignedPrekeyStaleness`, high) — detects signed prekey rotation failures,
7. PQ prekey pool depletion (`PQMSGPQBundleLastResortServed`, high) — alerts when bundles serve last-resort PQ prekeys,
8. device revocation spike (`PQMSGDeviceRevocationSpike`, high) — abnormal burst of device revocations,
9. PQ ratchet stall (`PQMSGPQRatchetStall`, high) — detects cessation of PQ ratchet steps while messages continue flowing,
10. nonce replay burst (`PQMSGNonceReplayBurst`, critical) — spikes in `auth_nonce_replay` events indicating active attack,
11. registration spike (`PQMSGRegistrationSpike`, medium) — abnormal burst of user registrations indicating bot activity.

The default Alertmanager routing maps:

1. `severity=critical` -> `oncall-critical`,
2. `severity=high` -> `oncall-high`,
3. `severity in {medium,low}` -> `oncall-standard`.

Receiver email routing in the local stack is:

- `oncall-critical` -> `${ALERT_EMAIL_CRITICAL_TO}`
- `oncall-high` -> `${ALERT_EMAIL_HIGH_TO}`
- `oncall-standard` -> `${ALERT_EMAIL_STANDARD_TO}`

SMTP configuration uses these environment variables:

- `ALERT_EMAIL_SMARTHOST`
- `ALERT_EMAIL_FROM`
- `ALERT_EMAIL_USERNAME`
- `ALERT_EMAIL_PASSWORD`
- `ALERT_EMAIL_REQUIRE_TLS`

Compose source of truth:

- `.env.alerting` (local defaults),
- `.env.alerting.example` (production template).

## 5.1 Escalation Drill

Run synthetic alert drills:

```bash
./scripts/security/alert_drill.sh
```

```powershell
./scripts/security/alert_drill.ps1
```

Inspect sink delivery traces:

```bash
curl -sS http://127.0.0.1:8025/api/v1/messages
```

Alert handling and escalation policy are defined in `docs/OPERATIONS.md`.

## 6. Log Aggregation

Promtail scrapes:

- `/var/log/pqmsg/server.log` (application logs),
- `/var/log/pqmsg/*.jsonl` (audit logs).

Loki labels include `job`, `source`, and parsed fields such as `request_id`, `event`, and `outcome`.

## 7. Sentry Error Tracking

Set the following environment variables for production deployments:

- `PQMSG_SENTRY_DSN`: Sentry DSN.
- `PQMSG_SENTRY_TRACES_SAMPLE_RATE`: floating-point value in `[0.0, 1.0]`.

Example:

```bash
export PQMSG_SENTRY_DSN='https://public@example.ingest.sentry.io/project-id'
export PQMSG_SENTRY_TRACES_SAMPLE_RATE='0.1'
```

With DSN configured, `pqmsg-server` installs Sentry tracing integration and forwards runtime error-level events.

## 8. Kubernetes and Helm Inputs

Kubernetes defaults:

- `deploy/k8s/configmap.yaml` includes `PQMSG_SENTRY_TRACES_SAMPLE_RATE`.
- `deploy/k8s/secret.example.yaml` includes `PQMSG_SENTRY_DSN`.

Helm defaults:

- `deploy/helm/pqmsg-server/values.yaml` includes
  - `env.PQMSG_SENTRY_TRACES_SAMPLE_RATE`
  - `secretEnv.PQMSG_SENTRY_DSN`
