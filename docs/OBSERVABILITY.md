# OBSERVABILITY

## 1. Scope

This document defines the default observability stack for `pqmsg-server`:

- metrics: Prometheus scraping `/metrics`,
- dashboards: Grafana with provisioned PQMSG dashboard,
- logs: Loki with Promtail ingestion,
- error tracking: Sentry via runtime DSN configuration.

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

## 5. Log Aggregation

Promtail scrapes:

- `/var/log/pqmsg/server.log` (application logs),
- `/var/log/pqmsg/*.jsonl` (audit logs).

Loki labels include `job`, `source`, and parsed fields such as `request_id`, `event`, and `outcome`.

## 6. Sentry Error Tracking

Set the following environment variables for production deployments:

- `PQMSG_SENTRY_DSN`: Sentry DSN.
- `PQMSG_SENTRY_TRACES_SAMPLE_RATE`: floating-point value in `[0.0, 1.0]`.

Example:

```bash
export PQMSG_SENTRY_DSN='https://public@example.ingest.sentry.io/project-id'
export PQMSG_SENTRY_TRACES_SAMPLE_RATE='0.1'
```

With DSN configured, `pqmsg-server` installs Sentry tracing integration and forwards runtime error-level events.

## 7. Kubernetes and Helm Inputs

Kubernetes defaults:

- `deploy/k8s/configmap.yaml` includes `PQMSG_SENTRY_TRACES_SAMPLE_RATE`.
- `deploy/k8s/secret.example.yaml` includes `PQMSG_SENTRY_DSN`.

Helm defaults:

- `deploy/helm/pqmsg-server/values.yaml` includes
  - `env.PQMSG_SENTRY_TRACES_SAMPLE_RATE`
  - `secretEnv.PQMSG_SENTRY_DSN`
