# pqmsg promote incident: v1.2.3 (prod/production) severity=critical

- Operation: `promote`
- Release tag: `v1.2.3`
- Environment: `prod`
- Deployment mode: `production`
- Release name: `pqmsg-server`
- Namespace: `pqmsg`
- Target image: `ghcr.io/example/pqmsg-server@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- Job status: `failure`
- Failed check count: `2`
- Suspicious drift count: `1`
- Top failed checks: `runtime_contract:health_status_ok, live_routing:live_service_routing_contract`

## Next Actions
- Freeze further promotion or rollback actions until the failing checks are reviewed.
- Inspect live Service/Ingress wiring and compare it to the rendered chart.
