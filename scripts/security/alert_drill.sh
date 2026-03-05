#!/usr/bin/env bash
set -euo pipefail

ALERTMANAGER="${1:-http://127.0.0.1:9093}"
MAILPIT="${2:-http://127.0.0.1:8025}"

payload='[
  {
    "labels": {
      "alertname": "PQMSGManualDrill",
      "service": "pqmsg-server",
      "severity": "critical"
    },
    "annotations": {
      "summary": "manual drill critical",
      "description": "manual escalation drill for critical receiver"
    }
  },
  {
    "labels": {
      "alertname": "PQMSGManualDrill",
      "service": "pqmsg-server",
      "severity": "high"
    },
    "annotations": {
      "summary": "manual drill high",
      "description": "manual escalation drill for high receiver"
    }
  },
  {
    "labels": {
      "alertname": "PQMSGManualDrill",
      "service": "pqmsg-server",
      "severity": "medium"
    },
    "annotations": {
      "summary": "manual drill standard",
      "description": "manual escalation drill for standard receiver"
    }
  }
]'

echo "[1/3] submit synthetic drill alerts"
curl -sS -o /tmp/pqmsg-alert-drill-submit.txt -w "status=%{http_code}\n" \
  -H "content-type: application/json" \
  -d "$payload" \
  "${ALERTMANAGER}/api/v2/alerts"
cat /tmp/pqmsg-alert-drill-submit.txt || true
echo

echo "[2/3] query active drill alerts"
curl -sS -o /tmp/pqmsg-alert-drill-active.json -w "status=%{http_code}\n" \
  "${ALERTMANAGER}/api/v2/alerts?filter=alertname%3DPQMSGManualDrill"
cat /tmp/pqmsg-alert-drill-active.json
echo

echo "[3/3] inspect local email sink"
curl -sS -o /tmp/pqmsg-alert-drill-mailpit.json -w "status=%{http_code}\n" \
  "${MAILPIT}/api/v1/messages"
cat /tmp/pqmsg-alert-drill-mailpit.json
echo
echo "Mailpit UI: ${MAILPIT}"
