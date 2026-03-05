Param(
    [string]$Alertmanager = "http://127.0.0.1:9093",
    [string]$Mailpit = "http://127.0.0.1:8025"
)

$payload = @(
    @{
        labels = @{
            alertname = "PQMSGManualDrill"
            service = "pqmsg-server"
            severity = "critical"
        }
        annotations = @{
            summary = "manual drill critical"
            description = "manual escalation drill for critical receiver"
        }
    },
    @{
        labels = @{
            alertname = "PQMSGManualDrill"
            service = "pqmsg-server"
            severity = "high"
        }
        annotations = @{
            summary = "manual drill high"
            description = "manual escalation drill for high receiver"
        }
    },
    @{
        labels = @{
            alertname = "PQMSGManualDrill"
            service = "pqmsg-server"
            severity = "medium"
        }
        annotations = @{
            summary = "manual drill standard"
            description = "manual escalation drill for standard receiver"
        }
    }
) | ConvertTo-Json -Depth 10

Write-Host "[1/3] submit synthetic drill alerts"
$submit = Invoke-WebRequest -Uri "$Alertmanager/api/v2/alerts" -Method POST -ContentType "application/json" -Body $payload -UseBasicParsing
Write-Host ("status={0}" -f [int]$submit.StatusCode)
if ($submit.Content) {
    $submit.Content
}

Write-Host "[2/3] query active drill alerts"
$active = Invoke-WebRequest -Uri "$Alertmanager/api/v2/alerts?filter=alertname%3DPQMSGManualDrill" -Method GET -UseBasicParsing
Write-Host ("status={0}" -f [int]$active.StatusCode)
$active.Content

Write-Host "[3/3] inspect local email sink"
$messages = Invoke-WebRequest -Uri "$Mailpit/api/v1/messages" -Method GET -UseBasicParsing
Write-Host ("status={0}" -f [int]$messages.StatusCode)
$messages.Content
Write-Host "Mailpit UI: $Mailpit"
