[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$InstanceHost,
  [Parameter(Mandatory = $true)]
  [string]$KeyFile,
  [string]$SshUser = "ubuntu",
  [string]$ApiDomain,
  [string]$AcmeEmail,
  [string]$CorsOrigin = "https://pqmsg-web.pages.dev",
  [string]$PqmsgServerImage = "ghcr.io/erenari/pqmsg-server:latest",
  [switch]$RunBackupSmokeCheck
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
  throw "ssh was not found in PATH. Install OpenSSH client first."
}
if (-not (Get-Command scp -ErrorAction SilentlyContinue)) {
  throw "scp was not found in PATH. Install OpenSSH client first."
}

$keyFullPath = (Resolve-Path -Path $KeyFile).Path
$remote = "$SshUser@$InstanceHost"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$localEc2Dir = Join-Path $repoRoot "deploy\aws\ec2"

if (-not $AcmeEmail) {
  $AcmeEmail = (git config --get user.email).Trim()
  if (-not $AcmeEmail) {
    $AcmeEmail = "ops@example.com"
  }
}

if (-not $ApiDomain) {
  $ApiDomain = $InstanceHost
}

$chars = (48..57 + 65..90 + 97..122 | ForEach-Object { [char]$_ })
$postgresPassword = -join (1..32 | ForEach-Object {
  $chars[(Get-Random -Minimum 0 -Maximum $chars.Count)]
})
$senderKeyBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
  $rng.GetBytes($senderKeyBytes)
} finally {
  $rng.Dispose()
}
$senderCertSigningKey = [Convert]::ToBase64String($senderKeyBytes)

$tmpDir = Join-Path $env:TEMP ("pqmsg-ec2-{0}" -f ([Guid]::NewGuid().ToString("N")))
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
  $envContent = Get-Content (Join-Path $localEc2Dir ".env.example") -Raw
  $envContent = $envContent -replace "(?m)^API_DOMAIN=.*$", "API_DOMAIN=$ApiDomain"
  $envContent = $envContent -replace "(?m)^ACME_EMAIL=.*$", "ACME_EMAIL=$AcmeEmail"
  $envContent = $envContent -replace "(?m)^POSTGRES_PASSWORD=.*$", "POSTGRES_PASSWORD=$postgresPassword"
  $envContent = $envContent -replace "(?m)^PQMSG_SERVER_IMAGE=.*$", "PQMSG_SERVER_IMAGE=$PqmsgServerImage"
  Set-Content -Path (Join-Path $tmpDir ".env") -Value $envContent -Encoding utf8

  $serverContent = Get-Content (Join-Path $localEc2Dir "pqmsg-server.aws.env.example") -Raw
  $serverContent = $serverContent -replace "(?m)^PQMSG_CORS_ALLOWED_ORIGINS=.*$", "PQMSG_CORS_ALLOWED_ORIGINS=$CorsOrigin"
  if ($serverContent -match "(?m)^PQMSG_SENDER_CERT_SIGNING_KEY=") {
    $serverContent = $serverContent -replace "(?m)^PQMSG_SENDER_CERT_SIGNING_KEY=.*$", "PQMSG_SENDER_CERT_SIGNING_KEY=$senderCertSigningKey"
  } else {
    $serverContent = $serverContent.TrimEnd() + "`nPQMSG_SENDER_CERT_SIGNING_KEY=$senderCertSigningKey`n"
  }
  Set-Content -Path (Join-Path $tmpDir "pqmsg-server.aws.env") -Value $serverContent -Encoding utf8

  scp -i $keyFullPath (Join-Path $tmpDir ".env") ($remote + ":/tmp/.env")
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to upload .env"
  }
  scp -i $keyFullPath (Join-Path $tmpDir "pqmsg-server.aws.env") ($remote + ":/tmp/pqmsg-server.aws.env")
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to upload pqmsg-server.aws.env"
  }

  $remoteCmd = "set -eu; mv /tmp/.env /opt/pqmsg/deploy/aws/ec2/.env; mv /tmp/pqmsg-server.aws.env /opt/pqmsg/deploy/aws/ec2/pqmsg-server.aws.env; sudo systemctl enable --now pqmsg-backend-compose.service; sudo systemctl is-active pqmsg-backend-compose.service; sudo docker compose --env-file /opt/pqmsg/deploy/aws/ec2/.env -f /opt/pqmsg/deploy/aws/ec2/docker-compose.ec2.yml ps"
  ssh -i $keyFullPath $remote $remoteCmd
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to start backend service"
  }

  if ($RunBackupSmokeCheck) {
    $smokeScript = Join-Path $repoRoot "scripts\dev\aws\smoke_check_ec2_backup_recovery.ps1"
    if (-not (Test-Path $smokeScript)) {
      throw "Smoke-check script was not found: $smokeScript"
    }
    $apiBaseUrl = "https://$ApiDomain"
    Write-Host "Running backup upload/recovery smoke check against $apiBaseUrl" -ForegroundColor Cyan
    & $smokeScript -ApiBaseUrl $apiBaseUrl
  }

  Write-Output "POSTGRES_PASSWORD=$postgresPassword"
  Write-Output "PQMSG_SENDER_CERT_SIGNING_KEY=$senderCertSigningKey"
  Write-Output "API_DOMAIN=$ApiDomain"
  Write-Output "ACME_EMAIL=$AcmeEmail"
  Write-Output "CORS_ORIGIN=$CorsOrigin"
  Write-Output "PQMSG_SERVER_IMAGE=$PqmsgServerImage"
  Write-Output "RUN_BACKUP_SMOKE_CHECK=$RunBackupSmokeCheck"
} finally {
  Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
