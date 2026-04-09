[CmdletBinding()]
param(
  [string]$PrimaryWebOrigin = "https://pqmsg-web.pages.dev",
  [string[]]$AdditionalWebOrigins = @(),
  [string]$Bind = "127.0.0.1:3000",
  [string]$DatabasePath = ".tmp/local-run/hosted-web-backend/pqmsg-server.db",
  [switch]$UsePlaintextSqlite
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot

$dbFullPath = Join-Path $repoRoot $DatabasePath
$dbDir = Split-Path -Parent $dbFullPath
New-Item -ItemType Directory -Force -Path $dbDir | Out-Null

$origins = @($PrimaryWebOrigin.Trim()) + $AdditionalWebOrigins
$origins = $origins |
  ForEach-Object { $_.Trim() } |
  Where-Object { $_ } |
  Select-Object -Unique

if ($origins.Count -eq 0) {
  throw "At least one web origin is required."
}

$env:PQMSG_DATABASE_URL = "sqlite:///$($dbFullPath.Replace('\', '/'))?mode=rwc"
$env:PQMSG_BIND = $Bind
$env:PQMSG_SECURITY_PROFILE = "research"
$env:PQMSG_DEPLOYMENT_MODE = "development"
$env:PQMSG_WEB_CLIENT_POLICY = "interop_candidate"
$env:PQMSG_CORS_ALLOWED_ORIGINS = ($origins -join ",")
$env:RUST_LOG = "pqmsg_server=info"

if (-not $UsePlaintextSqlite) {
  $secretDir = Join-Path $HOME ".pqmsg\local-hosted-web"
  $keyFile = Join-Path $secretDir "sqlite-key.b64"
  New-Item -ItemType Directory -Force -Path $secretDir | Out-Null
  if (-not (Test-Path $keyFile)) {
    $rawKey = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
      $rng.GetBytes($rawKey)
    } finally {
      $rng.Dispose()
    }
    [Convert]::ToBase64String($rawKey) | Set-Content -Path $keyFile -NoNewline
  }
  $env:PQMSG_SQLITE_ENCRYPTION_KEY_B64 = (Get-Content -Path $keyFile -Raw).Trim()
} else {
  Remove-Item Env:PQMSG_SQLITE_ENCRYPTION_KEY_B64 -ErrorAction SilentlyContinue
}

Write-Host "Starting pqmsg-server for hosted web testing..." -ForegroundColor Cyan
Write-Host "  Bind: $($env:PQMSG_BIND)"
Write-Host "  DB:   $($env:PQMSG_DATABASE_URL)"
Write-Host "  Web policy: $($env:PQMSG_WEB_CLIENT_POLICY)"
Write-Host "  CORS: $($env:PQMSG_CORS_ALLOWED_ORIGINS)"

cargo run -p pqmsg-server --bin pqmsg-server --features pqmsg-core/pq-rust
