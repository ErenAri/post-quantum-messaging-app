[CmdletBinding()]
param(
  [string]$LocalUrl = "http://127.0.0.1:3000"
)

$ErrorActionPreference = "Stop"

$cloudflared = Get-Command cloudflared -ErrorAction SilentlyContinue
if (-not $cloudflared) {
  $fallback = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
  if (Test-Path $fallback) {
    $cloudflared = Get-Item $fallback
  } else {
    throw "cloudflared was not found on PATH and fallback '$fallback' does not exist."
  }
}
$cloudflareConfig = Join-Path $HOME ".cloudflared\config.yml"

if (Test-Path $cloudflareConfig) {
  Write-Warning "Quick Tunnels do not work when $cloudflareConfig exists. Rename it temporarily if this command fails."
}

Write-Host "Starting Cloudflare Quick Tunnel for $LocalUrl" -ForegroundColor Cyan
Write-Host "When cloudflared prints a https://*.trycloudflare.com URL, use that as your public relay URL."

& $cloudflared.FullName tunnel --url $LocalUrl
