$ErrorActionPreference = "Stop"

param(
    [string]$DatabaseUrl = $env:PQMSG_DATABASE_URL,
    [string]$FromKeyB64 = $env:PQMSG_SQLITE_ROTATE_FROM_KEY_B64,
    [string]$ToKeyB64 = $env:PQMSG_SQLITE_ENCRYPTION_KEY_B64,
    [Nullable[int]]$CipherCompatibility,
    [Nullable[int]]$CipherPageSize,
    [switch]$GenerateTargetKey
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$prereqScript = Join-Path $scriptDir "check_sqlcipher_server_prereqs.ps1"

if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) {
    throw "Provide -DatabaseUrl or set PQMSG_DATABASE_URL."
}
if ([string]::IsNullOrWhiteSpace($FromKeyB64)) {
    throw "Provide -FromKeyB64 or set PQMSG_SQLITE_ROTATE_FROM_KEY_B64."
}
if ($GenerateTargetKey.IsPresent -and -not [string]::IsNullOrWhiteSpace($ToKeyB64)) {
    throw "Use either -GenerateTargetKey or -ToKeyB64, not both."
}
if ($GenerateTargetKey.IsPresent) {
    $raw = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($raw)
    $ToKeyB64 = [Convert]::ToBase64String($raw)
}
if ([string]::IsNullOrWhiteSpace($ToKeyB64)) {
    throw "Provide -ToKeyB64, set PQMSG_SQLITE_ENCRYPTION_KEY_B64, or use -GenerateTargetKey."
}

& $prereqScript

$args = @(
    "run", "-p", "pqmsg-server", "--bin", "sqlite_rotate_key", "--",
    "--database-url", $DatabaseUrl,
    "--from-key-b64", $FromKeyB64,
    "--to-key-b64", $ToKeyB64
)
if ($CipherCompatibility -ne $null) {
    $args += @("--cipher-compatibility", $CipherCompatibility.ToString())
}
if ($CipherPageSize -ne $null) {
    $args += @("--cipher-page-size", $CipherPageSize.ToString())
}

Write-Host "Running offline SQLite SQLCipher key rotation..."
Write-Host "Database URL: $DatabaseUrl"
cargo @args

Write-Host ""
Write-Host "Rotation finished. Update the server secret/config to use only the new key:"
Write-Host "PQMSG_SQLITE_ENCRYPTION_KEY_B64=$ToKeyB64"
