[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ApiBaseUrl,
  [string]$WorkingDir = "tmp/ec2-backup-smoke",
  [switch]$KeepArtifacts
)

$ErrorActionPreference = "Stop"

function Invoke-ExternalChecked {
  param(
    [string]$Description,
    [scriptblock]$Action
  )
  Write-Host $Description -ForegroundColor Cyan
  & $Action
  if ($LASTEXITCODE -ne 0) {
    throw "Failed: $Description"
  }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
  throw "cargo was not found in PATH. Install Rust toolchain first."
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "node was not found in PATH. Install Node.js first."
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Push-Location $repoRoot

try {
  $apiUri = [Uri]$ApiBaseUrl
  if (-not $apiUri.Scheme.StartsWith("http")) {
    throw "ApiBaseUrl must start with http:// or https://"
  }

  $workingDirAbs = Join-Path $repoRoot $WorkingDir
  New-Item -ItemType Directory -Force -Path $workingDirAbs | Out-Null

  $stamp = Get-Date -Format "yyyyMMddHHmmss"
  $user = "smoke$stamp"
  $device = "$user-dev-1"
  $keysPath = Join-Path $workingDirAbs ("keys-" + $user + ".json")
  $nodeScriptPath = Join-Path $workingDirAbs "backup-roundtrip-check.mjs"

  Invoke-ExternalChecked -Description "Generating smoke-test keys" -Action {
    cargo run -p pqmsg-cli -- --server $ApiBaseUrl --security-profile research keygen --user $user --out $keysPath --suite ml-kem-768 --one-time-count 2 --device-id $device
  }

  Invoke-ExternalChecked -Description "Registering smoke-test user" -Action {
    cargo run -p pqmsg-cli -- --server $ApiBaseUrl --security-profile research register --user $user --keys $keysPath
  }

  @'
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, sign } from "node:crypto";

const [server, keysPath] = process.argv.slice(2);
if (!server || !keysPath) {
  throw new Error("usage: node backup-roundtrip-check.mjs <server> <keysPath>");
}

const keys = JSON.parse(readFileSync(keysPath, "utf8"));
const userId = keys.user_id;
const deviceId = keys.device_id;
const backupVersion = 1;
const backupBytes = Buffer.from(JSON.stringify({ kind: "backup-smoke", userId, ts: Date.now() }), "utf8");
const backupBase64 = backupBytes.toString("base64");

const healthResp = await fetch(`${server}/health`);
if (!healthResp.ok) {
  throw new Error(`health check failed: HTTP ${healthResp.status}`);
}

const timestamp = Math.floor(Date.now() / 1000).toString();
const nonce = `backups-upload-${Date.now().toString(36)}`;
const blobHash = createHash("sha256").update(backupBytes).digest("hex");
const message = `backups-upload:${userId}:${deviceId}:${timestamp}:${nonce}:${backupVersion}:${blobHash}`;

const seed = Buffer.from(keys.identity_sig_secret_b64, "base64");
if (seed.length !== 32) {
  throw new Error(`identity_sig_secret_b64 decoded length ${seed.length} != 32`);
}
const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const privateKey = createPrivateKey({
  key: Buffer.concat([pkcs8Prefix, seed]),
  format: "der",
  type: "pkcs8",
});
const signature = sign(null, Buffer.from(message, "utf8"), privateKey).toString("base64");

const uploadResp = await fetch(`${server}/v1/users/${encodeURIComponent(userId)}/backups`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-pqmsg-auth-user": userId,
    "x-pqmsg-auth-device": deviceId,
    "x-pqmsg-auth-timestamp": timestamp,
    "x-pqmsg-auth-nonce": nonce,
    "x-pqmsg-auth-signature": signature,
  },
  body: JSON.stringify({
    device_id: deviceId,
    backup_version: backupVersion,
    recovery_hint: deviceId,
    encrypted_backup_bytes_base64: backupBase64,
  }),
});
const uploadText = await uploadResp.text();
if (!uploadResp.ok) {
  throw new Error(`backup upload failed: HTTP ${uploadResp.status} ${uploadText}`);
}
const uploadJson = JSON.parse(uploadText);

const recoveryResp = await fetch(`${server}/v1/users/${encodeURIComponent(userId)}/backups/recovery`, {
  method: "GET",
});
const recoveryText = await recoveryResp.text();
if (!recoveryResp.ok) {
  throw new Error(`recovery download failed: HTTP ${recoveryResp.status} ${recoveryText}`);
}
const recoveryJson = JSON.parse(recoveryText);

if (recoveryJson.encrypted_backup_bytes_base64 !== backupBase64) {
  throw new Error("recovery payload mismatch");
}

console.log(JSON.stringify({
  smoke_user: userId,
  smoke_device: deviceId,
  upload_status: uploadResp.status,
  recovery_status: recoveryResp.status,
  backup_id: uploadJson.backup_id,
  uploaded_version: uploadJson.backup_version,
  recovered_version: recoveryJson.backup_version,
}, null, 2));
'@ | Set-Content -Path $nodeScriptPath -Encoding utf8

  Invoke-ExternalChecked -Description "Running backup upload/recovery smoke roundtrip" -Action {
    node $nodeScriptPath $ApiBaseUrl $keysPath
  }

  Write-Host "Backup recovery smoke check passed." -ForegroundColor Green
  Write-Output "SMOKE_API_BASE_URL=$ApiBaseUrl"
  Write-Output "SMOKE_USER=$user"
  Write-Output "SMOKE_DEVICE=$device"
  Write-Output "SMOKE_KEYS_FILE=$keysPath"
} finally {
  Pop-Location
  if (-not $KeepArtifacts) {
    Remove-Item -Path (Join-Path $repoRoot $WorkingDir) -Recurse -Force -ErrorAction SilentlyContinue
  }
}
