param(
    [Parameter(Mandatory = $true)]
    [string]$DistDir,
    [string]$Repo
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $DistDir -PathType Container)) {
    throw "release dist directory not found: $DistDir"
}

$requiredFiles = @(
    "pqmsg-server-linux-x86_64",
    "sbom.tar.gz",
    "release-manifest.json",
    "release-security-posture.json",
    "container-image.txt",
    "helm-image-overrides.yaml",
    "checksums.txt"
)

foreach ($file in $requiredFiles) {
    $path = Join-Path $DistDir $file
    if (-not (Test-Path $path -PathType Leaf)) {
        throw "missing release artifact: $path"
    }
}

$checksumsPath = Join-Path $DistDir "checksums.txt"
$lines = Get-Content $checksumsPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
foreach ($line in $lines) {
    if ($line -notmatch '^(?<hash>[0-9a-fA-F]{64})[ *](?<path>.+)$') {
        throw "invalid checksum line: $line"
    }
    $expected = $Matches["hash"].ToLowerInvariant()
    $relativePath = $Matches["path"].Trim()
    if ($relativePath.StartsWith("dist/")) {
        $relativePath = $relativePath.Substring(5)
    }
    $artifactPath = Join-Path $DistDir $relativePath
    if (-not (Test-Path $artifactPath -PathType Leaf)) {
        throw "checksum entry points to missing file: $artifactPath"
    }
    $actual = (Get-FileHash $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "checksum mismatch for $artifactPath"
    }
}

$manifestPath = Join-Path $DistDir "release-manifest.json"
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
if ($null -eq $manifest.container_images -or $manifest.container_images.Count -lt 1) {
    throw "release manifest does not contain any container image records"
}
foreach ($image in $manifest.container_images) {
    if ([string]::IsNullOrWhiteSpace($image.name)) {
        throw "release manifest container image is missing name"
    }
    if ([string]::IsNullOrWhiteSpace($image.digest) -or $image.digest -notmatch '^sha256:[0-9a-fA-F]{64}$') {
        throw "release manifest container image has invalid digest: $($image.digest)"
    }
    $expectedRef = "$($image.name)@$($image.digest)"
    if ($image.immutable_ref -ne $expectedRef) {
        throw "release manifest container image has invalid immutable_ref: $($image.immutable_ref)"
    }
}

$containerImagePath = Join-Path $DistDir "container-image.txt"
$containerImageRef = (Get-Content $containerImagePath -Raw).Trim()
if ($containerImageRef -ne $manifest.container_images[0].immutable_ref) {
    throw "container-image.txt does not match release manifest immutable_ref"
}

$helmOverridesPath = Join-Path $DistDir "helm-image-overrides.yaml"
$helmOverrides = Get-Content $helmOverridesPath -Raw
if ($helmOverrides -notmatch [regex]::Escape("repository: $($manifest.container_images[0].name)")) {
    throw "helm-image-overrides.yaml does not contain the manifest image repository"
}
if ($helmOverrides -notmatch [regex]::Escape("digest: $($manifest.container_images[0].digest)")) {
    throw "helm-image-overrides.yaml does not contain the manifest image digest"
}

$posturePath = Join-Path $DistDir "release-security-posture.json"
$posture = Get-Content $posturePath -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($posture.support_matrix.path) -or [string]::IsNullOrWhiteSpace($posture.support_matrix.sha256)) {
    throw "release-security-posture.json is missing support matrix evidence"
}
if ([string]::IsNullOrWhiteSpace($posture.audit_findings.path) -or [string]::IsNullOrWhiteSpace($posture.audit_findings.sha256)) {
    throw "release-security-posture.json is missing audit findings evidence"
}
if ($null -eq $posture.release_audit_gate -or $null -eq $posture.release_audit_gate.blocking_findings) {
    throw "release-security-posture.json is missing release audit gate details"
}
if ($posture.release_audit_gate.blocking_findings.Count -ne 0) {
    throw "release-security-posture.json contains blocking release audit findings"
}

if (-not [string]::IsNullOrWhiteSpace($Repo)) {
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if ($null -eq $gh) {
        Write-Warning "gh CLI not found; skipping attestation verification"
        exit 0
    }
    & $gh.Source attestation verify (Join-Path $DistDir "pqmsg-server-linux-x86_64") -R $Repo
    & $gh.Source attestation verify (Join-Path $DistDir "release-manifest.json") -R $Repo
    & $gh.Source attestation verify (Join-Path $DistDir "release-security-posture.json") -R $Repo
    & $gh.Source attestation verify (Join-Path $DistDir "sbom.tar.gz") -R $Repo
}
