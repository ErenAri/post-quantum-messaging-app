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

if (-not [string]::IsNullOrWhiteSpace($Repo)) {
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if ($null -eq $gh) {
        Write-Warning "gh CLI not found; skipping attestation verification"
        exit 0
    }
    & $gh.Source attestation verify (Join-Path $DistDir "pqmsg-server-linux-x86_64") -R $Repo
    & $gh.Source attestation verify (Join-Path $DistDir "release-manifest.json") -R $Repo
    & $gh.Source attestation verify (Join-Path $DistDir "sbom.tar.gz") -R $Repo
}
