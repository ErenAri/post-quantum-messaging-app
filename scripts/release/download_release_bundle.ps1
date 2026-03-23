param(
    [Parameter(Mandatory = $true)]
    [string]$ReleaseTag,
    [Parameter(Mandatory = $true)]
    [string]$DistDir,
    [string]$Repo
)

$ErrorActionPreference = "Stop"

$gh = Get-Command gh -ErrorAction SilentlyContinue
if ($null -eq $gh) {
    throw "gh CLI not found"
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$args = @(
    "release",
    "download",
    $ReleaseTag,
    "--dir",
    $DistDir,
    "--clobber",
    "--pattern",
    "pqmsg-server-linux-x86_64",
    "--pattern",
    "sbom.tar.gz",
    "--pattern",
    "release-manifest.json",
    "--pattern",
    "container-image.txt",
    "--pattern",
    "helm-image-overrides.yaml",
    "--pattern",
    "checksums.txt",
    "--pattern",
    "checksums.txt.sig",
    "--pattern",
    "checksums.txt.pem"
)

if (-not [string]::IsNullOrWhiteSpace($Repo)) {
    $args += @("-R", $Repo)
}

& $gh.Source @args
