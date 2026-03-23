param(
    [Parameter(Mandatory = $true)]
    [string]$PromotionRunId,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseTag,
    [Parameter(Mandatory = $true)]
    [string]$DeploymentMode,
    [Parameter(Mandatory = $true)]
    [string]$DistDir,
    [string]$Repo
)

$ErrorActionPreference = "Stop"

$gh = Get-Command gh -ErrorAction SilentlyContinue
if ($null -eq $gh) {
    throw "gh CLI not found"
}

$artifactName = "promotion-bundle-$ReleaseTag-$DeploymentMode"
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$args = @(
    "run",
    "download",
    $PromotionRunId,
    "--dir",
    $DistDir,
    "--name",
    $artifactName
)

if (-not [string]::IsNullOrWhiteSpace($Repo)) {
    $args += @("-R", $Repo)
}

& $gh.Source @args
