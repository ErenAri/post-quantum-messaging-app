param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("promotion", "rollback")]
    [string]$BundleKind,
    [Parameter(Mandatory = $true)]
    [string]$DistDir,
    [string]$Repo
)

$ErrorActionPreference = "Stop"

$args = @(
    "scripts/release/verify_workflow_bundle.py",
    "--bundle-kind",
    $BundleKind,
    "--dist-dir",
    $DistDir
)

if (-not [string]::IsNullOrWhiteSpace($Repo)) {
    $args += @("--repo", $Repo)
}

python @args
