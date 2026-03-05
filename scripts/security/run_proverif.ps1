Param(
    [string]$ModelPath = "verification/proverif/pqxdh_hybrid_model.pv"
)

$proverif = Get-Command proverif -ErrorAction SilentlyContinue
if (-not $proverif) {
    Write-Error "proverif executable not found in PATH"
    exit 1
}

& $proverif.Source $ModelPath
