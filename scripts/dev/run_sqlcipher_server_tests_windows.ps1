$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$prereqScript = Join-Path $scriptDir "check_sqlcipher_server_prereqs.ps1"

& $prereqScript -RunTests
