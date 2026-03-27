param(
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"

function Test-CommandAvailable {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Resolve-PerlPath {
    if (Test-CommandAvailable "perl") {
        $commandPath = (Get-Command perl).Source
        if ($commandPath -like "C:\Strawberry\*") {
            return $commandPath
        }
    }
    $candidates = @(
        "C:\Strawberry\perl\bin\perl.exe",
        "C:\Program Files\Git\usr\bin\perl.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    if (Test-CommandAvailable "perl") {
        return (Get-Command perl).Source
    }
    return $null
}

function Resolve-VcVarsPath {
    if (Test-CommandAvailable "vswhere") {
        $vsInstallPath = & vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if (-not [string]::IsNullOrWhiteSpace($vsInstallPath)) {
            $candidate = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvars64.bat"
            if (Test-Path $candidate) {
                return $candidate
            }
        }
    }
    $candidates = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    return $null
}

function Write-CheckResult {
    param(
        [string]$Label,
        [bool]$Ok,
        [string]$Detail
    )
    $status = if ($Ok) { "OK" } else { "MISSING" }
    Write-Host ("[{0}] {1}: {2}" -f $status, $Label, $Detail)
}

$windowsOs = $env:OS -eq "Windows_NT"
$macOs = $IsMacOS
$linuxOs = $IsLinux

if ($windowsOs) {
    Write-Host "Checking Windows SQLCipher server prerequisites (vendored OpenSSL path)..."

    $perlPath = Resolve-PerlPath
    $vcvarsPath = Resolve-VcVarsPath
    $perlOk = -not [string]::IsNullOrWhiteSpace($perlPath)
    $clOk = Test-CommandAvailable "cl"
    $nmakeOk = Test-CommandAvailable "nmake"
    $nasmOk = Test-CommandAvailable "nasm"

    if ((-not $clOk -or -not $nmakeOk) -and -not [string]::IsNullOrWhiteSpace($vcvarsPath)) {
        $vsProbe = & cmd /c "call `"$vcvarsPath`" >nul && where cl && where nmake" 2>$null
        $clOk = $LASTEXITCODE -eq 0
        $nmakeOk = $LASTEXITCODE -eq 0
    }

    Write-CheckResult "perl" $perlOk ($(if ($perlOk) { $perlPath } else { "required by vendored OpenSSL build" }))
    Write-CheckResult "vcvars64.bat" (-not [string]::IsNullOrWhiteSpace($vcvarsPath)) ($(if ($vcvarsPath) { $vcvarsPath } else { "used to surface MSVC build tools" }))
    Write-CheckResult "cl.exe" $clOk "required for MSVC native compilation"
    Write-CheckResult "nmake" $nmakeOk "used by OpenSSL build tooling on MSVC"
    Write-CheckResult "nasm" $nasmOk "optional; enables OpenSSL assembly optimizations"

    if (-not $perlOk -or -not $clOk -or -not $nmakeOk) {
        throw @"
Missing Windows SQLCipher prerequisites.

Install or ensure availability of:
- Strawberry Perl (or another perl distribution on PATH)
- Visual Studio C++ build tools / Developer PowerShell providing cl.exe and nmake
- nasm is optional but recommended for faster OpenSSL builds
"@
    }
} elseif ($linuxOs) {
    Write-Host "Checking Linux SQLCipher server prerequisites..."

    $pkgConfigOk = Test-CommandAvailable "pkg-config"
    $perlOk = Test-CommandAvailable "perl"
    $makeOk = Test-CommandAvailable "make"
    $opensslPkgOk = $false
    if ($pkgConfigOk) {
        & pkg-config --exists openssl
        $opensslPkgOk = $LASTEXITCODE -eq 0
    }

    Write-CheckResult "pkg-config" $pkgConfigOk "required for OpenSSL discovery"
    Write-CheckResult "perl" $perlOk "needed if vendored OpenSSL is used"
    Write-CheckResult "make" $makeOk "build prerequisite"
    Write-CheckResult "openssl pkg-config" $opensslPkgOk "requires OpenSSL development package"

    if (-not $pkgConfigOk -or -not $makeOk -or -not $opensslPkgOk) {
        throw "Missing Linux SQLCipher prerequisites. Install pkg-config, perl, make, and OpenSSL development headers/libs."
    }
} elseif ($macOs) {
    Write-Host "Checking macOS SQLCipher server prerequisites..."

    $brewOk = Test-CommandAvailable "brew"
    $perlOk = Test-CommandAvailable "perl"
    $makeOk = Test-CommandAvailable "make"
    $opensslPrefix = ""
    if ($brewOk) {
        $opensslPrefix = & brew --prefix openssl@3 2>$null
    }
    $opensslOk = -not [string]::IsNullOrWhiteSpace($opensslPrefix)

    Write-CheckResult "brew" $brewOk "used to install OpenSSL"
    Write-CheckResult "perl" $perlOk "needed if vendored OpenSSL is used"
    Write-CheckResult "make" $makeOk "build prerequisite"
    Write-CheckResult "openssl@3" $opensslOk "expected via Homebrew"

    if (-not $brewOk -or -not $makeOk -or -not $opensslOk) {
        throw "Missing macOS SQLCipher prerequisites. Install Homebrew openssl@3, perl, and make."
    }
} else {
    Write-Host "Unknown platform; skipping SQLCipher prerequisite checks."
}

if ($RunTests) {
    if ($windowsOs) {
        $perlDir = Split-Path -Parent (Resolve-PerlPath)
        $vcvarsPath = Resolve-VcVarsPath
        if (-not $vcvarsPath) {
            throw "vcvars64.bat not found"
        }
        & cmd /c "set PATH=$perlDir;%PATH% && call `"$vcvarsPath`" >nul && cargo test -p pqmsg-server db::tests::sqlite_ --lib"
        exit $LASTEXITCODE
    }
    cargo test -p pqmsg-server db::tests::sqlite_ --lib
}
