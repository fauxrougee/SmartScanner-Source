# SmartScanner Build Script for Windows
# Usage: .\build.ps1 [-QtPath "C:\Qt\6.8.3\msvc2022_64"] [-BuildType Release]

param(
    [string]$QtPath = "",
    [string]$BuildType = "Release"
)

$ErrorActionPreference = "Stop"

# Find Qt if not specified
if (-not $QtPath) {
    $possiblePaths = @(
        "C:\Qt\6.8.3\msvc2022_64",
        "C:\Qt\6.7.2\msvc2022_64",
        "C:\Qt\6.6.0\msvc2022_64",
        "$env:USERPROFILE\Qt\6.8.3\msvc2022_64"
    )
    foreach ($p in $possiblePaths) {
        if (Test-Path "$p\bin\qmake.exe") {
            $QtPath = $p
            break
        }
    }
}

if (-not $QtPath -or -not (Test-Path $QtPath)) {
    Write-Error "Qt not found. Please specify -QtPath parameter."
    exit 1
}

Write-Host "Using Qt: $QtPath" -ForegroundColor Cyan
Write-Host "Build type: $BuildType" -ForegroundColor Cyan

# Set up environment
$env:CMAKE_PREFIX_PATH = $QtPath
$env:PATH = "$QtPath\bin;$env:PATH"

# Create build directory
$buildDir = Join-Path $PSScriptRoot "build"
if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

Push-Location $buildDir

try {
    # Configure
    Write-Host "`nConfiguring..." -ForegroundColor Yellow
    cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=$BuildType
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed" }

    # Build
    Write-Host "`nBuilding..." -ForegroundColor Yellow
    cmake --build . --config $BuildType
    if ($LASTEXITCODE -ne 0) { throw "Build failed" }

    # Show results
    Write-Host "`n=== BUILD SUCCESSFUL ===" -ForegroundColor Green
    $sms = Get-Item "sms.exe" -ErrorAction SilentlyContinue
    $gui = Get-Item "gui.exe" -ErrorAction SilentlyContinue
    if ($sms) { Write-Host "sms.exe: $($sms.Length) bytes" }
    if ($gui) { Write-Host "gui.exe: $($gui.Length) bytes" }
    Write-Host "`nExecutables are in: $buildDir" -ForegroundColor Cyan

} finally {
    Pop-Location
}
