# SmartScanner Deployment Script
# Copies required Qt DLLs and plugins after building

param(
    [string]$QtPath = "",
    [string]$BuildDir = "build"
)

$ErrorActionPreference = "Stop"

# Find Qt if not specified
if (-not $QtPath) {
    $possiblePaths = @(
        "C:\Qt\6.8.3\msvc2022_64",
        "C:\Qt\6.7.2\msvc2022_64",
        "$env:USERPROFILE\Qt\6.8.3\msvc2022_64"
    )
    foreach ($p in $possiblePaths) {
        if (Test-Path "$p\bin\Qt6Core.dll") {
            $QtPath = $p
            break
        }
    }
}

if (-not $QtPath -or -not (Test-Path $QtPath)) {
    Write-Error "Qt not found. Please specify -QtPath parameter."
    exit 1
}

$buildPath = Join-Path $PSScriptRoot $BuildDir
if (-not (Test-Path "$buildPath\sms.exe")) {
    Write-Error "Build not found in $buildPath. Run build.ps1 first."
    exit 1
}

Write-Host "Deploying from: $QtPath" -ForegroundColor Cyan
Write-Host "To: $buildPath" -ForegroundColor Cyan

# Required DLLs
$dlls = @(
    "Qt6Core.dll", "Qt6Gui.dll", "Qt6Widgets.dll", "Qt6Network.dll",
    "Qt6WebChannel.dll", "Qt6WebEngineCore.dll", "Qt6WebEngineWidgets.dll",
    "Qt6Xml.dll", "Qt6Quick.dll", "Qt6Qml.dll", "Qt6QmlModels.dll",
    "Qt6QmlWorkerScript.dll", "Qt6Positioning.dll", "Qt6PrintSupport.dll",
    "Qt6OpenGL.dll", "Qt6Svg.dll", "Qt6QmlMeta.dll", "Qt6QuickWidgets.dll"
)

Write-Host "`nCopying DLLs..." -ForegroundColor Yellow
foreach ($dll in $dlls) {
    $src = "$QtPath\bin\$dll"
    if (Test-Path $src) {
        Copy-Item $src $buildPath -Force
        Write-Host "  $dll" -ForegroundColor Gray
    }
}

# Plugins
$plugins = @(
    @{src="platforms\qwindows.dll"; dest="platforms"},
    @{src="tls\*"; dest="tls"},
    @{src="imageformats\*"; dest="imageformats"},
    @{src="iconengines\*"; dest="iconengines"}
)

Write-Host "`nCopying plugins..." -ForegroundColor Yellow
foreach ($p in $plugins) {
    $src = "$QtPath\plugins\$($p.src)"
    $dest = "$buildPath\$($p.dest)"
    if (Test-Path $src) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Copy-Item $src $dest -Force
        Write-Host "  $($p.dest)" -ForegroundColor Gray
    }
}

# WebEngine resources
Write-Host "`nCopying WebEngine resources..." -ForegroundColor Yellow
$weResources = @("resources", "translations")
foreach ($r in $weResources) {
    $src = "$QtPath\$r"
    if (Test-Path $src) {
        Copy-Item $src $buildPath -Recurse -Force
        Write-Host "  $r" -ForegroundColor Gray
    }
}

# QtWebEngineProcess
$weProcess = "$QtPath\bin\QtWebEngineProcess.exe"
if (Test-Path $weProcess) {
    Copy-Item $weProcess $buildPath -Force
    Write-Host "  QtWebEngineProcess.exe" -ForegroundColor Gray
}

Write-Host "`n=== DEPLOYMENT COMPLETE ===" -ForegroundColor Green
Write-Host "sms.exe and gui.exe are ready in: $buildPath" -ForegroundColor Cyan
