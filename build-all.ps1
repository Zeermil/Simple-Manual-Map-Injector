# Universal Build Script for Manual Map Injector
# Builds both x86 and x64 versions automatically
# PowerShell version for modern Windows systems

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Manual Map Injector - Universal Build Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will build both x86 and x64 versions" -ForegroundColor Yellow
Write-Host ""

# Check if cmake is available
$cmakeExists = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmakeExists) {
    Write-Host "ERROR: CMake is not found in PATH" -ForegroundColor Red
    Write-Host "Please install CMake and add it to your PATH" -ForegroundColor Red
    Write-Host "Download from: https://cmake.org/download/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Determine Visual Studio version
$vsGenerator = "Visual Studio 16 2019"
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -property installationPath
    if ($vsPath -match "2022") {
        $vsGenerator = "Visual Studio 17 2022"
        Write-Host "Detected Visual Studio 2022" -ForegroundColor Green
    } elseif ($vsPath -match "2019") {
        Write-Host "Detected Visual Studio 2019" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Could not detect Visual Studio version" -ForegroundColor Yellow
        Write-Host "Using default: Visual Studio 16 2019" -ForegroundColor Yellow
    }
} else {
    Write-Host "WARNING: Could not detect Visual Studio version" -ForegroundColor Yellow
    Write-Host "Using default: Visual Studio 16 2019" -ForegroundColor Yellow
}
Write-Host ""

# Clean previous builds
Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
Remove-Item -Path "build-x86" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "build-x64" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "bin" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""

# Build x64 version
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Building x64 version..." -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

New-Item -ItemType Directory -Path "build-x64" | Out-Null
Set-Location "build-x64"

cmake .. -G $vsGenerator -A x64
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: CMake configuration failed for x64" -ForegroundColor Red
    Set-Location ..
    Read-Host "Press Enter to exit"
    exit 1
}

cmake --build . --config Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed for x64" -ForegroundColor Red
    Set-Location ..
    Read-Host "Press Enter to exit"
    exit 1
}

Set-Location ..
Write-Host "x64 build completed successfully!" -ForegroundColor Green
Write-Host ""

# Build x86 version
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Building x86 version..." -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

New-Item -ItemType Directory -Path "build-x86" | Out-Null
Set-Location "build-x86"

cmake .. -G $vsGenerator -A Win32
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: CMake configuration failed for x86" -ForegroundColor Red
    Set-Location ..
    Read-Host "Press Enter to exit"
    exit 1
}

cmake --build . --config Release
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed for x86" -ForegroundColor Red
    Set-Location ..
    Read-Host "Press Enter to exit"
    exit 1
}

Set-Location ..
Write-Host "x86 build completed successfully!" -ForegroundColor Green
Write-Host ""

# Copy outputs to bin directory
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Organizing output files..." -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

New-Item -ItemType Directory -Path "bin" -Force | Out-Null

# Copy x64 outputs
if (Test-Path "build-x64\Release\*.dll") {
    Copy-Item -Path "build-x64\Release\*.dll" -Destination "bin\"
}
if (Test-Path "build-x64\Release\*.exe") {
    Copy-Item -Path "build-x64\Release\*.exe" -Destination "bin\"
}

# Copy x86 outputs
if (Test-Path "build-x86\Release\*.dll") {
    Copy-Item -Path "build-x86\Release\*.dll" -Destination "bin\"
}
if (Test-Path "build-x86\Release\*.exe") {
    Copy-Item -Path "build-x86\Release\*.exe" -Destination "bin\"
}

Write-Host ""

# List output files
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Build Complete! Output files:" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Get-ChildItem "bin\" | ForEach-Object { Write-Host $_.Name -ForegroundColor Yellow }
Write-Host ""
Write-Host "All files are located in the 'bin' directory" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit"
