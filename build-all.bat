@echo off
REM Universal Build Script for Manual Map Injector
REM Builds both x86 and x64 versions automatically

echo ================================================
echo Manual Map Injector - Universal Build Script
echo ================================================
echo.
echo This script will build both x86 and x64 versions
echo.

REM Check if cmake is available
where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake is not found in PATH
    echo Please install CMake and add it to your PATH
    echo Download from: https://cmake.org/download/
    pause
    exit /b 1
)

REM Determine Visual Studio version
set VS_GENERATOR="Visual Studio 16 2019"
where devenv 2>nul | findstr "2022" >nul
if %ERRORLEVEL% EQU 0 (
    set VS_GENERATOR="Visual Studio 17 2022"
    echo Detected Visual Studio 2022
) else (
    where devenv 2>nul | findstr "2019" >nul
    if %ERRORLEVEL% EQU 0 (
        echo Detected Visual Studio 2019
    ) else (
        echo WARNING: Could not detect Visual Studio version
        echo Using default: Visual Studio 16 2019
        echo.
    )
)

REM Clean previous builds
echo Cleaning previous builds...
if exist build-x86 rmdir /s /q build-x86
if exist build-x64 rmdir /s /q build-x64
if exist bin rmdir /s /q bin
echo.

REM Build x64 version
echo ================================================
echo Building x64 version...
echo ================================================
mkdir build-x64
cd build-x64
cmake .. -G %VS_GENERATOR% -A x64
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configuration failed for x64
    cd ..
    pause
    exit /b 1
)

cmake --build . --config Release
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed for x64
    cd ..
    pause
    exit /b 1
)
cd ..
echo x64 build completed successfully!
echo.

REM Build x86 version
echo ================================================
echo Building x86 version...
echo ================================================
mkdir build-x86
cd build-x86
cmake .. -G %VS_GENERATOR% -A Win32
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configuration failed for x86
    cd ..
    pause
    exit /b 1
)

cmake --build . --config Release
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed for x86
    cd ..
    pause
    exit /b 1
)
cd ..
echo x86 build completed successfully!
echo.

REM Copy outputs to bin directory
echo ================================================
echo Organizing output files...
echo ================================================
mkdir bin 2>nul
if exist build-x64\Release\*.dll copy build-x64\Release\*.dll bin\ >nul
if exist build-x64\Release\*.exe copy build-x64\Release\*.exe bin\ >nul
if exist build-x86\Release\*.dll copy build-x86\Release\*.dll bin\ >nul
if exist build-x86\Release\*.exe copy build-x86\Release\*.exe bin\ >nul
echo.

REM List output files
echo ================================================
echo Build Complete! Output files:
echo ================================================
dir /b bin\
echo.
echo All files are located in the 'bin' directory
echo ================================================
echo.
pause
