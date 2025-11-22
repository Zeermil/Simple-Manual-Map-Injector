@echo off
REM Build script for creating both x86 and x64 versions of Manual Map Injector

echo ========================================
echo Building Manual Map Injector
echo ========================================
echo.

REM Clean up old build directories
if exist build-x64 rmdir /s /q build-x64
if exist build-x86 rmdir /s /q build-x86
if exist build rmdir /s /q build

REM Create output directory
if not exist build mkdir build

echo ========================================
echo Building x64 version...
echo ========================================
mkdir build-x64
cd build-x64
cmake .. -G "Visual Studio 16 2019" -A x64
if errorlevel 1 (
    echo Failed to configure x64 build
    cd ..
    pause
    exit /b 1
)
cmake --build . --config Release
if errorlevel 1 (
    echo Failed to build x64 version
    cd ..
    pause
    exit /b 1
)
cd ..

echo.
echo ========================================
echo Building x86 version...
echo ========================================
mkdir build-x86
cd build-x86
cmake .. -G "Visual Studio 16 2019" -A Win32
if errorlevel 1 (
    echo Failed to configure x86 build
    cd ..
    pause
    exit /b 1
)
cmake --build . --config Release
if errorlevel 1 (
    echo Failed to build x86 version
    cd ..
    pause
    exit /b 1
)
cd ..

echo.
echo ========================================
echo Copying output files...
echo ========================================

REM Copy x64 files
copy build-x64\Release\ManualMapInjector-x64.dll build\ >nul
copy build-x64\Release\Injector-x64.exe build\ >nul

REM Copy x86 files
copy build-x86\Release\ManualMapInjector-x86.dll build\ >nul
copy build-x86\Release\Injector-x86.exe build\ >nul

echo.
echo ========================================
echo Build complete!
echo ========================================
echo Output files in build\ directory:
dir build\*.dll build\*.exe
echo.
echo The x64 injector (Injector-x64.exe) can now inject into both
echo 32-bit and 64-bit processes. It will automatically use the
echo x86 helper (Injector-x86.exe) when targeting 32-bit processes.
echo.
echo Make sure to keep both Injector-x64.exe and Injector-x86.exe
echo in the same directory for cross-architecture injection to work.
echo.
pause
