#!/bin/bash
# Build script for creating both x86 and x64 versions of Manual Map Injector
# Note: This script requires MinGW cross-compiler or WSL with Visual Studio
# to build Windows executables on Linux/macOS

echo "========================================"
echo "Building Manual Map Injector"
echo "========================================"
echo ""

# Clean up old build directories
rm -rf build-x64
rm -rf build-x86
rm -rf build

# Create output directory
mkdir -p build

echo "========================================"
echo "Building x64 version..."
echo "========================================"
mkdir build-x64
cd build-x64
cmake .. -G "Visual Studio 16 2019" -A x64
if [ $? -ne 0 ]; then
    echo "Failed to configure x64 build"
    cd ..
    exit 1
fi
cmake --build . --config Release
if [ $? -ne 0 ]; then
    echo "Failed to build x64 version"
    cd ..
    exit 1
fi
cd ..

echo ""
echo "========================================"
echo "Building x86 version..."
echo "========================================"
mkdir build-x86
cd build-x86
cmake .. -G "Visual Studio 16 2019" -A Win32
if [ $? -ne 0 ]; then
    echo "Failed to configure x86 build"
    cd ..
    exit 1
fi
cmake --build . --config Release
if [ $? -ne 0 ]; then
    echo "Failed to build x86 version"
    cd ..
    exit 1
fi
cd ..

echo ""
echo "========================================"
echo "Copying output files..."
echo "========================================"

# Copy x64 files (check if they exist first)
if [ -f build-x64/Release/ManualMapInjector-x64.dll ]; then
    cp build-x64/Release/ManualMapInjector-x64.dll build/
    cp build-x64/Release/Injector-x64.exe build/
else
    echo "Warning: x64 output files not found in expected location"
    echo "This script requires MinGW or Visual Studio to build Windows executables"
fi

# Copy x86 files (check if they exist first)
if [ -f build-x86/Release/ManualMapInjector-x86.dll ]; then
    cp build-x86/Release/ManualMapInjector-x86.dll build/
    cp build-x86/Release/Injector-x86.exe build/
else
    echo "Warning: x86 output files not found in expected location"
    echo "This script requires MinGW or Visual Studio to build Windows executables"
fi

echo ""
echo "========================================"
echo "Build complete!"
echo "========================================"
echo "Output files in build/ directory:"
if ls build/*.dll build/*.exe 2>/dev/null; then
    ls -lh build/*.dll build/*.exe
else
    echo "Warning: No output files found. Build may have failed."
fi
echo ""
echo "The x64 injector (Injector-x64.exe) can now inject into both"
echo "32-bit and 64-bit processes. It will automatically use the"
echo "x86 helper (Injector-x86.exe) when targeting 32-bit processes."
echo ""
echo "Make sure to keep both Injector-x64.exe and Injector-x86.exe"
echo "in the same directory for cross-architecture injection to work."
echo ""
