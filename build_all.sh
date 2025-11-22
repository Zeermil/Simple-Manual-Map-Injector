#!/bin/bash
# Build script for creating both x86 and x64 versions of Manual Map Injector

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

# Copy x64 files
cp build-x64/Release/ManualMapInjector-x64.dll build/
cp build-x64/Release/Injector-x64.exe build/

# Copy x86 files
cp build-x86/Release/ManualMapInjector-x86.dll build/
cp build-x86/Release/Injector-x86.exe build/

echo ""
echo "========================================"
echo "Build complete!"
echo "========================================"
echo "Output files in build/ directory:"
ls -lh build/*.dll build/*.exe
echo ""
echo "The x64 injector (Injector-x64.exe) can now inject into both"
echo "32-bit and 64-bit processes. It will automatically use the"
echo "x86 helper (Injector-x86.exe) when targeting 32-bit processes."
echo ""
echo "Make sure to keep both Injector-x64.exe and Injector-x86.exe"
echo "in the same directory for cross-architecture injection to work."
echo ""
