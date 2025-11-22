# Build Instructions

This document provides detailed instructions for building the Manual Map Injector as a DLL using CMake.

## Prerequisites

Before building, ensure you have the following installed:

1. **CMake** (version 3.15 or higher)
   - Download from: https://cmake.org/download/
   - Add CMake to your PATH during installation

2. **Visual Studio** (2019 or higher)
   - Required workload: "Desktop development with C++"
   - Download from: https://visualstudio.microsoft.com/downloads/

3. **Windows SDK**
   - Usually installed with Visual Studio
   - Minimum version: Windows 10 SDK

## Building the DLL

### Option 1: Using Visual Studio Developer Command Prompt (Recommended)

1. Open "Developer Command Prompt for VS 2019" (or your Visual Studio version)
   - Start Menu → Visual Studio 2019 → Developer Command Prompt

2. Navigate to the project directory:
   ```cmd
   cd path\to\Simple-Manual-Map-Injector
   ```

3. Create and enter build directory:
   ```cmd
   mkdir build
   cd build
   ```

4. Configure CMake (choose your architecture):
   
   **For x64:**
   ```cmd
   cmake .. -G "Visual Studio 16 2019" -A x64
   ```
   
   **For x86:**
   ```cmd
   cmake .. -G "Visual Studio 16 2019" -A Win32
   ```

5. Build the project:
   
   **Release build (recommended):**
   ```cmd
   cmake --build . --config Release
   ```
   
   **Debug build:**
   ```cmd
   cmake --build . --config Debug
   ```

6. Find your output files in `build/Release/` or `build/Debug/`:
   - `ManualMapInjector-x64.dll` (or x86 version)
   - `Injector-x64.exe` (CLI tool)

### Option 2: Using CMake GUI

1. Open CMake GUI
2. Set "Where is the source code" to the project root directory
3. Set "Where to build the binaries" to `project_root/build`
4. Click "Configure"
5. Select your Visual Studio version and platform (x64 or Win32)
6. Click "Generate"
7. Click "Open Project" to open in Visual Studio
8. Build using Visual Studio (Build → Build Solution)

### Option 3: Using Visual Studio Directly

1. Open the project folder in Visual Studio
2. Select CMake → Configure
3. Choose your configuration (Release/Debug, x64/Win32)
4. Build → Build All

## Building Both x86 and x64 (Recommended for Cross-Architecture Support)

The project now includes build scripts to build both architectures in one step:

### Using the Build Script (Windows)

```cmd
build_all.bat
```

This script will:
1. Build the x64 version (can inject into both 32-bit and 64-bit processes)
2. Build the x86 version (used as a helper for x64 when targeting 32-bit processes)
3. Copy all output files to the `build/` directory

Output files in `build/`:
- `Injector-x64.exe` - 64-bit injector with cross-architecture support
- `Injector-x86.exe` - 32-bit helper injector
- `ManualMapInjector-x64.dll` - 64-bit DLL for Python
- `ManualMapInjector-x86.dll` - 32-bit DLL for Python

**Important:** Keep both `Injector-x64.exe` and `Injector-x86.exe` in the same directory. The x64 injector will automatically use the x86 helper when targeting 32-bit processes.

### Manual Build (Advanced)

To build both architectures manually:

```cmd
# Build x64
mkdir build-x64
cd build-x64
cmake .. -G "Visual Studio 16 2019" -A x64
cmake --build . --config Release
cd ..

# Build x86
mkdir build-x86
cd build-x86
cmake .. -G "Visual Studio 16 2019" -A Win32
cmake --build . --config Release
cd ..

# Copy files to unified build directory
mkdir build
copy build-x64\Release\*.dll build\
copy build-x64\Release\*.exe build\
copy build-x86\Release\*.dll build\
copy build-x86\Release\*.exe build\
```

## Output Files

After building, you will have:

### Using build_all.bat (Recommended)
All files will be in the `build/` directory:
- `Injector-x64.exe` - **Main 64-bit injector** (supports both 32-bit and 64-bit targets)
- `Injector-x86.exe` - 32-bit helper (automatically used by x64 injector)
- `ManualMapInjector-x64.dll` - 64-bit DLL for Python
- `ManualMapInjector-x86.dll` - 32-bit DLL for Python

### Manual Build
Files will be in separate directories:

#### DLL (for Python ctypes)
- `build-x64/Release/ManualMapInjector-x64.dll` (x64 build)
- `build-x86/Release/ManualMapInjector-x86.dll` (x86 build)

#### Executable (command-line tool)
- `build-x64/Release/Injector-x64.exe` (x64 build with cross-architecture support)
- `build-x86/Release/Injector-x86.exe` (x86 build)

## Verifying the Build

To verify your DLL was built correctly:

1. Check the file exists:
   ```cmd
   dir build\Release\ManualMapInjector-x64.dll
   ```

2. Use `dumpbin` to verify exports:
   ```cmd
   dumpbin /EXPORTS build\Release\ManualMapInjector-x64.dll
   ```

   You should see:
   - `InjectDllFromMemory`
   - `InjectDllFromMemorySimple`

## Using with Python

After building, you can use the DLL with Python:

```python
import ctypes

# Load the DLL (use correct architecture)
injector = ctypes.CDLL("build/Release/ManualMapInjector-x64.dll")

# Read your DLL to inject
with open("target.dll", "rb") as f:
    dll_bytes = f.read()

# Setup and call
injector.InjectDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t
]
dll_array = (ctypes.c_ubyte * len(dll_bytes)).from_buffer_copy(dll_bytes)
result = injector.InjectDllFromMemorySimple(b"notepad.exe", dll_array, len(dll_bytes))
```

See `example_python.py` for a complete example.

## Troubleshooting

### "CMake not found"
- Ensure CMake is installed and in your PATH
- Restart your terminal after installation

### "Cannot open include file: 'Windows.h'"
- Install Visual Studio with "Desktop development with C++" workload
- Ensure Windows SDK is installed

### "Generator not found"
- Use the correct generator name for your Visual Studio version:
  - VS 2022: `"Visual Studio 17 2022"`
  - VS 2019: `"Visual Studio 16 2019"`
  - VS 2017: `"Visual Studio 15 2017"`

### "Architecture mismatch" when using Python
- Use x64 DLL with 64-bit Python
- Use x86 DLL with 32-bit Python
- Check your Python architecture: `python -c "import sys; print(sys.maxsize > 2**32)"`
  - True = 64-bit
  - False = 32-bit

### "x86 helper injector not found" when using Injector-x64.exe
- This happens when trying to inject into a 32-bit process
- Ensure `Injector-x86.exe` is in the same directory as `Injector-x64.exe`
- Use `build_all.bat` to build both versions automatically

### Build fails with optimization errors
- Try building in Debug mode first: `cmake --build . --config Debug`
- Disable optimizations in CMakeLists.txt if needed

## Clean Build

To perform a clean build:

```cmd
# Delete build directory
rmdir /s /q build

# Rebuild
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019" -A x64
cmake --build . --config Release
```

## Advanced: Custom Build Options

You can customize the build by editing `CMakeLists.txt`:

- Change optimization levels
- Add/remove compiler flags
- Add preprocessor definitions (e.g., `DISABLE_OUTPUT`)
- Modify output directories

## Notes

- The DLL requires administrator privileges to inject into processes
- Some antivirus software may flag the injector as malicious
- Use only on processes you own or have permission to modify
- Always match the architecture (x86/x64) between the injector, target process, and DLL
