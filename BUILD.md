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

## Building Both x86 and x64

To build both architectures:

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
```

## Output Files

After building, you will have:

### DLL (for Python ctypes)
- `build/Release/ManualMapInjector-x64.dll` (x64 build)
- `build/Release/ManualMapInjector-x86.dll` (x86 build)

### Executable (command-line tool)
- `build/Release/Injector-x64.exe` (x64 build)
- `build/Release/Injector-x86.exe` (x86 build)

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
