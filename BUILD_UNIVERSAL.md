# Universal Build Guide

This guide explains how to build the injector for both x86 and x64 architectures automatically.

## Quick Start - Universal Build

The easiest way to build for both architectures is using the provided build scripts:

### Option 1: Batch Script (Windows)

```cmd
build-all.bat
```

This will:
- Automatically detect your Visual Studio version
- Build both x86 and x64 versions
- Create a `bin` directory with all outputs:
  - `ManualMapInjector-x64.dll` - DLL for 64-bit processes
  - `ManualMapInjector-x86.dll` - DLL for 32-bit processes
  - `Injector-x64.exe` - CLI tool for 64-bit processes
  - `Injector-x86.exe` - CLI tool for 32-bit processes
  - `UniversalInjector.exe` - Smart launcher that auto-detects target architecture

### Option 2: PowerShell Script (Recommended for Windows 10/11)

```powershell
.\build-all.ps1
```

Same functionality as the batch script but with colored output and better error handling.

## Using the Universal Injector

The `UniversalInjector.exe` is a smart launcher that automatically detects whether the target process is 32-bit or 64-bit and launches the appropriate injector.

### Command Line Usage

```cmd
UniversalInjector.exe <dll_path> <process_name>
```

**Example:**
```cmd
UniversalInjector.exe mydll.dll notepad.exe
```

**How it works:**
1. Detects the target process architecture (x86 or x64)
2. Automatically launches either `Injector-x86.exe` or `Injector-x64.exe`
3. Passes all parameters to the appropriate injector
4. Returns the result

**Benefits:**
- ✅ No need to manually choose the correct injector
- ✅ Works with both 32-bit and 64-bit processes
- ✅ Single command for all scenarios
- ✅ Requires both `Injector-x86.exe` and `Injector-x64.exe` in the same directory

## Manual Build (Individual Architectures)

If you need to build only one architecture:

### Build x64 Only
```cmd
mkdir build-x64
cd build-x64
cmake .. -G "Visual Studio 16 2019" -A x64
cmake --build . --config Release
```

### Build x86 Only
```cmd
mkdir build-x86
cd build-x86
cmake .. -G "Visual Studio 16 2019" -A Win32
cmake --build . --config Release
```

## Architecture Compatibility

| Injector Architecture | Can Inject Into | Notes |
|----------------------|-----------------|-------|
| x64 (64-bit) | 64-bit processes only | Most common on modern Windows |
| x86 (32-bit) | 32-bit processes only | Required for legacy applications |
| UniversalInjector | Both x86 and x64 | Requires both injectors present |

## Python Usage with Multiple Architectures

When using with Python, ensure your Python architecture matches the DLL:

### Check Python Architecture
```python
import sys
print("64-bit" if sys.maxsize > 2**32 else "32-bit")
```

### Use Correct DLL
```python
import ctypes
import sys

# Automatically select the correct DLL
is_64bit = sys.maxsize > 2**32
dll_name = "ManualMapInjector-x64.dll" if is_64bit else "ManualMapInjector-x86.dll"

injector = ctypes.CDLL(dll_name)
# ... rest of your code
```

## Build Requirements

- **CMake** 3.15 or higher
- **Visual Studio** 2019 or higher (2022 recommended)
  - With "Desktop development with C++" workload
- **Windows SDK** (usually installed with Visual Studio)

## Troubleshooting

### "CMake not found"
Ensure CMake is in your system PATH. Restart your terminal after installation.

### "Visual Studio not found"
Install Visual Studio with the "Desktop development with C++" workload.

### UniversalInjector.exe can't find other injectors
Ensure all three executables are in the same directory:
- `UniversalInjector.exe`
- `Injector-x64.exe`
- `Injector-x86.exe`

### Architecture mismatch errors
- For Python: Use DLL matching your Python architecture (check with `sys.maxsize`)
- For CLI: Use `UniversalInjector.exe` to automatically select the correct one
- For manual use: Match injector architecture to target process architecture

## Output Directory Structure

After running `build-all.bat` or `build-all.ps1`:

```
Simple-Manual-Map-Injector/
├── bin/                          # All final outputs
│   ├── ManualMapInjector-x64.dll
│   ├── ManualMapInjector-x86.dll
│   ├── Injector-x64.exe
│   ├── Injector-x86.exe
│   └── UniversalInjector.exe
├── build-x64/                    # x64 build artifacts
│   └── Release/
├── build-x86/                    # x86 build artifacts
│   └── Release/
└── ...
```

## Advanced Usage

### Custom Build Configurations

Edit `build-all.bat` or `build-all.ps1` to customize:
- Build configuration (Debug/Release)
- Output directories
- Additional CMake options

### Building with Different Visual Studio Versions

The scripts auto-detect your VS version, but you can manually specify:

```cmd
cmake .. -G "Visual Studio 17 2022" -A x64
```

Supported generators:
- `"Visual Studio 17 2022"` - VS 2022
- `"Visual Studio 16 2019"` - VS 2019
- `"Visual Studio 15 2017"` - VS 2017

## Clean Build

To clean all build artifacts:

```cmd
# Windows Command Prompt
rmdir /s /q build-x86 build-x64 bin

# PowerShell
Remove-Item -Recurse -Force build-x86, build-x64, bin
```

Then run the build script again.

## Notes

- Building both architectures requires approximately 2x the disk space
- Build time is roughly double (both architectures are built sequentially)
- The `UniversalInjector.exe` is always built as 64-bit (it can detect both 32-bit and 64-bit processes)
- Always run with administrator privileges when injecting into processes
