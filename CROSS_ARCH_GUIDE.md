# Cross-Architecture Injection Guide

This guide explains how the Manual Map Injector supports injecting into both 32-bit and 64-bit processes from a single 64-bit injector.

## Overview

The Manual Map Injector now supports **cross-architecture injection**, allowing a 64-bit injector to inject DLLs into both 32-bit and 64-bit target processes. This is accomplished through an intelligent helper system.

## How It Works

### Architecture Detection

When you run `Injector-x64.exe`, it:

1. Opens the target process
2. Checks if the target is 32-bit or 64-bit using `IsWow64Process`
3. If the target is 64-bit → injects directly
4. If the target is 32-bit → launches `Injector-x86.exe` as a helper

### Helper System

The x64 injector automatically launches the x86 helper when needed:

```
User runs: Injector-x64.exe my.dll target32bit.exe
     ↓
Injector-x64.exe detects 32-bit target
     ↓
Launches: Injector-x86.exe my.dll target32bit.exe
     ↓
x86 helper performs injection
     ↓
Returns result to user
```

## Building for Cross-Architecture Support

### Quick Build (Recommended)

Run the build script to build both architectures:

```cmd
build_all.bat
```

This creates:
- `build/Injector-x64.exe` - Main injector
- `build/Injector-x86.exe` - Helper injector
- `build/ManualMapInjector-x64.dll` - For 64-bit Python
- `build/ManualMapInjector-x86.dll` - For 32-bit Python

### Manual Build

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

## Usage Examples

### Example 1: Injecting into a 64-bit Process

```cmd
Injector-x64.exe myDll-x64.dll notepad.exe
```

Output:
```
Process pid: 1234
File ok
Mapping...
OK
```

### Example 2: Injecting into a 32-bit Process

```cmd
Injector-x64.exe myDll-x86.dll some32bitApp.exe
```

Output:
```
Process pid: 5678
Target process is 32-bit, using x86 helper injector...
Launching x86 helper injector for 32-bit target process...
Process pid: 5678
File ok
Mapping...
OK
```

## Important Notes

### File Organization

**Both executables must be in the same directory:**

```
your_folder/
├── Injector-x64.exe  ← Main injector
├── Injector-x86.exe  ← Helper (must be here!)
├── my-x64.dll
└── my-x86.dll
```

If `Injector-x86.exe` is not found, you'll see:
```
x86 helper injector not found: C:\path\to\Injector-x86.exe
Please ensure Injector-x86.exe is in the same directory as Injector-x64.exe
```

### DLL Architecture

**Critical:** The DLL architecture must match the target process:

| Target Process | Use DLL |
|----------------|---------|
| 32-bit process | 32-bit DLL |
| 64-bit process | 64-bit DLL |

If architectures don't match, injection will fail.

### Python Usage

For Python, use the appropriate DLL architecture:

```python
import ctypes
import sys

# Detect Python architecture
is_64bit = sys.maxsize > 2**32

# Load correct DLL
if is_64bit:
    injector = ctypes.CDLL("ManualMapInjector-x64.dll")
else:
    injector = ctypes.CDLL("ManualMapInjector-x86.dll")

# The DLL you inject must match the target process (not your Python!)
with open("target-x64.dll", "rb") as f:  # Use x64 DLL for 64-bit target
    dll_bytes = f.read()

# Setup and inject
injector.InjectDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t
]
dll_array = (ctypes.c_ubyte * len(dll_bytes)).from_buffer_copy(dll_bytes)
result = injector.InjectDllFromMemorySimple(b"notepad.exe", dll_array, len(dll_bytes))
```

## Error Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| -1 | Process not found |
| -2 | Failed to open process (check admin rights) |
| -3 | Architecture mismatch (should not occur with x64 injector) |
| -4 | Invalid DLL file |
| -5 | Injection failed |
| -6 | Invalid file size |
| -7 | Memory allocation failed |
| -8 | Mapping error |
| -10 | x86 helper not found |
| -11 | Failed to launch helper |

## Troubleshooting

### "x86 helper injector not found"

**Problem:** `Injector-x86.exe` is not in the same directory as `Injector-x64.exe`

**Solution:**
1. Run `build_all.bat` to build both versions
2. Copy both EXE files to your working directory
3. Verify with: `dir Injector-*.exe`

### "Invalid Process Architecture"

**Problem:** Trying to use `Injector-x86.exe` to inject into a 64-bit process

**Solution:** Always use `Injector-x64.exe` as your main injector. It handles both architectures automatically.

### "Injection failed"

**Problem:** DLL architecture doesn't match target process

**Solution:**
1. Check target process architecture: Task Manager → Details → Platform column
2. Use matching DLL architecture:
   - 32-bit target → use 32-bit DLL
   - 64-bit target → use 64-bit DLL

### Permission Denied

**Problem:** Insufficient privileges to inject

**Solution:**
1. Run as Administrator (right-click → Run as administrator)
2. Check antivirus settings (may block injection)
3. Ensure target process allows injection

## Technical Details

### Architecture Detection Code

The injector uses Windows API to detect process architecture:

```cpp
bool IsTargetProcess32Bit(HANDLE hProc) {
    BOOL bTarget = FALSE;
    if (!IsWow64Process(hProc, &bTarget)) {
        return false;
    }
    return bTarget == TRUE;
}
```

### Helper Launch Mechanism

When a 32-bit target is detected:

1. Get current executable directory
2. Construct path to `Injector-x86.exe`
3. Build command line with DLL path and process name
4. Launch helper with `CreateProcessW`
5. Wait for completion
6. Return helper's exit code

## Benefits

✅ **Single main executable** - Use `Injector-x64.exe` for all injections  
✅ **Automatic architecture handling** - No manual switching needed  
✅ **Clean error messages** - Clear indication when helper is used  
✅ **Backward compatible** - Can still use x86 injector directly if needed  
✅ **No administrator changes** - Works with existing privilege elevation

## Limitations

⚠️ **Both executables required** - Cannot work with only x64 injector  
⚠️ **DLL must match target** - Cannot inject x64 DLL into x86 process  
⚠️ **Windows only** - Cross-architecture injection is Windows-specific  
⚠️ **Requires build of both** - Must compile both x86 and x64 versions

## Best Practices

1. **Always build both architectures** using `build_all.bat`
2. **Keep executables together** in the same directory
3. **Use x64 as main injector** for all injections
4. **Match DLL to target** process architecture
5. **Run as administrator** when targeting system processes
6. **Test with simple DLLs** first (like provided hello-world DLLs)

## See Also

- [README.md](README.md) - Main documentation
- [BUILD.md](BUILD.md) - Build instructions
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
