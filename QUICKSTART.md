# Quick Start Guide

This guide will get you up and running with the Manual Map Injector in 5 minutes.

## Step 1: Build Everything (Universal)

The easiest way - build both x86 and x64 versions with one command:

```bash
cd path\to\Simple-Manual-Map-Injector
build-all.bat
```

Or using PowerShell:
```powershell
.\build-all.ps1
```

**Output:** All files in the `bin` directory:
- `ManualMapInjector-x64.dll` & `ManualMapInjector-x86.dll`
- `Injector-x64.exe` & `Injector-x86.exe`
- `UniversalInjector.exe` (smart launcher)

### Alternative: Build Single Architecture

For x64 only:
```bash
mkdir build-x64 && cd build-x64
cmake .. -G "Visual Studio 16 2019" -A x64
cmake --build . --config Release
```

## Step 2: Using the Universal Injector (Easiest)

The universal launcher automatically detects if the target process is 32-bit or 64-bit:

```bash
cd bin
UniversalInjector.exe mydll.dll notepad.exe
```

That's it! No need to worry about architectures.

## Step 3: Using with Python

### Auto-detect Python Architecture

Create `inject.py`:

```python
import ctypes
import sys

# Automatically select correct DLL based on Python architecture
is_64bit = sys.maxsize > 2**32
dll_name = "bin/ManualMapInjector-x64.dll" if is_64bit else "bin/ManualMapInjector-x86.dll"

# Load injector DLL
injector = ctypes.CDLL(dll_name)

# Read DLL to inject
with open("target.dll", "rb") as f:
    dll_bytes = f.read()

# Setup function
injector.InjectDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t
]
injector.InjectDllFromMemorySimple.restype = ctypes.c_int

# Convert and inject
dll_array = (ctypes.c_ubyte * len(dll_bytes)).from_buffer_copy(dll_bytes)
result = injector.InjectDllFromMemorySimple(b"notepad.exe", dll_array, len(dll_bytes))

print(f"Result: {result}")  # 0 = success
```

### Run It

```bash
python inject.py
```

Or use the provided example:

```bash
python example_python.py hello-world-x64.dll notepad.exe
```

## Return Codes

| Code | Meaning |
|------|---------|
| 0    | ✓ Success |
| -1   | ✗ Process not found |
| -2   | ✗ Failed to open process (need admin rights) |
| -3   | ✗ Architecture mismatch (x86 vs x64) |
| -4   | ✗ Invalid DLL data |
| -5   | ✗ Injection failed |

## Common Issues

### "DLL not found"
Make sure the DLL path is correct:
```python
injector = ctypes.CDLL("./build/Release/ManualMapInjector-x64.dll")
```

### "Architecture mismatch"
- Use x64 DLL with 64-bit Python and 64-bit target process
- Use x86 DLL with 32-bit Python and 32-bit target process

### "Failed to open process"
Run Python with administrator privileges:
```bash
# Right-click → Run as Administrator
python inject.py
```

## Advanced Usage

For more control, use `InjectDllFromMemory`:

```python
result = injector.InjectDllFromMemory(
    b"process.exe",      # Process name
    dll_array,           # DLL bytes
    len(dll_bytes),      # Size
    True,                # Clear PE header
    True,                # Clear non-needed sections
    True,                # Adjust protections
    True                 # SEH exception support (x64)
)
```

## Need Help?

- Full documentation: `README.md`
- Build guide: `BUILD.md`
- Russian docs: `README.ru.md`
- Example code: `example_python.py`
