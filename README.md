
# Simple Manual Map Injector

- **Cross-architecture support**: 64-bit injector can inject into both 32-bit and 64-bit processes
- Supports x86 and x64
- Supports x64 exceptions (SEH) (only /EHa and /EHc)
- Release & Debug
- Removes PE Header and some sections (Configurable)
- Configurable DllMain params (default DLL_PROCESS_ATTACH)
- Add sections protections (Configurable)

## Usage

### Command Line (EXE)

- Injector_path.exe dll_path [process_name]

### Python (DLL via ctypes)

```python
import ctypes

# Load the injector DLL
injector = ctypes.CDLL("ManualMapInjector-x64.dll")

# Read DLL to inject
with open("target.dll", "rb") as f:
    dll_bytes = f.read()

# Setup function signature
injector.InjectDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t
]
injector.InjectDllFromMemorySimple.restype = ctypes.c_int

# Convert to ctypes
dll_array = (ctypes.c_ubyte * len(dll_bytes)).from_buffer_copy(dll_bytes)
process_name = b"notepad.exe"

# Inject
result = injector.InjectDllFromMemorySimple(process_name, dll_array, len(dll_bytes))
print(f"Injection result: {result}")  # 0 = success
```

See `example_python.py` for a complete working example.

## Building with CMake

### Prerequisites

- CMake 3.15 or higher
- Visual Studio 2019 or higher (with C++ Desktop Development workload)
- Windows SDK

### Quick Build - All Architectures (Recommended)

To build both x86 and x64 versions in one step, use the build script:

**Windows:**
```bash
build_all.bat
```

**Linux/macOS (using MinGW or WSL):**
```bash
./build_all.sh
```

This will create:
- `build/Injector-x64.exe` - 64-bit injector (can inject into 32-bit and 64-bit processes)
- `build/Injector-x86.exe` - 32-bit injector helper (automatically used by x64 injector)
- `build/ManualMapInjector-x64.dll` - 64-bit DLL for Python
- `build/ManualMapInjector-x86.dll` - 32-bit DLL for Python

**Important:** Keep both `Injector-x64.exe` and `Injector-x86.exe` in the same directory. The x64 injector automatically uses the x86 helper when targeting 32-bit processes.

### Manual Build - Single Architecture

#### Building x64 version:

1. **Create build directory:**
```bash
mkdir build && cd build
```

2. **Configure CMake for x64:**
```bash
cmake .. -G "Visual Studio 16 2019" -A x64
```

3. **Build the project:**
```bash
cmake --build . --config Release
```

#### Building x86 version:

1. **Create build directory:**
```bash
mkdir build && cd build
```

2. **Configure CMake for x86:**
```bash
cmake .. -G "Visual Studio 16 2019" -A Win32
```

3. **Build the project:**
```bash
cmake --build . --config Release
```

4. **Output files:**
   - DLL: `build/Release/ManualMapInjector-x64.dll` (or `ManualMapInjector-x86.dll`)
   - CLI EXE: `build/Release/Injector-x64.exe` (or `Injector-x86.exe`)

### Using the Built DLL with Python

After building, run the example:
```bash
python example_python.py hello-world-x64.dll notepad.exe
```

**Note:** Make sure to use the correct architecture DLL that matches your Python installation (x64 Python needs x64 DLL).

## API Reference

### InjectDllFromMemorySimple (Recommended)

Simple function with default parameters for most use cases.

**Signature:**
```c
int InjectDllFromMemorySimple(
    const char* processName,
    const unsigned char* dllData,
    size_t dllSize
)
```

**Parameters:**
- `processName`: Name of the target process (e.g., "notepad.exe")
- `dllData`: Pointer to DLL bytes in memory
- `dllSize`: Size of the DLL data in bytes

**Return Values:**
- `0`: Success
- `-1`: Process not found
- `-2`: Failed to open process (check privileges)
- `-3`: Process architecture mismatch (x86 vs x64)
- `-4`: Invalid DLL data
- `-5`: Injection failed

### InjectDllFromMemory (Advanced)

Advanced function with configurable parameters.

**Signature:**
```c
int InjectDllFromMemory(
    const char* processName,
    const unsigned char* dllData,
    size_t dllSize,
    bool clearHeader,
    bool clearNonNeededSections,
    bool adjustProtections,
    bool sehExceptionSupport
)
```

**Additional Parameters:**
- `clearHeader`: Clear PE header after injection (recommended: true)
- `clearNonNeededSections`: Clear non-essential sections (recommended: true)
- `adjustProtections`: Adjust memory protections (recommended: true)
- `sehExceptionSupport`: Enable SEH exception support for x64 (recommended: true)

### InjectEncryptedDllFromMemorySimple (New - Encrypted Injection)

Function for injecting encrypted DLL from memory. The DLL is decrypted at injection time for enhanced security.

**Signature:**
```c
int InjectEncryptedDllFromMemorySimple(
    const char* processName,
    const unsigned char* encryptedDllData,
    size_t encryptedDllSize,
    const unsigned char* encryptionKey,
    size_t keySize
)
```

**Parameters:**
- `processName`: Name of the target process (e.g., "notepad.exe")
- `encryptedDllData`: Pointer to encrypted DLL bytes in memory
- `encryptedDllSize`: Size of the encrypted DLL data in bytes
- `encryptionKey`: AES encryption key (16 bytes for AES-128)
- `keySize`: Size of the encryption key in bytes (must be 16)

**Return Values:**
- `0`: Success
- `-1`: Process not found
- `-2`: Failed to open process (check privileges)
- `-3`: Process architecture mismatch (x86 vs x64)
- `-4`: Invalid DLL data
- `-5`: Injection failed
- `-6`: Decryption failed

**Python Example:**
```python
import ctypes

# Load the injector DLL
injector = ctypes.CDLL("ManualMapInjector-x64.dll")

# Read encrypted DLL
with open("encrypted_target.dll", "rb") as f:
    encrypted_dll_bytes = f.read()

# Define AES key (16 bytes for AES-128)
encryption_key = b'sixteen byte key'

# Setup function signature
injector.InjectEncryptedDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t
]
injector.InjectEncryptedDllFromMemorySimple.restype = ctypes.c_int

# Convert to ctypes
dll_array = (ctypes.c_ubyte * len(encrypted_dll_bytes)).from_buffer_copy(encrypted_dll_bytes)
key_array = (ctypes.c_ubyte * len(encryption_key)).from_buffer_copy(encryption_key)
process_name = b"notepad.exe"

# Inject
result = injector.InjectEncryptedDllFromMemorySimple(
    process_name, dll_array, len(encrypted_dll_bytes),
    key_array, len(encryption_key)
)
print(f"Injection result: {result}")  # 0 = success
```

### InjectEncryptedDllFromMemory (Advanced - Encrypted Injection)

Advanced function for encrypted DLL injection with configurable parameters.

**Signature:**
```c
int InjectEncryptedDllFromMemory(
    const char* processName,
    const unsigned char* encryptedDllData,
    size_t encryptedDllSize,
    const unsigned char* encryptionKey,
    size_t keySize,
    bool clearHeader,
    bool clearNonNeededSections,
    bool adjustProtections,
    bool sehExceptionSupport
)
```

## Additional Documentation

- **[PR_SUMMARY.md](PR_SUMMARY.md)** - Summary of cross-architecture implementation
- **[CROSS_ARCH_GUIDE.md](CROSS_ARCH_GUIDE.md)** - Detailed guide on cross-architecture injection
- **[CHANGES.md](CHANGES.md)** - Complete changelog of recent updates
- **[BUILD.md](BUILD.md)** - Comprehensive build instructions
- **[QUICKSTART.md](QUICKSTART.md)** - Quick start guide

## Devs

- Add **DISABLE_OUTPUT** definition if you want to disable injector.cpp output
- main.cpp is just an example but powerfull
- Hello World dlls added from https://github.com/carterjones/hello-world-dll for easy testing
