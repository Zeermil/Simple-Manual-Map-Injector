# Python Implementation of Manual Map Injector

## Overview

This document explains the pure Python implementation of the manual map DLL injector and its relationship to the C++ implementation.

## Files

### 1. `injector.py` - Pure Python Implementation
A complete pure Python implementation that demonstrates manual map injection concepts using Windows APIs via ctypes.

**Features:**
- Process enumeration and PID lookup
- SeDebugPrivilege elevation
- Architecture compatibility checking
- Complete PE header parsing
- Comprehensive error handling
- Educational demonstration of manual mapping concepts

**Limitations:**
- Cannot generate shellcode (position-independent machine code)
- Cannot fully execute the injection (returns error -100)
- Useful for learning and understanding the process

### 2. `example_python.py` - Recommended Python Wrapper
A Python wrapper that uses the compiled C++ DLL via ctypes to provide full injection functionality.

**Features:**
- Full manual map injection support
- Cross-architecture support (x64 can inject into x86)
- All C++ features available from Python
- Simple and reliable
- **Recommended for production use**

### 3. `manual_map_injector.py` - Alternative Implementation
Another pure Python implementation with partial functionality and additional helper methods.

## Why Pure Python Manual Map is Limited

Manual map injection requires executing code in the target process to:

1. **Process base relocations**: Adjust addresses in the DLL for the new base address
2. **Resolve imports**: Call `LoadLibraryA` and `GetProcAddress` in the target process
3. **Handle TLS callbacks**: Execute thread-local storage initialization
4. **Call DllMain**: Invoke the DLL's entry point
5. **Setup SEH exceptions**: Register exception handlers (x64)

These operations require **shellcode** - position-independent machine code that runs in the target process. Generating shellcode requires either:

### Option A: Assembly Code Generation
```python
# Would need to generate something like this:
shellcode = b'\x48\x83\xEC\x28'  # sub rsp, 0x28
shellcode += b'\x48\x8B\x01'     # mov rax, [rcx]
# ... hundreds more bytes of x86/x64 assembly
```

This is extremely complex and error-prone.

### Option B: Use an Assembler Library
```python
from keystone import *

ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm("mov rax, rbx; add rax, rcx")
```

Requires additional dependencies (keystone-engine).

### Option C: Pre-compiled Shellcode
Include pre-compiled shellcode as bytes for each architecture. This works but:
- Hard to maintain
- Architecture-specific
- Difficult to modify
- Security concerns

### Option D: Use C++ DLL (Recommended)
The C++ compiler generates optimized, correct machine code automatically:

```python
import ctypes

injector = ctypes.CDLL("ManualMapInjector-x64.dll")
result = injector.InjectDllFromMemorySimple(b"notepad.exe", dll_bytes, len(dll_bytes))
```

## Usage Comparison

### Pure Python (Educational)
```bash
# Shows the process but cannot complete injection
python injector.py hello-world-x64.dll notepad.exe
# Result: Error -100 (not fully implemented)
```

### Python + C++ DLL (Recommended)
```bash
# Full functionality, easy to use
python example_python.py hello-world-x64.dll notepad.exe
# Result: Success (0)
```

## When to Use Each

### Use `injector.py` when:
- Learning about manual map injection
- Understanding PE file format
- Studying Windows internals
- Prototyping or testing concepts

### Use `example_python.py` when:
- You need working injection functionality
- Building production tools
- Requiring cross-architecture support
- Maximum reliability is important

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Manual Map Injection                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
        ┌───────────────┐         ┌─────────────────┐
        │  Python Only  │         │  Python + C++   │
        │  (Limited)    │         │  (Full)         │
        └───────────────┘         └─────────────────┘
                │                           │
                │                           │
                ▼                           ▼
        ┌───────────────┐         ┌─────────────────┐
        │ injector.py   │         │example_python.py│
        │               │         │        +        │
        │ - PE parsing  │         │ C++ DLL (ctypes)│
        │ - Process mgmt│         │                 │
        │ - WinAPI calls│         │ - Full inject   │
        │ ✗ Shellcode   │         │ - Shellcode ✓   │
        │ ✗ Execution   │         │ - Cross-arch ✓  │
        └───────────────┘         └─────────────────┘
```

## Implementation Details

### What Pure Python CAN Do

✅ **Process Management**
```python
def get_process_id_by_name(self, process_name: str) -> int:
    # Use CreateToolhelp32Snapshot, Process32First, Process32Next
    # to find process by name
```

✅ **PE Parsing**
```python
def parse_pe_headers(self, dll_data: bytes) -> Dict:
    # Parse DOS header, NT headers, sections, data directories
    # Validate architecture, extract important offsets
```

✅ **Memory Operations**
```python
# Allocate memory in target process
target_base = kernel32.VirtualAllocEx(h_process, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

# Write DLL to target process
kernel32.WriteProcessMemory(h_process, target_base, dll_data, len(dll_data), None)
```

✅ **Privilege Elevation**
```python
def enable_debug_privilege(self) -> bool:
    # Use OpenProcessToken, LookupPrivilegeValue, AdjustTokenPrivileges
    # to enable SeDebugPrivilege
```

### What Pure Python CANNOT Do Easily

❌ **Shellcode Generation**
- Requires generating x86/x64 machine code
- Must be position-independent (no absolute addresses)
- Complex logic for relocations, imports, TLS

❌ **In-Process Execution**
- Cannot easily execute complex logic in target process
- Would need remote thread + shellcode
- Or use CreateRemoteThread with LoadLibrary (standard injection, not manual map)

## Possible Solutions for Pure Python

### 1. Use Keystone Engine (Assembly)
```python
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

ks = Ks(KS_ARCH_X86, KS_MODE_64)
shellcode, _ = ks.asm("""
    push rbp
    mov rbp, rsp
    ; ... implement manual mapping logic in assembly
    pop rbp
    ret
""")
```

**Pros:** Can generate correct shellcode
**Cons:** Still need to write complex assembly, architecture-specific

### 2. Pre-compiled Shellcode Blobs
Include shellcode as hex bytes:
```python
SHELLCODE_X64 = bytes.fromhex("4883EC28488B01...")
SHELLCODE_X86 = bytes.fromhex("5589E583EC18...")
```

**Pros:** Works without dependencies
**Cons:** Hard to maintain, security risks, not flexible

### 3. Hybrid Approach (Recommended)
Use Python for high-level logic, C++ for low-level operations:
```python
# Python wrapper (example_python.py)
injector = ctypes.CDLL("ManualMapInjector-x64.dll")
result = injector.InjectDllFromMemorySimple(process, dll_bytes, size)
```

**Pros:** Best of both worlds, maintainable, performant
**Cons:** Requires compilation step (but we provide pre-built DLLs)

## Conclusion

The pure Python implementation (`injector.py`) is valuable for:
- **Education**: Understanding manual map injection process
- **Prototyping**: Testing ideas and concepts
- **Analysis**: PE file parsing and process enumeration

For **production use**, the recommended approach is `example_python.py` which wraps the C++ DLL. This provides:
- ✅ Full functionality
- ✅ Cross-architecture support
- ✅ Reliability and performance
- ✅ Easy Python interface
- ✅ Maintained and tested

## Further Reading

- [Manual Map Injection Theory](https://www.unknowncheats.me/forum/programming-beginners/268939-manual-mapping-injection.html)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Keystone Engine](https://www.keystone-engine.org/) - For assembly in Python

## Examples

### Example 1: Using Pure Python (Educational)
```python
from injector import PythonManualMapInjector

with open("target.dll", "rb") as f:
    dll_data = f.read()

injector = PythonManualMapInjector(verbose=True)
result = injector.inject_simple("notepad.exe", dll_data)

if result == -100:
    print("As expected, pure Python cannot complete the injection")
    print("But we successfully demonstrated the process!")
```

### Example 2: Using Python + C++ (Production)
```python
import ctypes

# Load C++ DLL
injector = ctypes.CDLL("build/ManualMapInjector-x64.dll")

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

# Convert to ctypes array
dll_array = (ctypes.c_ubyte * len(dll_bytes)).from_buffer_copy(dll_bytes)

# Inject!
result = injector.InjectDllFromMemorySimple(b"notepad.exe", dll_array, len(dll_bytes))

if result == 0:
    print("✓ Injection successful!")
else:
    print(f"✗ Error: {result}")
```

## Contributing

If you want to contribute a full pure Python implementation with shellcode generation, please:

1. Use a well-maintained assembly library (e.g., keystone-engine)
2. Support both x86 and x64 architectures
3. Include comprehensive tests
4. Document the shellcode logic thoroughly
5. Consider security implications

However, we recommend focusing efforts on improving the C++ implementation, as it's more maintainable and reliable.
