# Quick Start: Python Injector

## TL;DR (Быстрый старт)

### Production Use (Продакшн)
```bash
python example_python.py your-dll.dll target-process.exe
```
✅ Full functionality / Полная функциональность

### Learning (Обучение)
```bash
python injector.py your-dll.dll target-process.exe
```
ℹ️ Educational demo / Образовательная демонстрация

---

## Two Approaches (Два подхода)

### 1. Python + C++ DLL (Recommended / Рекомендуется)

**File:** `example_python.py`

**Advantages:**
- ✅ Full manual map injection
- ✅ Cross-architecture support (x64 → x86)
- ✅ All features from C++ implementation
- ✅ Fast and reliable
- ✅ Production ready

**Requirements:**
- Built C++ DLL (`ManualMapInjector-x64.dll` or `ManualMapInjector-x86.dll`)
- Match Python architecture to DLL architecture

**Usage:**
```bash
# Build DLL first (one time)
build_all.bat

# Then use Python script
python example_python.py hello-world-x64.dll notepad.exe
```

---

### 2. Pure Python (Educational / Образовательный)

**File:** `injector.py`

**Advantages:**
- ✅ No compilation needed
- ✅ Easy to read and understand
- ✅ Shows manual map process step-by-step
- ✅ Great for learning Windows internals

**Limitations:**
- ❌ Cannot generate shellcode
- ❌ Cannot complete full injection
- ⚠️ Returns error -100 with explanation

**Usage:**
```bash
# Run directly
python injector.py hello-world-x64.dll notepad.exe

# Result: Shows process, explains why it can't complete
```

---

## Which Should I Use? (Что использовать?)

### Use `example_python.py` if you want to:
- Actually inject a DLL ✅
- Build production tools
- Maximum reliability
- Cross-architecture injection

### Use `injector.py` if you want to:
- Learn how manual map works 📚
- Understand Windows APIs
- See PE file parsing
- Study injection concepts

---

## Code Comparison (Сравнение кода)

### Production: example_python.py
```python
import ctypes

# Load injector DLL
injector = ctypes.CDLL("build/ManualMapInjector-x64.dll")

# Read target DLL
with open("target.dll", "rb") as f:
    dll_bytes = f.read()

# Setup function signature
injector.InjectDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t
]
injector.InjectDllFromMemorySimple.restype = ctypes.c_int

# Inject
dll_array = (ctypes.c_ubyte * len(dll_bytes)).from_buffer_copy(dll_bytes)
result = injector.InjectDllFromMemorySimple(b"notepad.exe", dll_array, len(dll_bytes))

if result == 0:
    print("✓ Success!")
```

### Educational: injector.py
```python
from injector import PythonManualMapInjector

# Read target DLL
with open("target.dll", "rb") as f:
    dll_bytes = f.read()

# Create injector
injector = PythonManualMapInjector(verbose=True)

# Attempt injection (will explain limitations)
result = injector.inject_simple("notepad.exe", dll_bytes)

# Result will be -100 with detailed explanation of what works
# and what doesn't work in pure Python
```

---

## Error Codes (Коды ошибок)

Both implementations use the same error codes:

| Code | Meaning | Solution |
|------|---------|----------|
| 0 | Success | ✓ Injection completed |
| -1 | Process not found | Check process name, make sure it's running |
| -2 | Failed to open process | Run as Administrator |
| -3 | Architecture mismatch | Use matching architecture (x86/x64) |
| -4 | Invalid DLL data | Check DLL file is valid PE |
| -5 | Injection failed | Check DLL compatibility with target |
| -100 | Not implemented | Pure Python limitation (use example_python.py) |

---

## Platform Requirements (Требования платформы)

### Both Approaches:
- ✅ Windows only (Win32 API required)
- ✅ Python 3.6+
- ✅ Administrator privileges (for most targets)

### Python + C++ DLL additionally needs:
- ✅ Built DLL files (use `build_all.bat`)
- ✅ Visual Studio build tools (for compilation)

---

## Examples (Примеры)

### Example 1: Inject into Notepad (x64)
```bash
# Start notepad
start notepad.exe

# Inject (production)
python example_python.py hello-world-x64.dll notepad.exe
```

### Example 2: Learn the Process
```bash
# Educational - shows all steps
python injector.py hello-world-x64.dll notepad.exe

# Output shows:
# [*] Finding process...
# [+] Found PID: 12345
# [*] Parsing PE headers...
# [+] PE parsed successfully
# ... (detailed steps)
# [!] Limitation: Cannot generate shellcode in pure Python
```

### Example 3: Programmatic Use
```python
import ctypes
import os

# Determine correct DLL based on Python architecture
import sys
is_64bit = sys.maxsize > 2**32
dll_name = "ManualMapInjector-x64.dll" if is_64bit else "ManualMapInjector-x86.dll"
dll_path = os.path.join("build", dll_name)

# Load injector
injector = ctypes.CDLL(dll_path)

# Configure function
injector.InjectDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t
]
injector.InjectDllFromMemorySimple.restype = ctypes.c_int

# Read DLL to inject
with open("my-dll.dll", "rb") as f:
    dll_data = f.read()

# Convert to ctypes array
dll_array = (ctypes.c_ubyte * len(dll_data)).from_buffer_copy(dll_data)

# Inject
result = injector.InjectDllFromMemorySimple(
    b"target-process.exe",
    dll_array,
    len(dll_data)
)

# Handle result
if result == 0:
    print("✓ Injection successful!")
elif result == -1:
    print("✗ Process not found")
elif result == -2:
    print("✗ Access denied (run as admin)")
elif result == -3:
    print("✗ Architecture mismatch")
else:
    print(f"✗ Error: {result}")
```

---

## Architecture Guide (Руководство по архитектуре)

### Matching Architectures

| Your Python | Target Process | Use This DLL | Result |
|-------------|----------------|--------------|--------|
| 64-bit | 64-bit | ManualMapInjector-x64.dll | ✅ Works |
| 32-bit | 32-bit | ManualMapInjector-x86.dll | ✅ Works |
| 64-bit | 32-bit | ManualMapInjector-x64.dll | ✅ Works (C++ cross-arch) |
| 32-bit | 64-bit | N/A | ❌ Not supported |

**Note:** The pure Python version (`injector.py`) requires exact architecture match. Only the C++ version supports cross-architecture injection.

---

## Troubleshooting (Решение проблем)

### "Process not found"
```bash
# Check if process is running
tasklist | findstr "notepad.exe"

# Make sure to use .exe extension
python example_python.py dll.dll notepad.exe  # ✓ Correct
python example_python.py dll.dll notepad      # ✗ Wrong
```

### "Access denied"
```bash
# Run as Administrator
# Right-click Command Prompt → "Run as administrator"
python example_python.py dll.dll notepad.exe
```

### "DLL not found" (ManualMapInjector-x64.dll)
```bash
# Build the DLL first
build_all.bat

# Or build manually
mkdir build && cd build
cmake .. -G "Visual Studio 16 2019" -A x64
cmake --build . --config Release
```

### "Architecture mismatch"
```bash
# Check Python architecture
python -c "import sys; print('64-bit' if sys.maxsize > 2**32 else '32-bit')"

# Use matching DLL
# 64-bit Python → ManualMapInjector-x64.dll
# 32-bit Python → ManualMapInjector-x86.dll
```

---

## Further Reading (Дополнительная информация)

- 📘 **[PYTHON_IMPLEMENTATION.md](PYTHON_IMPLEMENTATION.md)** - Detailed technical explanation
- 📗 **[PYTHON_PORT_SUMMARY.md](PYTHON_PORT_SUMMARY.md)** - Complete work summary (bilingual)
- 📕 **[README.md](README.md)** - Main project documentation
- 📙 **[BUILD.md](BUILD.md)** - Building the C++ DLL

---

## Summary (Итог)

### For Real Use → `example_python.py` ✅
Full functionality, production ready, recommended

### For Learning → `injector.py` 📚
Educational, shows concepts, explains limitations

Both are valuable for different purposes!
