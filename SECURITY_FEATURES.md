# Security Features Documentation

This document describes the security features added to the Simple Manual Map Injector.

## Overview

The injector now includes three main security features:
1. **Anti-Debug Protection** - Detects and prevents injection when debuggers are present
2. **Anti-Dump Protection** - Makes injected DLLs harder to detect and dump from memory
3. **DLL Encryption** - Allows DLLs to be encrypted before injection and decrypted in-memory

## Anti-Debug Protection

### Purpose
Prevents the injector from being analyzed or reverse-engineered by detecting debugger presence.

### Detection Methods

1. **IsDebuggerPresent()**
   - Windows API function that checks if the process is being debugged
   - Fast and reliable for basic debugger detection

2. **CheckRemoteDebuggerPresent()**
   - Checks if a remote debugger is attached to the process
   - More comprehensive than IsDebuggerPresent()

3. **NtQueryInformationProcess()**
   - Uses NT kernel API to query process debug port
   - Detects kernel-level debuggers
   - More difficult to bypass than user-mode checks

4. **PEB BeingDebugged Flag**
   - Directly checks the Process Environment Block
   - Low-level detection that works even when API hooks are in place

### Behavior
When a debugger is detected, the injection is immediately aborted with an error message. This prevents attackers from analyzing the injection process or the target DLL.

### Implementation
- Located in `Manual Map Injector/anti_debug.h`
- Called at the start of `ManualMapDll()` function
- Uses exception handling to prevent crashes if PEB access fails

## Anti-Dump Protection

### Purpose
Makes it harder for security tools and analysts to dump the injected DLL from the target process memory.

### Techniques

1. **PEB BeingDebugged Flag Clearing**
   - Clears the BeingDebugged flag in the target process
   - Makes the process appear as if it's not being debugged
   - Executed in the shellcode that runs in the target process

2. **PE Header Clearing** (Optional)
   - Removes the PE header after injection
   - Makes it harder to identify the DLL in memory
   - Controlled by the `clearHeader` parameter

3. **Section Clearing** (Optional)
   - Removes non-essential sections (.rsrc, .reloc, .pdata)
   - Reduces the DLL footprint in memory
   - Controlled by the `clearNonNeededSections` parameter

### Behavior
Anti-dump protection is applied automatically during injection in the target process. The shellcode that executes in the target process clears the BeingDebugged flag before calling the DLL's entry point.

### Implementation
- Located in `Manual Map Injector/anti_debug.h` (AntiDump namespace)
- Called in the `Shellcode()` function that executes in target process
- Uses exception handling to prevent crashes

## DLL Encryption

### Purpose
Encrypts DLL payloads to avoid detection by antivirus software and make static analysis more difficult.

### Encryption Algorithm
Uses XOR cipher with a user-provided key:
- Simple and fast
- Same function for encryption and decryption
- Primarily for obfuscation, not strong cryptographic protection

**Note:** XOR encryption is not cryptographically strong. For production use with sensitive payloads, consider stronger encryption like AES.

### Workflow

1. **Encryption (Python side)**
   ```python
   # Encrypt DLL with key
   encrypted_dll = xor_encrypt(dll_bytes, encryption_key)
   ```

2. **Transmission**
   - Encrypted DLL is passed to the injector DLL API

3. **Decryption (C++ side)**
   - Injector decrypts the DLL in-memory before injection
   - Original DLL is never written to disk
   - Decryption happens in the injector process, not target

### API Functions

**For Encrypted Injection:**
- `InjectEncryptedDllFromMemorySimple()` - Simple interface with defaults
- `InjectEncryptedDllFromMemory()` - Advanced interface with options

**Python Utilities:**
- `dll_encryptor.py` - Command-line tool for encrypting/decrypting DLL files
- `example_encrypted_python.py` - Complete example of encrypted injection

### Security Considerations

1. **Key Management**
   - Keep encryption keys secret
   - Don't hardcode keys in source code
   - Use strong, randomly generated keys

2. **Encryption Strength**
   - XOR is breakable with known-plaintext attacks
   - Consider it obfuscation rather than true encryption
   - For sensitive use cases, implement AES or similar

3. **Memory Safety**
   - Decrypted DLL exists in memory temporarily
   - Memory is zeroed after use when possible
   - Use appropriate memory protection

## Implementation Details

### Files Added
- `Manual Map Injector/anti_debug.h` - Anti-debug and anti-dump functions
- `Manual Map Injector/encryption.h` - XOR encryption functions
- `example_encrypted_python.py` - Python example for encrypted injection
- `dll_encryptor.py` - Python utility for DLL encryption

### Files Modified
- `Manual Map Injector/injector.h` - Added includes for new headers
- `Manual Map Injector/injector.cpp` - Added anti-debug check and anti-dump protection
- `Manual Map Injector/injector_dll.cpp` - Added encrypted injection functions
- `README.md` - Updated with security features documentation
- `README.ru.md` - Updated Russian documentation

### Safety Features

1. **Exception Handling**
   - All PEB accesses are wrapped in `__try`/`__except` blocks
   - Prevents crashes if memory is corrupted or inaccessible

2. **Null Pointer Checks**
   - All pointer dereferences are validated
   - Prevents crashes and potential exploits

3. **Error Codes**
   - Consistent error reporting across all APIs
   - Clear distinction between different failure types

## Usage Examples

### Python - Basic Encrypted Injection

```python
import ctypes

# Simple XOR encryption
def xor_encrypt(data, key):
    key_bytes = key.encode('utf-8')
    return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])

# Load injector
injector = ctypes.CDLL("ManualMapInjector-x64.dll")

# Read and encrypt DLL
with open("payload.dll", "rb") as f:
    dll_bytes = f.read()

key = "SecureKey123"
encrypted = xor_encrypt(dll_bytes, key)

# Inject
injector.InjectEncryptedDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t
]
injector.InjectEncryptedDllFromMemorySimple.restype = ctypes.c_int

dll_array = (ctypes.c_ubyte * len(encrypted)).from_buffer_copy(encrypted)
key_array = (ctypes.c_ubyte * len(key)).from_buffer_copy(key.encode('utf-8'))

result = injector.InjectEncryptedDllFromMemorySimple(
    b"target.exe",
    dll_array,
    len(encrypted),
    key_array,
    len(key)
)
```

### Command Line - DLL Encryption

```bash
# Generate encryption key
python dll_encryptor.py genkey

# Encrypt DLL
python dll_encryptor.py encrypt payload.dll payload.dll.enc MyKey123

# Use with injector
python example_encrypted_python.py payload.dll.enc target.exe MyKey123
```

## Security Summary

### What This Protects Against
- ✓ Basic debugger detection during injection
- ✓ Memory dumping of the injected DLL
- ✓ Static signature detection of DLL payloads
- ✓ Basic reverse engineering attempts

### What This Does NOT Protect Against
- ✗ Advanced anti-anti-debug techniques
- ✗ Kernel-level monitoring and debugging
- ✗ Hardware debugging (JTAG, etc.)
- ✗ Cryptanalysis of XOR-encrypted DLLs with known plaintext
- ✗ Runtime behavior analysis

### Recommendations

1. **For Development/Testing:**
   - Current implementation is sufficient
   - Provides good protection against casual analysis

2. **For Production:**
   - Consider stronger encryption (AES-256)
   - Implement additional anti-debugging techniques
   - Add code obfuscation
   - Consider kernel-mode components for better protection

3. **For High-Security Applications:**
   - This injector alone is not sufficient
   - Combine with other security measures
   - Use hardware-based security (TPM, HSM)
   - Implement proper key management infrastructure

## Limitations

1. **XOR Encryption**
   - Easily broken with frequency analysis or known-plaintext attacks
   - Should be considered obfuscation only

2. **Anti-Debug Checks**
   - Can be bypassed by experienced reverse engineers
   - Not effective against kernel debuggers

3. **Anti-Dump Protection**
   - PE header clearing may break exception handling
   - Some dump tools can still detect and dump memory

4. **No Obfuscation**
   - Code is not obfuscated
   - Easy to reverse engineer the injector itself

## Future Improvements

Potential enhancements for future versions:

1. **Stronger Encryption**
   - Implement AES-256 encryption
   - Add proper key derivation (PBKDF2)

2. **Additional Anti-Debug**
   - Hardware breakpoint detection
   - Timing checks
   - Debugger window detection

3. **Code Obfuscation**
   - Obfuscate the injector code
   - Add control flow flattening

4. **Integrity Checking**
   - Verify DLL hasn't been tampered with
   - Implement secure checksum/signature

5. **Sandboxing Detection**
   - Detect virtual machines
   - Detect sandboxed environments
