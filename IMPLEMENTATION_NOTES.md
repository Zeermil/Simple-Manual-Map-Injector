# Implementation Notes: Encrypted DLL Injection

## Problem Statement (Translation)

The user requested the following functionality (translated from Russian):

> "Add functionality so that the loader passes encrypted DLL bytes to the injector instead of plain bytes, and the loader decrypts them only at the moment of injection. So the loader downloads the DLL but doesn't decrypt it, simply passes the encrypted bytes to the injector and the injector decrypts them."
>
> "P.S. The loader downloads ManualMapInjector-x64.dll from the server and uses its functions."

## Solution Overview

The implementation adds support for encrypted DLL injection with the following architecture:

### Before (Original Flow)
```
Server → [Encrypted DLL] → Loader → [Decrypt] → [Plain DLL bytes] → Injector → Process
                                                  ^
                                                  | Vulnerable window
```

### After (New Flow)
```
Server → [Encrypted DLL] → Loader → [Encrypted DLL bytes] → Injector → [Decrypt] → Process
                                                                           ^
                                                                           | Minimal exposure
```

## Changes Made

### 1. C++ Injector Changes

#### New Files

**`Manual Map Injector/crypto.h`**
- Header file defining AES decryption functions
- Exports `AES_ECB_Decrypt()` function
- Exports `UnpadPKCS7()` helper function

**`Manual Map Injector/crypto.cpp`**
- Implements AES-128 ECB decryption using Windows CNG API
- Uses `bcrypt.lib` for cryptographic operations
- Implements PKCS7 padding removal
- Handles memory management for decrypted data

#### Modified Files

**`Manual Map Injector/injector_dll.cpp`**
- Added `#include "crypto.h"`
- Added `InjectEncryptedDllFromMemory()` function
  - Accepts encrypted DLL bytes and encryption key
  - Decrypts the DLL using AES-128 ECB
  - Validates decrypted data
  - Performs standard injection
  - Returns `-6` error code for decryption failures
- Added `InjectEncryptedDllFromMemorySimple()` convenience function
  - Simplified API with default parameters
  - Wrapper around `InjectEncryptedDllFromMemory()`

**`CMakeLists.txt`**
- Added `crypto.cpp` to `SOURCE_FILES`
- Added `crypto.h` to `HEADER_FILES`

### 2. Python Loader Changes

**`loader_gui_test.py`**

Modified `download_dll()` method:
- **Before**: Downloaded encrypted DLL and decrypted it immediately
- **After**: Downloads encrypted DLL and returns it without decryption

Added `inject_encrypted_dll_from_memory_simple()` function:
- New Python function to call the encrypted injection API
- Sets up ctypes signatures for the new C++ function
- Passes encrypted bytes and encryption key to the injector

Modified `inject_dll()` method:
- Changed to use `inject_encrypted_dll_from_memory_simple()`
- Passes encrypted DLL bytes directly to the injector
- Includes encryption key from `DECRYPTION_KEY`
- Added handling for `-6` (decryption error) return code

### 3. Documentation

**New Files:**
- `ENCRYPTION.md` - Comprehensive guide to encrypted injection
- `encrypt_dll.py` - Helper script to encrypt DLLs for testing
- `example_encrypted_injection.py` - Example demonstrating encrypted injection

**Updated Files:**
- `README.md` - Added encrypted injection API documentation and examples
- `README.ru.md` - Added Russian documentation for encrypted injection
- `example_python.py` - Added `inject_encrypted_dll_from_memory_simple()` function

## Technical Details

### Encryption Algorithm

- **Algorithm**: AES-128
- **Mode**: ECB (Electronic Codebook)
- **Key Size**: 16 bytes (128 bits)
- **Padding**: PKCS7

### Windows CNG API Usage

The decryption implementation uses Windows Cryptography API: Next Generation (CNG):

1. `BCryptOpenAlgorithmProvider()` - Opens AES algorithm provider
2. `BCryptSetProperty()` - Sets ECB chaining mode
3. `BCryptGenerateSymmetricKey()` - Creates key from key bytes
4. `BCryptDecrypt()` - Decrypts the data
5. Manual PKCS7 unpadding - Removes padding bytes

### Error Codes

The new functions return standard error codes plus:
- `-6`: Decryption failed (new error code)

Possible causes for `-6`:
- Incorrect encryption key
- Corrupted encrypted data
- Invalid padding
- Wrong encryption algorithm/mode used

## Compatibility

### Backward Compatibility

The implementation maintains full backward compatibility:
- Existing `InjectDllFromMemory()` functions remain unchanged
- Existing `InjectDllFromMemorySimple()` functions remain unchanged
- Old code continues to work without modifications

### New Features

Applications can now choose between:
1. **Traditional injection**: `InjectDllFromMemorySimple()` with plain bytes
2. **Encrypted injection**: `InjectEncryptedDllFromMemorySimple()` with encrypted bytes

## Security Benefits

1. **Reduced Attack Surface**: DLL bytes remain encrypted during download and storage
2. **Memory Protection**: Plain DLL bytes only exist briefly during injection
3. **Anti-Analysis**: Makes it harder to analyze the DLL before injection
4. **Defense in Depth**: Additional security layer for sensitive payloads

## Usage Example (Python)

```python
import ctypes
from key_data import KEY as DECRYPTION_KEY

# Download encrypted DLL (kept encrypted)
encrypted_dll_bytes = download_encrypted_dll_from_server()

# Load injector
injector = ctypes.CDLL("ManualMapInjector-x64.dll")

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
key_array = (ctypes.c_ubyte * len(DECRYPTION_KEY)).from_buffer_copy(DECRYPTION_KEY)

# Inject - decryption happens here
result = injector.InjectEncryptedDllFromMemorySimple(
    b"target.exe",
    dll_array,
    len(encrypted_dll_bytes),
    key_array,
    len(DECRYPTION_KEY)
)

if result == 0:
    print("Success!")
elif result == -6:
    print("Decryption failed - check key")
```

## Testing

Since this is a Windows-specific project requiring Visual Studio, testing requires:

1. Build the project on Windows using CMake and Visual Studio
2. Use `encrypt_dll.py` to encrypt a test DLL
3. Run `example_encrypted_injection.py` to test the encrypted injection
4. Verify the DLL is properly decrypted and injected

Test command sequence:
```bash
# Build the project
build_all.bat

# Encrypt a test DLL
python encrypt_dll.py hello-world-x64.dll hello-world-x64-encrypted.dll

# Test encrypted injection
python example_encrypted_injection.py hello-world-x64-encrypted.dll notepad.exe
```

## Future Improvements

Possible enhancements for future versions:

1. **Better Encryption Mode**: Replace ECB with CBC or GCM for enhanced security
2. **Key Derivation**: Add PBKDF2 or similar for key derivation
3. **Multiple Algorithms**: Support for different encryption algorithms
4. **Compression**: Add optional compression before encryption
5. **Integrity Check**: Add HMAC or similar for integrity verification

## Files Modified Summary

### New Files (6)
1. `Manual Map Injector/crypto.h` - Crypto header
2. `Manual Map Injector/crypto.cpp` - Crypto implementation
3. `ENCRYPTION.md` - Documentation
4. `IMPLEMENTATION_NOTES.md` - This file
5. `encrypt_dll.py` - Encryption helper script
6. `example_encrypted_injection.py` - Example script

### Modified Files (5)
1. `Manual Map Injector/injector_dll.cpp` - Added encrypted injection functions
2. `CMakeLists.txt` - Added crypto files to build
3. `loader_gui_test.py` - Updated to use encrypted injection
4. `README.md` - Added encrypted injection documentation
5. `README.ru.md` - Added Russian documentation
6. `example_python.py` - Added encrypted injection example function

## Commit History

1. **Initial plan** - Outlined implementation strategy
2. **Add encrypted DLL injection support** - Core C++ and Python implementation
3. **Add comprehensive documentation** - Documentation for encrypted injection
4. **Add helper scripts and examples** - Utility scripts and examples

## Build Requirements

No additional dependencies are required beyond the existing project requirements:
- CMake 3.15+
- Visual Studio 2019+ with C++ Desktop Development
- Windows SDK (for bcrypt.lib)

The Windows CNG API (`bcrypt.lib`) is part of the standard Windows SDK and doesn't require separate installation.

## Notes for Maintainers

1. **Key Management**: The encryption key is currently stored in `key_data.py`. Consider secure key management in production.
2. **ECB Mode**: ECB mode is used for simplicity. For production, consider CBC/GCM modes.
3. **Error Handling**: The implementation includes comprehensive error handling and cleanup.
4. **Memory Safety**: Uses smart pointers and proper cleanup to prevent memory leaks.
5. **Backward Compatibility**: All existing APIs remain unchanged and functional.
