# Encrypted DLL Injection

This document describes the encrypted DLL injection feature, which enhances security by keeping DLL bytes encrypted until the moment of injection.

## Overview

The encrypted injection feature allows you to:
- Download/store DLLs in encrypted form
- Pass encrypted bytes to the injector
- Have the injector decrypt the DLL only at injection time
- Reduce the window of time that unencrypted DLL bytes exist in memory

## Architecture

### Traditional Flow (Without Encryption)
```
Server → Encrypted DLL → Loader (Decrypts) → Plaintext DLL → Injector → Process
```

### New Flow (With Encryption)
```
Server → Encrypted DLL → Loader → Encrypted DLL → Injector (Decrypts) → Process
```

## Benefits

1. **Enhanced Security**: DLL bytes remain encrypted during transport and storage
2. **Reduced Detection**: Plaintext DLL bytes only exist briefly during injection
3. **Defense in Depth**: Additional layer of protection against memory scanning

## Encryption Algorithm

- **Algorithm**: AES-128 (ECB mode)
- **Key Size**: 16 bytes (128 bits)
- **Padding**: PKCS7

## API Functions

### C/C++ API

#### InjectEncryptedDllFromMemorySimple

Simple function for encrypted DLL injection with default parameters.

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
- `encryptedDllData`: Pointer to encrypted DLL bytes
- `encryptedDllSize`: Size of encrypted data in bytes
- `encryptionKey`: AES encryption key (must be 16 bytes)
- `keySize`: Size of the key (must be 16)

**Return Values:**
- `0`: Success
- `-1`: Process not found
- `-2`: Failed to open process
- `-3`: Process architecture mismatch
- `-4`: Invalid DLL data
- `-5`: Injection failed
- `-6`: Decryption failed

#### InjectEncryptedDllFromMemory

Advanced function with configurable injection parameters.

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

### Python API

#### Basic Usage

```python
import ctypes

# Load the injector DLL
injector = ctypes.CDLL("ManualMapInjector-x64.dll")

# Read encrypted DLL
with open("encrypted_target.dll", "rb") as f:
    encrypted_dll_bytes = f.read()

# Define AES key (16 bytes)
encryption_key = b'sixteen byte key'

# Setup function signature
injector.InjectEncryptedDllFromMemorySimple.argtypes = [
    ctypes.c_char_p,                    # processName
    ctypes.POINTER(ctypes.c_ubyte),     # encryptedDllData
    ctypes.c_size_t,                    # encryptedDllSize
    ctypes.POINTER(ctypes.c_ubyte),     # encryptionKey
    ctypes.c_size_t                     # keySize
]
injector.InjectEncryptedDllFromMemorySimple.restype = ctypes.c_int

# Convert to ctypes arrays
dll_array = (ctypes.c_ubyte * len(encrypted_dll_bytes)).from_buffer_copy(encrypted_dll_bytes)
key_array = (ctypes.c_ubyte * len(encryption_key)).from_buffer_copy(encryption_key)
process_name = b"notepad.exe"

# Perform injection
result = injector.InjectEncryptedDllFromMemorySimple(
    process_name,
    dll_array,
    len(encrypted_dll_bytes),
    key_array,
    len(encryption_key)
)

if result == 0:
    print("✓ Injection successful!")
elif result == -6:
    print("✗ Decryption failed - check encryption key")
else:
    print(f"✗ Injection failed with code: {result}")
```

## Encrypting DLLs

To encrypt a DLL for use with this feature, you can use Python with PyCryptodome:

```python
from Crypto.Cipher import AES

def pad(data: bytes) -> bytes:
    """Add PKCS7 padding"""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def encrypt_dll(dll_path: str, output_path: str, key: bytes):
    """Encrypt a DLL file using AES-128 ECB"""
    # Read DLL
    with open(dll_path, 'rb') as f:
        dll_data = f.read()
    
    # Pad and encrypt
    padded_data = pad(dll_data)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(padded_data)
    
    # Save encrypted DLL
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"Encrypted {len(dll_data)} bytes to {len(encrypted_data)} bytes")

# Example usage
encryption_key = b'sixteen byte key'
encrypt_dll('target.dll', 'target_encrypted.dll', encryption_key)
```

## Integration with Loaders

When integrating with a loader that downloads DLLs from a server:

1. **Server Side**: Encrypt the DLL before storing/serving
2. **Loader Side**: Download encrypted DLL, keep it encrypted
3. **Injection**: Pass encrypted bytes + key to injector
4. **Injector**: Decrypts and injects in one operation

Example loader code:

```python
def download_and_inject(dll_url, process_name, encryption_key):
    # Download encrypted DLL
    response = requests.get(dll_url)
    encrypted_dll = response.content
    
    # Load injector
    injector = ctypes.CDLL("ManualMapInjector-x64.dll")
    
    # Setup function
    injector.InjectEncryptedDllFromMemorySimple.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t
    ]
    injector.InjectEncryptedDllFromMemorySimple.restype = ctypes.c_int
    
    # Convert to ctypes
    dll_array = (ctypes.c_ubyte * len(encrypted_dll)).from_buffer_copy(encrypted_dll)
    key_array = (ctypes.c_ubyte * len(encryption_key)).from_buffer_copy(encryption_key)
    
    # Inject
    result = injector.InjectEncryptedDllFromMemorySimple(
        process_name.encode(),
        dll_array,
        len(encrypted_dll),
        key_array,
        len(encryption_key)
    )
    
    return result == 0
```

## Security Considerations

1. **Key Management**: Store encryption keys securely
2. **Key Rotation**: Consider rotating encryption keys periodically
3. **Transport Security**: Use HTTPS when downloading encrypted DLLs
4. **Memory Protection**: The decrypted DLL exists briefly in injector memory
5. **ECB Mode**: While ECB mode is used for simplicity, consider CBC/GCM for enhanced security in production

## Troubleshooting

### Decryption Failed (-6)

Common causes:
- Incorrect encryption key
- DLL was not properly encrypted
- Wrong padding scheme
- Corrupted encrypted data

### Invalid DLL Data (-4)

After decryption, the data is not a valid PE file:
- Check encryption/decryption key matches
- Verify padding was applied correctly during encryption
- Ensure complete encrypted data was received

## Implementation Details

The decryption is implemented using Windows CNG (Cryptography API: Next Generation) in the C++ injector:

- **Library**: `bcrypt.lib`
- **Algorithm Provider**: `BCRYPT_AES_ALGORITHM`
- **Chaining Mode**: `BCRYPT_CHAIN_MODE_ECB`
- **Padding**: Removed using PKCS7 unpadding

The implementation automatically:
1. Opens AES algorithm provider
2. Sets ECB chaining mode
3. Generates symmetric key from key bytes
4. Decrypts the data
5. Removes PKCS7 padding
6. Validates the decrypted PE structure
7. Proceeds with injection

## Compatibility

- **Operating System**: Windows (uses Windows CNG API)
- **Architectures**: x86 and x64
- **Python**: Works with ctypes in Python 2.7+ and Python 3.x
- **Encryption Library**: Compatible with PyCryptodome, PyCrypto, and other AES implementations
