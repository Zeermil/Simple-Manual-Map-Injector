#!/usr/bin/env python3
"""
Example script demonstrating encrypted DLL injection.

This script shows how to:
1. Load an encrypted DLL from disk
2. Use the injector to decrypt and inject it at runtime

Usage:
    python example_encrypted_injection.py <encrypted_dll> <process_name> [key]

Example:
    python example_encrypted_injection.py hello-world-x64-encrypted.dll notepad.exe
    python example_encrypted_injection.py encrypted.dll notepad.exe "sixteen byte key"

Note: You must first encrypt your DLL using encrypt_dll.py
"""

import ctypes
import sys
import os
from pathlib import Path


def inject_encrypted_dll(injector_dll_path, encrypted_dll_bytes, encryption_key, process_name):
    """
    Inject encrypted DLL from memory.
    
    Args:
        injector_dll_path: Path to the ManualMapInjector DLL
        encrypted_dll_bytes: Encrypted bytes of the DLL to inject
        encryption_key: AES encryption key (16 bytes)
        process_name: Name of the target process (e.g., "notepad.exe")
    
    Returns:
        0 on success, negative error code on failure:
        -1: Process not found
        -2: Failed to open process
        -3: Invalid process architecture
        -4: Invalid DLL data
        -5: Injection failed
        -6: Decryption failed
    """
    # Load the injector DLL
    try:
        injector = ctypes.CDLL(str(injector_dll_path))
    except Exception as e:
        print(f"Error loading injector DLL: {e}")
        return -100
    
    # Define the function signature
    injector.InjectEncryptedDllFromMemorySimple.argtypes = [
        ctypes.c_char_p,                    # processName
        ctypes.POINTER(ctypes.c_ubyte),     # encryptedDllData
        ctypes.c_size_t,                    # encryptedDllSize
        ctypes.POINTER(ctypes.c_ubyte),     # encryptionKey
        ctypes.c_size_t                     # keySize
    ]
    injector.InjectEncryptedDllFromMemorySimple.restype = ctypes.c_int
    
    # Convert encrypted DLL bytes to ctypes array
    dll_array = (ctypes.c_ubyte * len(encrypted_dll_bytes)).from_buffer_copy(encrypted_dll_bytes)
    
    # Convert encryption key to ctypes array
    key_array = (ctypes.c_ubyte * len(encryption_key)).from_buffer_copy(encryption_key)
    
    # Convert process name to bytes
    process_name_bytes = process_name.encode('utf-8')
    
    # Call the injection function
    result = injector.InjectEncryptedDllFromMemorySimple(
        process_name_bytes,
        dll_array,
        len(encrypted_dll_bytes),
        key_array,
        len(encryption_key)
    )
    
    return result


def main():
    if len(sys.argv) < 3:
        print("Usage: python example_encrypted_injection.py <encrypted_dll> <process_name> [key]")
        print("\nExample:")
        print("  python example_encrypted_injection.py hello-world-x64-encrypted.dll notepad.exe")
        print('  python example_encrypted_injection.py encrypted.dll notepad.exe "sixteen byte key"')
        print("\nNote: Encrypt your DLL first using encrypt_dll.py")
        sys.exit(1)
    
    encrypted_dll_path = sys.argv[1]
    process_name = sys.argv[2]
    
    # Get encryption key
    if len(sys.argv) >= 4:
        # Key provided as argument
        key_str = sys.argv[3]
        if len(key_str) != 16:
            print(f"Error: Encryption key must be exactly 16 bytes, got {len(key_str)} bytes")
            sys.exit(1)
        encryption_key = key_str.encode('utf-8')
    else:
        # Use default key from key_data.py
        try:
            from key_data import KEY
            encryption_key = KEY
            print(f"Using default encryption key from key_data.py")
        except ImportError:
            print("Error: Could not import key_data.py")
            print("Please provide a key as the third argument")
            sys.exit(1)
    
    # Check if encrypted DLL file exists
    if not os.path.exists(encrypted_dll_path):
        print(f"Error: Encrypted DLL file '{encrypted_dll_path}' not found")
        print("Please encrypt your DLL first using encrypt_dll.py")
        sys.exit(1)
    
    # Determine the injector DLL path based on Python architecture
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    if pointer_size == 8:
        # 64-bit Python
        injector_dll = "build/ManualMapInjector-x64.dll"
    elif pointer_size == 4:
        # 32-bit Python
        injector_dll = "build/ManualMapInjector-x86.dll"
    else:
        print(f"Error: Unsupported pointer size: {pointer_size}")
        sys.exit(1)
    
    if not os.path.exists(injector_dll):
        print(f"Error: Injector DLL '{injector_dll}' not found")
        print("Please build the DLL first using CMake")
        sys.exit(1)
    
    # Read the encrypted DLL
    print(f"Reading encrypted DLL: {encrypted_dll_path}")
    with open(encrypted_dll_path, 'rb') as f:
        encrypted_dll_bytes = f.read()
    
    print(f"Encrypted DLL size: {len(encrypted_dll_bytes)} bytes")
    print(f"Target process: {process_name}")
    print(f"Using injector: {injector_dll}")
    print(f"Encryption key: {encryption_key.hex()}")
    print()
    print("Injecting encrypted DLL...")
    print("(The injector will decrypt the DLL at injection time)")
    print()
    
    # Perform the encrypted injection
    result = inject_encrypted_dll(injector_dll, encrypted_dll_bytes, encryption_key, process_name)
    
    # Interpret the result
    if result == 0:
        print("✓ Encrypted injection successful!")
        print("  The DLL was decrypted and injected in one operation")
    elif result == -1:
        print(f"✗ Error: Process '{process_name}' not found")
    elif result == -2:
        print("✗ Error: Failed to open process (insufficient privileges?)")
        print("  Try running as administrator")
    elif result == -3:
        print("✗ Error: Process architecture mismatch")
        print("  Use matching x86/x64 DLL and Python version")
    elif result == -4:
        print("✗ Error: Invalid DLL data after decryption")
        print("  The decrypted data is not a valid PE file")
        print("  Check that the encryption key is correct")
    elif result == -5:
        print("✗ Error: Injection failed")
    elif result == -6:
        print("✗ Error: Decryption failed")
        print("  Possible causes:")
        print("  - Incorrect encryption key")
        print("  - DLL was not properly encrypted")
        print("  - Corrupted encrypted data")
    else:
        print(f"✗ Error: Unknown error code {result}")
    
    sys.exit(0 if result == 0 else 1)


if __name__ == "__main__":
    main()
