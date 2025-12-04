#!/usr/bin/env python3
"""
Example Python script for using the Manual Map Injector DLL with encryption.

This script demonstrates how to:
1. Load the ManualMapInjector DLL
2. Read a DLL file into memory
3. Encrypt it with XOR cipher
4. Inject it into a target process using encrypted DLL bytes

Usage:
    python example_encrypted_python.py <dll_to_inject> <process_name> [encryption_key]

Example:
    python example_encrypted_python.py hello-world-x64.dll notepad.exe MySecretKey123
"""

import ctypes
import sys
import os
from pathlib import Path


def xor_encrypt(data, key):
    """
    Simple XOR encryption/decryption.
    The same function works for both encryption and decryption.
    
    Args:
        data: bytes to encrypt/decrypt
        key: encryption key as bytes
    
    Returns:
        encrypted/decrypted bytes
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    key_length = len(key)
    return bytes([data[i] ^ key[i % key_length] for i in range(len(data))])


def inject_encrypted_dll_from_memory(injector_dll_path, encrypted_dll_bytes, 
                                     encryption_key, process_name,
                                     clear_header=True, 
                                     clear_non_needed_sections=True,
                                     adjust_protections=True,
                                     seh_exception_support=True):
    """
    Inject an encrypted DLL from memory into a target process.
    
    Args:
        injector_dll_path: Path to the ManualMapInjector DLL
        encrypted_dll_bytes: Encrypted bytes of the DLL to inject
        encryption_key: Encryption key as bytes or string
        process_name: Name of the target process (e.g., "notepad.exe")
        clear_header: Whether to clear PE header after injection
        clear_non_needed_sections: Whether to clear non-needed sections
        adjust_protections: Whether to adjust memory protections
        seh_exception_support: Whether to enable SEH exception support (x64 only)
    
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

    # Convert key to bytes if string
    if isinstance(encryption_key, str):
        encryption_key = encryption_key.encode('utf-8')
    
    # Define the function signature
    # int InjectEncryptedDllFromMemory(const char* processName, 
    #                                   const unsigned char* encryptedDllData,
    #                                   size_t dllSize,
    #                                   const unsigned char* encryptionKey,
    #                                   size_t keySize,
    #                                   bool clearHeader,
    #                                   bool clearNonNeededSections,
    #                                   bool adjustProtections,
    #                                   bool sehExceptionSupport)
    injector.InjectEncryptedDllFromMemory.argtypes = [
        ctypes.c_char_p,  # processName
        ctypes.POINTER(ctypes.c_ubyte),  # encryptedDllData
        ctypes.c_size_t,  # dllSize
        ctypes.POINTER(ctypes.c_ubyte),  # encryptionKey
        ctypes.c_size_t,  # keySize
        ctypes.c_bool,    # clearHeader
        ctypes.c_bool,    # clearNonNeededSections
        ctypes.c_bool,    # adjustProtections
        ctypes.c_bool     # sehExceptionSupport
    ]
    injector.InjectEncryptedDllFromMemory.restype = ctypes.c_int
    
    # Convert DLL bytes to ctypes array
    dll_array = (ctypes.c_ubyte * len(encrypted_dll_bytes)).from_buffer_copy(encrypted_dll_bytes)
    
    # Convert key to ctypes array
    key_array = (ctypes.c_ubyte * len(encryption_key)).from_buffer_copy(encryption_key)
    
    # Convert process name to bytes
    process_name_bytes = process_name.encode('utf-8')
    
    # Call the injection function
    result = injector.InjectEncryptedDllFromMemory(
        process_name_bytes,
        dll_array,
        len(encrypted_dll_bytes),
        key_array,
        len(encryption_key),
        clear_header,
        clear_non_needed_sections,
        adjust_protections,
        seh_exception_support
    )
    
    return result


def inject_encrypted_dll_from_memory_simple(injector_dll_path, encrypted_dll_bytes, 
                                            encryption_key, process_name):
    """
    Simplified version of inject_encrypted_dll_from_memory with default parameters.
    
    Args:
        injector_dll_path: Path to the ManualMapInjector DLL
        encrypted_dll_bytes: Encrypted bytes of the DLL to inject
        encryption_key: Encryption key as bytes or string
        process_name: Name of the target process (e.g., "notepad.exe")
    
    Returns:
        0 on success, negative error code on failure
    """
    try:
        injector = ctypes.CDLL(str(injector_dll_path))
    except Exception as e:
        print(f"Error loading injector DLL: {e}")
        return -100

    # Convert key to bytes if string
    if isinstance(encryption_key, str):
        encryption_key = encryption_key.encode('utf-8')
    
    # Define the function signature for the simple version
    injector.InjectEncryptedDllFromMemorySimple.argtypes = [
        ctypes.c_char_p,  # processName
        ctypes.POINTER(ctypes.c_ubyte),  # encryptedDllData
        ctypes.c_size_t,  # dllSize
        ctypes.POINTER(ctypes.c_ubyte),  # encryptionKey
        ctypes.c_size_t   # keySize
    ]
    injector.InjectEncryptedDllFromMemorySimple.restype = ctypes.c_int
    
    # Convert DLL bytes to ctypes array
    dll_array = (ctypes.c_ubyte * len(encrypted_dll_bytes)).from_buffer_copy(encrypted_dll_bytes)
    
    # Convert key to ctypes array
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


def save_encrypted_dll(dll_path, output_path, encryption_key):
    """
    Encrypt a DLL file and save it to disk.
    
    Args:
        dll_path: Path to the DLL to encrypt
        output_path: Path where to save encrypted DLL
        encryption_key: Encryption key as string or bytes
    """
    with open(dll_path, 'rb') as f:
        dll_bytes = f.read()
    
    encrypted_bytes = xor_encrypt(dll_bytes, encryption_key)
    
    with open(output_path, 'wb') as f:
        f.write(encrypted_bytes)
    
    print(f"Encrypted DLL saved to: {output_path}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python example_encrypted_python.py <dll_to_inject> <process_name> [encryption_key]")
        print("Example: python example_encrypted_python.py hello-world-x64.dll notepad.exe MySecretKey123")
        print()
        print("If encryption_key is not provided, a default key will be used.")
        sys.exit(1)
    
    dll_to_inject = sys.argv[1]
    process_name = sys.argv[2]
    
    # Use provided encryption key or default
    if len(sys.argv) >= 4:
        encryption_key = sys.argv[3]
    else:
        encryption_key = "DefaultEncryptionKey2024"
        print(f"Using default encryption key: {encryption_key}")
    
    # Check if DLL file exists
    if not os.path.exists(dll_to_inject):
        print(f"Error: DLL file '{dll_to_inject}' not found")
        sys.exit(1)
    
    # Determine the injector DLL path based on Python architecture
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    if pointer_size == 8:
        injector_dll = "build/ManualMapInjector-x64.dll"
    elif pointer_size == 4:
        injector_dll = "build/ManualMapInjector-x86.dll"
    else:
        print(f"Error: Unsupported pointer size: {pointer_size}")
        sys.exit(1)
    
    if not os.path.exists(injector_dll):
        print(f"Error: Injector DLL '{injector_dll}' not found")
        print("Please build the DLL first using CMake")
        sys.exit(1)
    
    # Read the DLL to inject into memory
    print(f"Reading DLL: {dll_to_inject}")
    with open(dll_to_inject, 'rb') as f:
        dll_bytes = f.read()
    
    print(f"DLL size: {len(dll_bytes)} bytes")
    print(f"Encryption key: {encryption_key}")
    
    # Encrypt the DLL
    print("Encrypting DLL...")
    encrypted_dll_bytes = xor_encrypt(dll_bytes, encryption_key)
    print(f"Encrypted DLL size: {len(encrypted_dll_bytes)} bytes")
    
    print(f"Target process: {process_name}")
    print(f"Using injector: {injector_dll}")
    print()
    print("Injecting encrypted DLL...")
    
    # Perform the injection using the simple interface
    result = inject_encrypted_dll_from_memory_simple(
        injector_dll, 
        encrypted_dll_bytes, 
        encryption_key,
        process_name
    )
    
    # Interpret the result
    if result == 0:
        print("✓ Injection successful!")
    elif result == -1:
        print(f"✗ Error: Process '{process_name}' not found")
    elif result == -2:
        print("✗ Error: Failed to open process (insufficient privileges?)")
    elif result == -3:
        print("✗ Error: Process architecture mismatch (use matching x86/x64 DLL)")
    elif result == -4:
        print("✗ Error: Invalid DLL data or encryption key")
    elif result == -5:
        print("✗ Error: Injection failed")
    elif result == -6:
        print("✗ Error: Decryption failed")
    else:
        print(f"✗ Error: Unknown error code {result}")
    
    sys.exit(0 if result == 0 else 1)


if __name__ == "__main__":
    main()
