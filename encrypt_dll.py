#!/usr/bin/env python3
"""
Helper script to encrypt DLL files for use with encrypted injection.

This script encrypts a DLL using AES-128 ECB with PKCS7 padding,
making it compatible with the InjectEncryptedDllFromMemory* functions.

Usage:
    python encrypt_dll.py <input_dll> <output_encrypted_dll> [key]

Example:
    python encrypt_dll.py hello-world-x64.dll hello-world-x64-encrypted.dll
    python encrypt_dll.py target.dll encrypted.dll "sixteen byte key"
"""

import sys
import os
from Crypto.Cipher import AES


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """Add PKCS7 padding to data"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def encrypt_dll(dll_path: str, output_path: str, key: bytes):
    """
    Encrypt a DLL file using AES-128 ECB with PKCS7 padding.
    
    Args:
        dll_path: Path to the input DLL file
        output_path: Path for the encrypted output file
        key: 16-byte AES encryption key
    """
    if len(key) != 16:
        raise ValueError("Encryption key must be exactly 16 bytes for AES-128")
    
    # Read DLL
    print(f"Reading DLL: {dll_path}")
    with open(dll_path, 'rb') as f:
        dll_data = f.read()
    
    print(f"Original size: {len(dll_data)} bytes")
    
    # Add PKCS7 padding
    padded_data = pad_pkcs7(dll_data)
    print(f"Padded size: {len(padded_data)} bytes")
    
    # Encrypt using AES-128 ECB
    # Note: ECB mode is used for compatibility with the C++ injector implementation.
    # For production use, consider using CBC or GCM mode for enhanced security.
    # ECB is acceptable here as the DLL content has high entropy and is not
    # sensitive to pattern analysis in this specific use case.
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(padded_data)
    
    print(f"Encrypted size: {len(encrypted_data)} bytes")
    
    # Save encrypted DLL
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"✓ Encrypted DLL saved to: {output_path}")
    print(f"✓ Use this key for injection: {key.hex()}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python encrypt_dll.py <input_dll> <output_encrypted_dll> [key]")
        print("\nExample:")
        print("  python encrypt_dll.py hello-world-x64.dll hello-world-x64-encrypted.dll")
        print('  python encrypt_dll.py target.dll encrypted.dll "sixteen byte key"')
        print("\nIf no key is provided, the default key from key_data.py will be used.")
        sys.exit(1)
    
    input_dll = sys.argv[1]
    output_dll = sys.argv[2]
    
    # Get encryption key
    if len(sys.argv) >= 4:
        # Key provided as argument
        key_str = sys.argv[3]
        if len(key_str) != 16:
            print(f"Error: Encryption key must be exactly 16 bytes, got {len(key_str)} bytes")
            print("Please provide a 16-character key or use the default from key_data.py")
            sys.exit(1)
        key = key_str.encode('utf-8')
    else:
        # Use default key from key_data.py
        try:
            from key_data import KEY
            key = KEY
            print(f"Using default encryption key from key_data.py")
        except ImportError:
            print("Error: Could not import key_data.py")
            print("Please provide a key as the third argument")
            sys.exit(1)
    
    # Check if input file exists
    if not os.path.exists(input_dll):
        print(f"Error: Input DLL '{input_dll}' not found")
        sys.exit(1)
    
    # Encrypt the DLL
    try:
        encrypt_dll(input_dll, output_dll, key)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
