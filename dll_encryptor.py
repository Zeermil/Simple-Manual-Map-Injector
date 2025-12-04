#!/usr/bin/env python3
"""
DLL Encryption/Decryption Utility

This script provides utilities for encrypting and decrypting DLL files
using XOR cipher for use with the Manual Map Injector.

Usage:
    # Encrypt a DLL
    python dll_encryptor.py encrypt input.dll output.dll.enc MySecretKey

    # Decrypt a DLL
    python dll_encryptor.py decrypt input.dll.enc output.dll MySecretKey

    # Generate a random encryption key
    python dll_encryptor.py genkey

Note: XOR encryption is symmetric, so encryption and decryption use the same operation.
"""

import sys
import os
import secrets
import string


def xor_cipher(data, key):
    """
    Simple XOR encryption/decryption.
    The same function works for both encryption and decryption.
    
    Args:
        data: bytes to encrypt/decrypt
        key: encryption key as bytes or string
    
    Returns:
        encrypted/decrypted bytes
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    key_length = len(key)
    return bytes([data[i] ^ key[i % key_length] for i in range(len(data))])


def encrypt_file(input_path, output_path, key):
    """
    Encrypt a file using XOR cipher.
    
    Args:
        input_path: Path to input file
        output_path: Path to output encrypted file
        key: Encryption key as string or bytes
    """
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
        
        print(f"Read {len(data)} bytes from {input_path}")
        
        encrypted_data = xor_cipher(data, key)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"Encrypted {len(encrypted_data)} bytes to {output_path}")
        print("✓ Encryption successful!")
        return True
    except Exception as e:
        print(f"✗ Error during encryption: {e}")
        return False


def decrypt_file(input_path, output_path, key):
    """
    Decrypt a file using XOR cipher.
    Note: For XOR, decryption is the same as encryption.
    
    Args:
        input_path: Path to input encrypted file
        output_path: Path to output decrypted file
        key: Decryption key as string or bytes
    """
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
        
        print(f"Read {len(data)} bytes from {input_path}")
        
        decrypted_data = xor_cipher(data, key)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"Decrypted {len(decrypted_data)} bytes to {output_path}")
        print("✓ Decryption successful!")
        return True
    except Exception as e:
        print(f"✗ Error during decryption: {e}")
        return False


def generate_key(length=32):
    """
    Generate a random encryption key.
    
    Args:
        length: Length of the key to generate (default: 32)
    
    Returns:
        Random key string
    """
    alphabet = string.ascii_letters + string.digits + string.punctuation
    key = ''.join(secrets.choice(alphabet) for _ in range(length))
    return key


def print_usage():
    """Print usage information."""
    print("DLL Encryption/Decryption Utility")
    print()
    print("Usage:")
    print("  Encrypt:  python dll_encryptor.py encrypt <input_dll> <output_file> <encryption_key>")
    print("  Decrypt:  python dll_encryptor.py decrypt <input_file> <output_dll> <encryption_key>")
    print("  Gen Key:  python dll_encryptor.py genkey [length]")
    print()
    print("Examples:")
    print("  python dll_encryptor.py encrypt hello-world.dll hello-world.dll.enc MySecretKey123")
    print("  python dll_encryptor.py decrypt hello-world.dll.enc hello-world-decrypted.dll MySecretKey123")
    print("  python dll_encryptor.py genkey")
    print("  python dll_encryptor.py genkey 64")
    print()
    print("Note: Keep your encryption key secret and safe!")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "genkey":
        # Generate a random key
        key_length = 32
        if len(sys.argv) >= 3:
            try:
                key_length = int(sys.argv[2])
            except ValueError:
                print("Error: Invalid key length")
                sys.exit(1)
        
        key = generate_key(key_length)
        print(f"Generated random encryption key ({key_length} characters):")
        print(key)
        print()
        print("Save this key in a secure location!")
        
    elif command == "encrypt":
        if len(sys.argv) != 5:
            print("Error: Invalid arguments for encrypt command")
            print()
            print_usage()
            sys.exit(1)
        
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        key = sys.argv[4]
        
        if not os.path.exists(input_path):
            print(f"Error: Input file '{input_path}' not found")
            sys.exit(1)
        
        if not encrypt_file(input_path, output_path, key):
            sys.exit(1)
    
    elif command == "decrypt":
        if len(sys.argv) != 5:
            print("Error: Invalid arguments for decrypt command")
            print()
            print_usage()
            sys.exit(1)
        
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        key = sys.argv[4]
        
        if not os.path.exists(input_path):
            print(f"Error: Input file '{input_path}' not found")
            sys.exit(1)
        
        if not decrypt_file(input_path, output_path, key):
            sys.exit(1)
    
    else:
        print(f"Error: Unknown command '{command}'")
        print()
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
