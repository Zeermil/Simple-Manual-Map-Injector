#pragma once

#include <Windows.h>
#include <memory>

// Simple AES ECB decryption for DLL bytes
// Uses Windows CNG (Cryptography API: Next Generation)
bool AES_ECB_Decrypt(const BYTE* encryptedData, SIZE_T dataSize, const BYTE* key, SIZE_T keySize, BYTE** outDecryptedData, SIZE_T* outDecryptedSize);

// Helper function to unpad PKCS7 padding
SIZE_T UnpadPKCS7(BYTE* data, SIZE_T dataSize);
