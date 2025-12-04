#include "crypto.h"
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

// Unpad PKCS7 padding
SIZE_T UnpadPKCS7(BYTE* data, SIZE_T dataSize) {
    if (dataSize == 0) {
        return 0;
    }
    
    BYTE padValue = data[dataSize - 1];
    
    // Check if padding value is valid (1-16 for AES)
    if (padValue == 0 || padValue > 16 || padValue > dataSize) {
        return dataSize; // Invalid padding, return original size
    }
    
    // Verify all padding bytes are the same
    for (SIZE_T i = dataSize - padValue; i < dataSize; i++) {
        if (data[i] != padValue) {
            return dataSize; // Invalid padding, return original size
        }
    }
    
    return dataSize - padValue;
}

// AES ECB Decryption using Windows CNG API
bool AES_ECB_Decrypt(const BYTE* encryptedData, SIZE_T dataSize, const BYTE* key, SIZE_T keySize, BYTE** outDecryptedData, SIZE_T* outDecryptedSize) {
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;
    BYTE* decryptedData = NULL;
    DWORD cbData = 0;
    bool success = false;

    // Open an algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Set the chaining mode to ECB
    status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Generate the key from the key bytes
    status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, (PBYTE)key, (ULONG)keySize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Allocate buffer for decrypted data
    decryptedData = new (std::nothrow) BYTE[dataSize];
    if (!decryptedData) {
        goto cleanup;
    }

    // Decrypt the data
    status = BCryptDecrypt(hKey, (PBYTE)encryptedData, (ULONG)dataSize, NULL, NULL, 0, decryptedData, (ULONG)dataSize, &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Unpad the decrypted data (PKCS7)
    SIZE_T unpaddedSize = UnpadPKCS7(decryptedData, cbData);

    *outDecryptedData = decryptedData;
    *outDecryptedSize = unpaddedSize;
    success = true;

cleanup:
    if (hKey) {
        BCryptDestroyKey(hKey);
    }
    if (hAesAlg) {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }
    if (!success && decryptedData) {
        delete[] decryptedData;
    }
    
    return success;
}
