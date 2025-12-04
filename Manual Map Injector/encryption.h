#pragma once

#include <Windows.h>
#include <vector>
#include <memory>

// Simple XOR encryption/decryption
namespace Encryption {

    // XOR cipher - same function for encryption and decryption
    inline void XORCipher(BYTE* data, SIZE_T dataSize, const BYTE* key, SIZE_T keySize) {
        if (!data || !key || dataSize == 0 || keySize == 0) {
            return;
        }

        for (SIZE_T i = 0; i < dataSize; i++) {
            data[i] ^= key[i % keySize];
        }
    }

    // Decrypt data in-place
    inline bool DecryptDLL(BYTE* encryptedData, SIZE_T dataSize, const BYTE* key, SIZE_T keySize) {
        if (!encryptedData || !key || dataSize == 0 || keySize == 0) {
            return false;
        }

        XORCipher(encryptedData, dataSize, key, keySize);
        return true;
    }

    // Encrypt data in-place (same as decrypt for XOR)
    inline bool EncryptDLL(BYTE* data, SIZE_T dataSize, const BYTE* key, SIZE_T keySize) {
        return DecryptDLL(data, dataSize, key, keySize);
    }
}
