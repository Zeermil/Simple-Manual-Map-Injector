#include "injector.h"
#include "crypto.h"
#include <memory>

// Constants
constexpr SIZE_T MIN_DLL_SIZE = 0x1000;

// DLL export macro for Windows
#ifdef _WIN32
    #define DLL_EXPORT extern "C" __declspec(dllexport)
#else
    #define DLL_EXPORT extern "C"
#endif

// Helper function to get process ID by name
DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    // Convert char* to wchar_t*
    wchar_t wProcessName[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, processName, -1, wProcessName, MAX_PATH);

    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) {
            if (_wcsicmp(entry.szExeFile, wProcessName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}

// Helper function to check target architecture
bool IsCorrectTargetArchitecture(HANDLE hProc) {
    BOOL bTarget = FALSE;
    if (!IsWow64Process(hProc, &bTarget)) {
        return false;
    }

    BOOL bHost = FALSE;
    IsWow64Process(GetCurrentProcess(), &bHost);

    return (bTarget == bHost);
}

// Exported function for injecting DLL from memory
// Returns:
//   0: Success
//  -1: Invalid process name
//  -2: Failed to open process
//  -3: Invalid process architecture
//  -4: Invalid DLL data
//  -5: Injection failed
DLL_EXPORT int InjectDllFromMemory(
    const char* processName,
    const unsigned char* dllData,
    size_t dllSize,
    bool clearHeader,
    bool clearNonNeededSections,
    bool adjustProtections,
    bool sehExceptionSupport
) {
    // Get process ID by name
    DWORD PID = GetProcessIdByName(processName);
    if (PID == 0) {
        return -1; // Process not found
    }

    // Enable debug privileges
    TOKEN_PRIVILEGES priv = { 0 };
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
            AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

        CloseHandle(hToken);
    }

    // Open target process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc) {
        return -2; // Failed to open process
    }

    // Check architecture
    if (!IsCorrectTargetArchitecture(hProc)) {
        CloseHandle(hProc);
        return -3; // Invalid process architecture
    }

    // Validate DLL data
    if (dllSize < MIN_DLL_SIZE) {
        CloseHandle(hProc);
        return -4; // Invalid DLL data
    }

    // Copy DLL data to local buffer using smart pointer for automatic cleanup
    std::unique_ptr<BYTE[]> pSrcData(new (std::nothrow) BYTE[dllSize]);
    if (!pSrcData) {
        CloseHandle(hProc);
        return -4; // Memory allocation failed
    }
    memcpy(pSrcData.get(), dllData, dllSize);

    // Perform injection
    bool result = ManualMapDll(
        hProc,
        pSrcData.get(),
        dllSize,
        clearHeader,
        clearNonNeededSections,
        adjustProtections,
        sehExceptionSupport,
        DLL_PROCESS_ATTACH,
        0
    );

    CloseHandle(hProc);

    return result ? 0 : -5; // 0 for success, -5 for injection failure
}

// Simplified version with default parameters
DLL_EXPORT int InjectDllFromMemorySimple(
    const char* processName,
    const unsigned char* dllData,
    size_t dllSize
) {
    return InjectDllFromMemory(
        processName,
        dllData,
        dllSize,
        true,  // clearHeader
        true,  // clearNonNeededSections
        true,  // adjustProtections
        true   // sehExceptionSupport
    );
}

// Exported function for injecting ENCRYPTED DLL from memory
// This function decrypts the DLL data before injection
// Returns:
//   0: Success
//  -1: Invalid process name
//  -2: Failed to open process
//  -3: Invalid process architecture
//  -4: Invalid DLL data
//  -5: Injection failed
//  -6: Decryption failed
DLL_EXPORT int InjectEncryptedDllFromMemory(
    const char* processName,
    const unsigned char* encryptedDllData,
    size_t encryptedDllSize,
    const unsigned char* encryptionKey,
    size_t keySize,
    bool clearHeader,
    bool clearNonNeededSections,
    bool adjustProtections,
    bool sehExceptionSupport
) {
    // Get process ID by name
    DWORD PID = GetProcessIdByName(processName);
    if (PID == 0) {
        return -1; // Process not found
    }

    // Enable debug privileges
    TOKEN_PRIVILEGES priv = { 0 };
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        priv.PrivilegeCount = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
            AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

        CloseHandle(hToken);
    }

    // Open target process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc) {
        return -2; // Failed to open process
    }

    // Check architecture
    if (!IsCorrectTargetArchitecture(hProc)) {
        CloseHandle(hProc);
        return -3; // Invalid process architecture
    }

    // Decrypt the DLL data
    BYTE* decryptedDataRaw = nullptr;
    SIZE_T decryptedSize = 0;
    
    if (!AES_ECB_Decrypt(encryptedDllData, encryptedDllSize, encryptionKey, keySize, &decryptedDataRaw, &decryptedSize)) {
        CloseHandle(hProc);
        return -6; // Decryption failed
    }

    // Use smart pointer for automatic cleanup
    std::unique_ptr<BYTE[]> decryptedData(decryptedDataRaw);

    // Validate decrypted DLL data
    if (decryptedSize < MIN_DLL_SIZE) {
        CloseHandle(hProc);
        return -4; // Invalid DLL data
    }

    // Perform injection
    bool result = ManualMapDll(
        hProc,
        decryptedData.get(),
        decryptedSize,
        clearHeader,
        clearNonNeededSections,
        adjustProtections,
        sehExceptionSupport,
        DLL_PROCESS_ATTACH,
        0
    );

    // decryptedData is automatically cleaned up by unique_ptr
    CloseHandle(hProc);

    return result ? 0 : -5; // 0 for success, -5 for injection failure
}

// Simplified version for encrypted DLL injection with default parameters
DLL_EXPORT int InjectEncryptedDllFromMemorySimple(
    const char* processName,
    const unsigned char* encryptedDllData,
    size_t encryptedDllSize,
    const unsigned char* encryptionKey,
    size_t keySize
) {
    return InjectEncryptedDllFromMemory(
        processName,
        encryptedDllData,
        encryptedDllSize,
        encryptionKey,
        keySize,
        true,  // clearHeader
        true,  // clearNonNeededSections
        true,  // adjustProtections
        true   // sehExceptionSupport
    );
}
