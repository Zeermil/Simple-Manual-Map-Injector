#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <conio.h>

namespace fs = std::filesystem;

// Safe pause function for Windows
void SafePause() {
    std::wcout << L"Press any key to continue..." << std::endl;
    _getch();
}

// Get process ID by name
DWORD GetProcessIdByName(const wchar_t* name) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

// Check if a process is 64-bit
bool Is64BitProcess(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        std::wcerr << L"Failed to open process: " << GetLastError() << std::endl;
        return false;
    }

    BOOL isWow64 = FALSE;
    if (!IsWow64Process(hProcess, &isWow64)) {
        CloseHandle(hProcess);
        std::wcerr << L"Failed to check process architecture: " << GetLastError() << std::endl;
        return false;
    }

    CloseHandle(hProcess);

    // On 64-bit Windows:
    // - 64-bit processes: isWow64 = FALSE
    // - 32-bit processes: isWow64 = TRUE
    BOOL isSystem64Bit = FALSE;
    IsWow64Process(GetCurrentProcess(), &isSystem64Bit);
    
    if (isSystem64Bit) {
        // We're on 64-bit Windows
        return !isWow64;  // TRUE if process is 64-bit
    } else {
        // We're on 32-bit Windows
        return false;  // All processes are 32-bit
    }
}

// Get the directory where the launcher is located
std::wstring GetLauncherDirectory() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    fs::path exePath(buffer);
    return exePath.parent_path().wstring();
}

// Launch the appropriate injector
int LaunchInjector(const std::wstring& injectorPath, const std::wstring& dllPath, const std::wstring& processName) {
    std::wstring commandLine = L"\"" + injectorPath + L"\" \"" + dllPath + L"\" " + processName;
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    // Create command line buffer (CreateProcess may modify it)
    std::vector<wchar_t> cmdLine(commandLine.begin(), commandLine.end());
    cmdLine.push_back(L'\0');
    
    BOOL success = CreateProcessW(
        NULL,           // Application name
        cmdLine.data(), // Command line
        NULL,           // Process security attributes
        NULL,           // Thread security attributes
        FALSE,          // Inherit handles
        0,              // Creation flags
        NULL,           // Environment
        NULL,           // Current directory
        &si,            // Startup info
        &pi             // Process information
    );
    
    if (!success) {
        std::wcerr << L"Failed to launch injector: " << GetLastError() << std::endl;
        return -1;
    }
    
    // Wait for the injector to complete
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return exitCode;
}

int wmain(int argc, wchar_t* argv[]) {
    std::wcout << L"================================================" << std::endl;
    std::wcout << L"Universal Manual Map Injector Launcher" << std::endl;
    std::wcout << L"================================================" << std::endl;
    std::wcout << std::endl;

    if (argc < 3) {
        std::wcout << L"Usage: " << argv[0] << L" <dll_path> <process_name>" << std::endl;
        std::wcout << L"Example: " << argv[0] << L" mydll.dll notepad.exe" << std::endl;
        SafePause();
        return -1;
    }

    std::wstring dllPath = argv[1];
    std::wstring processName = argv[2];

    // Check if DLL exists
    if (!fs::exists(dllPath)) {
        std::wcerr << L"ERROR: DLL file not found: " << dllPath << std::endl;
        SafePause();
        return -2;
    }

    // Get process ID
    std::wcout << L"Looking for process: " << processName << std::endl;
    DWORD processId = GetProcessIdByName(processName.c_str());
    
    if (processId == 0) {
        std::wcerr << L"ERROR: Process not found: " << processName << std::endl;
        SafePause();
        return -3;
    }

    std::wcout << L"Found process ID: " << processId << std::endl;

    // Determine process architecture
    bool is64Bit = Is64BitProcess(processId);
    std::wstring architecture = is64Bit ? L"x64" : L"x86";
    std::wcout << L"Target process architecture: " << architecture << std::endl;

    // Determine injector path
    std::wstring launcherDir = GetLauncherDirectory();
    std::wstring injectorName = is64Bit ? L"Injector-x64.exe" : L"Injector-x86.exe";
    std::wstring injectorPath = launcherDir + L"\\" + injectorName;

    // Check if injector exists
    if (!fs::exists(injectorPath)) {
        std::wcerr << L"ERROR: Injector not found: " << injectorPath << std::endl;
        std::wcerr << L"Please ensure both Injector-x64.exe and Injector-x86.exe are in the same directory as the launcher." << std::endl;
        SafePause();
        return -4;
    }

    std::wcout << L"Using injector: " << injectorName << std::endl;
    std::wcout << L"================================================" << std::endl;
    std::wcout << L"Launching injector..." << std::endl;
    std::wcout << std::endl;

    // Launch the appropriate injector
    int result = LaunchInjector(injectorPath, dllPath, processName);

    if (result == 0) {
        std::wcout << std::endl;
        std::wcout << L"================================================" << std::endl;
        std::wcout << L"Injection completed successfully!" << std::endl;
        std::wcout << L"================================================" << std::endl;
    } else {
        std::wcerr << std::endl;
        std::wcerr << L"================================================" << std::endl;
        std::wcerr << L"Injection failed with code: " << result << std::endl;
        std::wcerr << L"================================================" << std::endl;
    }

    return result;
}
