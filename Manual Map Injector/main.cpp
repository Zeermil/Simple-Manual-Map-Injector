#include "injector.h"


#include <stdio.h>
#include <string>
#include <iostream>

using namespace std;

bool IsCorrectTargetArchitecture(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {
		printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

bool IsTargetProcess32Bit(HANDLE hProc) {
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget)) {
		return false;
	}
	return bTarget == TRUE;
}

bool IsCurrentProcess64Bit() {
#ifdef _WIN64
	return true;
#else
	return false;
#endif
}

int LaunchHelperInjector(wchar_t* dllPath, wchar_t* processName) {
	// Get the directory of the current executable
	wchar_t exePath[MAX_PATH];
	DWORD pathLen = GetModuleFileNameW(NULL, exePath, MAX_PATH);
	if (pathLen == 0 || pathLen >= MAX_PATH) {
		printf("Failed to get executable path: 0x%X\n", GetLastError());
		return -10;
	}
	
	// Remove the executable name to get the directory
	wchar_t* lastSlash = wcsrchr(exePath, L'\\');
	if (!lastSlash) {
		// No directory separator found, use current directory
		wcscpy_s(exePath, MAX_PATH, L".\\");
		lastSlash = exePath + 1;
	}
	*(lastSlash + 1) = L'\0';
	
	// Construct path to x86 helper
	wchar_t helperPath[MAX_PATH];
	if (swprintf_s(helperPath, MAX_PATH, L"%sInjector-x86.exe", exePath) < 0) {
		printf("Helper path too long\n");
		return -10;
	}
	
	// Check if helper exists
	DWORD fileAttr = GetFileAttributesW(helperPath);
	if (fileAttr == INVALID_FILE_ATTRIBUTES) {
		DWORD err = GetLastError();
		printf("x86 helper injector not found: %ls (Error: 0x%X)\n", helperPath, err);
		printf("Please ensure Injector-x86.exe is in the same directory as Injector-x64.exe\n");
		return -10;
	}
	
	// Build command line - using dynamic allocation for safety
	size_t cmdLineLen = wcslen(helperPath) + wcslen(dllPath) + wcslen(processName) + 10; // +10 for quotes and spaces
	wchar_t* cmdLine = new (std::nothrow) wchar_t[cmdLineLen];
	if (!cmdLine) {
		printf("Memory allocation failed for command line\n");
		return -10;
	}
	
	if (swprintf_s(cmdLine, cmdLineLen, L"\"%ls\" \"%ls\" \"%ls\"", helperPath, dllPath, processName) < 0) {
		printf("Failed to build command line\n");
		delete[] cmdLine;
		return -10;
	}
	
	printf("Launching x86 helper injector for 32-bit target process...\n");
	
	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	
	if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		DWORD err = GetLastError();
		printf("Failed to launch helper injector: 0x%X\n", err);
		delete[] cmdLine;
		return -11;
	}
	
	delete[] cmdLine; // No longer needed after process creation
	
	// Wait for helper to complete
	WaitForSingleObject(pi.hProcess, INFINITE);
	
	DWORD exitCode;
	GetExitCodeProcess(pi.hProcess, &exitCode);
	
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	
	return exitCode;
}

DWORD GetProcessIdByName(wchar_t* name) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (_wcsicmp(entry.szExeFile, name) == 0) {
				CloseHandle(snapshot); //thanks to Pvt Comfy
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {

	wchar_t* dllPath;
	wchar_t* processName = NULL;
	wchar_t* allocatedProcessName = NULL;
	DWORD PID;
	if (argc == 3) {
		dllPath = argv[1];
		processName = argv[2];
		PID = GetProcessIdByName(processName);
	}
	else if (argc == 2) {
		dllPath = argv[1];
		std::string pname;
		printf("Process Name:\n");
		std::getline(std::cin, pname);

		char* vIn = (char*)pname.c_str();
		allocatedProcessName = new wchar_t[strlen(vIn) + 1];
		mbstowcs_s(NULL, allocatedProcessName, strlen(vIn) + 1, vIn, strlen(vIn));
		processName = allocatedProcessName;
		PID = GetProcessIdByName(processName);
	}
	else {
		printf("Invalid Params\n");
		printf("Usage: dll_path [process_name]\n");
		system("pause");
		return 0;
	}

	if (PID == 0) {
		printf("Process not found\n");
		if (allocatedProcessName) delete[] allocatedProcessName;
		system("pause");
		return -1;
	}

	printf("Process pid: %d\n", PID);

	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc) {
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		if (allocatedProcessName) delete[] allocatedProcessName;
		system("PAUSE");
		return -2;
	}

	// Check if we need to use helper for cross-architecture injection
	if (!IsCorrectTargetArchitecture(hProc)) {
		// If we're 64-bit and target is 32-bit, use helper
		if (IsCurrentProcess64Bit() && IsTargetProcess32Bit(hProc)) {
			CloseHandle(hProc);
			printf("Target process is 32-bit, using x86 helper injector...\n");
			int result = LaunchHelperInjector(dllPath, processName);
			if (allocatedProcessName) delete[] allocatedProcessName;
			if (result != 0) {
				printf("Helper injector failed with code: %d\n", result);
				system("PAUSE");
			}
			return result;
		}
		
		printf("Invalid Process Architecture.\n");
		CloseHandle(hProc);
		if (allocatedProcessName) delete[] allocatedProcessName;
		system("PAUSE");
		return -3;
	}

	if (GetFileAttributes(dllPath) == INVALID_FILE_ATTRIBUTES) {
		printf("Dll file doesn't exist\n");
		CloseHandle(hProc);
		if (allocatedProcessName) delete[] allocatedProcessName;
		system("PAUSE");
		return -4;
	}

	std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

	if (File.fail()) {
		printf("Opening the file failed: %X\n", (DWORD)File.rdstate());
		File.close();
		CloseHandle(hProc);
		if (allocatedProcessName) delete[] allocatedProcessName;
		system("PAUSE");
		return -5;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		printf("Filesize invalid.\n");
		File.close();
		CloseHandle(hProc);
		if (allocatedProcessName) delete[] allocatedProcessName;
		system("PAUSE");
		return -6;
	}

	BYTE * pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData) {
		printf("Can't allocate dll file.\n");
		File.close();
		CloseHandle(hProc);
		if (allocatedProcessName) delete[] allocatedProcessName;
		system("PAUSE");
		return -7;
	}

	File.seekg(0, std::ios::beg);
	File.read((char*)(pSrcData), FileSize);
	File.close();

	printf("Mapping...\n");
	if (!ManualMapDll(hProc, pSrcData, FileSize)) {
		delete[] pSrcData;
		CloseHandle(hProc);
		if (allocatedProcessName) delete[] allocatedProcessName;
		printf("Error while mapping.\n");
		system("PAUSE");
		return -8;
	}
	delete[] pSrcData;

	CloseHandle(hProc);
	if (allocatedProcessName) delete[] allocatedProcessName;
	printf("OK\n");
	return 0;
}
