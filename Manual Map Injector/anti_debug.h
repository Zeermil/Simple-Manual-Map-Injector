#pragma once

#include <Windows.h>
#include <winternl.h>

// Anti-Debug detection functions
namespace AntiDebug {

    // Check for debugger using IsDebuggerPresent API
    inline bool CheckDebuggerPresent() {
        return IsDebuggerPresent() != 0;
    }

    // Check for remote debugger
    inline bool CheckRemoteDebugger() {
        BOOL bDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent);
        return bDebuggerPresent != 0;
    }

    // Check using NtQueryInformationProcess
    inline bool CheckNtQueryInformationProcess() {
        typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            pNtQueryInformationProcess NtQueryInformationProcess = 
                (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            
            if (NtQueryInformationProcess) {
                DWORD dwDebugPort = 0;
                NTSTATUS status = NtQueryInformationProcess(
                    GetCurrentProcess(),
                    ProcessDebugPort,
                    &dwDebugPort,
                    sizeof(DWORD),
                    NULL
                );
                
                if (status == 0 && dwDebugPort != 0) {
                    return true;
                }
            }
        }
        return false;
    }

    // Check PEB BeingDebugged flag
    inline bool CheckPEB() {
        __try {
#ifdef _WIN64
            PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
            PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
            return pPeb && pPeb->BeingDebugged;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // If accessing PEB fails, assume not being debugged
            return false;
        }
    }

    // Perform all anti-debug checks
    inline bool IsDebuggerDetected() {
        return CheckDebuggerPresent() ||
               CheckRemoteDebugger() ||
               CheckNtQueryInformationProcess() ||
               CheckPEB();
    }
}

// Anti-Dump protection functions
namespace AntiDump {

    // Hide module from PEB
    inline bool HideModuleFromPEB(HMODULE hModule) {
        __try {
            typedef struct _LDR_DATA_TABLE_ENTRY {
                LIST_ENTRY InLoadOrderLinks;
                LIST_ENTRY InMemoryOrderLinks;
                LIST_ENTRY InInitializationOrderLinks;
                PVOID DllBase;
                PVOID EntryPoint;
                ULONG SizeOfImage;
                UNICODE_STRING FullDllName;
                UNICODE_STRING BaseDllName;
            } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#ifdef _WIN64
            PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
            PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

            if (!pPeb || !pPeb->Ldr) {
                return false;
            }

            PLIST_ENTRY pListHead = &pPeb->Ldr->InMemoryOrderModuleList;
            if (!pListHead) {
                return false;
            }

            PLIST_ENTRY pListEntry = pListHead->Flink;
            if (!pListEntry) {
                return false;
            }

            while (pListEntry && pListEntry != pListHead) {
                PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
                    pListEntry,
                    LDR_DATA_TABLE_ENTRY,
                    InMemoryOrderLinks
                );

                if (!pEntry) {
                    break;
                }

                if (pEntry->DllBase == hModule) {
                    // Validate pointers before unlinking
                    if (!pEntry->InLoadOrderLinks.Flink || !pEntry->InLoadOrderLinks.Blink ||
                        !pEntry->InMemoryOrderLinks.Flink || !pEntry->InMemoryOrderLinks.Blink ||
                        !pEntry->InInitializationOrderLinks.Flink || !pEntry->InInitializationOrderLinks.Blink) {
                        return false;
                    }

                    // Unlink from all lists
                    pEntry->InLoadOrderLinks.Flink->Blink = pEntry->InLoadOrderLinks.Blink;
                    pEntry->InLoadOrderLinks.Blink->Flink = pEntry->InLoadOrderLinks.Flink;
                    
                    pEntry->InMemoryOrderLinks.Flink->Blink = pEntry->InMemoryOrderLinks.Blink;
                    pEntry->InMemoryOrderLinks.Blink->Flink = pEntry->InMemoryOrderLinks.Flink;
                    
                    pEntry->InInitializationOrderLinks.Flink->Blink = pEntry->InInitializationOrderLinks.Blink;
                    pEntry->InInitializationOrderLinks.Blink->Flink = pEntry->InInitializationOrderLinks.Flink;

                    return true;
                }

                pListEntry = pListEntry->Flink;
            }

            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // If any operation fails, return false safely
            return false;
        }
    }

    // Clear PEB BeingDebugged flag to hide from basic debugger detection
    inline void ClearPEBBeingDebugged() {
        __try {
#ifdef _WIN64
            PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
            PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
            if (pPeb) {
                pPeb->BeingDebugged = 0;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // If clearing fails, silently continue
        }
    }
}
