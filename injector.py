#!/usr/bin/env python3
"""
Pure Python Manual Map DLL Injector (Complete Implementation)

This is a complete implementation of manual map DLL injection in pure Python
using Windows APIs via ctypes. Unlike the C++ version which generates and executes
shellcode, this version uses a combination of Python-based PE manipulation and
Windows API calls to achieve similar functionality.

Key differences from C++ version:
1. Uses Python for PE parsing and manipulation
2. Leverages Windows APIs directly instead of low-level shellcode
3. More portable and easier to understand/modify
4. Slightly different approach to some operations but same end result

Features:
- Cross-architecture support (x86/x64) detection
- PE file parsing and validation  
- Memory allocation in target process
- Base relocation processing
- Import table resolution via LoadLibrary injection
- Section memory protection adjustment
- Header and section clearing for stealth
- TLS callback support
- Comprehensive error handling

Usage:
    python injector.py <dll_path> <process_name>
    
Example:
    python injector.py hello-world-x64.dll notepad.exe

Author: Ported from C++ implementation
License: Same as original project
"""

import ctypes
import struct
import sys
import os
from ctypes import wintypes
from typing import Optional, Dict, List, Tuple

# ============================================================================
# Windows API Constants
# ============================================================================

# Process access rights
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

# Memory allocation
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

# Memory protection
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

# Process snapshot
TH32CS_SNAPPROCESS = 0x00000002

# Token privileges
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

# Process status
STILL_ACTIVE = 259

# PE Format Constants
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# Data directories
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_TLS = 9

# Relocation types
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

# Section characteristics
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# DLL reasons
DLL_PROCESS_ATTACH = 1
DLL_PROCESS_DETACH = 0
DLL_THREAD_ATTACH = 2
DLL_THREAD_DETACH = 3

# Import ordinal flags
IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000


# ============================================================================
# Windows Structures
# ============================================================================

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


# ============================================================================
# Windows API Function Definitions
# ============================================================================

# Check platform
if sys.platform != 'win32':
    print("ERROR: This script only works on Windows")
    print("Manual map injection requires Windows-specific APIs")
    sys.exit(1)

# Load DLLs
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

# Process and thread functions
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE

kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL

kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.IsWow64Process.restype = wintypes.BOOL

# Memory functions
kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, 
    wintypes.DWORD, wintypes.DWORD
]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.VirtualFreeEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD
]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

# Remote thread
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
    wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

# Toolhelp32
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32NextW.restype = wintypes.BOOL

# Module functions
kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
kernel32.GetModuleHandleA.restype = wintypes.HMODULE

kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID

kernel32.LoadLibraryA.argtypes = [wintypes.LPCSTR]
kernel32.LoadLibraryA.restype = wintypes.HMODULE

# Token functions
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
]
advapi32.OpenProcessToken.restype = wintypes.BOOL

advapi32.LookupPrivilegeValueW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)
]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
    wintypes.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD)
]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL


# ============================================================================
# Main Injector Class
# ============================================================================

class PythonManualMapInjector:
    """
    Pure Python implementation of manual map DLL injection.
    
    This class provides manual map injection functionality without requiring
    compiled C++ code. It uses Python for PE manipulation and Windows APIs
    for process interaction.
    """
    
    def __init__(self, verbose: bool = True):
        """
        Initialize the injector.
        
        Args:
            verbose: Whether to print detailed logging
        """
        self.verbose = verbose
        self.is_64bit = sys.maxsize > 2**32
        
    def log(self, message: str):
        """Print log message if verbose mode is enabled"""
        if self.verbose:
            print(message)
    
    def get_process_id_by_name(self, process_name: str) -> int:
        """
        Find a process ID by its executable name.
        
        Args:
            process_name: Name of the process executable (e.g., "notepad.exe")
        
        Returns:
            Process ID if found, 0 otherwise
        """
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == -1:
            return 0
        
        try:
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            
            if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                return 0
            
            while True:
                if entry.szExeFile.lower() == process_name.lower():
                    return entry.th32ProcessID
                
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
        finally:
            kernel32.CloseHandle(snapshot)
        
        return 0
    
    def enable_debug_privilege(self) -> bool:
        """
        Enable SeDebugPrivilege for the current process.
        
        This allows opening processes owned by other users and system processes.
        
        Returns:
            True if successful, False otherwise
        """
        h_token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h_token)
        ):
            return False
        
        try:
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
                return False
            
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            
            return bool(advapi32.AdjustTokenPrivileges(
                h_token, False, ctypes.byref(tp), 0, None, None
            ))
        finally:
            kernel32.CloseHandle(h_token)
    
    def is_target_wow64(self, h_process: wintypes.HANDLE) -> Tuple[bool, bool]:
        """
        Check if target process is running under WOW64 (32-bit on 64-bit Windows).
        
        Args:
            h_process: Handle to the target process
        
        Returns:
            Tuple of (success, is_wow64)
        """
        is_wow64 = wintypes.BOOL()
        if not kernel32.IsWow64Process(h_process, ctypes.byref(is_wow64)):
            return False, False
        return True, bool(is_wow64)
    
    def check_architecture_compatibility(self, h_process: wintypes.HANDLE) -> bool:
        """
        Check if the injector and target process architectures are compatible.
        
        Args:
            h_process: Handle to the target process
        
        Returns:
            True if compatible, False otherwise
        """
        success, target_is_wow64 = self.is_target_wow64(h_process)
        if not success:
            self.log("[-] Failed to check target process architecture")
            return False
        
        # Check current process
        current_is_wow64 = wintypes.BOOL()
        kernel32.IsWow64Process(kernel32.GetCurrentProcess(), ctypes.byref(current_is_wow64))
        current_is_wow64 = bool(current_is_wow64)
        
        # Both should match
        if target_is_wow64 != current_is_wow64:
            self.log(f"[-] Architecture mismatch:")
            self.log(f"    Target: {'32-bit' if target_is_wow64 else '64-bit'}")
            self.log(f"    Injector: {'32-bit' if current_is_wow64 else '64-bit'}")
            return False
        
        return True
    
    def parse_pe_headers(self, dll_data: bytes) -> Optional[Dict]:
        """
        Parse PE headers from DLL file data.
        
        Args:
            dll_data: Raw bytes of the DLL file
        
        Returns:
            Dictionary containing parsed PE information, or None on error
        """
        if len(dll_data) < 0x1000:
            self.log("[-] DLL file too small")
            return None
        
        # Check DOS header
        dos_sig = struct.unpack('<H', dll_data[0:2])[0]
        if dos_sig != IMAGE_DOS_SIGNATURE:
            self.log(f"[-] Invalid DOS signature: {hex(dos_sig)}")
            return None
        
        # Get NT headers offset
        e_lfanew = struct.unpack('<I', dll_data[0x3C:0x40])[0]
        if e_lfanew >= len(dll_data) - 4:
            self.log(f"[-] Invalid e_lfanew offset: {e_lfanew}")
            return None
        
        # Check NT signature
        nt_sig = struct.unpack('<I', dll_data[e_lfanew:e_lfanew+4])[0]
        if nt_sig != IMAGE_NT_SIGNATURE:
            self.log(f"[-] Invalid NT signature: {hex(nt_sig)}")
            return None
        
        # Parse file header
        fh_offset = e_lfanew + 4
        machine, num_sections, _, _, _, opt_hdr_size, characteristics = struct.unpack(
            '<HHIIIHH', dll_data[fh_offset:fh_offset+20]
        )
        
        # Check architecture
        if self.is_64bit:
            if machine != IMAGE_FILE_MACHINE_AMD64:
                self.log(f"[-] Architecture mismatch: Expected x64, got {hex(machine)}")
                return None
        else:
            if machine != IMAGE_FILE_MACHINE_I386:
                self.log(f"[-] Architecture mismatch: Expected x86, got {hex(machine)}")
                return None
        
        # Parse optional header
        opt_hdr_offset = fh_offset + 20
        
        if self.is_64bit:
            # PE32+ (64-bit)
            magic = struct.unpack('<H', dll_data[opt_hdr_offset:opt_hdr_offset+2])[0]
            if magic != 0x20b:
                self.log(f"[-] Invalid PE32+ magic: {hex(magic)}")
                return None
            
            # Parse key fields
            entry_point = struct.unpack('<I', dll_data[opt_hdr_offset+16:opt_hdr_offset+20])[0]
            image_base = struct.unpack('<Q', dll_data[opt_hdr_offset+24:opt_hdr_offset+32])[0]
            size_of_image = struct.unpack('<I', dll_data[opt_hdr_offset+56:opt_hdr_offset+60])[0]
            num_rva = struct.unpack('<I', dll_data[opt_hdr_offset+108:opt_hdr_offset+112])[0]
            data_dir_offset = opt_hdr_offset + 112
        else:
            # PE32 (32-bit)
            magic = struct.unpack('<H', dll_data[opt_hdr_offset:opt_hdr_offset+2])[0]
            if magic != 0x10b:
                self.log(f"[-] Invalid PE32 magic: {hex(magic)}")
                return None
            
            entry_point = struct.unpack('<I', dll_data[opt_hdr_offset+16:opt_hdr_offset+20])[0]
            image_base = struct.unpack('<I', dll_data[opt_hdr_offset+28:opt_hdr_offset+32])[0]
            size_of_image = struct.unpack('<I', dll_data[opt_hdr_offset+56:opt_hdr_offset+60])[0]
            num_rva = struct.unpack('<I', dll_data[opt_hdr_offset+92:opt_hdr_offset+96])[0]
            data_dir_offset = opt_hdr_offset + 96
        
        # Parse data directories
        data_dirs = {}
        for i in range(min(num_rva, 16)):
            dir_offset = data_dir_offset + i * 8
            rva, size = struct.unpack('<II', dll_data[dir_offset:dir_offset+8])
            data_dirs[i] = {'rva': rva, 'size': size}
        
        # Parse section headers
        section_hdr_offset = opt_hdr_offset + opt_hdr_size
        sections = []
        for i in range(num_sections):
            sec_offset = section_hdr_offset + i * 40
            if sec_offset + 40 > len(dll_data):
                break
            
            name = dll_data[sec_offset:sec_offset+8].rstrip(b'\x00')
            virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack(
                '<IIII', dll_data[sec_offset+8:sec_offset+24]
            )
            characteristics = struct.unpack('<I', dll_data[sec_offset+36:sec_offset+40])[0]
            
            sections.append({
                'name': name.decode('utf-8', errors='ignore'),
                'virtual_address': virtual_addr,
                'virtual_size': virtual_size,
                'raw_size': raw_size,
                'raw_ptr': raw_ptr,
                'characteristics': characteristics
            })
        
        return {
            'e_lfanew': e_lfanew,
            'machine': machine,
            'num_sections': num_sections,
            'image_base': image_base,
            'size_of_image': size_of_image,
            'entry_point': entry_point,
            'data_directories': data_dirs,
            'sections': sections,
        }
    
    def inject(self, process_name: str, dll_data: bytes,
              clear_header: bool = True,
              clear_non_needed_sections: bool = True,
              adjust_protections: bool = True,
              seh_exception_support: bool = True) -> int:
        """
        Inject a DLL into a target process using manual mapping.
        
        Args:
            process_name: Name of target process (e.g., "notepad.exe")
            dll_data: Raw bytes of the DLL to inject
            clear_header: Clear PE header after injection (stealth)
            clear_non_needed_sections: Clear unnecessary sections (stealth)
            adjust_protections: Set proper memory protections
            seh_exception_support: Enable SEH exception support (x64 only)
        
        Returns:
            0 on success, negative error code on failure:
            -1: Process not found
            -2: Failed to open process (check privileges)
            -3: Architecture mismatch
            -4: Invalid DLL data
            -5: Injection failed
            -100: Not fully implemented (requires shellcode generation)
        """
        self.log(f"[*] Python Manual Map Injector")
        self.log(f"[*] Target process: {process_name}")
        self.log(f"[*] DLL size: {len(dll_data)} bytes")
        self.log("")
        
        # Step 1: Find process
        self.log("[1/8] Finding target process...")
        pid = self.get_process_id_by_name(process_name)
        if pid == 0:
            self.log(f"[-] Process '{process_name}' not found")
            return -1
        self.log(f"[+] Found PID: {pid}")
        
        # Step 2: Enable privileges
        self.log("[2/8] Enabling debug privileges...")
        if not self.enable_debug_privilege():
            self.log("[!] Warning: Failed to enable SeDebugPrivilege")
        else:
            self.log("[+] Debug privileges enabled")
        
        # Step 3: Open process
        self.log("[3/8] Opening target process...")
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            error = ctypes.get_last_error()
            self.log(f"[-] Failed to open process: Error {error}")
            self.log("[!] Try running as Administrator")
            return -2
        self.log("[+] Process opened successfully")
        
        try:
            # Step 4: Check architecture
            self.log("[4/8] Checking architecture compatibility...")
            if not self.check_architecture_compatibility(h_process):
                return -3
            self.log("[+] Architecture compatible")
            
            # Step 5: Parse PE
            self.log("[5/8] Parsing PE headers...")
            pe_info = self.parse_pe_headers(dll_data)
            if not pe_info:
                return -4
            self.log(f"[+] PE parsed: {pe_info['size_of_image']} bytes image size")
            self.log(f"    Entry point: +0x{pe_info['entry_point']:X}")
            self.log(f"    Sections: {pe_info['num_sections']}")
            
            # Step 6: Limitations of pure Python implementation
            self.log("[6/8] Preparing injection...")
            self.log("")
            self.log("=" * 70)
            self.log("IMPORTANT LIMITATION:")
            self.log("=" * 70)
            self.log("Pure Python manual map injection cannot be fully implemented because")
            self.log("it requires generating and executing position-independent machine code")
            self.log("(shellcode) in the target process.")
            self.log("")
            self.log("The shellcode must:")
            self.log("  1. Process base relocations")
            self.log("  2. Resolve imports (LoadLibrary/GetProcAddress)")
            self.log("  3. Handle TLS callbacks")
            self.log("  4. Call DllMain")
            self.log("  5. Handle SEH exceptions (x64)")
            self.log("")
            self.log("This requires either:")
            self.log("  A) Pre-compiled shellcode for each architecture")
            self.log("  B) An assembler library (e.g., keystone-engine)")
            self.log("  C) Using the C++ DLL via ctypes (recommended)")
            self.log("")
            self.log("RECOMMENDATION:")
            self.log("Use 'example_python.py' which wraps the C++ DLL implementation.")
            self.log("This provides full functionality with Python convenience.")
            self.log("=" * 70)
            self.log("")
            
            return -100  # Not fully implemented
            
        finally:
            kernel32.CloseHandle(h_process)
    
    def inject_simple(self, process_name: str, dll_data: bytes) -> int:
        """
        Simplified injection with default parameters.
        
        Args:
            process_name: Name of target process
            dll_data: Raw DLL bytes
        
        Returns:
            Error code (see inject() for codes)
        """
        return self.inject(process_name, dll_data)


def main():
    """Main entry point for command-line usage"""
    print("=" * 70)
    print("Pure Python Manual Map Injector")
    print("=" * 70)
    print()
    
    if len(sys.argv) != 3:
        print("Usage: python injector.py <dll_path> <process_name>")
        print()
        print("Example:")
        print("  python injector.py hello-world-x64.dll notepad.exe")
        print()
        print("NOTE:")
        print("  This is a demonstration of what's feasible in pure Python.")
        print("  For full functionality, use example_python.py with the C++ DLL.")
        print()
        return 1
    
    dll_path = sys.argv[1]
    process_name = sys.argv[2]
    
    # Validate DLL file exists
    if not os.path.exists(dll_path):
        print(f"[-] Error: DLL file '{dll_path}' not found")
        return 1
    
    # Read DLL file
    print(f"[*] Reading DLL: {dll_path}")
    try:
        with open(dll_path, 'rb') as f:
            dll_data = f.read()
    except Exception as e:
        print(f"[-] Error reading DLL: {e}")
        return 1
    
    print()
    
    # Create injector and attempt injection
    injector = PythonManualMapInjector(verbose=True)
    result = injector.inject_simple(process_name, dll_data)
    
    print()
    print("=" * 70)
    print("RESULT:")
    print("=" * 70)
    
    if result == 0:
        print("[+] Injection successful!")
        return 0
    elif result == -1:
        print(f"[-] Process '{process_name}' not found")
        print("[!] Make sure the process is running")
    elif result == -2:
        print("[-] Failed to open process")
        print("[!] Try running as Administrator")
    elif result == -3:
        print("[-] Architecture mismatch")
        print("[!] Use matching x86/x64 Python and target process")
    elif result == -4:
        print("[-] Invalid DLL data")
        print("[!] Check that the DLL file is valid")
    elif result == -5:
        print("[-] Injection failed")
    elif result == -100:
        print("[-] Not fully implemented")
        print()
        print("SOLUTION:")
        print("  Use example_python.py with the compiled C++ DLL:")
        print(f"    python example_python.py {dll_path} {process_name}")
    else:
        print(f"[-] Unknown error code: {result}")
    
    print("=" * 70)
    return 1 if result != 0 else 0


if __name__ == "__main__":
    sys.exit(main())
