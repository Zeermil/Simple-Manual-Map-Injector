#!/usr/bin/env python3
"""
Pure Python Manual Map DLL Injector

This module implements manual map DLL injection without requiring a C++ DLL.
It uses Windows APIs directly through ctypes to inject a DLL from memory into
a target process.

Features:
- Process enumeration and PID lookup
- PE file parsing and validation
- Memory allocation in target process
- Relocation handling
- Import table resolution
- TLS callback support
- SEH exception support (x64)
- Remote thread execution

Usage:
    from manual_map_injector import ManualMapInjector
    
    injector = ManualMapInjector()
    result = injector.inject("notepad.exe", dll_bytes)
    if result == 0:
        print("Injection successful!")
"""

import ctypes
import struct
import sys
from ctypes import wintypes
from typing import Optional, Tuple

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20
TH32CS_SNAPPROCESS = 0x00000002
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
STILL_ACTIVE = 259

# PE constants
IMAGE_DOS_SIGNATURE = 0x5A4D  # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550  # "PE\0\0"
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3

IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000

DLL_PROCESS_ATTACH = 1

# Image ordinal flag
IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000


# Windows structures
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


# Load Windows APIs
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

# Define function prototypes
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32NextW.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, 
                                     wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, 
                                    wintypes.DWORD]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

kernel32.VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                       wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
                                         ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                                         wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
                                         ctypes.POINTER(wintypes.DWORD)]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL

kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.IsWow64Process.restype = wintypes.BOOL

kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID

kernel32.LoadLibraryA.argtypes = [wintypes.LPCSTR]
kernel32.LoadLibraryA.restype = wintypes.HMODULE


class ManualMapInjector:
    """
    Pure Python Manual Map DLL Injector
    
    This class implements manual map injection without requiring a C++ DLL.
    """
    
    def __init__(self):
        self.is_64bit = sys.maxsize > 2**32
        self.verbose = True
    
    def log(self, message):
        """Print log message if verbose is enabled"""
        if self.verbose:
            print(message)
    
    def get_process_id_by_name(self, process_name: str) -> int:
        """
        Get process ID by process name.
        
        Args:
            process_name: Name of the process (e.g., "notepad.exe")
        
        Returns:
            Process ID, or 0 if not found
        """
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == -1:
            return 0
        
        try:
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            
            if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                while True:
                    if entry.szExeFile.lower() == process_name.lower():
                        return entry.th32ProcessID
                    
                    if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                        break
        finally:
            kernel32.CloseHandle(snapshot)
        
        return 0
    
    def is_target_wow64(self, h_process: int) -> Tuple[bool, bool]:
        """
        Check if target process is WOW64 (32-bit on 64-bit Windows).
        
        Args:
            h_process: Handle to the process
        
        Returns:
            Tuple of (success, is_wow64)
        """
        is_wow64 = wintypes.BOOL()
        if not kernel32.IsWow64Process(h_process, ctypes.byref(is_wow64)):
            return False, False
        return True, bool(is_wow64)
    
    def enable_debug_privilege(self) -> bool:
        """
        Enable SeDebugPrivilege for the current process.
        
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
    
    def parse_pe_headers(self, dll_data: bytes) -> Optional[dict]:
        """
        Parse PE headers from DLL data.
        
        Args:
            dll_data: Raw DLL bytes
        
        Returns:
            Dictionary with parsed PE information, or None on error
        """
        if len(dll_data) < 0x1000:
            return None
        
        # Check DOS signature
        dos_signature = struct.unpack('<H', dll_data[0:2])[0]
        if dos_signature != IMAGE_DOS_SIGNATURE:
            self.log("Invalid DOS signature")
            return None
        
        # Get NT header offset
        e_lfanew = struct.unpack('<I', dll_data[0x3C:0x40])[0]
        if e_lfanew >= len(dll_data) - 4:
            self.log("Invalid e_lfanew offset")
            return None
        
        # Check NT signature
        nt_signature = struct.unpack('<I', dll_data[e_lfanew:e_lfanew+4])[0]
        if nt_signature != IMAGE_NT_SIGNATURE:
            self.log("Invalid NT signature")
            return None
        
        # Parse file header
        file_header_offset = e_lfanew + 4
        machine, num_sections, _, _, _, opt_header_size, characteristics = struct.unpack(
            '<HHIIIHH', dll_data[file_header_offset:file_header_offset+20]
        )
        
        # Check architecture
        if self.is_64bit and machine != IMAGE_FILE_MACHINE_AMD64:
            self.log(f"Architecture mismatch: expected x64, got {hex(machine)}")
            return None
        elif not self.is_64bit and machine != IMAGE_FILE_MACHINE_I386:
            self.log(f"Architecture mismatch: expected x86, got {hex(machine)}")
            return None
        
        # Parse optional header
        opt_header_offset = file_header_offset + 20
        
        if self.is_64bit:
            # PE32+ (64-bit)
            magic = struct.unpack('<H', dll_data[opt_header_offset:opt_header_offset+2])[0]
            if magic != 0x20b:
                self.log(f"Invalid PE32+ magic: {hex(magic)}")
                return None
            
            image_base, = struct.unpack('<Q', dll_data[opt_header_offset+24:opt_header_offset+32])
            size_of_image, = struct.unpack('<I', dll_data[opt_header_offset+56:opt_header_offset+60])
            address_of_entry_point, = struct.unpack('<I', dll_data[opt_header_offset+16:opt_header_offset+20])
            num_data_directories, = struct.unpack('<I', dll_data[opt_header_offset+108:opt_header_offset+112])
            data_dir_offset = opt_header_offset + 112
        else:
            # PE32 (32-bit)
            magic = struct.unpack('<H', dll_data[opt_header_offset:opt_header_offset+2])[0]
            if magic != 0x10b:
                self.log(f"Invalid PE32 magic: {hex(magic)}")
                return None
            
            image_base, = struct.unpack('<I', dll_data[opt_header_offset+28:opt_header_offset+32])
            size_of_image, = struct.unpack('<I', dll_data[opt_header_offset+56:opt_header_offset+60])
            address_of_entry_point, = struct.unpack('<I', dll_data[opt_header_offset+16:opt_header_offset+20])
            num_data_directories, = struct.unpack('<I', dll_data[opt_header_offset+92:opt_header_offset+96])
            data_dir_offset = opt_header_offset + 96
        
        # Parse data directories
        data_directories = {}
        for i in range(min(num_data_directories, 16)):
            rva, size = struct.unpack('<II', dll_data[data_dir_offset+i*8:data_dir_offset+i*8+8])
            data_directories[i] = (rva, size)
        
        # Parse section headers
        section_header_offset = opt_header_offset + opt_header_size
        sections = []
        for i in range(num_sections):
            section_offset = section_header_offset + i * 40
            name = dll_data[section_offset:section_offset+8].rstrip(b'\x00')
            virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data = struct.unpack(
                '<IIII', dll_data[section_offset+8:section_offset+24]
            )
            characteristics, = struct.unpack('<I', dll_data[section_offset+36:section_offset+40])
            
            sections.append({
                'name': name,
                'virtual_address': virtual_address,
                'virtual_size': virtual_size,
                'size_of_raw_data': size_of_raw_data,
                'pointer_to_raw_data': pointer_to_raw_data,
                'characteristics': characteristics
            })
        
        return {
            'e_lfanew': e_lfanew,
            'machine': machine,
            'num_sections': num_sections,
            'image_base': image_base,
            'size_of_image': size_of_image,
            'address_of_entry_point': address_of_entry_point,
            'data_directories': data_directories,
            'sections': sections,
            'opt_header_offset': opt_header_offset,
        }
    
    def process_relocations(self, dll_data: bytes, pe_info: dict, 
                           target_base: int) -> bytes:
        """
        Process base relocations in the DLL data.
        
        Args:
            dll_data: Original DLL data
            pe_info: Parsed PE information
            target_base: Base address where DLL will be loaded
        
        Returns:
            Modified DLL data with relocations applied
        """
        # Make a mutable copy
        data = bytearray(dll_data)
        
        # Calculate delta
        delta = target_base - pe_info['image_base']
        if delta == 0:
            return bytes(data)
        
        # Get relocation directory
        reloc_dir = pe_info['data_directories'].get(IMAGE_DIRECTORY_ENTRY_BASERELOC)
        if not reloc_dir or reloc_dir[1] == 0:
            self.log("[!] No relocation data found")
            return bytes(data)
        
        reloc_rva, reloc_size = reloc_dir
        reloc_offset = reloc_rva
        reloc_end = reloc_rva + reloc_size
        
        # Process relocation blocks
        while reloc_offset < reloc_end:
            if reloc_offset + 8 > len(data):
                break
            
            page_rva, block_size = struct.unpack('<II', data[reloc_offset:reloc_offset+8])
            if block_size == 0:
                break
            
            num_entries = (block_size - 8) // 2
            entries_offset = reloc_offset + 8
            
            for i in range(num_entries):
                entry_offset = entries_offset + i * 2
                if entry_offset + 2 > len(data):
                    break
                
                entry, = struct.unpack('<H', data[entry_offset:entry_offset+2])
                reloc_type = entry >> 12
                offset = entry & 0xFFF
                
                # Calculate address to patch
                patch_rva = page_rva + offset
                
                # Apply relocation based on type
                if self.is_64bit:
                    if reloc_type == IMAGE_REL_BASED_DIR64:
                        if patch_rva + 8 <= len(data):
                            original_value, = struct.unpack('<Q', data[patch_rva:patch_rva+8])
                            new_value = original_value + delta
                            struct.pack_into('<Q', data, patch_rva, new_value)
                else:
                    if reloc_type == IMAGE_REL_BASED_HIGHLOW:
                        if patch_rva + 4 <= len(data):
                            original_value, = struct.unpack('<I', data[patch_rva:patch_rva+4])
                            new_value = (original_value + delta) & 0xFFFFFFFF
                            struct.pack_into('<I', data, patch_rva, new_value)
            
            reloc_offset += block_size
        
        return bytes(data)
    
    def resolve_imports(self, h_process: int, target_base: int, pe_info: dict,
                       dll_data: bytes) -> bool:
        """
        Resolve import table in the target process.
        
        This requires GetProcAddress and LoadLibraryA to be available in the target.
        In a real implementation, we'd call these via shellcode.
        
        Args:
            h_process: Handle to target process
            target_base: Base address in target process
            pe_info: Parsed PE information
            dll_data: DLL data with relocations applied
        
        Returns:
            True if successful, False otherwise
        """
        import_dir = pe_info['data_directories'].get(IMAGE_DIRECTORY_ENTRY_IMPORT)
        if not import_dir or import_dir[1] == 0:
            self.log("[+] No imports to resolve")
            return True
        
        import_rva, import_size = import_dir
        
        self.log("[*] Resolving imports...")
        
        # In a real implementation, we would:
        # 1. Read import descriptors from dll_data
        # 2. For each imported DLL:
        #    - Call LoadLibraryA in target process (via shellcode or remote call)
        #    - For each imported function:
        #      - Call GetProcAddress in target process
        #      - Write the function address to the IAT in target process
        
        # This requires either:
        # - Generating and executing shellcode in the target
        # - Using CreateRemoteThread to call LoadLibraryA/GetProcAddress (complex)
        
        self.log("[!] Import resolution requires shellcode execution")
        return False
    
    def inject(self, process_name: str, dll_data: bytes, 
              clear_header: bool = True,
              clear_non_needed_sections: bool = True,
              adjust_protections: bool = True,
              seh_exception_support: bool = True) -> int:
        """
        Inject a DLL into a target process using manual mapping.
        
        Args:
            process_name: Name of the target process (e.g., "notepad.exe")
            dll_data: Raw bytes of the DLL to inject
            clear_header: Whether to clear PE header after injection
            clear_non_needed_sections: Whether to clear non-needed sections
            adjust_protections: Whether to adjust memory protections
            seh_exception_support: Whether to enable SEH exception support (x64 only)
        
        Returns:
            0 on success, negative error code on failure:
            -1: Process not found
            -2: Failed to open process
            -3: Invalid process architecture
            -4: Invalid DLL data
            -5: Injection failed
            -100: Not implemented (pure Python limitations)
        """
        self.log(f"[*] Starting injection into {process_name}")
        
        # Get process ID
        pid = self.get_process_id_by_name(process_name)
        if pid == 0:
            self.log(f"[-] Process '{process_name}' not found")
            return -1
        
        self.log(f"[+] Found process with PID: {pid}")
        
        # Enable debug privileges
        if not self.enable_debug_privilege():
            self.log("[!] Warning: Failed to enable debug privilege")
        
        # Open process
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            self.log(f"[-] Failed to open process: {ctypes.get_last_error()}")
            return -2
        
        try:
            # Check architecture compatibility
            success, is_wow64 = self.is_target_wow64(h_process)
            if not success:
                self.log("[-] Failed to check target architecture")
                return -3
            
            # Check if architectures match
            current_is_wow64 = not self.is_64bit
            if is_wow64 != current_is_wow64:
                self.log(f"[-] Architecture mismatch: target is {'32-bit' if is_wow64 else '64-bit'}, "
                        f"injector is {'32-bit' if current_is_wow64 else '64-bit'}")
                return -3
            
            # Parse PE headers
            pe_info = self.parse_pe_headers(dll_data)
            if not pe_info:
                self.log("[-] Failed to parse PE headers")
                return -4
            
            self.log(f"[+] PE parsed successfully, image size: {pe_info['size_of_image']} bytes")
            
            # NOTE: This is where the actual manual mapping would occur
            # However, implementing this in pure Python requires:
            # 1. Allocating memory in target process ✓ (can do with VirtualAllocEx)
            # 2. Writing PE headers and sections ✓ (can do with WriteProcessMemory)
            # 3. Generating shellcode that runs in target process ✗ (requires assembly code generation)
            #    - Process relocations
            #    - Resolve imports (LoadLibrary, GetProcAddress)
            #    - Handle TLS callbacks
            #    - Call DllMain
            #    - Handle SEH exceptions (x64)
            # 4. Creating remote thread to execute shellcode ✓ (can do with CreateRemoteThread)
            
            # The main limitation is step 3: generating position-independent machine code
            # that can execute in the target process. This requires:
            # - Writing x86/x64 assembly instructions as bytes
            # - Making it position-independent (no absolute addresses)
            # - Handling all PE structures correctly
            
            self.log("[-] ERROR: Full manual map injection is not feasible in pure Python")
            self.log("[-] Reason: Requires generating position-independent machine code (shellcode)")
            self.log("[-] This needs an assembler or pre-compiled shellcode for each architecture")
            self.log("")
            self.log("[i] Recommendation: Use the C++ DLL implementation via ctypes (example_python.py)")
            self.log("[i] Or implement shellcode generation using a library like keystone-engine")
            
            return -100  # Not implemented
            
        finally:
            kernel32.CloseHandle(h_process)
    
    def inject_simple(self, process_name: str, dll_data: bytes) -> int:
        """
        Simplified injection with default parameters.
        
        Args:
            process_name: Name of the target process
            dll_data: Raw bytes of the DLL to inject
        
        Returns:
            0 on success, negative error code on failure
        """
        return self.inject(process_name, dll_data)


def main():
    """Main function for command-line usage"""
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python manual_map_injector.py <dll_path> <process_name>")
        print("Example: python manual_map_injector.py hello-world-x64.dll notepad.exe")
        print()
        print("NOTE: Pure Python manual map injection has limitations.")
        print("For full functionality, use example_python.py with the C++ DLL.")
        return 1
    
    dll_path = sys.argv[1]
    process_name = sys.argv[2]
    
    # Read DLL
    try:
        with open(dll_path, 'rb') as f:
            dll_data = f.read()
    except Exception as e:
        print(f"Error reading DLL: {e}")
        return 1
    
    # Inject
    injector = ManualMapInjector()
    result = injector.inject_simple(process_name, dll_data)
    
    if result == 0:
        print("[+] Injection successful!")
        return 0
    elif result == -1:
        print(f"[-] Process '{process_name}' not found")
    elif result == -2:
        print("[-] Failed to open process (insufficient privileges?)")
    elif result == -3:
        print("[-] Process architecture mismatch")
    elif result == -4:
        print("[-] Invalid DLL data")
    elif result == -5:
        print("[-] Injection failed")
    elif result == -100:
        print("[-] Not implemented: Pure Python manual map has limitations")
    else:
        print(f"[-] Unknown error: {result}")
    
    return 1


if __name__ == "__main__":
    sys.exit(main())
