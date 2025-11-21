#!/usr/bin/env python3
"""
Example Python script for using the Manual Map Injector DLL via ctypes.

This script demonstrates how to:
1. Load the ManualMapInjector DLL
2. Read a DLL file into memory
3. Inject it into a target process using the DLL bytes

Usage:
    python example_python.py <dll_to_inject> <process_name>

Example:
    python example_python.py hello-world-x64.dll notepad.exe
"""

import ctypes
import sys
import os
from pathlib import Path


def inject_dll_from_memory(injector_dll_path, dll_bytes, process_name, 
                          clear_header=True, 
                          clear_non_needed_sections=True,
                          adjust_protections=True,
                          seh_exception_support=True):
    """
    Inject a DLL from memory into a target process.
    
    Args:
        injector_dll_path: Path to the ManualMapInjector DLL
        dll_bytes: Bytes of the DLL to inject
        process_name: Name of the target process (e.g., "notepad.exe")
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
    """
    # Load the injector DLL
    try:
        injector = ctypes.CDLL(str(injector_dll_path))
    except Exception as e:
        print(f"Error loading injector DLL: {e}")
        return -100
    
    # Define the function signature
    # int InjectDllFromMemory(const char* processName, const unsigned char* dllData, 
    #                         size_t dllSize, bool clearHeader, bool clearNonNeededSections,
    #                         bool adjustProtections, bool sehExceptionSupport)
    injector.InjectDllFromMemory.argtypes = [
        ctypes.c_char_p,  # processName
        ctypes.POINTER(ctypes.c_ubyte),  # dllData
        ctypes.c_size_t,  # dllSize
        ctypes.c_bool,    # clearHeader
        ctypes.c_bool,    # clearNonNeededSections
        ctypes.c_bool,    # adjustProtections
        ctypes.c_bool     # sehExceptionSupport
    ]
    injector.InjectDllFromMemory.restype = ctypes.c_int
    
    # Convert DLL bytes to ctypes array
    dll_array = (ctypes.c_ubyte * len(dll_bytes)).from_buffer_copy(dll_bytes)
    
    # Convert process name to bytes
    process_name_bytes = process_name.encode('utf-8')
    
    # Call the injection function
    result = injector.InjectDllFromMemory(
        process_name_bytes,
        dll_array,
        len(dll_bytes),
        clear_header,
        clear_non_needed_sections,
        adjust_protections,
        seh_exception_support
    )
    
    return result


def inject_dll_from_memory_simple(injector_dll_path, dll_bytes, process_name):
    """
    Simplified version of inject_dll_from_memory with default parameters.
    
    Args:
        injector_dll_path: Path to the ManualMapInjector DLL
        dll_bytes: Bytes of the DLL to inject
        process_name: Name of the target process (e.g., "notepad.exe")
    
    Returns:
        0 on success, negative error code on failure
    """
    try:
        injector = ctypes.CDLL(str(injector_dll_path))
    except Exception as e:
        print(f"Error loading injector DLL: {e}")
        return -100
    
    # Define the function signature for the simple version
    injector.InjectDllFromMemorySimple.argtypes = [
        ctypes.c_char_p,  # processName
        ctypes.POINTER(ctypes.c_ubyte),  # dllData
        ctypes.c_size_t   # dllSize
    ]
    injector.InjectDllFromMemorySimple.restype = ctypes.c_int
    
    # Convert DLL bytes to ctypes array
    dll_array = (ctypes.c_ubyte * len(dll_bytes)).from_buffer_copy(dll_bytes)
    
    # Convert process name to bytes
    process_name_bytes = process_name.encode('utf-8')
    
    # Call the injection function
    result = injector.InjectDllFromMemorySimple(
        process_name_bytes,
        dll_array,
        len(dll_bytes)
    )
    
    return result


def main():
    if len(sys.argv) != 3:
        print("Usage: python example_python.py <dll_to_inject> <process_name>")
        print("Example: python example_python.py hello-world-x64.dll notepad.exe")
        sys.exit(1)
    
    dll_to_inject = sys.argv[1]
    process_name = sys.argv[2]
    
    # Check if DLL file exists
    if not os.path.exists(dll_to_inject):
        print(f"Error: DLL file '{dll_to_inject}' not found")
        sys.exit(1)
    
    # Determine the injector DLL path based on system architecture
    if sys.maxsize > 2**32:
        # 64-bit Python
        injector_dll = "build/ManualMapInjector-x64.dll"
    else:
        # 32-bit Python
        injector_dll = "build/ManualMapInjector-x86.dll"
    
    if not os.path.exists(injector_dll):
        print(f"Error: Injector DLL '{injector_dll}' not found")
        print("Please build the DLL first using CMake")
        sys.exit(1)
    
    # Read the DLL to inject into memory
    print(f"Reading DLL: {dll_to_inject}")
    with open(dll_to_inject, 'rb') as f:
        dll_bytes = f.read()
    
    print(f"DLL size: {len(dll_bytes)} bytes")
    print(f"Target process: {process_name}")
    print(f"Using injector: {injector_dll}")
    print()
    print("Injecting...")
    
    # Perform the injection using the simple interface
    result = inject_dll_from_memory_simple(injector_dll, dll_bytes, process_name)
    
    # Interpret the result
    if result == 0:
        print("✓ Injection successful!")
    elif result == -1:
        print(f"✗ Error: Process '{process_name}' not found")
    elif result == -2:
        print("✗ Error: Failed to open process (insufficient privileges?)")
    elif result == -3:
        print("✗ Error: Process architecture mismatch (use matching x86/x64 DLL)")
    elif result == -4:
        print("✗ Error: Invalid DLL data")
    elif result == -5:
        print("✗ Error: Injection failed")
    else:
        print(f"✗ Error: Unknown error code {result}")
    
    sys.exit(0 if result == 0 else 1)


if __name__ == "__main__":
    main()
