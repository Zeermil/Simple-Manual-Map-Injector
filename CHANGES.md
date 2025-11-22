# Changelog - Cross-Architecture Injection Support

## Overview

This update adds cross-architecture injection support, allowing a single 64-bit injector to inject into both 32-bit and 64-bit processes.

## New Features

### 1. Cross-Architecture Detection and Injection

The 64-bit injector (`Injector-x64.exe`) now:
- Automatically detects if the target process is 32-bit or 64-bit
- Directly injects into 64-bit processes
- Automatically launches the 32-bit helper (`Injector-x86.exe`) for 32-bit targets
- Waits for helper completion and returns its exit code

### 2. Unified Build System

New build scripts that compile both architectures in one step:
- `build_all.bat` - Windows batch script
- `build_all.sh` - Linux/macOS shell script (requires MinGW)

These scripts:
- Build x64 version with cross-architecture support
- Build x86 helper version
- Copy all outputs to unified `build/` directory
- Provide clear status messages

### 3. Enhanced Error Handling

New error codes:
- `-10`: x86 helper injector not found
- `-11`: Failed to launch helper injector

Clear error messages guide users to resolve issues.

## Modified Files

### Code Changes

#### `Manual Map Injector/main.cpp`
**New Functions:**
- `IsTargetProcess32Bit(HANDLE hProc)` - Checks if target process is 32-bit
- `IsCurrentProcess64Bit()` - Checks if current process is 64-bit
- `LaunchHelperInjector(wchar_t* dllPath, wchar_t* processName)` - Launches x86 helper

**Modified Functions:**
- `wmain()` - Added cross-architecture detection and helper launch logic
- Added proper memory cleanup for allocated process names

**Key Changes:**
```cpp
// Detect architecture mismatch
if (!IsCorrectTargetArchitecture(hProc)) {
    // If we're 64-bit and target is 32-bit, use helper
    if (IsCurrentProcess64Bit() && IsTargetProcess32Bit(hProc)) {
        CloseHandle(hProc);
        printf("Target process is 32-bit, using x86 helper injector...\n");
        int result = LaunchHelperInjector(dllPath, processName);
        // ... cleanup and return
    }
}
```

#### `CMakeLists.txt`
- Minor comment updates for clarity
- No functional changes (already supported multi-arch builds)

### New Files

#### `build_all.bat` (Windows)
Automates building both x86 and x64 versions:
- Creates separate build directories
- Configures and builds each architecture
- Copies outputs to unified `build/` directory
- Provides status messages and error handling

#### `build_all.sh` (Linux/macOS)
Bash equivalent of build_all.bat for Unix-like systems

#### `CROSS_ARCH_GUIDE.md`
Comprehensive guide covering:
- How cross-architecture injection works
- Build instructions
- Usage examples
- Troubleshooting
- Error codes
- Best practices

#### `CHANGES.md`
This file - documents all changes in this update

### Documentation Updates

#### `README.md`
- Added "Cross-architecture support" to features list
- New section for unified build using `build_all.bat`
- Updated build instructions
- Added note about keeping both EXE files together

#### `README.ru.md` (Russian)
- Translated all new features and instructions
- Added cross-architecture support information
- Updated build instructions with `build_all.bat`

#### `BUILD.md`
- New "Building Both x86 and x64" section (recommended method)
- Added `build_all.bat` usage instructions
- Updated output files section
- New troubleshooting item for missing helper

#### `.gitignore`
- Added `build-x64/` directory
- Added `build-x86/` directory

## Usage Changes

### Before This Update

Users had to:
1. Build either x86 OR x64 (not both)
2. Use matching architecture injector for target process
3. Switch executables for different target architectures

### After This Update

Users can:
1. Build both architectures with one command: `build_all.bat`
2. Use only `Injector-x64.exe` for all injections
3. Automatic architecture handling (no manual switching)

## Example Workflow

### Old Workflow
```cmd
# For 32-bit target
Injector-x86.exe my32.dll target32.exe

# For 64-bit target
Injector-x64.exe my64.dll target64.exe
```

### New Workflow
```cmd
# Build once
build_all.bat

# Use for any target
Injector-x64.exe my32.dll target32.exe  # Automatically uses x86 helper
Injector-x64.exe my64.dll target64.exe  # Direct injection
```

## Technical Implementation

### Architecture Detection
Uses Windows API `IsWow64Process` to determine:
- If target process is 32-bit (WOW64)
- If current process is 32-bit (WOW64)

### Helper Launch
When 32-bit target detected:
1. Get current executable directory
2. Look for `Injector-x86.exe` in same directory
3. Build command line with same arguments
4. Launch using `CreateProcessW`
5. Wait for completion with `WaitForSingleObject`
6. Return helper's exit code

### Memory Management
Added cleanup for allocated wide strings:
```cpp
wchar_t* allocatedProcessName = NULL;
// ... use ...
if (allocatedProcessName) delete[] allocatedProcessName;
```

## Compatibility

### Backward Compatible
- Can still use `Injector-x86.exe` directly for 32-bit targets
- Can still use `Injector-x64.exe` for 64-bit targets only
- DLL exports unchanged
- Python interface unchanged

### Requirements
- Both `Injector-x64.exe` and `Injector-x86.exe` must be in same directory
- DLL architecture must still match target process architecture
- Windows OS (cross-architecture injection is Windows-specific)

## Testing Recommendations

Users should test:
1. ✅ Inject x64 DLL into 64-bit process using Injector-x64.exe
2. ✅ Inject x86 DLL into 32-bit process using Injector-x64.exe (uses helper)
3. ✅ Verify both EXE files in same directory
4. ✅ Check error messages when helper is missing
5. ✅ Test with provided hello-world DLLs

## Migration Guide

### For Existing Users

1. **Pull latest changes**
   ```cmd
   git pull origin main
   ```

2. **Rebuild using new script**
   ```cmd
   build_all.bat
   ```

3. **Update deployment**
   - Copy both `Injector-x64.exe` and `Injector-x86.exe`
   - Keep them in same directory
   - Use `Injector-x64.exe` as default

4. **Update scripts/automation**
   - Replace separate x86/x64 calls with single x64 call
   - Injector will handle architecture automatically

### For Python Users

No changes required! The DLL interface is unchanged:
```python
# Still works the same
injector = ctypes.CDLL("ManualMapInjector-x64.dll")  # Or x86
result = injector.InjectDllFromMemorySimple(...)
```

## Known Limitations

1. **Both executables required**: Cannot use cross-architecture injection with only x64 EXE
2. **Windows only**: Cross-architecture injection is Windows-specific feature
3. **DLL must match target**: Cannot inject x64 DLL into x86 process (Windows limitation)
4. **Same directory required**: Helper must be in same directory as main injector

## Future Improvements

Potential enhancements:
- Embed x86 helper as resource in x64 EXE
- Auto-detect DLL architecture and warn if mismatch
- Support for custom helper path
- Logging system for debugging
- GUI wrapper for easier use

## Support

For issues or questions:
1. Check [CROSS_ARCH_GUIDE.md](CROSS_ARCH_GUIDE.md) for detailed usage
2. Review [BUILD.md](BUILD.md) for build troubleshooting
3. Open issue on GitHub with:
   - Windows version
   - Visual Studio version
   - Build output
   - Error messages

## Credits

This update maintains the core injection functionality while adding convenience features for cross-architecture scenarios.
