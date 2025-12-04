import ctypes
import os
import sys
import time
import threading
import platform
from ctypes import wintypes

# ------------------------------------------------------
# Константы и глобальные переменные
# ------------------------------------------------------

IS_WINDOWS = platform.system().lower() == "windows"

PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
THREAD_ALL_ACCESS = 0x001FFFFF

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_NOACCESS = 0x01

ProcessBasicInformation = 0
ProcessDebugPort = 7
ProcessDebugObjectHandle = 30
ProcessDebugFlags = 31
ThreadHideFromDebugger = 17

STATUS_SUCCESS = 0

_protection_active = True
_protection_threads = []

if IS_WINDOWS:
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    user32 = ctypes.windll.user32
else:
    kernel32 = None
    ntdll = None
    user32 = None


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID),
        ("dwActiveProcessorMask", ctypes.POINTER(wintypes.DWORD)),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


# ------------------------------------------------------
# ВСПОМОГАТЕЛЬНОЕ
# ------------------------------------------------------

def _is_windows():
    return IS_WINDOWS


def _safe_call(default=False):
    """Декоратор: если платформа не Windows или произошла ошибка - вернуть default."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not _is_windows():
                return default
            try:
                return func(*args, **kwargs)
            except Exception:
                return default
        return wrapper
    return decorator


# ------------------------------------------------------
# АНТИ-ОТЛАДКА
# ------------------------------------------------------

@_safe_call(False)
def check_is_debugger_present():
    return bool(kernel32.IsDebuggerPresent())


@_safe_call(False)
def check_remote_debugger():
    is_debugged = wintypes.BOOL(False)
    h_process = kernel32.GetCurrentProcess()
    if kernel32.CheckRemoteDebuggerPresent(h_process, ctypes.byref(is_debugged)):
        return bool(is_debugged.value)
    return False


@_safe_call(False)
def check_nt_global_flag():
    """
    Проверка NtGlobalFlag через PEB.
    """
    # Для x64 обычно: PEB в RDX/RCX, но мы пойдём через NtQueryInformationProcess.
    class PROCESS_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Reserved1", ctypes.c_void_p),
            ("PebBaseAddress", ctypes.c_void_p),
            ("Reserved2", ctypes.c_void_p * 2),
            ("UniqueProcessId", ctypes.c_void_p),
            ("Reserved3", ctypes.c_void_p),
        ]

    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = wintypes.ULONG(0)

    NtQueryInformationProcess = ntdll.NtQueryInformationProcess
    status = NtQueryInformationProcess(
        kernel32.GetCurrentProcess(),
        ProcessBasicInformation,
        ctypes.byref(pbi),
        ctypes.sizeof(pbi),
        ctypes.byref(ret_len)
    )
    if status != STATUS_SUCCESS or not pbi.PebBaseAddress:
        return False

    # Смещение NtGlobalFlag в PEB отличается для x86/x64,
    # используем стандартные значения.
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        nt_global_flag_offset = 0xBC
    else:
        nt_global_flag_offset = 0x68

    nt_global_flag = ctypes.c_ulong(0)
    bytes_read = ctypes.c_size_t(0)

    if not kernel32.ReadProcessMemory(
        kernel32.GetCurrentProcess(),
        ctypes.c_void_p(pbi.PebBaseAddress + nt_global_flag_offset),
        ctypes.byref(nt_global_flag),
        ctypes.sizeof(nt_global_flag),
        ctypes.byref(bytes_read),
    ):
        return False

    debug_flags_mask = 0x70  # FLG_HEAP_ENABLE_TAIL_CHECK, FLG_HEAP_ENABLE_FREE_CHECK, FLG_HEAP_VALIDATE_PARAMETERS
    return bool(nt_global_flag.value & debug_flags_mask)


@_safe_call(False)
def check_debug_port():
    debug_port = ctypes.c_void_p()
    ret_len = wintypes.DWORD()
    status = ntdll.NtQueryInformationProcess(
        kernel32.GetCurrentProcess(),
        ProcessDebugPort,
        ctypes.byref(debug_port),
        ctypes.sizeof(debug_port),
        ctypes.byref(ret_len),
    )
    if status == STATUS_SUCCESS:
        return debug_port.value not in (0, None, -1)
    return False


@_safe_call(False)
def check_debug_object_handle():
    debug_handle = wintypes.HANDLE()
    ret_len = wintypes.DWORD()
    status = ntdll.NtQueryInformationProcess(
        kernel32.GetCurrentProcess(),
        ProcessDebugObjectHandle,
        ctypes.byref(debug_handle),
        ctypes.sizeof(debug_handle),
        ctypes.byref(ret_len),
    )
    # 0xC0000353 = STATUS_PORT_NOT_SET (нет debug object)
    if status == 0xC0000353:
        return False
    return status == STATUS_SUCCESS and bool(debug_handle.value)


@_safe_call(False)
def check_debug_flags():
    debug_flags = wintypes.DWORD()
    ret_len = wintypes.DWORD()
    status = ntdll.NtQueryInformationProcess(
        kernel32.GetCurrentProcess(),
        ProcessDebugFlags,
        ctypes.byref(debug_flags),
        ctypes.sizeof(debug_flags),
        ctypes.byref(ret_len),
    )
    if status == STATUS_SUCCESS:
        # Если процесс отлаживается – DebugFlags == 0
        return debug_flags.value == 0
    return False


@_safe_call(False)
def check_timing_attack():
    """
    Детект медленной эмуляции/песочницы на простых инструкциях.
    """
    iterations = 5000
    start = time.perf_counter_ns()
    for _ in range(iterations):
        _ = 1 + 1
    end = time.perf_counter_ns()
    elapsed_ns = end - start
    avg_per_iteration = elapsed_ns / iterations
    # Порог подбирается экспериментально; 2000 ns/iter уже подозрительно.
    return avg_per_iteration > 2000


@_safe_call(False)
def check_sleep_skipping():
    """
    Проверка на «пропуск сна» (faked Sleep):
    если Sleep(2000) занимает существенно меньше,
    чем 2000 мс — подозрительно.
    """
    start = time.perf_counter()
    kernel32.Sleep(2000)
    end = time.perf_counter()
    elapsed_ms = (end - start) * 1000.0
    # Если система «перемотала» время или эмуляция — может быть ~0-500 мс.
    return elapsed_ms < 1500.0


@_safe_call(False)
def check_hardware_breakpoints():
    """
    Проверка debug-регистров DR0-DR3, DR7.
    Для x64 CONTEXT сильно больше, поэтому выделяем с запасом.
    """
    CONTEXT_DEBUG_REGISTERS = 0x00000010 | 0x00010000  # CONTEXT_DEBUG_REGISTERS | CONTEXT_AMD64

    class CONTEXT(ctypes.Structure):
        _fields_ = [
            ("P1Home", ctypes.c_ulonglong),
            ("P2Home", ctypes.c_ulonglong),
            ("P3Home", ctypes.c_ulonglong),
            ("P4Home", ctypes.c_ulonglong),
            ("P5Home", ctypes.c_ulonglong),
            ("P6Home", ctypes.c_ulonglong),
            ("ContextFlags", wintypes.DWORD),
            ("MxCsr", wintypes.DWORD),
            # Rxx и т.д. пропускаем; нам нужны только DRx
            ("SegCs", wintypes.WORD),
            ("SegDs", wintypes.WORD),
            ("SegEs", wintypes.WORD),
            ("SegFs", wintypes.WORD),
            ("SegGs", wintypes.WORD),
            ("SegSs", wintypes.WORD),
            ("EFlags", wintypes.DWORD),
            ("Dr0", ctypes.c_ulonglong),
            ("Dr1", ctypes.c_ulonglong),
            ("Dr2", ctypes.c_ulonglong),
            ("Dr3", ctypes.c_ulonglong),
            ("Dr6", ctypes.c_ulonglong),
            ("Dr7", ctypes.c_ulonglong),
        ]

    ctx = CONTEXT()
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    thread_handle = kernel32.GetCurrentThread()

    if not kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
        return False

    if ctx.Dr0 or ctx.Dr1 or ctx.Dr2 or ctx.Dr3:
        return True
    if ctx.Dr7 != 0:
        return True
    return False


@_safe_call(False)
def check_software_breakpoints():
    """
    Проверка на int3 (0xCC) в критичных функциях.
    """
    critical_funcs = [
        kernel32.IsDebuggerPresent,
        kernel32.CheckRemoteDebuggerPresent,
        kernel32.GetTickCount,
    ]
    for func in critical_funcs:
        try:
            func_addr = ctypes.cast(func, ctypes.c_void_p).value
            if not func_addr:
                continue
            first_byte = ctypes.c_ubyte()
            bytes_read = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(
                kernel32.GetCurrentProcess(),
                ctypes.c_void_p(func_addr),
                ctypes.byref(first_byte),
                1,
                ctypes.byref(bytes_read),
            ):
                if first_byte.value == 0xCC:
                    return True
        except Exception:
            continue
    return False


@_safe_call(False)
def check_ntdll_inline_hooks():
    """
    Простая проверка inline-hooks в ntdll (NtQueryInformationProcess, NtClose и т.п.):
    первый байт должен быть 0x4C или 0x48 (prolog mov/ push для x64),
    если там jmp (0xE9 / 0xFF) — возможен хук.
    """
    suspicious = False
    funcs = ["NtQueryInformationProcess", "NtClose", "NtTerminateProcess"]
    for name in funcs:
        try:
            func = getattr(ntdll, name)
            addr = ctypes.cast(func, ctypes.c_void_p).value
            if not addr:
                continue
            first_byte = ctypes.c_ubyte()
            bytes_read = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(
                kernel32.GetCurrentProcess(),
                ctypes.c_void_p(addr),
                ctypes.byref(first_byte),
                1,
                ctypes.byref(bytes_read),
            ):
                if first_byte.value in (0xE9, 0xEA, 0xEB, 0xFF):  # jmp / call [..]
                    suspicious = True
        except Exception:
            continue
    return suspicious


@_safe_call(False)
def check_debugger_window():
    """
    Проверка заголовков окон и частично классов окон известных отладчиков.
    """
    debugger_windows = [
        "OLLYDBG",
        "x64dbg",
        "x32dbg",
        "IDA",
        "Immunity Debugger",
        "WinDbg",
        "Cheat Engine",
        "Process Hacker",
        "Process Monitor",
        "API Monitor",
        "Fiddler",
        "Wireshark",
        "HTTP Debugger",
        "x64dbg -",
        "dnSpy",
    ]

    for window_name in debugger_windows:
        hwnd = user32.FindWindowW(None, window_name)
        if hwnd:
            return True
        hwnd = user32.FindWindowA(None, window_name.encode(errors="ignore"))
        if hwnd:
            return True

    # Дополнительно пробежаться по окнам и искать подстроки в заголовках
    EnumWindows = user32.EnumWindows
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    titles = []

    @_safe_call(True)
    def _enum_proc(hwnd, lParam):
        length = user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            titles.append(buff.value)
        return True

    if EnumWindows(EnumWindowsProc(_enum_proc), 0):
        lw = [t.lower() for t in titles]
        keys = ["ollydbg", "x64dbg", "x32dbg", "ida", "windbg", "cheat engine"]
        for t in lw:
            if any(k in t for k in keys):
                return True

    return False


@_safe_call(False)
def hide_thread_from_debugger():
    """
    NtSetInformationThread(ThreadHideFromDebugger)
    """
    thread_handle = kernel32.GetCurrentThread()
    status = ntdll.NtSetInformationThread(
        thread_handle,
        ThreadHideFromDebugger,
        None,
        0
    )
    return status == STATUS_SUCCESS


@_safe_call(False)
def erase_pe_header():
    """
    Затирание заголовка PE только для упакованных (sys.frozen) бинарников.
    """
    if not getattr(sys, "frozen", False):
        return False

    base_addr = kernel32.GetModuleHandleW(None)
    if not base_addr:
        return False

    sys_info = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(sys_info))
    page_size = sys_info.dwPageSize

    old_protect = wintypes.DWORD()
    if not kernel32.VirtualProtect(
        ctypes.c_void_p(base_addr),
        page_size,
        PAGE_READWRITE,
        ctypes.byref(old_protect),
    ):
        return False

    ctypes.memset(base_addr, 0, page_size)

    kernel32.VirtualProtect(
        ctypes.c_void_p(base_addr),
        page_size,
        old_protect.value,
        ctypes.byref(old_protect),
    )
    return True


# ------------------------------------------------------
# ANTI-VM / ANTI-SANDBOX / ANALYSIS
# ------------------------------------------------------

@_safe_call(False)
def check_memory_tools():
    try:
        import psutil
    except ImportError:
        return False

    memory_tools = [
        "processhacker.exe",
        "procexp.exe",
        "procexp64.exe",
        "procmon.exe",
        "procmon64.exe",
        "pe-bear.exe",
        "lordpe.exe",
        "dumper.exe",
        "scylla.exe",
        "scylla_x86.exe",
        "scylla_x64.exe",
        "importrec.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "ida.exe",
        "ida64.exe",
        "idaq.exe",
        "idaq64.exe",
        "cheatengine-x86_64.exe",
        "cheatengine-i386.exe",
        "ghidra.exe",
        "windbg.exe",
        "dbgview.exe",
        "apimonitor-x86.exe",
        "apimonitor-x64.exe",
        "httpdebugger.exe",
        "fiddler.exe",
        "wireshark.exe",
        "dnspy.exe",
        "de4dot.exe",
        "hxd.exe",
        "hxd64.exe",
        "reclass.exe",
        "reclass.net.exe",
    ]

    tools_set = {t.lower() for t in memory_tools}
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info.get('name') or ""
            if name.lower() in tools_set:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


@_safe_call(False)
def check_vm_registry():
    import winreg

    vm_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxMouse"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxService"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxSF"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmci"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmhgfs"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmmouse"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\vmx86"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"),
    ]
    for hkey, subkey in vm_keys:
        try:
            key = winreg.OpenKey(hkey, subkey)
            winreg.CloseKey(key)
            return True
        except OSError:
            continue
    return False


@_safe_call(False)
def check_vm_processes():
    try:
        import psutil
    except ImportError:
        return False

    vm_processes = [
        "vmwareuser.exe",
        "vmwaretray.exe",
        "vmtoolsd.exe",
        "vmacthlp.exe",
        "vboxservice.exe",
        "vboxtray.exe",
        "vboxguest.exe",
        "qemu-ga.exe",
        "vmsrvc.exe",
        "vmusrvc.exe",
        "prl_tools.exe",
        "prl_cc.exe",
        "xenservice.exe",
        "joeboxcontrol.exe",
        "joeboxserver.exe",
        "sandboxierpcss.exe",
        "sandboxiedcomlaunch.exe",
    ]
    vm_set = {p.lower() for p in vm_processes}

    for proc in psutil.process_iter(['name']):
        try:
            name = (proc.info.get('name') or "").lower()
            if name in vm_set:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


@_safe_call(False)
def check_vm_files():
    vm_files = [
        r"C:\Windows\System32\drivers\vmmouse.sys",
        r"C:\Windows\System32\drivers\vmhgfs.sys",
        r"C:\Windows\System32\drivers\vm3dmp.sys",
        r"C:\Windows\System32\drivers\vmci.sys",
        r"C:\Windows\System32\drivers\VBoxMouse.sys",
        r"C:\Windows\System32\drivers\VBoxGuest.sys",
        r"C:\Windows\System32\drivers\VBoxSF.sys",
        r"C:\Windows\System32\drivers\VBoxVideo.sys",
        r"C:\Windows\System32\vboxdisp.dll",
        r"C:\Windows\System32\vboxhook.dll",
        r"C:\Windows\System32\vboxmrxnp.dll",
        r"C:\Windows\System32\vboxogl.dll",
        r"C:\Windows\System32\vboxoglarrayspu.dll",
        r"C:\Windows\System32\vboxoglcrutil.dll",
        r"C:\Windows\System32\vboxoglerrorspu.dll",
        r"C:\Windows\System32\vboxoglfeedbackspu.dll",
        r"C:\Windows\System32\vboxoglpackspu.dll",
        r"C:\Windows\System32\vboxoglpassthroughspu.dll",
        r"C:\Windows\System32\vmGuestLib.dll",
        r"C:\Windows\System32\vmhgfs.dll",
    ]
    for fp in vm_files:
        try:
            if os.path.exists(fp):
                return True
        except Exception:
            continue
    return False


@_safe_call(False)
def check_vm_mac_address():
    import uuid
    mac = uuid.getnode()
    mac_str = ':'.join(('%012X' % mac)[i:i + 2] for i in range(0, 12, 2))

    vm_mac_prefixes = [
        "00:0C:29",  # VMware
        "00:50:56",  # VMware
        "08:00:27",  # VirtualBox
        "52:54:00",  # QEMU/ KVM
        "00:1C:42",  # Parallels
        "00:16:3E",  # Xen
        "00:15:5D",  # Hyper-V
    ]

    for prefix in vm_mac_prefixes:
        if mac_str.upper().startswith(prefix):
            return True
    return False


@_safe_call(False)
def check_cpuid_hypervisor():
    import subprocess
    result = subprocess.run(
        ['wmic', 'computersystem', 'get', 'manufacturer,model'],
        capture_output=True,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    output = (result.stdout or "").lower()
    vm_indicators = [
        "vmware",
        "virtualbox",
        "virtual",
        "qemu",
        "xen",
        "hyper-v",
        "parallels",
        "kvm",
    ]
    return any(ind in output for ind in vm_indicators)


@_safe_call(False)
def check_sandbox_artifacts():
    username = os.environ.get('USERNAME', '').lower()
    sandbox_usernames = [
        'sandbox',
        'virus',
        'malware',
        'sample',
        'test',
        'analysis',
        'cuckoo',
        'john',
        'john doe',
        'joe sandbox',
        'currentuser',
        'admin',
        'user',
    ]
    for su in sandbox_usernames:
        if su and su in username:
            return True

    computername = os.environ.get('COMPUTERNAME', '').lower()
    sandbox_computers = [
        'sandbox',
        'virus',
        'malware',
        'sample',
        'cuckoo',
        'analysis',
        'test',
    ]
    for sc in sandbox_computers:
        if sc and sc in computername:
            return True

    return False


@_safe_call(False)
def check_disk_size():
    import shutil
    total, used, free = shutil.disk_usage("C:\\")
    total_gb = total / (1024 ** 3)
    # VM/песочницы часто дают 40-60 ГБ; порог можно подрегулировать.
    return total_gb < 60


@_safe_call(False)
def check_ram_size():
    try:
        import psutil
    except ImportError:
        return False
    ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    return ram_gb < 4


@_safe_call(False)
def check_processor_count():
    cpu_count = os.cpu_count()
    return cpu_count is not None and cpu_count < 2


@_safe_call([])
def get_loaded_modules():
    try:
        import psutil
    except ImportError:
        return []
    current_process = psutil.Process()
    paths = []
    for m in current_process.memory_maps():
        try:
            if m.path:
                paths.append(m.path.lower())
        except Exception:
            continue
    return paths


@_safe_call(False)
def check_suspicious_modules():
    try:
        import psutil
    except ImportError:
        return False

    suspicious_indicators = [
        "hook",
        "spy",
        "sniff",
        "monitor",
        "cheat",
        "hack",
        "trainer",
        "detour",
        "frida",
        "minhook",
        "easyhook",
    ]

    current_process = psutil.Process()
    for module in current_process.memory_maps():
        try:
            module_name = os.path.basename(module.path).lower()
            for indicator in suspicious_indicators:
                if indicator in module_name:
                    return True
        except Exception:
            continue
    return False


@_safe_call(False)
def check_parent_process():
    """
    Проверка родительского процесса для упакованных (sys.frozen) приложений.
    """
    if not getattr(sys, 'frozen', False):
        return False

    try:
        import psutil
    except ImportError:
        return False

    current = psutil.Process()
    parent = current.parent()
    if parent:
        parent_name = (parent.name() or "").lower()
        suspicious_parents = [
            "ollydbg.exe",
            "x64dbg.exe",
            "x32dbg.exe",
            "ida.exe",
            "ida64.exe",
            "windbg.exe",
            "processhacker.exe",
            "procexp.exe",
            "procexp64.exe",
            "memoryview.exe",
            "procexp64a.exe",
        ]
        if parent_name in suspicious_parents:
            return True
    return False


# ------------------------------------------------------
# АГРЕГАТОРЫ
# ------------------------------------------------------

def is_being_debugged():
    """
    Комплексная проверка отладчика.
    """
    checks = [
        check_is_debugger_present,
        check_remote_debugger,
        check_nt_global_flag,
        check_debug_port,
        check_debug_object_handle,
        check_debug_flags,
        check_hardware_breakpoints,
        check_software_breakpoints,
        check_debugger_window,
        check_ntdll_inline_hooks,
        check_sleep_skipping,
    ]
    for check in checks:
        try:
            if check():
                return True
        except Exception:
            continue
    return False


def is_in_vm():
    checks = [
        check_vm_registry,
        check_vm_processes,
        check_vm_files,
        check_vm_mac_address,
        check_cpuid_hypervisor,
    ]
    for check in checks:
        try:
            if check():
                return True
        except Exception:
            continue
    return False


def is_in_sandbox():
    """
    Счётная эвристика: если >= 2 сигналов из воображаемых «слабых» признаков – считаем sandbox.
    """
    checks = [
        check_sandbox_artifacts,
        check_disk_size,
        check_ram_size,
        check_processor_count,
    ]
    detected_count = 0
    for check in checks:
        try:
            if check():
                detected_count += 1
        except Exception:
            continue
    return detected_count >= 2


def is_analysis_environment():
    checks = [
        check_memory_tools,
        check_suspicious_modules,
        check_parent_process,
    ]
    for check in checks:
        try:
            if check():
                return True
        except Exception:
            continue
    return False


# ------------------------------------------------------
# ЗАЩИТНЫЙ ЦИКЛ
# ------------------------------------------------------

def _trigger_protection(reason="Protection triggered"):
    try:
        if _is_windows():
            erase_pe_header()
        os._exit(1)
    except Exception:
        sys.exit(1)


def protection_loop():
    global _protection_active
    while _protection_active:
        try:
            if is_being_debugged():
                _trigger_protection("Debugger detected")
                return
            if is_analysis_environment():
                _trigger_protection("Analysis environment detected")
                return
            if check_timing_attack():
                _trigger_protection("Timing anomaly detected")
                return
        except Exception:
            pass
        time.sleep(2)


def patch_mini_dump():
    if not _is_windows():
        return False
    try:
        dbghelp = ctypes.windll.dbghelp
        mini_dump_addr = ctypes.cast(dbghelp.MiniDumpWriteDump, ctypes.c_void_p).value
        if not mini_dump_addr:
            return False
        patch = (ctypes.c_ubyte * 6)(0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3)  # mov eax,0; ret
        old = ctypes.c_ulong()
        if not kernel32.VirtualProtect(mini_dump_addr, 6, PAGE_EXECUTE_READWRITE, ctypes.byref(old)):
            return False
        ctypes.memmove(mini_dump_addr, patch, 6)
        kernel32.VirtualProtect(mini_dump_addr, 6, old.value, ctypes.byref(old))
        return True
    except Exception:
        return False


def start_protection(check_vm=False, check_sandbox=False):
    """
    Запуск защиты.
    check_vm / check_sandbox – опциональные жёсткие проверки.
    """
    global _protection_active, _protection_threads

    try:
        if is_being_debugged():
            _trigger_protection("Initial debugger check failed")
            return False

        if is_analysis_environment():
            _trigger_protection("Analysis environment detected on startup")
            return False

        if check_vm and is_in_vm():
            _trigger_protection("VM detected")
            return False

        if check_sandbox and is_in_sandbox():
            _trigger_protection("Sandbox detected")
            return False

        if _is_windows():
            hide_thread_from_debugger()
            if getattr(sys, 'frozen', False):
                erase_pe_header()
            try:
                patch_mini_dump()
            except Exception:
                pass

        _protection_active = True
        protection_thread = threading.Thread(target=protection_loop, daemon=True)
        protection_thread.start()
        _protection_threads.append(protection_thread)
        return True
    except Exception:
        # В случае ошибок при инициализации лучше НЕ падать, а просто не включать защиту.
        return True


def stop_protection():
    global _protection_active
    _protection_active = False


if __name__ == "__main__":
    print("Anti-Protection Module Self-Test")
    print("=" * 50)

    print("\n[Debugger Detection Tests]")
    print(f"  IsDebuggerPresent: {check_is_debugger_present()}")
    print(f"  RemoteDebugger: {check_remote_debugger()}")
    print(f"  NtGlobalFlag: {check_nt_global_flag()}")
    print(f"  DebugPort: {check_debug_port()}")
    print(f"  DebugObjectHandle: {check_debug_object_handle()}")
    print(f"  DebugFlags: {check_debug_flags()}")
    print(f"  HardwareBreakpoints: {check_hardware_breakpoints()}")
    print(f"  SoftwareBreakpoints: {check_software_breakpoints()}")
    print(f"  DebuggerWindow: {check_debugger_window()}")
    print(f"  NtdllInlineHooks: {check_ntdll_inline_hooks()}")
    print(f"  SleepSkipping: {check_sleep_skipping()}")
    print(f"  TimingAttack: {check_timing_attack()}")
    print(f"  Combined: {is_being_debugged()}")
    print(f"  Dump patch: {patch_mini_dump()}")

    print("\n[VM Detection Tests]")
    print(f"  VMRegistry: {check_vm_registry()}")
    print(f"  VMProcesses: {check_vm_processes()}")
    print(f"  VMFiles: {check_vm_files()}")
    print(f"  VMMAcAddress: {check_vm_mac_address()}")
    print(f"  CPUIDHypervisor: {check_cpuid_hypervisor()}")
    print(f"  Combined: {is_in_vm()}")

    print("\n[Sandbox Detection Tests]")
    print(f"  SandboxArtifacts: {check_sandbox_artifacts()}")
    print(f"  DiskSize: {check_disk_size()}")
    print(f"  RAMSize: {check_ram_size()}")
    print(f"  ProcessorCount: {check_processor_count()}")
    print(f"  Combined: {is_in_sandbox()}")

    print("\n[Analysis Environment Tests]")
    print(f"  MemoryTools: {check_memory_tools()}")
    print(f"  SuspiciousModules: {check_suspicious_modules()}")
    print(f"  ParentProcess: {check_parent_process()}")
    print(f"  Combined: {is_analysis_environment()}")

    print("\n" + "=" * 50)
    print("Self-test complete.")