import ctypes
from ctypes import wintypes, Structure, POINTER, byref

MAX_MODULE_NAME32 = 255
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

class PROCESSENTRY32(Structure):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dwSize = ctypes.sizeof(self)

    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_ulonglong),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.WCHAR * wintypes.MAX_PATH),
    ]

class MODULEENTRY32(Structure):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dwSize = ctypes.sizeof(self)

    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('th32ModuleID', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('GlblcntUsage', wintypes.DWORD),
        ('ProccntUsage', wintypes.DWORD),
        ('modBaseAddr', POINTER(wintypes.BYTE)),
        ('modBaseSize', wintypes.DWORD),
        ('hModule', wintypes.HMODULE),
        ('szModule', (MAX_MODULE_NAME32 + 1) * wintypes.WCHAR),
        ('szExePath', wintypes.MAX_PATH * wintypes.WCHAR),
    ]

class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength', wintypes.DWORD),
        ('lpSecurityDescriptor', wintypes.LPVOID),
        ('bInheritHandle', wintypes.BOOL)
    ]

kernel32 = ctypes.windll.kernel32

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, POINTER(PROCESSENTRY32)]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes = [wintypes.HANDLE, POINTER(PROCESSENTRY32)]
kernel32.Process32NextW.restype = wintypes.BOOL

kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, POINTER(MODULEENTRY32)]
kernel32.Module32FirstW.restype = wintypes.BOOL

kernel32.Module32NextW.argtypes = [wintypes.HANDLE, POINTER(MODULEENTRY32)]
kernel32.Module32NextW.restype = wintypes.BOOL

kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = ctypes.c_void_p

kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
kernel32.GetModuleHandleA.restype = wintypes.HMODULE

kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32)
]

kernel32.CreateRemoteThread.restype = wintypes.HANDLE

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeThread.restype = wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
    ]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
    ]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)
    ]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL