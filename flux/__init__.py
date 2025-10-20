from .win32 import *
from pathlib import Path
import traceback
from functools import wraps

def safe_close(handle):
    if handle and handle not in (0, INVALID_HANDLE_VALUE):
        kernel32.CloseHandle(handle)

# Decorator for OpenProcess HANDLE
def open_process(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):

        previous = self._h_temporary
        self._h_temporary = self._h_open_process if self._block_with \
            else kernel32.OpenProcess(0x000F0000 | 0x00100000 | 0xFFFF, wintypes.BOOL(False), self._proc_id)
        
        if not self._h_temporary:
            raise ctypes.WinError(ctypes.get_last_error())
        
        try:
            result = func(self, *args, **kwargs)
            return result
        
        finally:
            if not self._block_with:
                kernel32.CloseHandle(self._h_temporary)
            self._h_temporary = previous
    return wrapper

# Decorator for CreateToolhelp32Snapshot HANDLE for processes
def snapshot_processes(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):

        previous = self._h_temporary
        self._h_temporary = self._h_snapshot_processes if self._block_with \
            else kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        
        if not self._h_temporary or self._h_temporary == INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
            
        try:
            result = func(self, *args, **kwargs)
            return result
        
        finally:
            if not self._block_with:
                kernel32.CloseHandle(self._h_temporary)
            self._h_temporary = previous

    return wrapper

# Decorator for CreateToolhelp32Snapshot HANDLE for modules
def snapshot_modules(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):

        previous = self._h_temporary
        self._h_temporary = self._h_snapshot_modules if self._block_with \
            else kernel32.CreateToolhelp32Snapshot(0x00000008 | 0x00000010, self._proc_id)
        
        if not self._h_temporary or self._h_temporary == INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
            
        try:
            result = func(self, *args, **kwargs)
            return result
        
        finally:
            if not self._block_with:
                kernel32.CloseHandle(self._h_temporary)
            self._h_temporary = previous

    return wrapper

class Process:
    def __init__(self, procName: str, modName: str = None) -> None:
        self._block_with = False
        self._h_temporary = None
        self._allocates = []
        self._proc_id = self._get_proc_id(procName)
        if self._proc_id < 0:
            raise Exception("Error: Process id is not found.")
        
        if modName == None:
            self._mod_base_addr = self._get_mod_base_addr(procName)
        else:
            self._mod_base_addr = self._get_mod_base_addr(modName)

        if self._mod_base_addr == 0:
            raise Exception("Error: Module base address is not found.")

    def __enter__(self: Process) -> Process:
        self._block_with = True
        self._h_open_process = kernel32.OpenProcess(0x000F0000 | 0x00100000 | 0xFFFF, wintypes.BOOL(False), self._proc_id)
        self._h_snapshot_processes = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        self._h_snapshot_modules = kernel32.CreateToolhelp32Snapshot(0x00000008 | 0x00000010, self._proc_id)
        return self
    
    def __exit__(self, exc_type, exc_value, exc_tb) -> bool:
        
        self.free_allocates()
        safe_close(self._h_open_process)
        safe_close(self._h_snapshot_processes)
        safe_close(self._h_snapshot_modules)

        if exc_type:
            traceback.print_exception(exc_type, exc_value, exc_tb)
        return True

    @open_process
    def free_allocates(self):
        """To clear all allocations made via allocate().\n
        Not needed in 'with' block."""
        if len(self._allocates) != 0:
            for addr in self._allocates:
                kernel32.VirtualFreeEx(self._h_temporary, addr, 0, 0x8000)
            self._allocates.clear()
    
    @snapshot_processes
    def _get_proc_id(self, procName: str) -> int:

        procEntry = PROCESSENTRY32()
        kernel32.Process32FirstW(self._h_temporary, byref(procEntry))
        while True:
            if str(procEntry.szExeFile).lower() == procName.lower():
                return procEntry.th32ProcessID
            if not kernel32.Process32NextW(self._h_temporary, byref(procEntry)):
                break
        return -1

    @snapshot_modules
    def _get_mod_base_addr(self, modName: str) -> int:
        modEntry = MODULEENTRY32()
        kernel32.Module32FirstW(self._h_temporary, byref(modEntry))
        while True:
            if modEntry.szModule.lower() == modName.lower():
                self._mod_size = modEntry.modBaseSize
                return ctypes.cast(modEntry.modBaseAddr, ctypes.c_void_p).value
            if not kernel32.Module32NextW(self._h_temporary, byref(modEntry)):
                break
        self._mod_size = 0
        return 0
    
    @snapshot_modules
    def get_all_modules(self) -> list[str]:
        mod_list = []
        modEntry = MODULEENTRY32()
        kernel32.Module32FirstW(self._h_temporary, byref(modEntry))
        while True:
            mod_list.append(modEntry.szModule)
            if not kernel32.Module32NextW(self._h_temporary, byref(modEntry)):
                break
        return mod_list
    
    @open_process
    def allocate(self, amount) -> wintypes.LPVOID:
        """Allocates the amount of bytes and returnes an address."""
        remoteAddr = kernel32.VirtualAllocEx(self._h_temporary, 0, amount, 0x00001000, 0x04)
        self._allocates.append(remoteAddr)
        return remoteAddr
    
    @open_process
    def inject_dll(self, dll_path: str) -> bool:
        """Injects a dll file into the process."""
        INFINITE = 0xFFFFFFFF
        p = Path(dll_path)
        if not p.exists():
            raise Exception("File doesn't exist.")
        elif p.suffix != ".dll":
            raise Exception("Wrong file extension (not .dll)")
        
        if not p.is_absolute():
            p = p.resolve()

        if self.has_module(p.name):
            return False
        
        dllPath = ctypes.create_string_buffer(str(p).encode("utf-8"))
        remoteAddr = kernel32.VirtualAllocEx(self._h_temporary, 0, ctypes.sizeof(dllPath), 0x00001000, 0x04)

        bytes_written = ctypes.c_size_t()
        kernel32.WriteProcessMemory(self._h_temporary, remoteAddr, dllPath, ctypes.sizeof(dllPath), byref(bytes_written))

        krnl_str = ctypes.create_string_buffer(b"kernel32.dll")
        krnl_handle = kernel32.GetModuleHandleA(krnl_str)

        load_lib_str = ctypes.create_string_buffer(b"LoadLibraryA")
        load_lib_addr = kernel32.GetProcAddress(krnl_handle, load_lib_str)

        thread_id = wintypes.DWORD()
        remote_thread = kernel32.CreateRemoteThread(self._h_temporary, 0, 0, load_lib_addr, remoteAddr, 0, byref(thread_id))
        
        if not remote_thread:
            kernel32.VirtualFreeEx(self._h_temporary, remoteAddr, 0, 0x8000)
            raise ctypes.WinError(ctypes.get_last_error())
        
        kernel32.WaitForSingleObject(remote_thread, INFINITE)
        kernel32.CloseHandle(remote_thread)

        kernel32.VirtualFreeEx(self._h_temporary, remoteAddr, 0, 0x8000)
        
        return True
    
    @snapshot_modules
    def _get_mod_handle(self, mod_name):
        
        modEntry = MODULEENTRY32()
        kernel32.Module32FirstW(self._h_temporary, byref(modEntry))
        while True:
            if str(modEntry.szModule).lower() == mod_name.lower():
                return int(modEntry.hModule)
            if not kernel32.Module32NextW(self._h_temporary, byref(modEntry)):
                break
        return 0

    @open_process
    def remove_dll(self, dll_name: str) -> bool:
        """Removes a dll from the process."""

        INFINITE = 0xFFFFFFFF
        if not self.has_module(dll_name):
            print("dll not found")
            return False
        
        dll_handle = self._get_mod_handle(dll_name)
        print(f"DLL HANDLE: {dll_handle}")
        if dll_handle == 0:
            return False
        
        krnl_handle = kernel32.GetModuleHandleA(ctypes.c_char_p(b"kernel32.dll"))
        free_lib_addr = kernel32.GetProcAddress(krnl_handle, ctypes.c_char_p(b"FreeLibrary"))

        dll_name_buff = ctypes.create_string_buffer(dll_name.encode("utf-8"))
        dll_name_addr = kernel32.VirtualAllocEx(self._h_temporary, 0, ctypes.sizeof(dll_name_buff), 0x00001000, 0x04)
        
        if not dll_name_addr:
            raise ctypes.WinError(ctypes.get_last_error())

        bytes_written = ctypes.c_size_t()
        kernel32.WriteProcessMemory(self._h_temporary, dll_name_addr, byref(dll_name_buff), ctypes.sizeof(dll_name_buff), byref(bytes_written))

        thread_id = wintypes.DWORD()
        remote_thread = kernel32.CreateRemoteThread(self._h_temporary, 0, 0, ctypes.c_void_p(free_lib_addr), ctypes.c_void_p(dll_handle), 0, byref(thread_id))

        if not remote_thread:
            kernel32.VirtualFreeEx(self._h_temporary, dll_name_addr, 0, 0x8000)
            raise ctypes.WinError(ctypes.get_last_error())

        kernel32.WaitForSingleObject(remote_thread, INFINITE)
        kernel32.VirtualFreeEx(self._h_temporary, dll_name_addr, 0, 0x8000)
        kernel32.CloseHandle(remote_thread)
        return True

    @snapshot_modules
    def has_module(self, mod_name: str) -> bool:
        """Checks if the dll is inside the process'es modules list."""
        result = False
        modEntry = MODULEENTRY32()
        kernel32.Module32FirstW(self._h_temporary, byref(modEntry))
        list_of_modules = []
        while True:
            current = str(modEntry.szModule).lower()
            list_of_modules.append(current)
            if current == mod_name.lower():
                result = True
                break
            if not kernel32.Module32NextW(self._h_temporary, byref(modEntry)):
                break
        print(list_of_modules)
        return result
    
    def find_pattern(self, pattern: bytes, mask: str = None) -> int:
        """Finds a sequence of bytes in a chosen module.\n
        Example of pattern: b'\\xb8\\x00\\x00\\x00'\n
        Example of mask: 'x??x'."""
        ptrn_size = len(pattern)
        if mask is not None and ptrn_size != len(mask):
            raise Exception("Error: mask length is not the same as pattern.")

        buffer = self.read_bytes(self._mod_base_addr, self._mod_size)

        if mask:
            for i in range(self._mod_size - ptrn_size):
                if buffer[i] == pattern[0]:
                    for j in range(ptrn_size):
                        if mask[j] != "?" and buffer[i+j] != pattern[j]:
                            break
                        if j == ptrn_size - 1:
                            return self._mod_base_addr + i
        else:
            for i in range(self._mod_size - ptrn_size):
                if buffer[i : i + ptrn_size] == pattern:
                    return self._mod_base_addr + i
                
        return -1
    
    @open_process
    def get_addr_by_offsets(self, offsets: list[int]) -> int: 
        """Finds the final address of a multi-level pointer.""" 
        bytes_read = ctypes.c_size_t()
        val = ctypes.c_longlong()
        addr = self._mod_base_addr

        for off in offsets[:-1]:
            addr += off
            kernel32.ReadProcessMemory(self._h_temporary, addr, byref(val), ctypes.sizeof(val), byref(bytes_read))
            addr = val.value
        return addr + offsets[-1]
    
    @open_process
    def read_bytes(self, address: int, amount: int) -> bytes:
        """Returns bytes from the given address."""
        if amount <= 1 or not isinstance(amount, int):
            raise Exception("Amount should be a number above 0.")
        bytes_read = ctypes.c_size_t()
        buffer = (ctypes.c_ubyte * amount)()
        kernel32.ReadProcessMemory(self._h_temporary, address, buffer, amount, byref(bytes_read))
        return bytes(buffer)
    
    @open_process
    def read_int(self, address: int) -> int:
        """Returns int32 from given the address."""
        bytes_read = ctypes.c_size_t()
        value = wintypes.INT()
        kernel32.ReadProcessMemory(self._h_temporary, address, byref(value), ctypes.sizeof(value), byref(bytes_read))
        return value.value
    
    @open_process
    def read_longlong(self, address: int): 
        """Returns int64 from given the address."""
        bytes_read = ctypes.c_size_t()
        value = ctypes.c_longlong()
        kernel32.ReadProcessMemory(self._h_temporary, address, byref(value), ctypes.sizeof(value), byref(bytes_read))
        return value.value
    
    @open_process
    def write_bytes(self, address: int, buff: bytes) -> int:
        """Writes bytes in a specified address."""
        if not isinstance(buff, list) or not all(isinstance(b, bytes) for b in buff):
            raise Exception("Buff should be a bytes array.")
        
        size = len(buff)
        buffer = (ctypes.c_byte * size)(*buff)

        oldProtect = wintypes.DWORD()
        bytes_written = ctypes.c_size_t()

        kernel32.VirtualProtectEx(self._h_temporary, address, size, 0x04, byref(oldProtect))
        kernel32.WriteProcessMemory(self._h_temporary, address, buffer, size, byref(bytes_written))
        kernel32.VirtualProtectEx(self._h_temporary, address, size, oldProtect.value, byref(oldProtect))
        return bytes_written.value

    @open_process
    def write_int(self, address: int, value: int) -> int:
        """Writes int32 in a specified address."""
        if not isinstance(value, int):
            raise Exception("Value should be a number.")
        
        oldProtect = wintypes.DWORD()
        bytes_written = ctypes.c_size_t()

        val = wintypes.INT(value)
        kernel32.VirtualProtectEx(self._h_temporary, address, ctypes.sizeof(val), 0x04, byref(oldProtect))
        kernel32.WriteProcessMemory(self._h_temporary, address, byref(val), ctypes.sizeof(val), byref(bytes_written))
        kernel32.VirtualProtectEx(self._h_temporary, address, ctypes.sizeof(val), oldProtect.value, byref(oldProtect))
        return bytes_written.value
    
    @open_process
    def write_longlong(self, address: int, value: int):
        """Writes int64 in a specified address."""
        if not isinstance(value, int):
            raise Exception("Value should be a number.")
        
        oldProtect = wintypes.DWORD()
        bytes_written = ctypes.c_size_t()

        val = ctypes.c_longlong(value)
        kernel32.VirtualProtectEx(self._h_temporary, address, ctypes.sizeof(val), 0x04, byref(oldProtect))
        kernel32.WriteProcessMemory(self._h_temporary, address, byref(val), ctypes.sizeof(val), byref(bytes_written))
        kernel32.VirtualProtectEx(self._h_temporary, address, ctypes.sizeof(val), oldProtect.value, byref(oldProtect))
        return bytes_written.value