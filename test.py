from flux import Process

# For a notepad.exe
with Process("notepad.exe") as proc:
    proc.inject_dll("libtest.dll")
    bts = proc.read_bytes(proc._mod_base_addr, 10)
    addr = proc.allocate(10)
    var = proc.has_module("libtest.dll")
    #proc.remove_dll("libtest.dll")
    print(bts, addr, var) 