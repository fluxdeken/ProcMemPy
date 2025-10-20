from flux import Process

# For a notepad.exe
with Process("notepad.exe") as proc:
    print(proc.read_bytes(proc._mod_base_addr, 20))
