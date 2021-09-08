
from ctypes import *
from ctypes.wintypes import *

PROCESS_ALL_ACCESS = 0x1F0FFF

def read_process_memory(pid, address, offsets, size_of_data):
    # Open the process and get the handle.
    process_handle = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    size_of_data = size_of_data  # Size of your data
    data = ""
    read_buff = create_string_buffer(size_of_data)
    count = c_ulong(0)
    current_address = address
    offsets.append(None)  # We want a final loop where we actually get the data out, this lets us do that in one go.
    for offset in offsets:
        if not windll.kernel32.ReadProcessMemory(process_handle, current_address, cast(read_buff, LPVOID), size_of_data, byref(count)):
            return -1  # Error, so we're quitting.
        else:
            val = read_buff.value
            result = int.from_bytes(val, byteorder='little')
            # Here that None comes into play.
            if(offset != None):
                current_address = result + offset
            else:
                windll.kernel32.CloseHandle(process_handle)
                return result