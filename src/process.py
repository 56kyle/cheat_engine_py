import ctypes
import os
import psutil
import pymem
import re
import struct
import time
import win32api
import win32con

import frida

from pymem import Pymem
from ReadWriteMemory import ReadWriteMemory

rwm = ReadWriteMemory()


def test():
    base = 0x7FFB697E33F0
    static_offset = 0x020F2858
    dumb_base = 0x1D753805980
    pointer_static_address = base + static_offset
    offsets = [0x190, 0x1E8, 0x10, 0x548]
    btd6 = rwm.get_process_by_id(Pymem('BloonsTD6.exe').process_id)
    btd6.open()
    pointer = btd6.get_pointer(dumb_base, offsets=offsets)
    pointer_value = btd6.read(pointer)
    print(pointer_value)


def main():
    btd6 = Pymem('BloonsTD6.exe')
    find(btd6)
    #bytes = b'\x40\x53\x48\x83\xEC\x30\x00\xF29\x74\x24\x20\x45\x33C0\x00\xF28\xF1\x48\x08\x0B\xD9\xE8\xC7FDFFFF\x48\x08\x0B\x43\x28\xF2\x00\xF11\x73\x28\x00\xF28\x74\x24\x20\x48\x89\x43\x30\x48\x83\xC4\x30\x05\x0B\xC3'
    #string_form = '40 53 48 83 EC 30 00 F29 74 24 20 45 33 C0 00 F28 F1 48 08 0B D9 E8 C7FDFFFF 48 08 0B 43 28 F2 00 F11 73 28 00 F28 74 24 20 48 89 43 30 48 83 C4 30 05 0B C3'
    #print(btd6.read_double(0x23a7455c3ed))


def find(btd6: Pymem):
    hwnd = ctypes.c_void_p(btd6.process_handle)
    game_assembly = pymem.process.module_from_name(btd6.process_handle, 'GameAssembly.dll')
    print(hex(0x7FFF36A59760 - game_assembly.lpBaseOfDll))


def scan(btd6):
    hwnd = ctypes.c_void_p(btd6.process_handle)
    print(pymem.memory.read_bytes(hwnd, 0x1D72381E028, pymem.struct.calcsize('d')))
    for i in range(btd6.base_address, btd6.base_address + btd6.process_base.SizeOfImage, 1024):
        chunk = pymem.memory.read_bytes(hwnd, i, 1024)
        match = re.match(b'\x90\x8a@', chunk)
        if match:
            print(match)
            print(chunk)
    for module in btd6.list_modules():
        for i in range(module.lpBaseOfDll, module.lpBaseOfDll + module.SizeOfImage, 1024):
            chunk = pymem.memory.read_bytes(hwnd, i, 1024)
            match = re.match(rb'\x90\x8a', chunk)
            if match:
                print(i)
                print(match)


def immediately_find(btd6: Pymem):
    btd6.read_bytes




if __name__ == '__main__':
    main()




