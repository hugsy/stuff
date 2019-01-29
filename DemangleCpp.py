"""

Demangle any C++ prototype (Python3 only)

Example:

c:\> python3 z:\stuff\DemangleCpp.py "?vFlushSpriteUpdates@DEVLOCKOBJ@@QEAAXH@Z"
public: void __cdecl DEVLOCKOBJ::vFlushSpriteUpdates(int) __ptr64

"""

import sys
from ctypes import *

def cpp_demange(name):
    prototype = WINFUNCTYPE(wintypes.HANDLE, c_char_p)
    paramflags = (1, "lpModuleName"),
    LoadLibraryA = prototype( ("LoadLibraryA", windll.kernel32), paramflags )

    prototype = WINFUNCTYPE(wintypes.HANDLE, wintypes.HANDLE, c_char_p)
    paramflags = (1, "ModuleHandle"), (1, "lpFunctionName")
    GetProcAddress = prototype( ("GetProcAddress", windll.kernel32), paramflags )

    DbgHelp = LoadLibraryA(create_string_buffer(b"C:\\Windows\\System32\\DbgHelp.dll"))
    if DbgHelp == 0:
        return (-1, "Failed to load DbgHelp.dll")
    # print("DbgHelp.dll", hex(DbgHelp))

    UnDecorateSymbolNameAddr = GetProcAddress(DbgHelp, create_string_buffer(b"UnDecorateSymbolName"))
    if UnDecorateSymbolNameAddr == 0:
        return (-2, "Failed to retrieve address of UnDecorateSymbolName")
    # print("UnDecorateSymbolName", hex(UnDecorateSymbolNameAddr))

    # DWORD IMAGEAPI UnDecorateSymbolName(
    #   PCSTR name,
    #   PSTR  outputString,
    #   DWORD maxStringLength,``
    #   DWORD flags
    # );
    UNDNAME_COMPLETE = 0
    flags = UNDNAME_COMPLETE
    out = create_string_buffer(1024)

    prototype = WINFUNCTYPE(wintypes.DWORD, c_char_p, c_char_p, wintypes.DWORD, wintypes.DWORD)
    UnDecorateSymbolName = prototype( UnDecorateSymbolNameAddr )

    res = UnDecorateSymbolName(
        create_string_buffer(bytes(name, "utf-8")),
        out,
        1024,
        flags
    )

    if res == 0:
        return (-3, "UnDecorateSymbolName() returned=%x" % res)

    return (0, str(out.value, "utf-8"))


if __name__ == "__main__":
    retcode, reason = cpp_demange(sys.argv[1])
    print(reason)