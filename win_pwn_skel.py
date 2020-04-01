#!/usr/bin/env python3.8 

"""
Basic pwn script for windows
"""
###################
# imports
import os, sys, socket, binascii, struct, ctypes, telnetlib

###################
# globals
ptrsize = ctypes.sizeof(ctypes.c_void_p)

###################
# methods
def hexdump(source: bytes, line_length: int = 0x10, separator: str = ".", base: int = 0x00) -> str:
    res = []
    align = ptrsize*2 + 2
    for i in range(0, len(source), line_length):
        chunk = bytearray(source[i:i + line_length])
        hexa = " ".join([chr(b) for b in chunk])
        text = "".join([chr(b) if 0x20 <= b < 0x7F else separator for b in chunk])
        res.append("{addr:#0{aw}x}   {data:<{dw}}    {text}".format(aw=align, addr=base+i, dw=3*line_length, data=hexa, text=text))
    return os.linesep.join(res)
    
def xlog(x: str)  -> None: sys.stderr.write(x + "\n") and sys.stderr.flush()
def err(msg: str) -> None: xlog("[!] %s" % msg)
def ok(msg: str)  -> None: xlog("[+] %s" % msg)
def dbg(msg: str) -> None: xlog("[*] %s" % msg)
def p8(x: int, s: bool = False) -> bytes: return struct.pack("<B",x) if not s else struct.pack("<b",x)
def p16(x: int, s: bool = False) -> bytes: return struct.pack("<H",x) if not s else struct.pack("<h",x)
def p32(x: int, s: bool = False) -> bytes: return struct.pack("<I",x) if not s else struct.pack("<i",x)
def p64(x: int, s: bool = False) -> bytes: return struct.pack("<Q",x) if not s else struct.pack("<q",x)
def u8(x: bytes, s: bool = False) -> int: return struct.unpack("<B",x)[0] if not s else struct.unpack("<b",x)[0]
def u16(x: bytes, s: bool = False) -> int: return struct.unpack("<H",x)[0] if not s else struct.unpack("<h",x)[0]
def u32(x: bytes, s: bool = False) -> int: return struct.unpack("<I",x)[0] if not s else struct.unpack("<i",x)[0]
def u64(x: bytes, s: bool = False) -> int: return struct.unpack("<Q",x)[0] if not s else struct.unpack("<q",x)[0]
def flat(*args, **kwargs) -> bytes: return b''.join(args)
