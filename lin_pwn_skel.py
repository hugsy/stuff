#!/usr/bin/env python3.9

import os, sys
from pwn import (
    context, ELF, process, remote, gdb, cyclic, hexdump,
    info, debug, success, warn, error,
    u8, p8, u16, p16, u32, p32, u64, p64,
)

context.log_level   = "debug"
context.arch        = "amd64" # arch="i386", arch="mips", arch="arm",
context.terminal    = ["tmux", "split-window", "-v", "-p 75"]

LOCAL = True
elf = ELF(os.path.realpath("./changeme"))
libc = ELF(os.path.realpath("./libc.so"))


def gdb_load_symbols_cmd(sym_file, e, base):
    sec_str = []
    for s in e.sections:
        if not s.name or not s.header.sh_addr:
            continue
        sec_addr = base + s.header.sh_addr
        sec_str.append(f'-s {s.name} 0x{sec_addr:x}')
    text_addr = e.get_section_by_name('.text').header.sh_addr + base
    return f'add-symbol-file {sym_file} 0x{text_addr:x} {" ".join(sec_str)} \n'


def attach(r):
    if LOCAL:
        # dbg_file = "libc/usr/lib/debug/.build-id/ce/17e023542265fc11d9bc8f534bb4f070493d30.debug"
        bkps = [
            # elf.symbols["main"],
        ]
        cmds = [
            # "heap-analysis-helper",
            # "format-string-helper",
            # gdb_load_symbols_cmd(dbg_file, libc, r.libs()[libc.path]),
            # "bp * $_base() + 0x1337",
        ]
        gdb.attach(r, '\n'.join(["break *{:#x}".format(x) for x in bkps] + cmds))
    return


def exploit(r):
    # r.sendlineafter(b"> ", b"HelloPwn" )
    r.interactive()
    return 0


if __name__ == "__main__":
    if len(sys.argv)>=2:
        LOCAL = False
        context.log_level = "info"
        r = remote(sys.argv[1], int(sys.argv[2]))
    else:
        r = process([elf.path, ]) #, env={"LD_PRELOAD": libc.path})
        attach(r)
        # or
        #r = gdb.debug([elf.path, ], gdbscript='')
    exit(exploit(r))
