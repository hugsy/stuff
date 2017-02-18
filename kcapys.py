#!/usr/bin/env python3


import os, sys, argparse, shutil
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86 import *

__author__    =   "hugsy"
__version__   =   0.1
__licence__   =   "WTFPL v.2"
__file__      =   "kcapys.py"
__desc__      =   """Keep Calm and Patch Your Shit:

Patch all calls to a function with NOPs. Supports only x86-32 and x86-64 but can be extended.

This script is an improved version of another I found somewhere on Internet (can't remember,
sorry for the author).

"""
__usage__     = """
{3} version {0}, {1}
by {2}
syntax: {3} [options] args
""".format(__version__, __licence__, __author__, sys.argv[0])


def get_call_got(elf):
    plt = elf.get_section_by_name(".rela.plt") or elf.get_section_by_name(".rel.plt")
    dynsym = elf.get_section_by_name(".dynsym")
    if not plt or not dynsym:
        return None

    for reloc in plt.iter_relocations():
        symbol = dynsym.get_symbol(reloc.entry.r_info_sym)
        if symbol.name == callname:
            return reloc.entry.r_offset
    return None


def get_call_instruction_from_arch(from_file):
    if elf.header.e_machine == "EM_X86_64" or elf.header.e_machine == "EM_386":
        return "call"
    return None


def get_call_plt(elf, cs, got_value):
    plt = elf.get_section_by_name(".plt")
    for insn in cs.disasm(plt.data(), plt.header.sh_addr):
        if insn.mnemonic == "jmp":
            value = None
            for op in insn.operands:
                if op.type == X86_OP_MEM:
                    if insn.reg_name(op.mem.base) == "rip" and op.mem.index == 0:
                        # x64
                        value = insn.address + insn.size + op.mem.disp
                    elif op.mem.base == 0 and op.mem.index == 0:
                        # x32
                        value = op.mem.disp
            if value == got_value:
                return insn.address
    return None


def get_xrefs(elf, cs, plt_value):
    xrefs = []
    text = elf.get_section_by_name(".text")
    for insn in cs.disasm(text.data(), text.header.sh_addr):
        if insn.mnemonic == "call":
            for op in insn.operands:
                value = None
                if op.type == X86_OP_IMM:
                    value = op.imm
                if value == plt_value:
                    offset = insn.address - text.header.sh_addr + text.header.sh_offset
                    xrefs += [ { "offset": offset, "length": insn.size } ]
                    print("[*] {:#x}: call {:s}@plt  (offset = {:d})".format(insn.address,  callname, offset))
    return xrefs


def find_call(path, callname):
    print("[*] looking for '{}' calls  in {}".format(callname, path))
    elf = ELFFile(open(path, "rb"))

    if elf.header.e_machine == "EM_X86_64":
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
    elif elf.header.e_machine == "EM_386":
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        # TODO add more architectures
        raise Exception("More architecture support coming soon")

    cs.detail = True

    call_got = get_call_got(elf)
    if call_got is None:
        print("[-] call_got failed")
        return []
    print("[+] {}@got = {:#x}".format(callname, call_got))

    call_plt = get_call_plt(elf, cs, call_got)
    if call_plt is None:
        print("[-] call_plt failed")
        return []
    print("[+] {}@plt = {:#x}".format(callname, call_plt))

    return get_xrefs(elf, cs, call_plt)


def get_nop_from_arch(from_file):
    elf = ELFFile(open(from_file, "rb"))
    if elf.header.e_machine == "EM_X86_64" or elf.header.e_machine == "EM_386":
        nop = b"\x90"
        print("[+] Using x86 NOP: {}".format(repr(nop)))
        return nop
    return None


def overwrite_with_nop(from_file, xref, to_file):
    nop = get_nop_from_arch(from_file)
    if nop is None:
        print("[-] get_nop_from() failed")
        return

    print("[*] creating patched file: '{}' -> '{}'".format(from_file, to_file))
    shutil.copy2(from_file, to_file)
    with open(to_file, "rb+") as fd:
        for x in sorted(xref, key=lambda x: x["offset"]):
            # move to the correct offset
            fd.seek(x["offset"] - fd.tell())
            # patch `length` with nop sled
            fd.write(nop * x["length"])
    print("[+] done")
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage = __usage__,
                                     description = __desc__)
    parser.add_argument("-v", "--verbose", default=False, action="store_true", dest="verbose",
	                help="increments verbosity")
    parser.add_argument("-c", "--call", dest="calls", nargs="+", default=["ptrace", "alarm"],
                        help="Specify the call to patch. Can be repeated (default : %(default)s)")
    parser.add_argument("--to-file", dest="to_file", default=None,
                        help="Patched binary name")
    parser.add_argument("binary", nargs="?", default="a.out",
                        help="specify the binary to patch (default: '%(default)s')")
    args = parser.parse_args()

    if not os.access(args.binary, os.R_OK):
        print("[-] Cannot read {}".format(args.binary))
        sys.exit(1)

    from_file = args.binary
    to_file = "{}.patched".format(from_file) if args.to_file is None else args.to_file

    if os.access(to_file, os.R_OK):
        print("[!] {} already exists, it will be overwritten...".format(to_file))

    for callname in args.calls:
        xref = find_call(from_file, callname)
        if xref:
            print("[+] Found {} calls to '{}' in '{}', patching...".format(len(xref), callname, from_file))
            overwrite_with_nop(from_file, xref, to_file)
        else:
            print("[-] Something went wrong, not patching '{}' in '{}'".format(callname, from_file))

    sys.exit(0)
