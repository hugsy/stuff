#!/usr/bin/env python3

import os
import sys
import argparse
import shutil
import logging
import abc

import elftools.elf.elffile as elffile
import capstone
import keystone
import termcolor


__author__    =   "hugsy"
__version__   =   0.1
__licence__   =   "WTFPL v.2"
__file__      =   "kcapys.py"
__desc__      =   """Keep Calm and Patch Your Shit:

Mass PLT patching: replace calls in binaries with NOPs.

"""
__usage__     = """{3} version {0}, {1}
by {2}
syntax: {3} [options] args
""".format(__version__, __licence__, __author__, __file__)

log = logging.getLogger("kcapys")


class Config:
    def __init__(self, *args, **kwargs):
        self.elf = None
        self.ks = None
        self.cs = None
        self.original_filename = None
        self.patched_filename = None
        self.nop = None
        self.asm = None
        self.arch = None
        return


class Arch(metaclass=abc.ABCMeta):
    def __init__(self, *args, **kwargs):
        return

    def get_relocs(self, cfg):
        plt = cfg.elf.get_section_by_name(".rela.plt") or cfg.elf.get_section_by_name(".rel.plt")
        return plt.iter_relocations()

    def get_call_got(self, cfg):
        dynsym = cfg.elf.get_section_by_name(".dynsym")
        if not dynsym:
            return None
        for reloc in self.get_relocs(cfg):
            symbol = dynsym.get_symbol(reloc.entry.r_info_sym)
            if symbol.name == callname:
                return reloc.entry.r_offset
        return None

    @abc.abstractmethod
    def get_call_plt(cfg, got_value): pass

    @abc.abstractmethod
    def get_xrefs(self, cfg, plt_value): pass


class X86(Arch):
    def get_call_plt(self, cfg, got_value):
        elf     = cfg.elf
        cs      = cfg.cs
        plt     = elf.get_section_by_name(".plt")
        code    = plt.data()
        length  = plt.header.sh_addr
        for insn in cs.disasm(code, length):
            if insn.mnemonic == "jmp":
                value = None
                for op in insn.operands:
                    if op.type==X86_OP_MEM and op.mem.base==0 and op.mem.index==0:
                        value = op.mem.disp
                if value == got_value:
                    return insn.address
        return None

    def get_xrefs(self, cfg, plt_value):
        elf = cfg.elf
        cs = cfg.cs
        xrefs = []
        text = elf.get_section_by_name(".text")
        code = text.data()
        length = text.header.sh_addr
        for insn in cs.disasm(code, length):
            if insn.mnemonic == "call":
                for op in insn.operands:
                    value = None
                    if op.type == X86_OP_IMM:
                        value = op.imm
                    if value == plt_value:
                        offset = insn.address - text.header.sh_addr + text.header.sh_offset
                        xrefs += [ { "offset": offset, "length": insn.size } ]
                        log.info("{:#x}: call {:s}@plt  (offset={:d}, length={:d})".format(insn.address, callname, offset, insn.size))
        return xrefs


class X64(X86):
    def get_call_plt(self, cfg, got_value):
        elf     = cfg.elf
        cs      = cfg.cs
        plt     = elf.get_section_by_name(".plt")
        code    = plt.data()
        addr    = plt.header.sh_addr
        for insn in cs.disasm(code, addr):
            if insn.mnemonic == "jmp":
                value = None
                for op in insn.operands:
                    if op.type==X86_OP_MEM and insn.reg_name(op.mem.base)=="rip" and op.mem.index==0:
                        value = insn.address + insn.size + op.mem.disp
                if value == got_value:
                    return insn.address
        return None


class ARM(Arch):
    def get_call_plt(self, cfg, got_value):
        plt     = cfg.elf.get_section_by_name(".plt")
        got_off = 0

        for insn in cfg.cs.disasm(plt.data(), plt.header.sh_addr):
            if insn.mnemonic == "add":
                select = False
                for op in insn.operands:
                    if op.type==ARM_OP_REG and insn.reg_name(op.reg)=="ip": select=True
                    if op.type==ARM_OP_IMM and select:
                        got_off = op.imm
                        log.debug("got offset={:#x}".format(got_off))
                continue

            if insn.mnemonic == "ldr" and got_off > 0:
                value = None
                for op in insn.operands:
                    if op.type==ARM_OP_MEM and insn.reg_name(op.mem.base)=="ip" and op.mem.index==0:
                        value = got_off + insn.address + op.mem.disp
                if value == got_value:
                    return insn.address - 8
        return None

    def get_xrefs(self, cfg, plt_value):
        xrefs = []
        text = cfg.elf.get_section_by_name(".text")

        for insn in cfg.cs.disasm(text.data(), text.header.sh_addr):
            if insn.mnemonic == "bl":
                for op in insn.operands:
                    value = None
                    if op.type == ARM_OP_IMM:
                        value = op.imm
                    if value == plt_value:
                        offset = insn.address - text.header.sh_addr + text.header.sh_offset
                        xrefs += [ { "offset": offset, "length": insn.size } ]
                        log.info("{:#x}: bl {:s}@plt (offset = {:d})".format(insn.address, callname, offset))
        return xrefs


class AARCH64(ARM):
    def get_call_plt(self, cfg, got_value):
        plt     = cfg.elf.get_section_by_name(".plt")
        got_base= cfg.elf.get_section_by_name(".got.plt").header.sh_addr + 0x18
        log.debug(".got.plt base={:#x}".format(got_base))

        for insn in cfg.cs.disasm(plt.data(), plt.header.sh_addr):
            if insn.mnemonic == "ldr":
                value = None
                for op in insn.operands:
                    if op.type==ARM64_OP_MEM and insn.reg_name(op.mem.base)=="x16" and op.mem.index==0:
                        value = got_base + op.mem.disp

                if value == got_value:
                    return insn.address-4
        return None

    def get_xrefs(self, cfg, plt_value):
        xrefs = []
        text = cfg.elf.get_section_by_name(".text")

        for insn in cfg.cs.disasm(text.data(), text.header.sh_addr):
            if insn.mnemonic == "bl":
                for op in insn.operands:
                    value = None
                    if op.type == ARM64_OP_IMM:
                        value = op.imm
                        print("{:#x} bl {:#x}".format(insn.address, value))
                    if value == plt_value:
                        offset = insn.address - text.header.sh_addr + text.header.sh_offset
                        xrefs += [ { "offset": offset, "length": insn.size } ]
                        log.info("{:#x}: bl {:s}@plt (offset = {:d})".format(insn.address, callname, offset))

        return xrefs



class MIPS(Arch):
    pass


def find_call(cfg, callname):
    elf = cfg.elf
    cs = cfg.cs
    arch = cfg.arch
    path = cfg.original_filename
    log.info("looking for '{}' calls in '{}'".format(callname, path))

    call_got = arch.get_call_got(cfg)
    if not call_got:
        log.error("No GOT entry for '{}'".format(callname))
        return []

    log.debug("{}@got = {:#x}".format(callname, call_got))

    call_plt = arch.get_call_plt(cfg, call_got)
    if not call_plt:
        log.error("No PLT entry for '{}'".format(callname))
        return []

    log.debug("{}@plt = {:#x}".format(callname, call_plt))
    return arch.get_xrefs(cfg, call_plt)


def overwrite_xref(cfg, xref):
    from_file = cfg.original_filename
    to_file = cfg.patched_filename
    log.info("creating patched file: '{}' -> '{}'".format(from_file, to_file))
    shutil.copy2(from_file, to_file)
    with open(to_file, "rb+") as fd:
        for x in sorted(xref, key=lambda x: x["offset"]):
            fd.seek(x["offset"])
            l = x["length"]
            if cfg.asm:
                if len(cfg.asm) <= l:
                    fd.write(cfg.asm + cfg.nop*(l-len(cfg.asm)))
                    continue

                log.warning("Instruction too large (room_size={}, insn_len={}), using nop".format(l, len(cfg.asm)))

            if cfg.arch.__class__.__name__ in ("X86", "X64"):
                fd.write(cfg.nop*l)
            else:
                fd.write(cfg.nop)

        log.info("Successfully patched to file '{}'".format(to_file))
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage = __usage__, description = __desc__)
    parser.add_argument("-v", "--verbose", default=False, action="store_true", dest="verbose",
	                help="increments verbosity")
    parser.add_argument("--debug", default=False, action="store_true", dest="debug",
	                help="enable debugging messages")
    parser.add_argument("-c", "--call", dest="calls", nargs="+", default=["ptrace", "alarm"],
                        help="Specify the call to patch. Can be repeated (default : %(default)s)")
    parser.add_argument("--to-file", dest="to_file", default=None,
                        help="Patched binary name")
    parser.add_argument("-a", "--assembly", dest="asm", type=str, default=None,
                        help="Write ASSEMBLY instead of NOP")
    parser.add_argument("-L", "--list", dest="list_plt_entries", action="store_true", default=False,
                        help="Dumps the patchable locations from binary")
    parser.add_argument("binary", nargs="?", default="a.out",
                        help="specify the binary to patch (default: '%(default)s')")
    args = parser.parse_args()

    fmt = "%(asctime)-15s {0} - %(message)s".format(termcolor.colored("%(levelname)s",attrs=["bold"]))
    logging.basicConfig(format=fmt)

    if args.debug:
        log.setLevel(logging.DEBUG)
        log.debug("Debug mode enabled")
    else:
        log.setLevel(logging.INFO)

    if not os.access(args.binary, os.R_OK):
        log.critical("Cannot read '{}'".format(args.binary))
        sys.exit(1)

    from_file = args.binary
    to_file = "{}.patched".format(from_file) if args.to_file is None else args.to_file

    if os.access(to_file, os.R_OK):
        log.warning("'{}' already exists, it will be overwritten...".format(to_file))

    cfg = Config()
    cfg.original_filename = from_file
    cfg.patched_filename = to_file
    cfg.elf = elffile.ELFFile(open(cfg.original_filename, "rb"))

    if cfg.elf.header.e_machine == "EM_X86_64":
        cfg.arch = X64()
        log.info("Architecture -> x86-64")
        from capstone.x86 import *
        cfg.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64|capstone.CS_MODE_LITTLE_ENDIAN)
        cfg.cs.detail = True
        cfg.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64|keystone.KS_MODE_LITTLE_ENDIAN)
        cfg.nop = b"\x90" # nop

    elif cfg.elf.header.e_machine == "EM_386":
        cfg.arch = X86()
        log.info("Architecture -> x86-32")
        from capstone.x86 import *
        cfg.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32|capstone.CS_MODE_LITTLE_ENDIAN)
        cfg.cs.detail = True
        cfg.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32|keystone.KS_MODE_LITTLE_ENDIAN)
        cfg.nop = b"\x90" # nop

    elif cfg.elf.header.e_machine == "EM_ARM":
        cfg.arch = ARM()
        log.info("Architecture -> ARM")
        from capstone.arm import *
        cfg.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM|capstone.CS_MODE_LITTLE_ENDIAN)
        cfg.cs.detail = True
        cfg.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM|keystone.KS_MODE_LITTLE_ENDIAN)
        cfg.nop = b"\x00\x00\xa0\xe1" # mov r0, r0


    elif cfg.elf.header.e_machine == "EM_AARCH64":
        cfg.arch = AARCH64()
        log.info("Architecture -> AARCH64")
        from capstone.arm64 import *
        cfg.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM|capstone.CS_MODE_LITTLE_ENDIAN)
        cfg.cs.detail = True
        cfg.ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
        cfg.nop = b"\xe0\x03\x00\xaa" # mov x0, x0

    # TODO:
    # elif cfg.elf.header.e_machine == "EM_MIPS":
    #     cfg.arch = MIPS()

    else:
        raise NotImplementedError("Architecture '{}' not supported yet".format(cfg.elf.header.e_machine))


    if args.list_plt_entries:
        log.info("Dumping overwritable PLT entries:")
        for reloc in cfg.arch.get_relocs(cfg):
            sym = cfg.elf.get_section_by_name(".dynsym").get_symbol(reloc.entry.r_info_sym)
            log.info("{}()".format(sym.name))
        sys.exit(0)


    if args.asm:
        asm, cnt = cfg.ks.asm(args.asm)
        if cnt>0:
            cfg.asm = bytes(asm)
            log.info("Matching calls will be overwritten with '{}'".format(args.asm))
            log.debug("{} instruction(s) compiled".format(cnt))
    else:
        log.info("Matching calls will be overwritten with NOPs")


    for callname in args.calls:
        xref = find_call(cfg, callname)
        if xref:
            log.info("Found {} call(s) to '{}' in '{}', patching...".format(len(xref), callname, from_file))
            overwrite_xref(cfg, xref)
        else:
            log.warning("Something went wrong, not patching '{}' in '{}'".format(callname, from_file))

    sys.exit(0)
