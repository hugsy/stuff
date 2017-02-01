#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86 import *

def find_call(path, callname):
    print('[*] open: %s' % path)
    elf = ELFFile(open(path, 'rb'))

    if elf.header.e_machine == 'EM_X86_64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif elf.header.e_machine == 'EM_386':
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        raise Exception("Unsupported arch")

    md.detail = True

    relx_plt = elf.get_section_by_name('.rela.plt') or elf.get_section_by_name('.rel.plt')
    dynsym = elf.get_section_by_name('.dynsym')
    for reloc in relx_plt.iter_relocations():
        symbol = dynsym.get_symbol(reloc.entry.r_info_sym)
        if symbol.name == callname:
            call_got = reloc.entry.r_offset
            break
    print('[+] %s@got = %#x' % (callname, call_got))

    plt = elf.get_section_by_name('.plt')
    for insn in md.disasm(plt.data(), plt.header.sh_addr):
        if insn.mnemonic == 'jmp':
            value = None
            for op in insn.operands:
                if op.type == X86_OP_MEM:
                    if insn.reg_name(op.mem.base) == 'rip' and op.mem.index == 0:
                        value = insn.address + insn.size + op.mem.disp
                    elif op.mem.base == 0 and op.mem.index == 0:
                        value = op.mem.disp
            if value == call_got:
                call_plt = insn.address
    print('[+] %s@plt = %#x' % (callname, call_plt))

    xref = []
    text = elf.get_section_by_name('.text')
    for insn in md.disasm(text.data(), text.header.sh_addr):
        if insn.mnemonic == 'call':
            for op in insn.operands:
                value = None
                if op.type == X86_OP_IMM:
                    value = op.imm
                if value == call_plt:
                    offset = insn.address - text.header.sh_addr + text.header.sh_offset
                    xref += [ { 'offset': offset, 'length': insn.size } ]
                    print('[*] %#x: call alarm@plt  (offset = %d)' % (insn.address, offset))
    return xref

def overwrite_with_nop(path, xref):
    print('[*] overwrite: %s' % path)
    with open(path+'.patched', 'rb+') as fh:
        for it in sorted(xref, key=lambda it: it['offset']):
            fh.seek(it['offset'] - fh.tell())
            fh.write(b'\x90' * it['length'])
    print('[+] done')


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('path', nargs='?', default='a.out')
    args = parser.parse_args()

    xref = find_call(args.path, "alarm")
    overwrite_with_nop(args.path, xref)

if __name__ == '__main__':
    main()
