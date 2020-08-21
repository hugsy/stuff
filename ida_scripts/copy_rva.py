#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
Send RVA to clipboard in a WinDBG compatible format

0.3 Fixed broken behavior
0.2 Python3 (IDA >= 7.4)
0.1 Python2 (IDA <= 7.3)
"""

import os, tkinter
from tkinter.constants import FALSE
import idaapi, idc
import ida_expr, ida_kernwin, ida_nalt

ida_version_below_74 = idaapi.get_kernel_version() < "7.4"

PLUGIN_NAME = "CopyRva"
PLUGIN_HOTKEY = "Ctrl-Alt-H"
PLUGIN_VERSION = "0.3"
PLUGIN_AUTHOR = "@_hugsy_"


def get_rva() -> int:
    ea = idc.get_screen_ea()
    base = idaapi.get_imagebase()
    rva = ea - base
    return rva


def get_filename() -> str:
    if ida_version_below_74:
        return idc.GetInputFile()
    return ida_nalt.get_root_filename()


def copy_ea_to_clipboard() -> bool:
    try:
        addr = get_rva()
        name = os.path.splitext( get_filename() )[0]
        f = "{:s}+{:x}".format(name, addr)
        r = tkinter.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append("{:s}".format(f))
        r.update()
        r.destroy()
        print("[+] Copied {:s}".format(f))
    except Exception as e:
        print("[-] Exception: {}".format(e))
        return False
    return True


class CopyRvaPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Quickly copy to clipboard the position of the cursor in IDA Pro"
    help = "Copy the position of the cursor in IDA Pro to clipboard in a WinDbg friendly format"
    wanted_name = PLUGIN_NAME
    # wanted_hotkey = PLUGIN_HOTKEY

    def __init__(self) -> None:
        if ida_version_below_74:
            idaapi.CompileLine('static send_ea_to_clipboard() { RunPythonStatement("copy_ea_to_clipboard()"); }')
            idc.AddHotkey(PLUGIN_HOTKEY, "send_ea_to_clipboard")
        else:
            ida_expr.compile_idc_text('static send_ea_to_clipboard() { RunPythonStatement("copy_ea_to_clipboard()"); }')
            ida_kernwin.add_idc_hotkey(PLUGIN_HOTKEY, "send_ea_to_clipboard")

        print("[+] Press '{:s}' to copy RVA to clipboard".format(PLUGIN_HOTKEY))
        return

    def run(self, arg=0) -> None:
        return

    def term(self) -> None:
        return


def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return CopyRvaPlugin()


if __name__ == "__main__":
    PLUGIN_ENTRY()

