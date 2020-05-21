#!/usr/bin/env python3
# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
Send RVA to clipboard in a WinDBG compatible format

0.2 Python3 (IDA >= 7.4)
0.1 Python2 (IDA <= 7.3)
"""

import os, tkinter

import idaapi, idc
import ida_expr


PLUGIN_NAME = "CopyRva"
PLUGIN_HOTKEY = "Ctrl-Alt-H"
PLUGIN_VERSION = "0.2"
PLUGIN_AUTHOR = "@_hugsy_"


class CopyRvaPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Quickly copy to clipboard the position of the cursor in IDA Pro"
    help = "Quickly copy to clipboard the position of the cursor in IDA Pro"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY


    def __init__(self):
        self.enable_shortcut()
        print("[+] Press '{:s}' to copy RVA to clipboard".format(PLUGIN_HOTKEY))
        return


    def copy_to_clipboard(self, addr):
        print("foio")
        name = os.path.splitext(idc.GetInputFile())[0]
        f = "{:s}+{:x}".format(name, addr)
        r = tkinter.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append("{:s}".format(f))
        r.update()
        r.destroy()
        print("[+] Copied {:s}".format(f))
        return


    def get_rva(self):
        ea = idc.get_screen_ea()
        base = idaapi.get_imagebase()
        rva = ea - base
        return rva


    def copy2clip(self):
        self.copy_to_clipboard( self.get_rva() )
        return


    def enable_shortcut(self):
        # idaapi.CompileLine('static copy2clip() { RunPythonStatement("copy2clip()"); }') # < 7.4 only
        ida_expr.compile_idc_text('static copy2clip() { RunPythonStatement("copy2clip()"); }') # >= 7.4 only
        #idc.AddHotkey(PLUGIN_HOTKEY, "copy2clip") # < 7.4
        ida_kernwin.add_idc_hotkey(PLUGIN_HOTKEY, "copy2clip") # >= 7.4 only
        return


    def run(self, arg=0):
        return


    def term(self):
        return



def PLUGIN_ENTRY():
    return CopyRvaPlugin()


if __name__ == "__main__":
    PLUGIN_ENTRY()

