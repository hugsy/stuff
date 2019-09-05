#!/usr/bin/env python2.7
# -*- mode: python -*-
# -*- coding: utf-8 -*-

"""
Send RVA to clipboard in a WinDBG compatible format
"""

import os, Tkinter
import idaapi, idc

PLUGIN_NAME = "CopyRva"
PLUGIN_HOTKEY = "Ctrl-Alt-H"
PLUGIN_VERSION = "0.1"
PLUGIN_AUTHOR = "@_hugsy_"


class CopyRvaPlugin(idaapi.plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "Quickly copy to clipboard the position of the cursor in IDA Pro"
    help = "Quickly copy to clipboard the position of the cursor in IDA Pro"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY


    def init(self):
        self.enable_shortcut()
        print("[+] Press '{:s}' to copy RVA to clipboard".format(PLUGIN_HOTKEY))
        return


    def copy_to_clipboard(self, addr):
        name = os.path.splitext(idc.GetInputFile())[0]
        f = "{:s}+{:x}".format(name, addr)
        r = Tkinter.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append("{:s}".format(f))
        r.update()
        r.destroy()
        print("[+] Copied {:s}".format(f))
        return


    def get_rva(self):
        ea = idc.ScreenEA()
        base = idaapi.get_imagebase()
        rva = ea - base
        return rva


    def copy2clip(self):
        self.copy_to_clipboard( self.get_rva() )
        return


    def enable_shortcut(self):
        idaapi.CompileLine('static copy2clip() { RunPythonStatement("copy2clip()"); }')
        idc.AddHotkey(PLUGIN_HOTKEY, "copy2clip")
        return


    def run(self, _=0):
        pass


    def term(self):
        pass



def PLUGIN_ENTRY():
    return CopyRvaPlugin()

