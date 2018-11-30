#!/usr/bin/env python2.7 -tt
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


def copy_to_clipboard(addr):
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


def get_rva():
    rva = here() - idaapi.get_imagebase()
    return rva


def copy2clip():
    copy_to_clipboard( get_rva() )
    return


def enable_shortcut():
    idaapi.CompileLine('static copy2clip() { RunPythonStatement("copy2clip()"); }')
    idc.AddHotkey(PLUGIN_HOTKEY, "copy2clip")
    return


def PLUGIN_ENTRY():
    enable_shortcut()
    print("[+] Press '{:s}' to copy RVA to clipboard".format(PLUGIN_HOTKEY))
    return

if __name__ == "__main__":
    PLUGIN_ENTRY()
