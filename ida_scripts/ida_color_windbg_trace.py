"""
IDA script to color execution flow, i.e. highlight all instructions taken by runtime
from a WinDBG log file.

In WinDBG, generate a trace log with the following sequence:
0:000> bp 0xStartAdress
0:000> .logopen c:\temp\myapp.log
0:000> pa 0xEndAddress
0:000> .logclose

Note: watch out for aslr

@_hugsy_
"""

from idc import *
from idaapi import *

__PLUGIN_NAME__ = "ColorExecFlow"
__PLUGIN_DESCRIPTION__ = "Use WinDBG logfile to colorize execution flow in IDB"

HILIGHT_COLOR = 0xaa0000

def get_next_eip(fd, module):
	while True:
		data = fd.readline()
		if len(data) == 0: #EOF
			break

		if not data.startswith("%s!" % module): continue
		data = data.strip().replace(":", "")

		mod, func = data.split("!")
		if module != mod:
			continue
		if "+" in func:
			func_name, offset = func.split("+")
			offset = int(offset, 16)
		else:
			func_name, offset = func, 0

		addr = idc.get_name_ea_simple(func_name)
		addr += offset
		yield addr


ea = idc.here()
#srcFileName = GetSourceFile(ea)
logFileName = ida_kernwin.ask_file(0, "*.*", "Enter path to WinDBG logfile")

if logFileName is not None:
	with open(logFileName, "r") as fd:
		print ("[+] Executing '%s'" % __PLUGIN_NAME__)
		print ("[+] WinDBG logfile: %s" % logFileName)
		for instr_addr in get_next_eip(fd, "tcpip"):
			#if instr_addr < 0x100000000:
			#addr = idc.get_name_ea_simple(instr_addr)
			print(hex(instr_addr))
			idc.set_color( instr_addr, CIC_ITEM, HILIGHT_COLOR)

