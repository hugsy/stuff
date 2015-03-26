#
# IDA script to color execution flow from GDB logfile
#
# @_hugsy_
#


from idc import *
from idaapi import *

__PLUGIN_NAME__ = "GDBColorExecFlow"
__PLUGIN_DESCRIPTION__ = "Use GDB logfile to colorize execution flow in IDB"

HILIGHT_COLOR = 0x005500

def get_next_eip(fd):
	while True:
		data = fd.readline()
		if len(data) == 0: #EOF
			break

		if not data.startswith("0x"):
			continue

		eip = data.split(" ",1)[0]
		eip = int(eip, 0x10)

		yield eip


ea = ScreenEA()
srcFileName = GetSourceFile(ea)
logFileName = AskFile(0, "*.*", "Enter path to GDB logfile")

if logFileName is not None:
	with open(logFileName, "r") as fd:
		print ("[+] Executing '%s'" % __PLUGIN_NAME__)
		print ("[+] GDB logfile: %s" % logFileName)
		for instr_addr in get_next_eip(fd):
			if instr_addr < 0x100000000:
				SetColor( instr_addr, CIC_ITEM, HILIGHT_COLOR)
