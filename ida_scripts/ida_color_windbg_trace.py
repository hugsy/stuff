#
# color execution flow from windbg logfile
#
# in windbg
# 0:000> bp 0xStartAdress
# 0:000> .logopen c:\temp\myapp.log
# 0:000> pa 0xEndAddress
# 0:000> .logclose
#
# note: watch out for aslr
#

from idc import *
from idaapi import *

__PLUGIN_NAME__ = "ColorExecFlow"
__PLUGIN_DESCRIPTION__ = "Use WinDBG logfile to colorize execution flow in IDB"

HILIGHT_COLOR = 0xe9967a

def get_next_eip(fd):
	while True:
		data = fd.readline()
		if len(data) == 0: #EOF
			break

		if not data.startswith("eip="):
			continue

		eip = data.split(" ")[0].replace("eip=", "")
		eip = int(eip, 0x10)

		yield eip


ea = ScreenEA()
srcFileName = GetSourceFile(ea)
logFileName = AskFile(0, "*.*", "Enter path to WinDBG logfile")

if logFileName is not None:
	with open(logFileName, "r") as fd:
		print ("[+] Executing '%s'" % __PLUGIN_NAME__)
		print ("[+] WinDBG logfile: %s" % logFileName)
		for instr_addr in get_next_eip(fd):
			if instr_addr < 0x100000000:
				SetColor( instr_addr, CIC_ITEM, HILIGHT_COLOR)

