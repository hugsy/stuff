"""
This simple script for IDA will look for function prolog sequence for x86 binaries
i.e. (in Intel syntax)

push ebp
mov ebp, esp

And will make IDA treat it as a procedure.

@_hugsy_
"""

import idc
import idaapi
import sys
import idautils


hilight_color = 0x009900
prolog_sequence = "55 89 e5"
ea = idc.ScreenEA()
addr = idc.SegStart(ea)
print "[!] Analyzing from %#x" % addr

while True:
    res = idc.FindBinary(addr, idaapi.BIN_SEARCH_FORWARD, prolog_sequence, 16)
    if res == idaapi.BADADDR:
        break

    func = idc.GetFuncOffset(res)
    if func is not None:
        print "[*] %#x already matching function %s" % (res, func)
    else:
        print "[+] Matching at %#x" % res
        idc.Jump(res)
        col = idc.GetColor(res, idc.CIC_ITEM)
        idc.SetColor(res, idc.CIC_ITEM, hilight_color)
        idc.SetColor(res + 1, idc.CIC_ITEM, hilight_color)

        ret = idc.AskYN(0, "Would you like to create a function at %#x ?" % res)
        if ret == 1:
            idc.MakeFunction(res)
            print "[+] Creating function at %#x" % res

        idc.SetColor(res, idc.CIC_ITEM, col)
        idc.SetColor(res + 1, idc.CIC_ITEM, col)

    addr = res + len(prolog_sequence)

print "[!] EOT"
