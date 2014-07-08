from idaapi import *

# sprintf
# func = ".sprintf"
# addr = LocByName( func )
# if addr != BADADDR:
    # for xref in XrefsTo( addr, False ):
        # print ("[+] Xref to `%s` (%#x) at %#x" % (func, addr, xref.frm))

        # # try to find last uses rsi
        # ea = xref.frm
        # for _ in xrange(10):
            # print DecodePrecedingInstruction(ea).get_canon_mnem()


func = ".printf"
addr = LocByName( func )
if addr != BADADDR:
    for xref in XrefsTo( addr, False ):
        print ("[+] Xref to `%s` (%#x) at %#x" % (func, addr, xref.frm))

        (decodedInstruction, farref) = DecodePrecedingInstruction(xref.frm)
        
        print GetDisasm(decodedInstruction.ea)

