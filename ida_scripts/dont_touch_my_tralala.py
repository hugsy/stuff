from idaapi import *

danger_funcs = ["strcpy", "sprintf", "strncpy", "gets", "system"]

for func in danger_funcs:
    print ("Searching for `%s`" % func)
    for a,f in Names():
        if func in f:
            xrefs = CodeRefsTo( a, False )
            print ("Cross References to `%s` (%#x)" % (f, a))
            print ("-------------------------------")
            for xref in xrefs:
                print ("Got Xref at %#x" % xref)
                SetColor( xref, CIC_ITEM, 0x0000ff)
