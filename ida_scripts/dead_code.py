from idaapi import *

__PLUGIN_NAME__ = "DeadCode"

for func in Functions():
    if func is None:
        continue
        
    fname = Name(func)
    
    xref_num = 0
    for i in XrefsTo(func, 0) :
        xref_num += 1
    if xref_num == 0:
        Message("[%s] %s (%#x) has no Xref\n" % (__PLUGIN_NAME__, fname, func))
