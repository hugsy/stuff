# x64 abi fast calling convention
# http://msdn.microsoft.com/en-us/library/ms235286.aspx
#
from idautils import *
from idc import *

def get_register_index(regs, reg):
    for i in regs.keys():
        if reg.endswith(i):
            return i
    return None

def dereference_register(ea, reg):
    return GetReg(ea, reg)

ea = ScreenEA()

for func in Functions(SegStart(ea), SegEnd(ea)):
    regs = {
        "di" : None,
        "si" : None,
        "dx" : None,
        "cx" : None,
        "r8" : None,
        "r9" : None,
    }
    
    name = GetFunctionName(func)
    for item in list(FuncItems(func)):
        # opc = GetDisasm(item)
        mnem = GetMnem(item)
        if mnem == "call":
            called_funcname = GetOpnd(item, 0)
            args = ""
            for i in regs.keys():
                if regs[i] is not None:
                    args+= "%s, " % regs[i]
                    regs[i] = None
            MakeComm(item, "%s ( %s )" % (called_funcname, args[:-2]))

        elif mnem == "mov":
            dst = GetOpnd(item, 0)
            src = GetOpnd(item, 1)
            # src = int(GetOperandValue(item, 1))
                
            idx = get_register_index(regs, dst)
            if idx is None:
                continue
            
            regs[idx] = src
            MakeComm(item, "$%s = %s;" % (dst, src))

        elif mnem == "xor":
            dst = GetOpnd(item, 0)
            src = GetOpnd(item, 1)

            if dst != src:
                MakeComm(item, "$%s = %s ^ %s;" % (dst, dst, src))
            else:
                MakeComm(item, "$%s = 0;" % (dst))

        elif mnem == "cmps":
            args = "%s, %s, %s" % (regs["di"], regs["si"], regs["cx"])
            MakeComm(item, "strcmp( %s )" % args)


Refresh()
