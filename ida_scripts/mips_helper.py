#
# Cavium Octeon MIPS64r2 N32 helper
#
# Basic reconstruction of calls (positionning arguments)
#
# https://msdn.microsoft.com/en-us/library/ms253512(v=vs.90).aspx
#
#
from idautils import *
from idc import *

# from gef
regs = {"$zero": None,
        "$v0": None,
        "$v1": None,

        "$a0": None,
        "$a1": None,
        "$a2": None,
        "$a3": None,
        "$a4": None,

        "$t0": None,
        "$t1": None,
        "$t2": None,
        "$t3": None,
        "$t4": None,
        "$t5": None,
        "$t6": None,
        "$t7": None,

        "$s0": None,
        "$s1": None,
        "$s2": None,
        "$s3": None,
        "$s4": None,
        "$s5": None,
        "$s6": None,
        "$s7": None,
        "$s8": None,

        "$t8": None,
        "$t9": None,
        "$k0": None,
        "$k1": None,
}

func_arg_regs = dict( [(i, regs[i]) for i in regs.keys() if i.startswith("$a") ])



def parse_current_function(ea):
    ea_off = GetFuncOffset(ea)
    if '+' not in ea_off:
        print("[-] Failed to get offset")
        return

    off = long(ea_off.split('+')[1], 16)
    start_addr = ea - off
    name = GetFunctionName(start_addr)
    previous_item = None
    is_previous_a_jump = False

    print("[+] Parsing function '%s()' [%#x]" % (name, start_addr))

    for item in FuncItems(start_addr):
        mnem = GetMnem(item)

        if mnem in ("jal", "jalr"):
            is_previous_a_jump = True
            previous_item = item
            continue

        elif mnem in ("move", "li", "la", "lui"):
            dst = GetOpnd(item, 0)
            src = GetOpnd(item, 1)

            if src == "$zero":
                src = "0"

            regs[dst] = src
            MakeComm(item, "%s = %s;" % (dst, src))

        elif mnem == "beqz":
            cond = GetOpnd(item, 0)
            target = GetOpnd(item, 1)
            MakeComm(item, "if (%s == 0) jump to %s;" % (cond, target))

        elif mnem in ("blez", "bltz"):
            cond = GetOpnd(item, 0)
            target = GetOpnd(item, 1)
            MakeComm(item, "if (%s %s 0) jump to %s;" % (cond, "<=" if mnem=="blez" else "<", target))

        elif mnem in ("bgez", "bgtz"):
            cond = GetOpnd(item, 0)
            target = GetOpnd(item, 1)
            MakeComm(item, "if (%s %s 0) jump to %s;" % (cond, ">=" if mnem=="bgez" else ">", target))

        if is_previous_a_jump:
            # mips pipelining can allow to have an argument being set after the
            # call to jal / jalr
            called_funcname = GetOpnd(previous_item, 0)
            args = ", ".join( [regs[i] for i in func_arg_regs.keys() if regs[i] is not None] )
            MakeComm(previous_item, "%s (%s)" % (called_funcname, args))

            for i in func_arg_regs.keys():
                # reset argument registers
                regs[i] = None

            previous_item = None
            is_previous_a_jump = False

    return


ea = ScreenEA()
parse_current_function(ea)
Refresh()
