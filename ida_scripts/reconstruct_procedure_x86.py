"""
This IDA simple script will look for function prolog sequence for x86 binaries
i.e. (in intel syntax)

push ebp
mov ebp, esp

And will make IDA treat it as a procedure.

@_hugsy_
"""

from idc import *
from idaapi import *
import idautils

prolog_sequence = "\x55\x89\xe5"

for seg in idautils.Segments():
    print seg
    if seg == ".text":
        found = True
        break

if found:
    addr = seg
    # DecodeInstruction
