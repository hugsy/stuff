#!/usr/bin/env python3

import sys

"""
stupid script to generate IDA structure the way I like
"""


name = sys.argv[1]
size = int(sys.argv[2],0)
ptrsize = int(sys.argv[3]) if len(sys.argv) == 4 else 8
struct_name = name.upper()
print("""#pragma pack(1)""")
print("""typedef struct _{} {{""".format(struct_name))
for idx, offset in enumerate(range(0, size, ptrsize)):
    print("    /* {0:04x} */  ULONG_PTR field_{0:x};".format(offset,))
print("""}} {0}, *P{0};""".format(struct_name))
