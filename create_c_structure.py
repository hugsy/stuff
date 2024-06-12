#!/usr/bin/env python3

import sys

"""
stupid script to generate IDA structure the way I like
"""


name = sys.argv[1]
size = int(sys.argv[2],0)
ptrsize = int(sys.argv[3]) if len(sys.argv) == 4 else 8
struct_name = name.upper()

while struct_name.startswith("_"):
    struct_name = struct_name.lstrip("_")

print("""#pragma pack(1)""")
print(f"typedef struct _{struct_name} {{")
for idx, offset in enumerate(range(0, size, ptrsize)):
    print(f"    /* {offset:04x} */  ULONG_PTR field_{offset:x};")
print(f"}} {struct_name}, *P{struct_name};")

print(f"static_assert( sizeof({struct_name}) == {size:#x});")
