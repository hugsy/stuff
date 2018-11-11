#!/usr/bin/env python2

import sys
import uuid
import struct

def u32(x): return struct.unpack("<I", x)


fname = sys.argv[1]
data = open(fname, "rb").read()
idx = data.find("RSDS")
if idx == -1:
    sys.exit(-1)

magic = data[idx:idx+4] # RSDS
idx+= 4

guid = uuid.UUID(bytes_le=data[idx:idx+0x10])
idx += 0x10

version = u32(data[idx:idx+4])
idx+= 4

pdb = data[idx: idx+data[idx:].find("\x00")]

print("RSDS = '%s'" % magic)
print("Version = %d" % version)
print("PDB = '%s'" % pdb)
print("GUID = '%s'" % str(guid))
