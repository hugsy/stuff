#!/usr/bin/env python2

import sys, pefile

name = sys.argv[1]
print("Listing IMPORT table for '{:s}'".format(name))
pe = pefile.PE(name, fast_load=False)

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('[+] {:s}'.format(entry.dll))
    for imp in entry.imports:
        print ('\t{:#x} : {:s}'.format(imp.address, imp.name))
