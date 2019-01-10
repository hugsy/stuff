"""

Create a snapshot of all DLL/EXE/drivers

"""


import glob, os

import IdaAutoAnalyze

DIRS = [
    r'C:\Windows\System32',
    r'C:\Windows\System32\drivers',
]

EXTS = [
    "*.dll",
    "*.exe",
    "*.sys",
]


for d in DIRS:
    for e in EXTS:
        pat = os.sep.join([d, e])
        for f in glob.glob(pat):
            IdaAutoAnalyze.auto_analyze_file(f)
