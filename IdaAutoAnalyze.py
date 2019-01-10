"""

Batch run IDA

Requires:
 - python-magic
 - python-magic-bin (WIN)

TODO:
 - use configparser
"""

from __future__ import print_function

import configparser
import glob
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

import magic

HOMEDIR = os.sep.join([os.environ["HOMEDRIVE"], os.environ["HOMEPATH"]])
cfg = configparser.ConfigParser(
    defaults={"HOME": HOMEDIR},
    allow_no_value=True
)
cfg.read(os.sep.join([HOMEDIR, "IdaAutoAnalyze.cfg"]))

IDA_BIN = "ida.exe"
IDA64_BIN = "ida64.exe"
IDA_PATH = cfg.get("IDA", "ida_path")
IDB_PATH = cfg.get("IDA", "idb_path")



def generate_idb_file(src, ida_path=IDA_BIN, idb_path=IDB_PATH):

    external_scripts = cfg.get("Scripts", "scripts").splitlines()


    #
    # init
    #

    dst = os.sep.join([idb_path, os.path.basename(src)])

    print("[+] Generating IDB file from '{}' in '{}'...".format(src, idb_path))

    shutil.copy(src, dst)

    ext = os.path.splitext(dst)[-1]

    if ida_path.endswith("ida64.exe"):
        ext2 = ".i64"
    else:
        ext2 = ".idb"


    idb = dst + ext2
    _hash = hashlib.sha1( open(src, "rb").read() ).hexdigest()
    idb_with_hash = idb.replace(ext2, "-{}{}".format(_hash, ext2))
    dst_with_hash = dst.replace(ext, "-{}{}".format(_hash, ext))

    if os.access(idb_with_hash, os.R_OK):
        return 0

    os.rename(dst, dst_with_hash)

    #
    # run IDA
    #
    # https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
    #

    os.environ["DIAPHORA_AUTO"] = "1"
    os.environ["DIAPHORA_EXPORT_FILE"] = dst_with_hash.replace(ext, ".sqlite")


    # ida in batch mode
    cmd = [ida_path, "-B"]

    # add the scripts
    for s in external_scripts:
        cmd.append("""-S"{}" """.format(s))

    # log
    logfile = dst_with_hash.replace(ext, ".log")
    cmd.append("-L{}".format(logfile))

    # add the target
    cmd.append(dst_with_hash)

    # run ida
    retcode = subprocess.call(cmd)


    #
    # cleanup
    #
    print("[+] Cleanup")

    os.unlink(dst_with_hash)
    # os.unlink(dst + ".asm")
    try:
        os.unlink(os.sep.join([idb_path, "pingme.txt"]))
        for p in glob.glob(os.sep.join([idb_path, "*.pdb"])):
            shutil.rmtree(p)
    except:
        pass

    if retcode == 0:
        os.unlink(logfile)
        print("[+] Success")
    else:
        print("[-] An error occured, retcode={}".format(retcode))

    return retcode


def guess_ida_from_file(src):
    try:
        if "x86-64" in magic.from_file(src):
            return os.sep.join([IDA_PATH, IDA64_BIN])
    except:
        pass
    return os.sep.join([IDA_PATH, IDA_BIN])


def auto_analyze_file(f, idb):
    ida = guess_ida_from_file(f)
    return generate_idb_file(f, ida, idb)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)

    src = sys.argv[1]
    idb_path = sys.argv[2] if len(sys.argv) > 2 else IDB_PATH
    auto_analyze_file(src, idb_path)
    sys.exit(0)