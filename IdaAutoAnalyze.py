"""

Batch run IDA

Requires:
 - python-magic
 - python-magic-bin (WIN)

"""

from __future__ import print_function

import glob
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

import magic


IDA_BIN = "ida.exe"
IDA64_BIN = "ida64.exe"
IDA_PATH = os.sep.join(["C:", "Program Files", "IDA 7.1"])
IDB_PATH = os.sep.join(["Y:", "IDBs"])



def generate_idb_file(src, ida_path=IDA_BIN, idb_path=IDB_PATH):

    external_scripts = [
        r'w:\win\IDA\plugins\diaphora\diaphora.py',
    ]


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

    #
    # run IDA
    #
    # https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
        #

    os.environ["DIAPHORA_AUTO"] = "1"
    os.environ["DIAPHORA_EXPORT_FILE"] = idb_with_hash.replace(ext2, ".sqlite")


    # ida in batch mode
    cmd = [ida_path, "-B"]

    # add the scripts
    for s in external_scripts:
        cmd.append("-S{}".format(s))

    # log
    logfile = idb_with_hash.replace(ext2, ".log")
    cmd.append("-L{}".format(logfile))

    # add the target
    cmd.append(dst)

    # run ida
    retcode = subprocess.call(cmd)

    # include sha1 in filename
    os.rename(idb, idb_with_hash)


    #
    # cleanup
    #
    print("[+] Cleanup")

    os.unlink(dst)
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


def auto_analyze_file(f):
    ida = guess_ida_from_file(f)
    return generate_idb_file(f, ida)


if __name__ == "__main__":
    auto_analyze_file( sys.argv[1] )
    sys.exit(0)