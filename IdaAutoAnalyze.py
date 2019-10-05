"""

Batch run IDA

Requires:
 - python-magic
 - python-magic-bin (WIN)

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
import datetime

import magic

HOMEDIR = os.sep.join([os.environ["HOMEDRIVE"], os.environ["HOMEPATH"]])
TEMPDIR = os.environ["TEMP"]
cfg = configparser.ConfigParser(
    defaults={"HOME": HOMEDIR, "TEMP": TEMPDIR},
    allow_no_value=True
)
cfg.read(os.sep.join([HOMEDIR, "IdaAutoAnalyze.cfg"]))

IDA_BIN = "ida.exe"
IDA64_BIN = "ida64.exe"
IDA_PATH = cfg.get("IDA", "ida_path")
IDB_PATH = cfg.get("IDA", "idb_path")
LOG_FILE = cfg.get("IDA", "log_file") or ".\\IdaAutoAnalyze.log"


def log(x):
    with open(LOG_FILE, "a+") as f:
        now = datetime.datetime.now()
        msg = "{:s} {:s}".format(now.strftime("%F"), x)
        print(msg)
        f.write(msg + os.linesep)
    return


def run_ida(ida_exe_path, source_file, idb_file, log_file):
    """
    Run IDA headlessly on the source file, and execute the scripts.
    Refs:
    - https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
    """

    # ida in batch mode
    cmd = [
        ida_exe_path,
        "-A",
        "-B",
        "-c",
        #'-o"{}"'.format(idb_file),
        #'-L"{}"'.format(log_file),
        source_file
    ]
    log("[+] Running '%s'" % cmd)
    res = subprocess.call(cmd)
    return res


def run_ida_scripts_on_idb(ida_exe_path, idb_file):
    """
    Executes scripts on the IDB file
    """
    idb_file_name, idb_file_ext = os.path.splitext( idb_file )
    external_scripts = cfg.get("Scripts", "scripts").splitlines()

    os.environ["DIAPHORA_AUTO"] = "1"
    os.environ["DIAPHORA_EXPORT_FILE"] = ".".join([idb_file_name, "sqlite"])

    # ida in batch mode
    cmd = [ida_exe_path, "-B"]

    # add the scripts
    for script_path in external_scripts:
        cmd.append('-S"{}"'.format(script_path))

    cmd.append(idb_file)

    return subprocess.call(cmd)


def cleanup():
    """
    Cleanup symbols downloaded by IDA
    """
    try:
        fname = os.sep.join([IDB_PATH, "pingme.txt"])
        os.unlink(fname)
        log("deleted '{}'".format(fname))
    except:
        pass

    for f in glob.glob(os.sep.join([IDB_PATH, "*.asm"])):
        try:
            os.unlink(f)
            log("deleted '{}'".format(f))
        except:
            pass

    for d in glob.glob(os.sep.join([IDB_PATH, "*.pdb"])):
        shutil.rmtree(d)
        log("deleted '{}'".format(d))

    return 0


def guess_ida_from_file(src):
    try:
        if "x86-64" in magic.from_file(src):
            return os.sep.join([IDA_PATH, IDA64_BIN])
    except:
        pass
    return os.sep.join([IDA_PATH, IDA_BIN])


def rename_idb_with_hash(source_file, idb_file):
    idb_file_name, idb_file_ext = os.path.splitext( idb_file )
    digest = hashlib.md5( open(source_file, "rb").read() ).hexdigest()
    new_idb_file_name = "".join([idb_file_name, "-", digest, idb_file_ext])
    try:
        os.rename(idb_file, new_idb_file_name)
    except Exception as e:
        log("[-] Got exception when renaming: {}'".format(str(e)))
        return None
    return new_idb_file_name


def generate_idb_filename(source_file, is_ida64):
    """
    Generates IDB full path (\path\source_filename.(ida,i64))
    @param `source_file` is the file in the IDB_PATH directory
    @param `is_ida64`
    @return a tuple with (idb_fullpath, log_fullpath)
    """
    source_file_basename = source_file #os.path.basename(source_file)
    target_ext = "i64" if is_ida64 else "idb"
    target_file_path = ".".join([source_file_basename, target_ext])
    target_log_path = ".".join([source_file_basename, "log"])
    return (target_file_path, target_log_path)


def auto_analyze_file(source_file):
    ida = guess_ida_from_file(source_file).lower()

    if not os.access(ida, os.R_OK):
        log("[-] Invalid IDA path: {}".format(ida))
        return 1

    # copy the source file to writable location
    shutil.copy(source_file, IDB_PATH)
    source_file = os.sep.join([IDB_PATH, os.path.basename(source_file)])
    if not os.access(source_file, os.R_OK):
        log("[-] Failed to copy '{}'".format(source_file))
        return 1

    if ida.endswith("ida64.exe"):
        log("[+] Using IDA64 ('{}')...".format(ida))
        idb_filepath, log_filepath = generate_idb_filename(source_file, True)
    else:
        log("[+] Using IDA ('{}')...".format(ida))
        idb_filepath, log_filepath = generate_idb_filename(source_file, False)

    res = run_ida(ida, source_file, idb_filepath, log_filepath)
    if res != 0:
        log("[-] IDA execution failed: retcode={}, check logs in '{}'".format(res, log_filepath))
        return 1

    idb_filepath = rename_idb_with_hash(source_file, idb_filepath)
    if idb_filepath is None:
        return 1

    log("[+] IDB created as '{}'...".format(idb_filepath))

    # cleanup
    os.unlink(source_file)
    os.unlink(log_filepath)
    cleanup()

    # scripts
    log("[+] running extra script(s) on '{}'...".format(idb_filepath))
    run_ida_scripts_on_idb(ida, idb_filepath)

    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)

    res = auto_analyze_file(sys.argv[1])
    log("{:s} returned {:d}".format(sys.argv[0], res))
    sys.exit(res)
