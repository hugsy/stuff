################################################################################
# gef - GDB Enhanced Features
#
# Tested on
# * x86-32/x86-64
# * arm-32/arm-64
# * mipsel
# * powerpc
# * sparc
#
# @_hugsy_
#
# tested on gdb 7.x / python 2.6 & 2.7
#
# to use: in gdb, type `source /path/to/gef.py'
#
#
# todo:
# - add autocomplete w/ gef args
# - add explicit actions for flags (jumps/overflow/negative/etc)
# - add ROPGadget support
# -
#
# todo commands:
# - patch N bytes in mem (\xcc, \x90, )
# - finish FormatStringSearchCommand
# -
#
# todo arch:
# * sparc64
# *
#
import cStringIO
import itertools
import math
import struct
import subprocess
import functools
import sys
import re
import tempfile
import os
import binascii

import gdb

class GefMissingDependencyException(Exception):
    def __init__(self, value):
        self.message = value
        return

    def __str__(self):
        return repr(self.message)


# https://wiki.python.org/moin/PythonDecoratorLibrary#Memoize
class memoize(object):
    """Custom Memoize class with resettable cache"""

    def __init__(self, func):
        self.func = func
        self.is_memoized = True
        self.cache = {}
        return

    def __call__(self, *args):
        if args not in self.cache:
            value = self.func(*args)
            self.cache[args] = value
            return value
        return self.func(*args)

    def __repr__(self):
        return self.func.__doc__

    def __get__(self, obj, objtype):
        fn = functools.partial(self.__call__, obj)
        fn.reset = self._reset
        return fn

    def reset(self):
        self.cache = {}
        return


def reset_all_caches():
    for s in dir(sys.modules['__main__']):
        o = getattr(sys.modules['__main__'], s)
        if hasattr(o, "is_memoized") and o.is_memoized:
            o.reset()
    return


# let's get fancy
class Color:
    NORMAL         = "\x1b[0m"
    RED            = "\x1b[31m"
    GREEN          = "\x1b[32m"
    YELLOW         = "\x1b[33m"
    BLUE           = "\x1b[34m"
    BOLD           = "\x1b[1m"
    UNDERLINE      = "\x1b[4m"

# helpers
class Address:
    pass


class Section:
    page_start      = None
    page_end        = None
    offset          = None
    permission      = None
    inode           = None
    path            = None


class Zone:
    name              = None
    zone_start        = None
    zone_end          = None
    filename          = None


class Elf:
    e_magic           = None
    e_class           = None
    e_endianness      = None
    e_eiversion       = None
    e_osabi           = None
    e_abiversion      = None
    e_pad             = None
    e_type            = None
    e_machine         = None
    e_version         = None
    e_entry           = None
    e_phoff           = None
    e_shoff           = None
    e_flags           = None
    e_ehsize          = None
    e_phentsize       = None
    e_phnum           = None
    e_shentsize       = None
    e_shnum           = None
    e_shstrndx        = None


def titlify(msg):
    return "{0}[{1} {3} {2}]{0}".format('='*20, Color.RED, Color.NORMAL, msg)

def ok(msg):
    print (Color.GREEN+"[+]"+Color.NORMAL+" "+msg)
    return

def warn(msg):
    print (Color.YELLOW+"[+]"+Color.NORMAL+" "+msg)
    return

def err(msg):
    print (Color.RED+"[+]"+Color.NORMAL+" "+msg)
    return

def info(msg):
    print (Color.BLUE+"[+]"+Color.NORMAL+" "+msg)
    return

def hexdump(src, l=0x10, show_line_num=True):
    f = ''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
    n = 0
    res = ''

    while src:
       s, src = src[:l], src[l:]
       hexa = ' '.join(["%02X" % ord(x) for x in s])
       s = s.translate(f)
       if show_line_num:
           res += "%04X   " % n
       res += "%-*s   %s\n" % (l*3, hexa, s)
       n += l

    return res

def gef_execute(command, as_list = False):

    output = []

    fd, fname = tempfile.mkstemp()
    os.close(fd)

    gdb.execute("set logging file " + fname)
    gdb.execute("set logging overwrite on")
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")

    try :
        lines = gdb.execute(command, to_string=True)
        lines = data.splitlines()

        for line in lines:
            address, content = x.split(" ", 1)
            address = int(address.strip()[:-1], 16)
            content = content.strip()

            output.append( (address, content) )

    except:
        pass

    finally:
        gdb.execute("set logging off")
        gdb.execute("set logging redirect off")
        os.unlink(fname)
        return output


def gef_execute_external(command, as_list=False):
    if as_list :
        return subprocess.check_output(command,
                                       stderr=subprocess.STDOUT,
                                       shell=True).splitlines()
    else:
        return subprocess.check_output(command,
                                       stderr=subprocess.STDOUT,
                                       shell=True)


def disassemble_parse(name, filter_opcode=None):
    lines = [x.split(":", 1) for x in gdb_exec("disassemble %s" % name).split('\n') if "0x" in x]
    dis   = []

    for address, opcode in lines:
        try:
            address = address.replace("=>", "  ").strip()
            address = int(address.split(" ")[0], 16)

            i = opcode.find("#")
            if i != -1:
                opcode = opcode[:i]

            i = opcode.find("<")
            if i != -1:
                opcode = opcode[:i]

            opcode = opcode.strip()

            if filter_opcode is None or filter_opcode in opcode:
                dis.append( (address, opcode) )

        except:
            continue

    return dis


def get_frame():
    return gdb.selected_inferior()


def get_arch():
    return gdb.execute("show architecture", to_string=True).strip().split(" ")[7][:-1]


def arm_registers():
    return ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6",
            "$r7", "$r8", "$r9", "$r10", "$r11", "$r12", "$sp",
            "$lr", "$pc", "$cpsr", ]


def x86_64_registers():
    return [ "$rax", "$rcx", "$rdx","$rbx","$rsp", "$rbp","$rsi",
             "$rdi","$rip", "$eflags", "$cs", "$ss", "$ds", "$es",
             "$fs", "$gs", ]


def x86_32_registers():
    return [ "$eax", "$ecx", "$edx","$ebx","$esp", "$ebp","$esi",
             "$edi","$eip", "$eflags", "$cs", "$ss", "$ds", "$es",
             "$fs", "$gs", ]


def powerpc_registers():
    return ["$r0", "$r1", "$r2", "$r3", "$r4", "$r5", "$r6", "$r7",
            "$r8", "$r9", "$r10", "$r11", "$r12", "$r13", "$r14", "$r15",
            "$r16", "$r17", "$r18", "$r19", "$r20", "$r21", "$r22", "$r23",
            "$r24", "$r25", "$r26", "$r27", "$r28", "$r29", "$r30", "$r31",
            "$pc", "$msr", "$cr", "$lr", "$ctr", "$xer", "$orig_r3", "$trap" ]

def sparc_registers():
    return ["$g0", "$g1", "$g2", "$g3", "$g4", "$g5", "$g6", "$g7",
            "$o0", "$o1", "$o2", "$o3", "$o4", "$o5",
            "$l0", "$l1", "$l2", "$l3", "$l4", "$l5", "$l6", "$l7",
            "$i0", "$i1", "$i2", "$i3", "$i4", "$i5",
            "$pc", "$sp", "$fp", "$psr",
            ]

def all_registers():
    if is_arm():
        return arm_registers()
    elif is_x86_32():
        return x86_32_registers()
    elif is_x86_64():
        return x86_64_registers()
    elif is_powerpc():
        return powerpc_registers()
    elif is_sparc():
        return sparc_registers()


def read_memory(addr, length=0x10):
    return gdb.selected_inferior().read_memory(addr, length)


def read_memory_until_null(address):
    buf = ''
    i = 0

    while True:
        c = read_memory(address + i, 1)
        if ord(c[0]) == 0x00:
            break

        buf += str(c)
        i += 1

    return buf


def read_string(address):
    buffer = read_memory_until_null(address)
    i = 0

    while 0x20 <= ord(buffer[i]) < 0x7f:
        i += 1

    buffer = buffer[:i].replace("\n","\\n").replace("\r","\\r")
    buffer = buffer.replace("\t","\\t").replace("\"","\\\"")
    return buffer


def is_alive():
    try:
        pid = get_frame().pid
        return pid > 0
    except gdb.error, e:
        return False

    return False


def get_register(regname):
    ret = -1

    try:
        t = gdb.lookup_type("unsigned long")
        reg = gdb.parse_and_eval(regname)
        ret = reg.cast(t)

    except :
        err("Cannot parse %s" % regname)

    return long(ret)


@memoize
def get_pid():
    return get_frame().pid


@memoize
def get_filename():
    return gdb.current_progspace().filename


@memoize
def get_process_maps():
    pid = get_pid()
    sections = []

    with open('/proc/%d/maps' % pid) as f:

        while True:
            line = f.readline()
            if len(line) == 0:
                break

            line = line.strip()
            addr, perm, off, dev, rest = line.split(" ", 4)
            rest = rest.split(" ", 1)
            if len(rest) == 1:
                inode = rest[0]
                pathname = ""
            else:
                inode = rest[0]
                pathname = rest[1].replace(' ', '')

            addr_start, addr_end = addr.split("-")
            addr_start, addr_end = int(addr_start, 16), int(addr_end, 16)
            off = int(off, 16)

            section = Section()
            section.page_start  = addr_start
            section.page_end    = addr_end
            section.offset      = off
            section.permission  = perm
            section.inode       = inode
            section.path        = pathname

            sections.append( section )

    return sections

@memoize
def get_info_files():
    infos = []
    stream = cStringIO.StringIO(gdb.execute("info files", to_string=True))

    while True:
            line = stream.readline()
            if len(line) == 0:
                break

            try:
                blobs = [x.strip() for x in line.split(' ')]
                addr_start = int(blobs[0], 16)
                addr_end = int(blobs[2], 16)
                section_name = blobs[4]

                if len(blobs) == 7:
                    filename = blobs[6]
                else:
                    filename = get_filename()


            except ValueError:
                continue

            except IndexError:
                continue

            info = Zone()
            info.name = section_name
            info.zone_start = addr_start
            info.zone_end = addr_end
            info.filename = filename

            infos.append( info )

    stream.close()
    return infos


def process_lookup_address(address):
    if not is_alive():
        err("Process is not running")
        return None

    for sect in get_process_maps():
        if sect.page_start <= address < sect.page_end:
            return sect

    return None


def file_lookup_address(address):
    for info in get_info_files():
        if info.zone_start <= address < info.zone_end:
            return info
    return None


def lookup_address(address):
    addr = Address()
    for attr in ["value", "section", "info"]:
        setattr(addr, attr, None)

    addr.value = address

    sect = process_lookup_address(address)
    info = file_lookup_address(address)
    if sect is None and info is None:
        # i.e. there is no info on this address
        return None

    if sect:
        addr.section = sect

    if info:
        addr.info = info

    return addr


def XOR(data, key):
    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in itertools.izip(data, itertools.cycle(key)))


# dirty hack from https://github.com/longld/peda
def define_user_command(cmd, code):
    commands = "define %s\n%s\nend\n" % (cmd, code)
    fd, fname = tempfile.mkstemp()
    os.write(fd, commands)
    os.close(fd)
    gdb.execute("source %s" % fname)
    os.unlink(fname)
    return


@memoize
def get_elf_headers(filename = None):
    if filename is None:
        filename = get_filename()

    f = open(filename, "rb")

    if not f:
        err("Failed to open %s" % filename)
        return None

    elf = Elf()

    # off 0x0
    elf.e_magic, elf.e_class, elf.e_endianness, elf.e_eiversion = struct.unpack(">IBBB", f.read(7))

    # adjust endianness in bin reading
    if elf.e_endianness == 0x01:
        endian = "<" # LE
    else:
        endian = ">" # BE

    # off 0x7
    elf.e_osabi, elf.e_abiversion = struct.unpack(endian + "BB", f.read(2))
    # off 0x9
    elf.e_pad = f.read(7)
    # off 0x10
    elf.e_type, elf.e_machine, elf.e_version = struct.unpack(endian + "HHI", f.read(8))
    # off 0x18
    if elf.e_class == 0x02: # arch 64bits
        elf.e_entry, elf.e_phoff, elf.e_shoff = struct.unpack(endian + "QQQ", f.read(24))
    else: # arch 32bits
        elf.e_entry, elf.e_phoff, elf.e_shoff = struct.unpack(endian + "III", f.read(12))

    elf.e_flags, elf.e_ehsize, elf.e_phentsize, elf.e_phnum = struct.unpack(endian + "HHHH", f.read(8))
    elf.e_shentsize, elf.e_shnum, elf.e_shstrndx = struct.unpack(endian + "HHH", f.read(6))

    f.close()
    return elf


@memoize
def is_elf64():
    fname = get_filename()
    elf = get_elf_headers(fname)
    return elf.e_class == 0x02


@memoize
def is_elf32():
    fname = get_filename()
    elf = get_elf_headers(fname)
    return elf.e_class == 0x01

@memoize
def is_x86_64():
    elf = get_elf_headers()
    return elf.e_machine==0x3e

@memoize
def is_x86_32():
    elf = get_elf_headers()
    return elf.e_machine==0x03

@memoize
def is_arm():
    elf = get_elf_headers()
    return elf.e_machine==0x28

@memoize
def is_mips():
    elf = get_elf_headers()
    return elf.e_machine==0x08

@memoize
def is_powerpc():
    elf = get_elf_headers()
    return elf.e_machine==0x14 # http://refspecs.freestandards.org/elf/elfspec_ppc.pdf

@memoize
def is_sparc():
    elf = get_elf_headers()
    return elf.e_machine==0x02  # http://www.sparc.org/standards/psABI3rd.pdf


def format_address(addr):
    if is_elf32():
        return "%#.8x" % addr
    elif is_elf64():
        return "%#.16x" % addr
    else:
        err("Unsupported address type")
        return ""



#
# breakpoints
#
class FormatStringBreakpoint(gdb.Breakpoint):
    ''' Inspect stack for format string '''
    def __init__(self, spec, num_args):
        super(FormatStringBreakpoint, self).__init__(spec, gdb.BP_BREAKPOINT, internal=False)
        self.num_args = num_args
        self.enabled = True
        return

    def stop(self):
        if is_arm():
            regs = ['$r0','$r1','$r2','$3']
            ref = regs[self.num_args]
        else :
            raise NotImplementedError()

        value = gdb.parse_and_eval(ref)
        address = long(value)
        pid = get_frame().pid

        addr = lookup_address(address)
        if 'w' in addr.permissions:
            print titlify("Format String Detection")
            info(">>> Possible writable format string %#x (%s): %s" % (addr, ref, content))
            print gdb.execute("backtrace")
            return True

        return False

#
# Functions
#

# credits: http://tromey.com/blog/?p=515
class CallerIs (gdb.Function):
    """Return True if the calling function's name is equal to a string.
    This function takes one or two arguments."""

    def __init__ (self):
        super (CallerIs, self).__init__ ("caller_is")
        return

    def invoke (self, name, nframes = 1):
        frame = gdb.get_current_frame ()
        while nframes > 0:
            frame = frame.get_prev ()
            nframes = nframes - 1
        return frame.get_name () == name.string ()

CallerIs()



#
# Commands
#

class GenericCommand(gdb.Command):
    """Generic class for invoking commands"""

    def __init__(self):
        self.pre_load()

        required_attrs = ["do_invoke", "_cmdline_", "_syntax_"]

        for attr in required_attrs:
            if not hasattr(self, attr):
                raise NotImplemented("Invalid class: missing '%s'" % attr)

        self.__doc__  += "\n" + "Syntax: " + self._syntax_
        super(GenericCommand, self).__init__(self._cmdline_, gdb.COMMAND_NONE)

        self.post_load()

        return


    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        self.do_invoke(argv)
        return


    def usage(self):
        info("Syntax\n" + self._syntax_ )
        return


    def pre_load(self):
        return


    def post_load(self):
        return


# class TemplateCommand(GenericCommand):
    # """TemplaceCommand: add description here."""

    # _cmdline_ = "template-fake"
    # _syntax_  = "%s" % _cmdline_

    # def do_invoke(self, argv):
        # return


class FileDescriptorCommand(GenericCommand):
    """Enumerate file descriptors opened by process."""

    _cmdline_ = "fd"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        pid = get_pid()
        path = "/proc/%s/fd" % pid

        for fname in os.listdir(path):
            fullpath = path+"/"+fname
            if os.path.islink(fullpath):
                print("- %s -> %s" % (fullpath, os.readlink(fullpath)))

        return


class AssembleCommand(GenericCommand):
    """AssembleCommand: using radare2 to assemble code (requires r2 Python bindings)"""

    _cmdline_ = "assemble"
    _syntax_  = "%s mode [instruction1;[instruction2;]] " % _cmdline_

    def pre_load(self):
        try:
            import r2, r2.r_asm

        except ImportError:
            raise GefMissingDependencyException("radare2 Python bindings could not be loaded")


    def do_invoke(self, argv):
        if len(argv) < 2:
            self.usage()
            print("Modes available:\n%s" % gef_execute_external("rasm2 -L; exit 0"))
            return

        mode = argv[0]
        instns = " ".join(argv[1:])
        print ( "%s" % self.assemble(mode, instns) )
        return


    def assemble(self, mode, instructions):
        r2 = sys.modules['r2']
        asm = r2.r_asm.RAsm()
        asm.use(mode)
        opcode = asm.massemble( instructions )
        return None if opcode is None else opcode.buf_hex


class InvokeCommand(GenericCommand):
    """InvokeCommand: invoke an external command and display result."""

    _cmdline_ = "invoke"
    _syntax_  = "%s [COMMAND]" % _cmdline_

    def do_invoke(self, argv):
        print ( "%s" % gef_execute_external(" ".join(argv)) )
        return


class ProcessListingCommand(GenericCommand):
    """List and filter process."""

    _cmdline_ = "ps"
    _syntax_  = "%s [PATTERN]" % _cmdline_


    def do_invoke(self, argv):
        processes = self.ps()

        if len(argv) == 0:
            pattern = re.compile("^.*$")
        else:
            pattern = re.compile(argv[0])

        for process in processes:
            command = process['command']

            if not re.search(pattern, command):
                continue

            line = ""
            line += "%s "  % process["user"]
            line += "%d "  % process["pid"]
            line += "%.f " % process["percentage_cpu"]
            line += "%.f " % process["percentage_mem"]
            line += "%s "  % process["tty"]
            line += "%d "  % process["vsz"]
            line += "%s "  % process["stat"]
            line += "%s "  % process["time"]
            line += "%s "  % process["command"]

            print (line)

        return None


    def ps(self):
        processes = list()
        output = gef_execute_external("/bin/ps auxww", True)[1:]

        for line in output:
            field = re.compile('\s+').split(line)

            processes.append({ 'user': field[0],
                               'pid': int(field[1]),
                               'percentage_cpu': eval(field[2]),
                               'percentage_mem': eval(field[3]),
                               'vsz': int(field[4]),
                               'rss': int(field[5]),
                               'tty': field[6],
                               'stat': field[7],
                               'start': field[8],
                               'time': field[9],
                               'command': field[10],
                               'args': field[11:] if len(field) > 11 else ''
                               })

        return processes


class ElfInfoCommand(GenericCommand):
    """Display ELF header informations."""

    _cmdline_ = "elf-info"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        classes = { 0x01: "32-bit",
                    0x02: "64-bit",
                    }
        endianness = { 0x01: "Little-Endian",
                       0x02: "Big-Endian",
                       }
        osabi = { 0x00: "System V",
                  0x01: "HP-UX",
                  0x02: "NetBSD",
                  0x03: "Linux",
                  0x06: "Solaris",
                  0x07: "AIX",
                  0x08: "IRIX",
                  0x09: "FreeBSD",
                  0x0C: "OpenBSD",
                  }

        types = { 0x01: "Relocatable",
                  0x02: "Executable",
                  0x03: "Shared",
                  0x04: "Core"
                  }

        machines = { 0x02: "SPARC",
                     0x03: "x86",
                     0x08: "MIPS",
                     0x14: "PowerPC",
                     0x28: "ARM",
                     0x32: "IA-64",
                     0x3E: "x86-64",
                     0xB7: "AArch64",
                     }

        elf = get_elf_headers()

        print ("Magic: %s" % hexdump(struct.pack(">I",elf.e_magic), show_line_num=False)),
        print ("Class: %#x - %s" % (elf.e_class, classes[elf.e_class]))
        print ("Endianness: %#x - %s" % (elf.e_endianness, endianness[ elf.e_endianness ]))
        print ("Version: %#x" % elf.e_eiversion)
        print ("OS ABI: %#x - %s" % (elf.e_osabi, osabi[ elf.e_osabi]))
        print ("ABI Version: %#x" % elf.e_abiversion)
        print ("Type: %#x - %s" % (elf.e_type, types[elf.e_type]) )

        print ("Machine: %#x" % elf.e_machine),
        if elf.e_machine in machines:
            print (" - %s" % machines[elf.e_machine] ),
        print ("")

        print ("ELF Version: %#x" % elf.e_version)
        print ("Entry point: %s" % format_address(elf.e_entry))

        # todo finish
        return


class EntryPointBreakCommand(GenericCommand):
    """Tries to find best entry point and sets a temporary breakpoint on it."""

    _cmdline_ = "entry-break"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        # has main() ?
        try:
            value = gdb.parse_and_eval("main")
            info("Breaking at '%s'" % value)
            gdb.execute("tbreak main")
            gdb.execute("run")
            return

        except gdb.error:
            pass

        # has __libc_start_main() ?
        try:
            value = gdb.parse_and_eval("__libc_start_main")
            info("Breaking at '%s'" % value)
            gdb.execute("tbreak __libc_start_main")
            gdb.execute("run")
            return

        except gdb.error:
            pass

        # break at entry point - never fail
        elf = get_elf_headers()
        value = elf.e_entry
        if value:
            info("Breaking at entry-point: %#x" % value)
            gdb.execute("tbreak *%x" % value)
            gdb.execute("run")
            return

        return



class ContextCommand(GenericCommand):
    """Display execution context."""

    _cmdline_ = "context"
    _syntax_  = "%s" % _cmdline_

    old_registers = {}

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        self.context_regs()
        self.context_stack()
        self.context_code()
        self.context_trace()

        self.update_registers()

        return

    def context_regs(self):
        print (Color.BLUE + "-"*80 + Color.BOLD + "[regs]" + Color.NORMAL)
        i = 0

        for reg in all_registers():
            new_value = gdb.parse_and_eval(reg)
            if reg in self.old_registers:
                old_value = self.old_registers[reg]
            else:
                old_value = 0x00

            if new_value.type.code == gdb.TYPE_CODE_INT:
                t_long = gdb.lookup_type("unsigned long")
                addr = long(new_value.cast(t_long))

                if new_value == old_value:
                    l= "%s  %s " % (Color.GREEN + reg + Color.NORMAL,
                                    format_address(addr) )
                else:
                    l= "%s  %s%s%s " % (Color.GREEN + reg + Color.NORMAL,
                                        Color.RED, format_address(addr), Color.NORMAL)
            else:
                l= "%10s  %s " % (Color.GREEN + reg + Color.NORMAL, new_value)

            i+=1
            print (l),
            if i and i%4==0: print("")
        print
        return

    def context_stack(self):
        print (Color.BLUE + "-"*80 + Color.BOLD + "[stack]" + Color.NORMAL)
        read_from = gdb.parse_and_eval("$sp")
        mem = read_memory(read_from, 0x50)
        print ( hexdump(mem) )
        return

    def context_code(self):
        print (Color.BLUE + "-"*80 + Color.BOLD + "[code]"  + Color.NORMAL)
        gdb.execute("x/6i $pc")
        return

    def context_trace(self):
        print (Color.BLUE + "-"*80 + Color.BOLD + "[trace]" + Color.NORMAL)
        gdb.execute("backtrace 5")
        return

    def update_registers(self):
        for reg in all_registers():
            self.old_registers[reg] = gdb.parse_and_eval(reg)
        return



class HexdumpCommand(GenericCommand):
    """Display arranged hexdump (according to architecture endianness) of memory range."""

    _cmdline_ = "xd"
    _syntax_  = "%s (q|d|w|b) [LOCATION] [SIZE]" % _cmdline_

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        if len(argv) < 2:
            self.usage()
            return

        if argv[0] not in ("q", "d", "w", "b"):
            self.usage()
            return

        fmt = argv[0]

        read_from = long(gdb.parse_and_eval( argv[1] ))
        if len(argv) == 2:
            read_len = 0x20
        else:
            read_len = int(argv[2])

        self._hexdump ( read_from, read_len, fmt )

        # todo add deref
        return


    def _hexdump(self, start_addr, length, arrange_as):
        elf = get_elf_headers()
        if elf.e_endianness == 0x01:
            end = "<"
        else:
            end = ">"

        i = 0
        mem = read_memory(start_addr, length)
        formats = { 'q': ('Q', 8),
                    'd': ('I', 4),
                    'w': ('H', 2),
                    'b': ('B', 1),
                    }
        r, l = formats[arrange_as]

        while i < length:
            fmt_str = "<%#x+%d> %#."+str(l*2)+"x"
            print (fmt_str % (start_addr, i, struct.unpack(end + r, mem[i:i+l])[0]))
            i += l

        return



class DereferenceCommand(GenericCommand):
    """Dereference recursively an address and display information"""

    _cmdline_ = "deref"
    _syntax_  = "%s" % _cmdline_


    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        if len(argv) != 1:
            err("Missing argument (register/address)")
            return

        pointer = gdb.parse_and_eval(argv[0])

        if pointer.type.code == gdb.TYPE_CODE_VOID:
            do_loop = False
        else:
            i = 1
            do_loop = True

        while do_loop:
            try:
                value = self.dereference( pointer )
                deref_pointer = long(value)

                line = "-> %s " % (format_address(deref_pointer))
                addr = lookup_address(deref_pointer)
                if addr is None:
                    do_loop = False
                else:
                    line+= " (%s)" % (addr.section.path)
                    pointer = deref_pointer
                    i += 1

            except gdb.MemoryError:
                do_loop = False

        print ("Pointer %s %s" % (format_address(long(pointer)), line))
        print ("Value:")
        data = read_memory_until_null(pointer)
        print ("%s" % hexdump(data))

        return


    def dereference(self, addr):
        p_long = gdb.lookup_type('unsigned long').pointer()
        return gdb.Value(addr).cast(p_long).dereference()


class ASLRCommand(GenericCommand):
    """View/modify GDB ASLR behavior."""

    _cmdline_ = "aslr"
    _syntax_  = "%s (on|off)" % _cmdline_

    def do_invoke(self, argv):
        argc = len(argv)

        if argc == 0:
            ret = gdb.execute("show disable-randomization", to_string=True)
            i = ret.find("virtual address space is ")
            if i < 0:
                return

            msg = "ASLR is currently "
            if ret[i+25:].strip() == "on.":
                msg+= Color.RED + "disabled" + Color.NORMAL
            else:
                msg+= Color.GREEN + "enabled" + Color.NORMAL

            print ("%s" % msg)

            return

        elif argc == 1:
            if argv[0] == "on":
                info("Enabling ASLR")
                gdb.execute("set disable-randomization off")
                return
            elif argv[0] == "off":
                info("Disabling ASLR")
                gdb.execute("set disable-randomization on")
                return

            warn("Invalid command")


        self.usage()
        return


class ResetCacheCommand(GenericCommand):
    """Reset cache of all stored data."""

    _cmdline_ = "reset-cache"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        reset_all_caches()
        return


class VMMapCommand(GenericCommand):
    """Display virtual memory mapping"""

    _cmdline_ = "vmmap"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if not is_alive():
            warn("No debugging session active")
            return

        vmmap = get_process_maps()

        if is_elf64():
            print ("%18s %18s %18s %4s %s" % ("Start", "End", "Offset", "Perm", "Path"))
        else:
            print ("%10s %10s %10s %4s %s" % ("Start", "End", "Offset", "Perm", "Path"))
        for entry in vmmap:
            l = []
            l.append( format_address( entry.page_start ))
            l.append( format_address( entry.page_end ))
            l.append( format_address( entry.offset ))
            if "rwx" in entry.permission:
                l.append( Color.RED+Color.BOLD+entry.permission+Color.NORMAL )
            else:
                l.append( entry.permission )
            l.append( entry.path )

            print " ".join(l)
        return


class XFilesCommand(GenericCommand):
    """Shows all libraries (and sections) loaded by binary (Truth is out there)."""

    _cmdline_ = "xfiles"
    _syntax_  = "%s" % _cmdline_

    def do_invoke(self, argv):
        if not is_alive():
            warn("Debugging session is not active")
            warn("Result may be incomplete (shared libs, etc.)")
            return

        print("%10s %10s %20s %s" % ("Start", "End", "Name", "File"))
        for xfile in get_info_files():
            l= ""
            l+= "%s %s" % (format_address(xfile.zone_start),
                           format_address(xfile.zone_end))
            l+= "%20s " % xfile.name
            l+= "%s" % xfile.filename
            print (l)
        return


class XAddressInfoCommand(GenericCommand):
    """Get virtual section information for specific address"""

    _cmdline_ = "xinfo"
    _syntax_  = "%s LOCATION" % _cmdline_


    def do_invoke (self, argv):
        if len(argv) < 1:
            err ("At least one valid address must be specified")
            return

        for addr in argv:
            try:
                addr = long(gdb.parse_and_eval(addr))
                print titlify("xinfo: %#x" % addr)

                self.infos(addr)

            except gdb.error, ve:
                err("Exception raised: %s" % ve)
                continue
        return


    def infos(self, address):
        addr = lookup_address(address)
        if addr is None:
            warn("Cannot reach %#x in memory space" % address)
            return

        sect = addr.section
        info = addr.info

        if sect:
            print "Found %s" % format_address(addr.value)
            print "Page: %s->%s (size=%#x)" % (format_address(sect.page_start),
                                               format_address(sect.page_end),
                                               sect.page_end-sect.page_start)
            print "Permissions: %s" % sect.permission
            print "Pathname: %s" % sect.path
            print "Offset (from page): +%#x" % (address-sect.page_start)
            print "Inode: %s" % sect.inode

        if info:
            print "Section: %s (%s-%s)" % (info.name,
                                           format_address(info.zone_start),
                                           format_address(info.zone_end))

        return


class XorMemoryCommand(GenericCommand):
    """Patch/display a block of memory by XOR-ing each key with a key."""

    _cmdline_ = "xor-memory"
    _syntax_  = "%s <address> <size_to_read> <xor_key> (display|patch)" % _cmdline_


    def do_invoke(self, argv):
        valid_actions = ("display", "patch")
        if len(argv) not in (3, 4):
            self.usage()
            return

        if len(argv) == 4:
            action = argv[3]
            if action not in self.valid_actions:
                err("Invalid action, must be in %s" % self.valid_actions)
                self.usage()
                return
        else:
            action = "display"

        address = long(gdb.parse_and_eval(argv[0]))
        length, key = int(argv[1]), argv[2]
        block = read_memory(address, length)
        info("%sing XOR-ing %#x-%#x with '%s'" % (action.capitalize(),
                                                  address,
                                                  address + len(block),
                                                  key))

        xored_block = XOR(block, key)

        if action == "display":
            print ( titlify("Original block") )
            print( hexdump( block ) )

            print ( titlify("XOR-ed block") )
            print( hexdump(xored_block) )

        elif action == "patch":
            if is_alive():
                info("todo")
            else:
                err("Cannot patch")

        return


class TraceRunCommand(GenericCommand):
    """Create a runtime trace of all instructions executed from $pc to LOCATION specified."""

    _cmdline_ = "trace-run"
    _syntax_  = "%s LOCATION [MAX_CALL_DEPTH]" % _cmdline_

    def do_invoke(self, argv):
        if len(argv) > 2:
            self.usage()
            return

        if not is_alive():
            warn("Debugging session is not active")
            return

        try:
            loc_start = long(gdb.parse_and_eval("$pc"))
            loc_end = long(argv[0], 16)

        except gdb.error, ve:
            err("Invalid location: %s" % e)
            return

        self.trace(loc_start, loc_end)
        return


    def trace(self, loc_start, loc_end):
        info("Tracing from %#x to  %#x" % (loc_start, loc_end))
        logfile = "./gdb-trace-%#x-%#x.txt" % (loc_start, loc_end)

        gdb.execute( "set logging overwrite" )
        gdb.execute( "set logging file %s" % logfile)
        gdb.execute( "set logging redirect on" )
        gdb.execute( "set logging on" )

        self._do_trace(loc_start, loc_end)

        gdb.execute( "set logging redirect off" )
        gdb.execute( "set logging off" )

        info("Formatting output")
        gdb.execute( "shell sed -i -e '/^[^0x]/d' -e '/^$/d'  %s" % logfile)
        ok("Done, logfile stored as '%s'" % logfile)
        info("Hint: use `ida_color_gdb_trace.py` script to visualize path")
        return


    def _do_trace(self, loc_start, loc_end):
        # todo: add max_depth
        loc_old = 0
        loc_cur = loc_start
        page_mask = 0xFFFF0000

        frame_old = 0
        frame_cur = gdb.selected_frame()

        while is_alive() and loc_cur != loc_end:
            gdb.execute( "nexti" )

        return



class PatternCommand(GenericCommand):
    """Metasploit-like pattern generation/search"""

    _cmdline_ = "pattern"
    _syntax_  = "%s create SIZE\n" % _cmdline_
    _syntax_ += "%s search SIZE PATTERN" % _cmdline_


    def do_invoke(self, argv):
        argc = len(argv)

        if argc < 1:
            self.usage()
            return

        if argv[0] == "create":
            if argc != 2:
                self.usage()

            else:
                limit = int(argv[1])
                info("Generating a pattern of %d bytes" % limit)
                print ( self.generate(limit) )

            return

        elif argv[0] == "search":
            if argc != 3:
                self.usage()

            size, pattern = int(argv[1]), argv[2]
            info("Searching for '%s'" % pattern)
            offset = self.search(pattern, size)

            if offset < 0:
                print ("Not found")

        else:
            err("Unknown command %s" % argv[0])

        return


    def generate(self, limit):
        pattern = ""
        for mj in range(ord('A'), ord('Z')+1) :             # from A to Z
            for mn in range(ord('a'), ord('z')+1) :         # from a to z
                for dg in range(ord('0'), ord('9')+1) :     # from 0 to 9
                    for c in (chr(mj), chr(mn), chr(dg)) :
                        if len(pattern) == limit :
                            return pattern
                        else:
                            pattern += "%s" % c
        # Should never be here, just for clarity
        return ""


    def search(self, pattern, size):
        try:
            addr = int( gdb.parse_and_eval(pattern) )
            pattern_be = struct.pack(">I", addr)
            pattern_le = struct.pack("<I", addr)

        except gdb.error:
            err("Incorrect pattern")
            return -1

        buffer = self.generate(size)
        found = False

        off = buffer.find(pattern_le)
        if off >= 0:
            ok("Found at offset %d (little-endian search)" % off)
            found = True

        off = buffer.find(pattern_be)
        if off >= 0:
            ok("Found at offset %d (big-endian search)" % off)
            found = True

        return -1 if not found else 0



class ChecksecCommand(GenericCommand):
    """Checksec.sh (http://www.trapkit.de/tools/checksec.html) port."""

    _cmdline_ = "checksec"
    _syntax_  = "%s (filename)" % _cmdline_


    def do_invoke(self, argv):
        argc = len(argv)

        if argc == 0:
            filename = get_filename()

        elif argc == 1:
            filename = argv[0]

        else:
            self.usage()
            return

        if not os.access("/usr/bin/readelf", os.X_OK):
            print("Could not access readelf")

        info("%s for '%s'" % (self._cmdline_, filename))
        self.checksec(filename)
        return


    def do_check(self, title, opt, filename, pattern, is_match):
        options = opt.split(" ")
        buf = "%-50s" % (title+":")
        cmd = ["readelf",]
        cmd+= options
        cmd+= [filename, ]
        lines = subprocess.check_output( cmd ).split("\n")
        found = False

        for line in lines:
            if re.search(pattern, line):
                buf += Color.GREEN
                if is_match:
                    buf += Color.GREEN + "Yes" + Color.NORMAL
                else:
                    buf += Color.RED + "No" + Color.NORMAL
                found = True
                break

        if not found:
            if is_match:
                buf+= Color.RED + "No"+ Color.NORMAL
            else:
                buf+= Color.GREEN + "Yes"+ Color.NORMAL

        print ("%s" % buf)
        return


    def checksec(self, filename):
        # check for canary
        self.do_check("Canary", "-s", filename, r'__stack_chk_fail', is_match=True)

        # check for NX
        self.do_check("NX Support", "-W -l", filename, r'GNU_STACK.*RWE', is_match=False)

        # check for PIE support
        self.do_check("PIE Support", "-h", filename, r'Type:.*EXEC', is_match=False)
        # todo : add check for (DEBUG) if .so

        # check for RPATH
        self.do_check("RPATH", "-d -l", filename, r'rpath', is_match=True)

        # check for RUNPATH
        self.do_check("RUNPATH", "-d -l", filename, r'runpath', is_match=True)

        return



class FormatStringSearchCommand(GenericCommand):
    """Exploitable format-string helper (experimental)"""
    _cmdline_ = "fmtstr-helper"
    _syntax_ = "%s" % _cmdline_


    def do_invoke(self, argv):
        dangerous_functions = {
            'printf':     0,
            'sprintf':    1,
            'vfprintf':   1,
            'vsprintf':   1,
            'fprintf':    1,
            'snprintf':   2,
            'vsnprintf':  2,
            }

        for func_name, num_arg in dangerous_functions.iteritems():
            FormatStringBreakpoint(func_name, num_arg)

        return


class GEFCommand(gdb.Command):
    """GEF Control Center"""

    _cmdline_ = "gef"
    _syntax_  = "%s (load/help)" % _cmdline_

    def __init__(self):
        super(GEFCommand, self).__init__(GEFCommand._cmdline_,
                                         gdb.COMMAND_SUPPORT)

        self.classes = [XAddressInfoCommand,
                        XorMemoryCommand,
                        FormatStringSearchCommand,
                        TraceRunCommand,
                        PatternCommand,
                        ChecksecCommand,
                        VMMapCommand,
                        XFilesCommand,
                        ResetCacheCommand,
                        ASLRCommand,
                        DereferenceCommand,
                        HexdumpCommand,
                        ContextCommand,
                        EntryPointBreakCommand,
                        ElfInfoCommand,
                        ProcessListingCommand,
                        InvokeCommand,
                        AssembleCommand,
                        FileDescriptorCommand,

                        # add new commands here
                        ]

        self.cmds = [ (x._cmdline_, x) for x in self.classes ]
        self.load()
        return


    def invoke(self, args, from_tty):
        argv = gdb.string_to_argv(args)
        if len(argv) < 1 :
            err("Missing command for gef -- `gef help` for help")
            return

        cmd = argv[0]
        if cmd == "help":
            self.help()
        else :
            err("Invalid command '%s' for gef -- `gef load' for help" % ' '.join(argv))

        return


    def load(self, mod=None):
        for (cmd, class_name) in self.cmds:
            try:
                class_name()
            except Exception, e:
                err("Failed to load `%s`: %s" % (cmd, e.message))

        print("%s, type `%s' to start" % (Color.GREEN + "gef loaded" +Color.NORMAL,
                                          Color.RED + "gef help" +Color.NORMAL))
        return


    def help(self):
        print titlify("GEF - GDB Enhanced Features")

        for (cmd, class_name) in self.cmds:
            try:
                msg = "%-20s -- %s" % (cmd, Color.GREEN+class_name.__doc__+Color.NORMAL)

            except AttributeError:
                msg = "%-20s: <Unspecified>" % (cmd,)

            print ("%s" % msg)

        return




if __name__  == "__main__":
    GEF_PROMPT = "gef> "

    # setup config
    gdb.execute("set confirm off")
    gdb.execute("set verbose off")
    gdb.execute("set output-radix 0x10")
    gdb.execute("set input-radix 0x10")
    gdb.execute("set height 0")
    gdb.execute("set width 0")
    gdb.execute("set prompt %s" % Color.RED+GEF_PROMPT+Color.NORMAL)
    gdb.execute("set follow-fork-mode child")

    # gdb history
    gdb.execute("set history filename ~/.gdb_history")
    gdb.execute("set history save")

    # aliases
    # WinDBG-like aliases (I like them)

    # breakpoints
    gdb.execute("alias -a bl = info breakpoints")
    gdb.execute("alias -a bp = break")
    gdb.execute("alias -a be = enable breakpoints")
    gdb.execute("alias -a bd = disable breakpoints")
    gdb.execute("alias -a bc = delete breakpoints")
    # gdb.execute("alias -a ba = awatch")
    gdb.execute("alias -a tbp = tbreak")
    gdb.execute("alias -a tba = thbreak")

    # runtime
    gdb.execute("alias -a g = run")

    # memory access
    # gdb.execute("alias -a u = x")
    gdb.execute("alias -a uf = disassemble")

    # context
    gdb.execute("alias -a argv = show args")
    gdb.execute("alias -a stack = info stack")

    try:
        # this will raise a gdb.error unless we're on x86
        # we can safely ignore this
        gdb.execute("set disassembly-flavor intel")
    except gdb.error:
        pass


    # load GEF
    GEFCommand()

    # post-loading stuff
    define_user_command("hook-stop", "context")

    # gdb.execute("alias -a -- dq = xd -q")
    # gdb.execute("alias -a -- dd = xd -d")
    # gdb.execute("alias dw = xd -w")
    # gdb.execute("alias db = xd -b")
