"""

> "Because IDA sucks"


Embed RPyc in IDA to expose IDA's API externally, by a background thread that runs the TCP server. Also in iPython this
provides autocomplete.

Props to https://github.com/vrtadmin/FIRST-plugin-ida/blob/master/first_plugin_ida/first.py#L87
for the workaround on the threading issue, for IDA Pro >= 7.2

Quick start
```
>>> import rpyc
>>> c = rpyc.connect("ida.rpyc.server", 18812)
#
# IDA namespace will be in `c.root`
#
>>> c.root.idaapi.get_root_filename()
'ntoskrnl.exe'
>>> hex( c.root.idc.here() )
0x140088194
>>> c.root.idaapi.jumpto( 0x1400881EE )
True
```

For generator objects, you now need to use the wrapper `c.root.iterate()`.

Example:
```
>>> idc = c.root.idc
>>> idautils = c.root.idautils
>>> for ea in c.root.iterate( idautils.Functions() ):
...    print( idc.get_func_name(ea) )
```

Blame HexRays for making their API more confusing at every release.

Ref:
- https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml


"""
import sys
import os
import random
import threading
import collections


import rpyc
import idc
import idaapi
import idautils



PLUGIN_NAME = "RunRpycServer"
PLUGIN_HOTKEY = "Ctrl-Alt-K"
PLUGIN_VERSION = "0.2"
PLUGIN_AUTHOR = "@_hugsy_"

HOST, PORT = "0.0.0.0", 18812
DEBUG = False

def xlog(x):
    sys.stderr.write("{} - {}\n".format(threading.current_thread().name, x)) and sys.stderr.flush()

def err(msg):
    xlog("[!] {}".format(msg,))

def ok(msg):
    xlog("[+] {}".format(msg,))

def dbg(msg):
    if DEBUG:
        xlog("[*] {}".format(msg,))



class IdaWrapper:
    def __getattribute__(self, name):
        default = "IDoNotExistButNoReallyISeriouslyDoNotAndCannotExist"

        dbg("trying to get {}".format(name,))

        if name.startswith("exposed_"):
            name = name.replace("exposed_", "")
            dbg("changed to get {}".format(name,))

        val = getattr(idaapi, name, default)
        if val == default:
            val = getattr(idc, name, default)
        if val == default:
            val = getattr(idautils, name, default)
        if val == default:
            raise AttributeError("unknown {}".format(name,))

        if hasattr(val, '__call__'):
            dbg("{} is callable".format(val,))
            def call(*args, **kwargs):
                holder = [None] # need a holder, because 'global' sucks

                def trampoline():
                    holder[0] = val(*args, **kwargs)
                    return 1

                idaapi.execute_sync(trampoline, idaapi.MFF_WRITE)
                return holder[0]
            return call
        else:
            return val



g_IdaWrapper     = IdaWrapper()


class IdaRpycService(rpyc.Service):
    ALIASES = ["ida", ]


    def on_connect(self, conn):
        ok("connect open: {}".format(conn,))
        return


    def on_disconnect(self, conn):
        ok("connection closed: {}".format(conn,))
        return


    def exposed_iterate(self, iterator):
        default = "IDoNotExistButNoReallyISeriouslyDoNotAndCannotExist {}".format(random.randint(0, 65535),)
        holder = [default]
        def trampoline():
            try:
                holder[0] = next(iterator)
            except StopIteration:
                holder[0] = default
            return 1
        while True:
            idaapi.execute_sync(trampoline, idaapi.MFF_WRITE)
            if holder[0] == default:
                return
            yield holder[0]


    exposed_idaapi    = g_IdaWrapper
    exposed_idc       = g_IdaWrapper
    exposed_idautils  = g_IdaWrapper



g_IdaServer = IdaRpycService()



def start():
    global g_IdaServer
    srv = None

    for i in range(1):
        port = PORT + i
        try:
            srv = rpyc.utils.server.OneShotServer(g_IdaServer, hostname=HOST, port=port) if DEBUG \
                else rpyc.utils.server.ThreadedServer(g_IdaServer, hostname=HOST, port=port)
            break
        except OSError:
            srv = None

    if not srv:
        err("failed to start server...")
        return

    ok("starting server...")
    srv.start()
    srv.close()
    ok("server closed")
    return


t = None

def main():
    global t
    if t is not None:
        err("thread is already running as {}".format(t))
        return

    t = threading.Thread(target=start)
    t.daemon = True
    t.start()
    ok("service listening on {}:{}...".format(HOST, PORT))


class dummy(idaapi.plugin_t):
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""

    def init(self): return idaapi.PLUGIN_OK
    def run(self, arg): pass
    def term(self): pass


def PLUGIN_ENTRY():
    main()
    return dummy()


if __name__ == "__main__":
    PLUGIN_ENTRY()