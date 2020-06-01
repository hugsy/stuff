#!C:\Python38\python.exe

"""

> "Because IDA sucks"


Embed RPyc in IDA to expose IDA's API externally, by a background thread that runs the TCP server.

Props to https://github.com/vrtadmin/FIRST-plugin-ida/blob/master/first_plugin_ida/first.py#L87
for the workaround on the threading issue, for IDA Pro >= 7.2

For generator objects, you now need to use the wrapper `c.root.iterate()`.

Example:
```
>>> import rpyc
>>> c = rpyc.connect("192.168.57.145", 18812)
>>> idc = c.root.idc
>>> for f in c.root.iterate( idc.Functions() ):
...    print(f)
```

Blame HexRays for making their API more shitty at every release.

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

def xlog(x: str)  -> None:
    sys.stderr.write(f"{threading.current_thread().name} - {x}\n") and sys.stderr.flush()

def err(msg: str) -> None:
    xlog(f"[!] {msg}")

def ok(msg: str)  -> None:
    xlog(f"[+] {msg}")

def dbg(msg: str) -> None:
    if DEBUG:
        xlog(f"[*] {msg}")



class IdaWrapper:
    def __getattr__(self, name):
        default = "IDoNotExistButNoReallyISeriouslyDoNotAndCannotExist"

        dbg(f"trying to get {name}")

        if name.startswith("exposed_"):
            name = name.replace("exposed_", "")
            dbg(f"changed to get {name}")

        val = getattr(idautils, name, default)
        if val == default:
            val = getattr(idaapi, name, default)

        if val == default:
            val = getattr(idc, name, default)

        if val == default:
            raise AttributeError(f"unknown {name}")

        if hasattr(val, '__call__'):
            dbg(f"{val} is callable")
            def call(*args, **kwargs):
                holder = [None] # need a holder, because 'global' sucks

                def trampoline():
                    holder[0] = val(*args, **kwargs)
                    return 1

                idaapi.execute_sync(trampoline, idaapi.MFF_WRITE)
                return holder[0]
            return call
        else:
            dbg(f"{val} is other")
            return val



g_IdaWrapper = IdaWrapper()

class IdaRpycService(rpyc.Service):
    ALIASES = ["ida", ]

    def on_connect(self, conn):
        ok(f"connect open: {conn}")
        return

    def on_disconnect(self, conn):
        ok(f"connection closed: {conn}")
        return


    @property
    def exposed_idaapi():
        return g_IdaWrapper


    @property
    def exposed_idc(self):
        return g_IdaWrapper


    @property
    def exposed_idautils(self):
        return g_IdaWrapper


    def exposed_iterate(self, iterator):
        default = "IDoNotExistButNoReallyISeriouslyDoNotAndCannotExist %d" % (random.randint(0, 65535))
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



g_IdaServer = IdaRpycService()



def start():
    global g_IdaServer
    if DEBUG:
        s = rpyc.utils.server.OneShotServer(g_IdaServer, hostname=HOST, port=PORT)
    else:
        s = rpyc.utils.server.ThreadedServer(g_IdaServer, hostname=HOST, port=PORT)
    s.start()
    ok("server started")
    s.close()
    ok("server closed")
    return



if __name__ == "__main__":
    t = threading.Thread(target=start)
    t.daemon = True
    t.start()
    ok(f"service listening on {HOST}:{PORT}...")
