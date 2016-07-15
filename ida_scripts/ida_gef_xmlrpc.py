#
# This script is the server-side of the XML-RPC defined for gef
# It must be run from inside IDA
#
# If you edit HOST/PORT, use `gef config` command to edit them
#
# Ref:
# - https://docs.python.org/2/library/simplexmlrpcserver.html
# - https://pymotw.com/2/SimpleXMLRPCServer/
#
# @_hugsy_
#

from __future__ import print_function

from threading import Thread
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer, list_public_methods
from idautils import *
from idc import *

import string
import inspect

HOST = "0.0.0.0"
PORT = 1337

DEBUG = True

def expose(f):
    "Decorator to set exposed flag on a function."
    f.exposed = True
    return f


def is_exposed(f):
    "Test whether another function should be publicly exposed."
    return getattr(f, 'exposed', False)


def ishex(s):
    if s.startswith("0x") or s.startswith("0X"): s = s[2:]
    return all(c in set(string.hexdigits) for c in s)


class Ida:
    """
    Top level class where exposed methods are declared.
    """

    def __init__(self, server, *args, **kwargs):
        self.server = server
        return


    def _dispatch(self, method, params):
        """
        Plugin dispatcher
        """
        if DEBUG:
            print("Received '%s'" % method)

        func = getattr(self, method)
        if not is_exposed(func):
            raise NotImplementedError('Method "%s" is not exposed' % method)

        if DEBUG:
            print("Executing %s(%s)" % (method, params))
        return func(*params)


    def _listMethods(self):
        """
        Class method listing (required for introspection API).
        """
        m = []
        for x in list_public_methods(self):
            if x.startswith("_"): continue
            if not is_exposed( getattr(self, x) ): continue
            m.append(x)
        return m


    def _methodHelp(self, method):
        """
        Method help (required for introspection API).
        """
        f = getattr(self, method)
        return inspect.getdoc(f)


    @expose
    def shutdown(self):
        """ shutdown() => None
        Cleanly shutdown the XML-RPC service.
        Example: ida shutdown
        """
        self.server.server_close()
        print("XMLRPC server stopped")
        return 0

    @expose
    def MakeComm(self, address, comment):
        """ MakeComm(int addr, string comment) => None
        Add a comment to the current IDB at the location `address`.
        Example: ida MakeComm 0x40000 "Important call here!"
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return MakeComm(addr, comment)

    @expose
    def SetColor(self, address, color="0x005500"):
        """ SetColor(int addr [, int color]) => None
        Set the location pointed by `address` in the IDB colored with `color`.
        Example: ida SetColor 0x40000
        """
        addr = long(address, 16) if ishex(address) else long(address)
        color = long(color, 16) if ishex(color) else long(color)
        return SetColor(addr, CIC_ITEM, color)

    @expose
    def MakeName(self, address, name):
        """ MakeName(int addr, string name]) => None
        Set the location pointed by `address` with the name specified as argument.
        Example: ida MakeName 0x00000000004049de __entry_point
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return MakeName(addr, name)

    @expose
    def Jump(self, address):
        """ Jump(int addr) => None
        Move the IDA EA pointer to the address pointed by `addr`.
        Example: ida Jump 0x0004049de
        """
        addr = long(address, 16) if ishex(address) else long(address)
        return Jump(addr)


    # ideas for commands:
    # - rebase program based on gdb runtime value
    # - run ida plugin remotely
    # - edit gdb/capstone disassembly view to integrate comments from idb
    # - generic command about idb : path/dir/hash etc.
    # - details of xref to a given address


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


def start_xmlrpc_server():
    """
    Initialize the XMLRPC thread
    """
    print("[+] Starting XMLRPC server: {}:{}".format(HOST, PORT))
    server = SimpleXMLRPCServer((HOST, PORT),
                                requestHandler=RequestHandler,
                                logRequests=DEBUG)
    server.register_introspection_functions()
    server.register_instance( Ida(server) )
    print("[+] Registered {} functions.".format( len(server.system_listMethods()) ))
    server.serve_forever()
    return


if __name__ == "__main__":
    t = Thread(target=start_xmlrpc_server, args=())
    t.daemon = True
    print("[+] Creating new thread for XMLRPC server: {}".format(t.name))
    t.start()
