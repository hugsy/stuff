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
    PREFIX = "ida"


    def __init__(self, server, *args, **kwargs):
        self.server = server
        return


    def _dispatch(self, method, params):
        """
        Plugin dispatcher
        """
        if not method.startswith(self.PREFIX + '.'):
            raise NotImplementedError('Method "%s" is not supported' % method)

        method_name = method.partition('.')[2]
        func = getattr(self, method_name)
        if not is_exposed(func):
            raise NotImplementedError('Method "%s" is not exposed' % method)

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
        """ ida.shutdown() => None
        Cleanly shutdown the XML-RPC service.
        Example: ida.shutdown
        """
        self.server.server_close()
        print("XMLRPC server stopped")
        return


    @expose
    def add_comment(self, address, comment):
        """ ida.add_comment(int addr, string comment) => None
        Add a comment to the current IDB at the location `address`.
        Example: ida.add_comment 0x40000 "Important call here!"
        """
        addr = long(address, 16) if ishex(address) else long(address)
        MakeComm(addr, comment)
        return


    @expose
    def set_color(self, address, color="0x005500"):
        """ ida.set_color(int addr [, int color]) => None
        Set the location pointed by `address` in the IDB colored with `color`.
        Example: ida.set_color 0x40000
        """
        addr = long(address, 16) if ishex(address) else long(address)
        color = long(color, 16) if ishex(color) else long(color)
        SetColor(addr, CIC_ITEM, color)
        return


    # ideas for commands:
    # - rebase program based on gdb runtime value
    # - run ida plugin remotely
    # - edit gdb/capstone disassembly view to integrate comments from idb
    # - generic command about idb : path/dir/hash etc.
    # - use MakeName(addr,name) to change a location/function name
    # - details of xref to a given address
    # -
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


def start_xmlrpc_server():
    """
    Initialize the XMLRPC thread
    """
    print("[+] Starting XMLRPC server: {}:{}".format(HOST, PORT))
    server = SimpleXMLRPCServer((HOST, PORT),
                                requestHandler=RequestHandler,
                                logRequests=True)
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
