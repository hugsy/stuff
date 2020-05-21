#!C:\Python38\python.exe

"""

> "Because IDA sucks"


Tiny mod of the original rpyc_classic server script to run the daemon in a background thread
allowing it to be exposed by IDA

"""
import sys
import os
from plumbum import cli
from rpyc.utils.server import ThreadedServer, ForkingServer, OneShotServer
from rpyc.utils.classic import DEFAULT_SERVER_PORT, DEFAULT_SERVER_SSL_PORT
from rpyc.utils.registry import REGISTRY_PORT
from rpyc.utils.registry import UDPRegistryClient, TCPRegistryClient
from rpyc.utils.authenticators import SSLAuthenticator
from rpyc.lib import setup_logger
from rpyc.core import SlaveService

import rpyc, idc, idaapi, idautils, random, threading


class ClassicServer(cli.Application):
    mode = cli.SwitchAttr(["-m", "--mode"], cli.Set("threaded", "forking", "stdio", "oneshot"),
                          default="threaded", help="The serving mode (threaded, forking, or 'stdio' for "
                          "inetd, etc.)")

    port = cli.SwitchAttr(["-p", "--port"], cli.Range(0, 65535), default=None,
                          help="The TCP listener port (default = %s, default for SSL = %s)" %
                          (DEFAULT_SERVER_PORT, DEFAULT_SERVER_SSL_PORT), group="Socket Options")
    host = cli.SwitchAttr(["--host"], str, default="", help="The host to bind to. "
                          "The default is localhost", group="Socket Options")
    ipv6 = cli.Flag(["--ipv6"], help="Enable IPv6", group="Socket Options")

    logfile = cli.SwitchAttr("--logfile", str, default=None, help="Specify the log file to use; "
                             "the default is stderr", group="Logging")
    quiet = cli.Flag(["-q", "--quiet"], help="Quiet mode (only errors will be logged)",
                     group="Logging")

    ssl_keyfile = cli.SwitchAttr("--ssl-keyfile", cli.ExistingFile,
                                 help="The keyfile to use for SSL. Required for SSL", group="SSL",
                                 requires=["--ssl-certfile"])
    ssl_certfile = cli.SwitchAttr("--ssl-certfile", cli.ExistingFile,
                                  help="The certificate file to use for SSL. Required for SSL", group="SSL",
                                  requires=["--ssl-keyfile"])
    ssl_cafile = cli.SwitchAttr("--ssl-cafile", cli.ExistingFile,
                                help="The certificate authority chain file to use for SSL. "
                                "Optional; enables client-side authentication",
                                group="SSL", requires=["--ssl-keyfile"])

    auto_register = cli.Flag("--register", help="Asks the server to attempt registering with "
                             "a registry server. By default, the server will not attempt to register",
                             group="Registry")
    registry_type = cli.SwitchAttr("--registry-type", cli.Set("UDP", "TCP"),
                                   default="UDP", help="Specify a UDP or TCP registry", group="Registry")
    registry_port = cli.SwitchAttr("--registry-port", cli.Range(0, 65535), default=REGISTRY_PORT,
                                   help="The registry's UDP/TCP port", group="Registry")
    registry_host = cli.SwitchAttr("--registry-host", str, default=None,
                                   help="The registry host machine. For UDP, the default is 255.255.255.255; "
                                   "for TCP, a value is required", group="Registry")

    def main(self):
        if not self.host:
            self.host = "::1" if self.ipv6 else "0.0.0.0"

        if self.registry_type == "UDP":
            if self.registry_host is None:
                self.registry_host = "255.255.255.255"
            self.registrar = UDPRegistryClient(ip=self.registry_host, port=self.registry_port)
        else:
            if self.registry_host is None:
                raise ValueError("With TCP registry, you must specify --registry-host")
            self.registrar = TCPRegistryClient(ip=self.registry_host, port=self.registry_port)

        if self.ssl_keyfile:
            self.authenticator = SSLAuthenticator(self.ssl_keyfile, self.ssl_certfile,
                                                  self.ssl_cafile)
            default_port = DEFAULT_SERVER_SSL_PORT
        else:
            self.authenticator = None
            default_port = DEFAULT_SERVER_PORT
        if self.port is None:
            self.port = default_port

        setup_logger(self.quiet, self.logfile)

        if self.mode == "threaded":
            self._serve_mode(ThreadedServer)
        elif self.mode == "forking":
            self._serve_mode(ForkingServer)
        elif self.mode == "oneshot":
            self._serve_oneshot()
        elif self.mode == "stdio":
            self._serve_stdio()

    def _serve_mode(self, factory):
        t = factory(SlaveService, hostname=self.host, port=self.port,
                    reuse_addr=True, ipv6=self.ipv6, authenticator=self.authenticator,
                    registrar=self.registrar, auto_register=self.auto_register)
        t.start()

    def _serve_oneshot(self):
        t = OneShotServer(SlaveService, hostname=self.host, port=self.port,
                          reuse_addr=True, ipv6=self.ipv6, authenticator=self.authenticator,
                          registrar=self.registrar, auto_register=self.auto_register)
        t._listen()
        sys.stdout.write("rpyc-oneshot\n")
        sys.stdout.write("%s\t%s\n" % (t.host, t.port))
        sys.stdout.flush()
        t.start()

    def _serve_stdio(self):
        origstdin = sys.stdin
        origstdout = sys.stdout
        sys.stdin = open(os.devnull, "r")
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")
        conn = rpyc.classic.connect_pipes(origstdin, origstdout)
        try:
            try:
                conn.serve_all()
            except KeyboardInterrupt:
                print("User interrupt!")
        finally:
            conn.close()



class IDAWrapper(object):
    ''' https://github.com/vrtadmin/FIRST-plugin-ida/blob/master/first_plugin_ida/first.py#L87 '''
    mapping = {
        'get_tform_type' : 'get_widget_type',
    }
    def __init__(self):
        self.version = idaapi.IDA_SDK_VERSION

    def __getattribute__(self, name):
        print(name)
        default = '[1st] default'
        if (idaapi.IDA_SDK_VERSION >= 700) and (name in IDAWrapper.mapping):
            name = IDAWrapper.mapping[name]
        val = getattr(idaapi, name, default)
        if val == default:
            val = getattr(idautils, name, default)
        if val == default:
            val = getattr(idc, name, default)

        if val == default:
            msg = 'Unable to find {}'.format(name)
            raise KeyError(msg)

        if hasattr(val, '__call__'):
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

IDAW = IDAWrapper()



def safe_generator(iterator):
    sentinel = '[1st] Sentinel %d' % (random.randint(0, 65535))
    holder = [sentinel] # need a holder, because 'global' sucks

    def trampoline():
        try:
            holder[0] = next(iterator)
        except StopIteration:
            holder[0] = sentinel
        return 1

    while True:
        idaapi.execute_sync(trampoline, idaapi.MFF_WRITE)
        if holder[0] == sentinel:
            return
        yield holder[0]



if __name__ == "__main__":
    # ensure that those objects/methods will be exposed via the conn.builtins
    __builtins__.ida = IDAW
    __builtins__.ida = Trampoline()
    __builtins__.ida_generator = safe_generator
    t = threading.Thread(target=ClassicServer.run)
    t.daemon = True
    t.start()
