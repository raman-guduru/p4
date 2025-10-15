#!/usr/bin/env python3
import sys
import socket
from scapy.all import sendp, get_if_hwaddr, get_if_list, Ether, IP, UDP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    if len(sys.argv) < 3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    # Use the correct destination MAC address for h2
    pkt = Ether(src=get_if_hwaddr(iface), dst='08:00:00:00:03:33') / IP(dst=addr) / UDP(dport=4321, sport=1234) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()