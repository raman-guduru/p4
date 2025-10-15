#!/usr/bin/env python3
import sys
from scapy.all import *

def main():
    if len(sys.argv) < 3:
        print("Usage: ./send.py <destination_ip> <message>")
        sys.exit(1)
    
    dst_ip = sys.argv[1]
    message = sys.argv[2]
    
    p = Ether(dst="ff:ff:ff:ff:ff:ff") / \
        IP(dst=dst_ip, tos=0) / \
        UDP(dport=4321, sport=1234) / \
        message
        
    print("Sending packet:")
    p.show2()
    sendp(p, iface="eth0")

if __name__ == '__main__':
    main()