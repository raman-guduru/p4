#!/usr/bin/env python3
import sys
import socket
import time # <-- Import time library for sleep
from scapy.all import sendp, get_if_hwaddr, get_if_list, Ether, IP, UDP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
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
    message = sys.argv[2]
    num_packets = 10 # <-- How many packets to send
    # delay_seconds = 0.0000001 # <-- Wait 100ms between packets

    print(f"Sending {num_packets} packets to {addr} via {iface}...")

    # Build the packet once
    pkt = Ether(src=get_if_hwaddr(iface), dst='08:00:00:00:01:00') / IP(dst=addr) / UDP(dport=4321, sport=1234) / message

    # Loop to send multiple packets
    for i in range(num_packets):
        # Optional: Modify payload per packet if needed (e.g., add sequence number)
        # current_message = f"{message} - Pkt {i+1}"
        # pkt_to_send = Ether(src=get_if_hwaddr(iface), dst='08:00:00:00:03:33') / IP(dst=addr) / UDP(dport=4321, sport=1234) / current_message
        # sendp(pkt_to_send, iface=iface, verbose=False)

        sendp(pkt, iface=iface, verbose=False)
        print(f"Sent packet {i + 1}/{num_packets}")
        # time.sleep(delay_seconds) # Wait before sending the next one

    print("Done sending packets.")

if __name__ == '__main__':
    main()