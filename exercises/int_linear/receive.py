#!/usr/bin/env python3
import sys
from scapy.all import *

class INTShim(Packet):
    name = "INTShim"
    fields_desc = [
        ByteField("int_type", 0),
        ByteField("rsvd1", 0),
        ByteField("len", 0),
        # *** FIX #1 IS HERE ***
        # Correctly define the 6-bit dscp and 2-bit reserved field
        BitField("dscp", 0, 6),
        BitField("rsvd2", 0, 2)
    ]

class INTHeader(Packet):
    name = "INTHeader"
    fields_desc = [
        BitField("ver", 0, 4),
        BitField("rep", 0, 2),
        BitField("c", 0, 1),
        BitField("e", 0, 1),
        BitField("m", 0, 1),
        # *** FIX #2 IS HERE ***
        # Correctly define the 7-bit and 3-bit reserved fields
        BitField("rsvd1", 0, 7),
        BitField("rsvd2", 0, 3),
        BitField("hop_metadata_len", 0, 5),
        ByteField("remaining_hop_cnt", 0),
        ShortField("instruction_mask", 0),
        ShortField("rsvd3", 0)
    ]

class INTMetadata(Packet):
    name = "INTMetadata"
    fields_desc = [
        IntField("switch_id", 0)
    ]

# Bind Scapy layers
bind_layers(UDP, INTShim, dport=4321)
bind_layers(INTShim, INTHeader)
bind_layers(INTHeader, INTMetadata)
bind_layers(INTMetadata, INTMetadata)

def handle_pkt(pkt):
    print("\n--- Got a packet ---")
    pkt.show()
    if INTHeader in pkt:
        print("\nINT Data:")
        int_layer = pkt[INTHeader]
        
        # The metadata stack is the payload of the INTHeader
        payload = bytes(int_layer.payload)
        
        # Each metadata entry is 4 bytes (switch_id)
        num_hops = len(payload) // 4
        
        for i in range(num_hops):
            sw_id_bytes = payload[i*4 : (i+1)*4]
            sw_id = int.from_bytes(sw_id_bytes, "big")
            print(f"  Hop {i+1}: Switch ID = {sw_id}")

    sys.stdout.flush()

def main():
    iface = "eth0"
    print(f"Sniffing on {iface}...")
    sniff(iface=iface, prn=lambda x: handle_pkt(x), filter="udp and port 4321")

if __name__ == '__main__':
    main()