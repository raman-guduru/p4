#!/usr/bin/env python3
import sys
import json
import struct
from scapy.all import *

# --- Scapy Layer Definitions (No Changes) ---
class ReportGroupHeader(Packet):
    name = "ReportGroupHeader"
    fields_desc = [
        BitField("ver", 0, 4),
        BitField("hw_id", 0, 6),
        BitField("seq_no", 0, 22),
        IntField("node_id", 0)
    ]

class ReportIndividualHeader(Packet):
    name = "ReportIndividualHeader"
    fields_desc = [
        BitField("rep_type", 0, 4),
        BitField("in_type", 0, 4),
        ByteField("len", 0),
        ByteField("rep_md_len", 0),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 0, 1),
        BitField("i", 0, 1),
        BitField("rsvd", 0, 4),
        ShortField("rep_md_bits", 0),
        ShortField("domain_specific_id", 0),
        ShortField("domain_specific_md_bits", 0),
        ShortField("domain_specific_md_status", 0)
    ]

class INTL4Shim(Packet):
    name = "INTL4Shim"
    fields_desc = [
        BitField("int_type", 0, 4),
        BitField("npt", 0, 2),
        BitField("rsvd1", 0, 2),
        ByteField("len", 0),
        ByteField("rsvd2", 0),
        BitField("original_dscp", 0, 6),
        BitField("rsvd3", 0, 2)
    ]

class INTHeader(Packet):
    name = "INTHeader"
    fields_desc = [
        BitField("ver", 0, 4),
        BitField("d", 0, 1),
        BitField("e", 0, 1),
        BitField("m", 0, 1),
        BitField("rsvd1", 0, 12),
        BitField("hop_metadata_len", 0, 5),
        ByteField("remaining_hop_cnt", 0),
        BitField("instruction_mask_0003", 0, 4),
        BitField("instruction_mask_0407", 0, 4),
        BitField("instruction_mask_0811", 0, 4),
        BitField("instruction_mask_1215", 0, 4),
        ShortField("domain_specific_id", 0),
        ShortField("ds_instruction", 0),
        ShortField("ds_flags", 0)
    ]

# --- Layer Bindings (No Changes) ---
bind_layers(UDP, ReportGroupHeader, dport=24576)
bind_layers(ReportGroupHeader, ReportIndividualHeader)
bind_layers(ReportIndividualHeader, IP, rep_type=1, in_type=4)
bind_layers(UDP, INTL4Shim)
bind_layers(INTL4Shim, INTHeader)

# --- Metadata Parsing Logic (FINAL FIX) ---
# This dictionary now defines the parsing in the
# *correct order* as defined by MyDeparser

INT_METADATA_PARSERS = [
    # (mask_bit, mask_group, size_bytes, format_string, field_names)
    (0x8, '0003', 4, "!I", ["node_id"]),
    (0x4, '0003', 4, "!HH", ["ingress_port_id", "egress_port_id"]),
    (0x2, '0003', 4, "!I", ["hop_latency"]),
    (0x1, '0003', 4, "!IB", ["q_occupancy", "q_id"], 3), # Special 24+8 bit packing
    (0x8, '0407', 8, "!Q", ["ingress_tstamp"]),
    (0x4, '0407', 8, "!Q", ["egress_tstamp"]),
    (0x2, '0407', 8, "!II", ["ingress_port_id_l2", "egress_port_id_l2"]),
    (0x1, '0407', 4, "!I", ["egress_port_tx_util"])
]

def parse_int_metadata(int_header, raw_payload):
    hops_data = []
    hop_len_bytes = int_header.hop_metadata_len * 4
    if hop_len_bytes == 0:
        return []

    num_hops = len(raw_payload) // hop_len_bytes
    
    mask_0003 = int_header.instruction_mask_0003
    mask_0407 = int_header.instruction_mask_0407
    masks = {'0003': mask_0003, '0407': mask_0407}
    
    offset = 0
    for _ in range(num_hops):
        hop_data = {}
        hop_payload = raw_payload[offset : offset + hop_len_bytes]
        hop_offset = 0
        
        # Iterate in the *correct* deparser order
        for (mask_bit, mask_group, field_size, fmt, names, *extra) in INT_METADATA_PARSERS:
            
            # Check if this field's bit is set in the correct mask
            if (masks[mask_group] & mask_bit):
                try:
                    # Special case for q_occupancy (24 bits + 8 bits)
                    if names[0] == "q_occupancy": 
                        val_a, val_b = struct.unpack_from("!IB", hop_payload, hop_offset)
                        hop_data[names[0]] = val_a >> 8 # 24 bits
                        hop_data[names[1]] = val_b      # 8 bits
                    else:
                        values = struct.unpack_from(fmt, hop_payload, hop_offset)
                        for i, name in enumerate(names):
                            hop_data[name] = values[i]
                            
                    hop_offset += field_size
                except struct.error as e:
                    print(f"[DEBUG] Struct unpack error: {e}. Hop offset: {hop_offset}, Field size: {field_size}, Hop len: {hop_len_bytes}")
                    break
        
        hops_data.append(hop_data)
        offset += hop_len_bytes

    return hops_data

# --- Main Packet Handler (No Changes) ---

all_reports = []
DSCP_INT = 0x17 # 23
packet_counter = 0

def process_packet(pkt):
    global packet_counter
    packet_counter += 1
    # print(f"\n--- [DEBUG] Packet {packet_counter} received on port 24576 ---")

    if not pkt.haslayer(ReportIndividualHeader):
        return

    report_hdr = pkt.getlayer(ReportIndividualHeader)
    try:
        raw_inner_payload = bytes(report_hdr.payload)
    except:
        return
        
    inner_pkt = IP(raw_inner_payload)
    inner_dscp = (inner_pkt.tos >> 2)
    
    if inner_dscp != DSCP_INT:
        return

    if not inner_pkt.haslayer(INTHeader):
        return
    
    int_hdr = inner_pkt.getlayer(INTHeader)
    metadata_payload = bytes(int_hdr.payload)
    hop_data = parse_int_metadata(int_hdr, metadata_payload)
    
    if hop_data:
        report = {
            "seq_no": pkt[ReportGroupHeader].seq_no,
            "source_ip": inner_pkt.src,
            "dest_ip": inner_pkt.dst,
            "hops": hop_data
        }
        all_reports.append(report)
        print(f"Captured INT report, sequence {report['seq_no']}, {len(hop_data)} hops")

# --- Main Function (No Changes) ---
def main(iface, out_file, pkt_count):
    print(f"Sniffing on {iface} for {pkt_count} INT reports (UDP port 24576)...")
    sniff(iface=iface, 
          filter="udp port 24576", 
          prn=process_packet, 
          count=pkt_count)
    
    if all_reports:
        print(f"\nSniffing complete. Saving {len(all_reports)} reports to {out_file}...")
        try:
            with open(out_file, 'w') as f:
                json.dump(all_reports, f, indent=4)
            print("Done.")
        except Exception as e:
            print(f"Error writing to file: {e}")
    else:
        print("\nSniffing complete. No INT reports found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./report.py <interface> <output.json> [count]")
        print("Example: ./report.py h3-eth0 int_reports.json 10")
        sys.exit(1)
    
    iface = sys.argv[1]
    out_file = sys.argv[2]
    pkt_count = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    main(iface, out_file, pkt_count)