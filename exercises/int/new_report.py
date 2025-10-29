#!/usr/bin/env python3
from scapy.all import sniff, UDP
from typing import Dict, Tuple, List, Any # Added List, Any
import struct
import json
import time
import os
import sys

# --- Configuration ---
REPORT_PORT = 1234
IFACE = "eth0"
OUTPUT_FILE = "./reports/int_report.jsonl"

# ---- [Parsing functions - UNCHANGED - Your original working code] ----
def read_u8(b: bytes, off: int) -> int:
    # ... (same as before) ...
    return b[off]
def read_u16(b: bytes, off: int) -> int:
    # ... (same as before) ...
    return (b[off] << 8) | b[off+1]
def read_u32(b: bytes, off: int) -> int:
    # ... (same as before) ...
    return (b[off] << 24) | (b[off+1] << 16) | (b[off+2] << 8) | b[off+3]
def read_u64(b: bytes, off: int) -> int:
    # ... (same as before) ...
    hi = read_u32(b, off); lo = read_u32(b, off+4); return (hi << 32) | lo
def mac_str(b: bytes) -> str:
    # ... (same as before) ...
    return ':'.join(f'{x:02x}' for x in b)
def ipv4_str(b: bytes) -> str:
    # ... (same as before) ...
    return '.'.join(str(x) for x in b)
def parse_eth(b: bytes, off: int) -> Tuple[Dict, int]:
    # ... (same as before) ...
    dst = b[off:off+6]; src = b[off+6:off+12]; ethertype = read_u16(b, off+12)
    return {'dst': mac_str(dst), 'src': mac_str(src), 'ethertype': ethertype}, off+14
def parse_ipv4_header(b: bytes, off: int) -> Tuple[Dict, int]:
    # ... (same as before) ...
    ver_ihl = b[off]; version = ver_ihl >> 4; ihl = ver_ihl & 0x0f; dscp = b[off+1] >> 2; ecn  = b[off+1] & 0x03; totalLen = read_u16(b, off+2); identification = read_u16(b, off+4); flags_frag = read_u16(b, off+6); flags = flags_frag >> 13; fragOffset = flags_frag & 0x1FFF; ttl = b[off+8]; protocol = b[off+9]; hdrChecksum = read_u16(b, off+10); src = ipv4_str(b[off+12:off+16]); dst = ipv4_str(b[off+16:off+20])
    parsed = {'version': version, 'ihl': ihl, 'dscp': dscp, 'ecn': ecn, 'totalLen': totalLen, 'id': identification, 'flags': flags, 'fragOffset': fragOffset, 'ttl': ttl, 'protocol': protocol, 'hdrChecksum': hdrChecksum, 'srcAddr': src, 'dstAddr': dst}
    return parsed, off + ihl*4
def parse_udp(b: bytes, off: int) -> Tuple[Dict, int]:
    # ... (same as before) ...
    srcPort = read_u16(b, off); dstPort = read_u16(b, off+2); length = read_u16(b, off+4); csum = read_u16(b, off+6)
    return {'srcPort': srcPort, 'dstPort': dstPort, 'len': length, 'csum': csum}, off+8
def parse_report_fixed_header(b: bytes, off: int) -> Tuple[Dict, int]:
    # ... (same as before) ...
    ver = b[off] >> 4; length = b[off] & 0x0F; switch_id = read_u32(b, off + 6); seq_num   = read_u32(b, off + 10); ingress_tstamp = read_u32(b, off + 14)
    parsed = {'ver': ver, 'len_words': length, 'switch_id': switch_id, 'seq_num': seq_num, 'ingress_tstamp': ingress_tstamp}
    return parsed, off + 16
def parse_int_shim_and_header(b: bytes, off: int) -> Tuple[Dict, int]:
    # ... (same as before) ...
    if off + 12 > len(b): return None, off
    int_type = b[off]; rsvd1 = b[off+1]; shim_len_words = b[off+2]; dscp = b[off+3] >> 2; rsvd3 = b[off+3] & 0x03
    shim = {'int_type': int_type, 'rsvd1': rsvd1, 'len_words': shim_len_words, 'dscp': dscp, 'rsvd3': rsvd3}
    hdr_b_off = off + 4; vrep = b[hdr_b_off]; ver = vrep >> 4; rep = (vrep >> 2) & 0x03; c = (vrep >> 1) & 0x01; e_flag = vrep & 0x01; hop_metadata_len = b[hdr_b_off + 2]; remaining_hop_cnt = b[hdr_b_off + 3]; instruction_mask = (b[hdr_b_off + 4] << 8) | b[hdr_b_off + 5]; seq = (b[hdr_b_off + 6] << 8) | b[hdr_b_off + 7]
    int_header = {'ver': ver, 'rep': rep, 'c': c, 'e': e_flag, 'hop_metadata_len': hop_metadata_len, 'remaining_hop_cnt': remaining_hop_cnt, 'instruction_mask': instruction_mask, 'seq': seq}
    return {'int_shim': shim, 'int_header': int_header}, off + 12
FIELD_ORDER = [
    (0x8000, 'int_switch_id', 4, lambda b,off: read_u32(b,off)), (0x4000, 'int_port_ids', 4, None), (0x2000, 'int_hop_latency', 4, lambda b,off: read_u32(b,off)), (0x1000, 'int_q_occupancy', 4, None),
    (0x0800, 'int_ingress_tstamp', 8, lambda b,off: read_u64(b,off)), (0x0400, 'int_egress_tstamp', 8, lambda b,off: read_u64(b,off)), (0x0200, 'int_level2_port_ids', 4, None), (0x0100, 'int_egress_port_tx_util', 4, lambda b,off: read_u32(b,off)),]
def parse_one_hop_fields(b: bytes, off: int, mask: int) -> Tuple[Dict, int]:
    # ... (same as before) ...
    hop = {}; ptr = off
    for bit, name, size, parser in FIELD_ORDER:
        if mask & bit:
            if ptr + size > len(b): hop[name] = None; ptr += size; continue
            if name == 'int_port_ids': hop['ingress_port_id'] = read_u16(b, ptr); hop['egress_port_id']  = read_u16(b, ptr+2)
            elif name == 'int_q_occupancy': hop['q_id'] = b[ptr]; hop['q_occupancy'] = (b[ptr+1] << 16) | (b[ptr+2] << 8) | b[ptr+3]
            elif name == 'int_level2_port_ids': hop['level2_ingress_port_id'] = read_u16(b, ptr); hop['level2_egress_port_id'] = read_u16(b, ptr+2)
            else: hop[name] = parser(b, ptr) if parser else b[ptr:ptr+size].hex()
            ptr += size
    return hop, ptr
def parse_int_report_packet(packet_bytes: bytes, assume_most_recent_first: bool = True) -> Dict:
    # ... (same as before, using mask & 0xFF00) ...
    b = packet_bytes; off = 0; result = {}
    try:
        outer_eth, off = parse_eth(b, off); result['report_eth'] = outer_eth
        report_ipv4, off = parse_ipv4_header(b, off); result['report_ipv4'] = report_ipv4
        report_udp, off = parse_udp(b, off); result['report_udp'] = report_udp
        report_fixed, off = parse_report_fixed_header(b, off); result['report_fixed_header'] = report_fixed
        inner_eth, off = parse_eth(b, off); result['inner_eth'] = inner_eth
        inner_ipv4, off = parse_ipv4_header(b, off); result['inner_ipv4'] = inner_ipv4

        inner_proto = inner_ipv4.get('protocol')
        if inner_proto == 17: # UDP
             inner_transp, off = parse_udp(b, off); result['inner_udp'] = inner_transp
        elif inner_proto == 6: # TCP
             if off + 13 <= len(b):
                 srcp = read_u16(b, off); dstp = read_u16(b, off+2); dataOffset = b[off+12] >> 4;
                 inner_tcp = {'srcPort': srcp, 'dstPort': dstp, 'dataOffset': dataOffset}; result['inner_tcp'] = inner_tcp;
                 tcp_hdr_len = dataOffset * 4
                 if off + tcp_hdr_len <= len(b): off = off + tcp_hdr_len
                 else: off = len(b)
             else: off = len(b)
        else:
             result['inner_transport'] = None

        if off >= len(b):
             result['int_shim'] = None; result['int_header'] = None; result['hops'] = []; return result

        ih, off = parse_int_shim_and_header(b, off)
        if ih is None: result['int_shim'] = None; result['int_header'] = None; result['hops'] = []; return result
        result['int_shim'] = ih['int_shim']; result['int_header'] = ih['int_header']
        shim_len_words = ih['int_shim']['len_words']; hop_word_len = ih['int_header']['hop_metadata_len']
        if hop_word_len == 0: result['hops'] = []; return result
        hop_data_words = max(0, shim_len_words - 3); num_hops = hop_data_words // hop_word_len; result['computed_num_hops'] = num_hops

        mask = ih['int_header']['instruction_mask'] & 0xFF00 # Use upper byte mask

        hops = []; hop_bytes_len = hop_word_len * 4; cur = off
        for i in range(num_hops):
            if cur + hop_bytes_len > len(b): break
            hop, newptr = parse_one_hop_fields(b, cur, mask); hops.append(hop);
            cur = cur + hop_bytes_len
        if not assume_most_recent_first: hops = list(reversed(hops))
        result['hops'] = hops
        return result
    except Exception as e:
         print(f"[ERROR] Exception during packet parsing: {e}", file=sys.stderr)
         import traceback
         traceback.print_exc()
         return {}

# --- [Function to write to file - unchanged] ---
def write_report_to_file(report: Dict, filename: str):
    # ... (same as before) ...
    try:
        report['collector_timestamp_utc'] = time.time()
        with open(filename, 'a') as f:
            json.dump(report, f, default=str)
            f.write('\n')
        print(f"[*] Report appended to {filename}")
    except IOError as e:
        print(f"[!] Error writing to file {filename}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Error processing report for file writing: {e}", file=sys.stderr)


# --- CORRECTED Packet Handling Callback ---
def handle_udp_packet(pkt):
    """
    Callback for scapy sniff; parses INT report and writes JSON to file.
    """
    # Check for UDP layer and correct port
    if not UDP in pkt or pkt[UDP].dport != REPORT_PORT:
        return

    # *** THE FIX: Pass the entire raw packet bytes to the parser ***
    raw_packet_bytes = bytes(pkt)

    try:
        print(f"\n[*] Received packet ({len(raw_packet_bytes)} bytes), parsing...")
        report = parse_int_report_packet(raw_packet_bytes) # Pass the full packet

        # Check if parsing produced meaningful data
        if report and 'hops' in report and report['hops']: # Check specifically if hops list is not empty
            print(f"[*] Parsing successful. Hops found: {len(report['hops'])}")
            write_report_to_file(report, OUTPUT_FILE)
        else:
            print("[!] Parsing failed or resulted in empty report (no hops found). Skipping file write.")
            print("    Report Fixed Header (if parsed):", report.get('report_fixed_header'))
            print("    INT Header (if parsed):", report.get('int_header'))
            print(f"    Raw Packet Snippet (first 64 bytes): {raw_packet_bytes[:64].hex()}")


    except Exception as e:
         print(f"[!] Error in handle_udp_packet: {e}", file=sys.stderr)
         print(f"    Raw Packet Data: {raw_packet_bytes.hex()}", file=sys.stderr)


# --- [__main__ block - unchanged] ---
if __name__ == "__main__":
    print("[*] INT Report JSON File Collector started.")
    print(f"[*] Reports will be written to: {OUTPUT_FILE}")
    try:
        if os.path.exists(OUTPUT_FILE): os.remove(OUTPUT_FILE); print(f"[*] Cleared existing log file: {OUTPUT_FILE}")
    except Exception as e: print(f"[WARN] Could not clear log file {OUTPUT_FILE}: {e}", file=sys.stderr)
    print(f"[*] Starting Scapy sniffer on {IFACE} for UDP port {REPORT_PORT}...")
    try:
        sniff(iface=IFACE, filter=f"udp and dst port {REPORT_PORT}", prn=handle_udp_packet)
    except Exception as e: print(f"[!] Scapy sniffer failed: {e}", file=sys.stderr); sys.exit(1)