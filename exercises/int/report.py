#!/usr/bin/env python3
from scapy.all import sniff, UDP
from typing import Dict

REPORT_PORT = 1234
IFACE = "eth0"

import struct
from typing import Tuple, Dict, List

# ---- low-level helpers ---------------------------------------------------
def read_u8(b: bytes, off: int) -> int:
    return b[off]

def read_u16(b: bytes, off: int) -> int:
    return (b[off] << 8) | b[off+1]

def read_u32(b: bytes, off: int) -> int:
    return (b[off] << 24) | (b[off+1] << 16) | (b[off+2] << 8) | b[off+3]

def read_u64(b: bytes, off: int) -> int:
    hi = read_u32(b, off)
    lo = read_u32(b, off+4)
    return (hi << 32) | lo

def mac_str(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b)

def ipv4_str(b: bytes) -> str:
    return '.'.join(str(x) for x in b)

# ---- parse outer/inner headers -------------------------------------------
def parse_eth(b: bytes, off: int) -> Tuple[Dict, int]:
    dst = b[off:off+6]; src = b[off+6:off+12]; ethertype = read_u16(b, off+12)
    return {'dst': mac_str(dst), 'src': mac_str(src), 'ethertype': ethertype}, off+14

def parse_ipv4_header(b: bytes, off: int) -> Tuple[Dict, int]:
    ver_ihl = b[off]
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0f
    dscp = b[off+1] >> 2
    ecn  = b[off+1] & 0x03
    totalLen = read_u16(b, off+2)
    identification = read_u16(b, off+4)
    flags_frag = read_u16(b, off+6)
    flags = flags_frag >> 13
    fragOffset = flags_frag & 0x1FFF
    ttl = b[off+8]
    protocol = b[off+9]
    hdrChecksum = read_u16(b, off+10)
    src = ipv4_str(b[off+12:off+16])
    dst = ipv4_str(b[off+16:off+20])
    parsed = {
        'version': version, 'ihl': ihl, 'dscp': dscp, 'ecn': ecn,
        'totalLen': totalLen, 'id': identification, 'flags': flags,
        'fragOffset': fragOffset, 'ttl': ttl, 'protocol': protocol,
        'hdrChecksum': hdrChecksum, 'srcAddr': src, 'dstAddr': dst
    }
    return parsed, off + ihl*4

def parse_udp(b: bytes, off: int) -> Tuple[Dict, int]:
    srcPort = read_u16(b, off)
    dstPort = read_u16(b, off+2)
    length = read_u16(b, off+4)
    csum = read_u16(b, off+6)
    return {'srcPort': srcPort, 'dstPort': dstPort, 'len': length, 'csum': csum}, off+8

# ---- parse INT report fixed header (16 bytes) -----------------------------
def parse_report_fixed_header(b: bytes, off: int) -> Tuple[Dict, int]:
    # Structure per int_report_fixed_header_t
    # bytes layout (16 bytes):
    # b0: ver(4) | len(4)
    # b1: nprot(3) | rep_md_bits_high(5)  (but original split different - we just parse fields)
    # b2.. b? etc - we'll parse by bit ops
    ver = b[off] >> 4
    length = b[off] & 0x0F
    # next byte: top bits are nprot and rep_md_bits_high etc - we'll extract fields as in struct
    # combine next 3 bytes to extract the bitfields comfortably
    # We'll extract switch_id (4), seq_num (4), ingress_tstamp (4) which appear after the bitfields
    # In the header layout above, rep_md_high and low occupy parts of bytes; we will directly read subsequent fields
    # In P4 struct: after first 2 bytes there are many small bitfields then 6 bytes reserved etc;
    # For practical parser we'll extract switch_id at offset+4 (per your p4 layout)
    # To be safe, read bytes as:
    switch_id = read_u32(b, off + 6)   # adjust below if your layout differs
    seq_num   = read_u32(b, off + 10)
    ingress_tstamp = read_u32(b, off + 14)
    parsed = {
        'ver': ver,
        'len_words': length,
        'switch_id': switch_id,
        'seq_num': seq_num,
        'ingress_tstamp': ingress_tstamp
    }
    # return and advance by 16 bytes
    return parsed, off + 16

# ---- parse int_shim + int_header -----------------------------------------
def parse_int_shim_and_header(b: bytes, off: int) -> Tuple[Dict, int]:
    if off + 12 > len(b):
        return None, off
    # int_shim (4 bytes)
    int_type = b[off]
    rsvd1 = b[off+1]
    shim_len_words = b[off+2]
    dscp = b[off+3] >> 2
    rsvd3 = b[off+3] & 0x03
    shim = {'int_type': int_type, 'rsvd1': rsvd1, 'len_words': shim_len_words, 'dscp': dscp, 'rsvd3': rsvd3}
    # int_header (8 bytes)
    hdr_b_off = off + 4
    vrep = b[hdr_b_off]
    ver = vrep >> 4
    rep = (vrep >> 2) & 0x03
    c = (vrep >> 1) & 0x01
    e_flag = vrep & 0x01
    # hop_metadata_len is at hdr_b_off+2, remaining_hop_cnt at +3
    hop_metadata_len = b[hdr_b_off + 2]
    remaining_hop_cnt = b[hdr_b_off + 3]
    instruction_mask = (b[hdr_b_off + 4] << 8) | b[hdr_b_off + 5]
    seq = (b[hdr_b_off + 6] << 8) | b[hdr_b_off + 7]
    int_header = {
        'ver': ver, 'rep': rep, 'c': c, 'e': e_flag,
        'hop_metadata_len': hop_metadata_len,
        'remaining_hop_cnt': remaining_hop_cnt,
        'instruction_mask': instruction_mask,
        'seq': seq
    }
    return {'int_shim': shim, 'int_header': int_header}, off + 12

# ---- per-hop field order & parsing --------------------------------------
# mapping & order - matches your int_transit tb mappings (upper-byte mask bits)
FIELD_ORDER = [
    (0x8000, 'int_switch_id', 4, lambda b,off: read_u32(b,off)),
    (0x4000, 'int_port_ids', 4, None),           # handle as two u16s
    (0x2000, 'int_hop_latency', 4, lambda b,off: read_u32(b,off)),
    (0x1000, 'int_q_occupancy', 4, None),        # q_id + 3-byte occupancy
    (0x0800, 'int_ingress_tstamp', 8, lambda b,off: read_u64(b,off)),
    (0x0400, 'int_egress_tstamp', 8, lambda b,off: read_u64(b,off)),
    (0x0200, 'int_level2_port_ids', 4, None),
    (0x0100, 'int_egress_port_tx_util', 4, lambda b,off: read_u32(b,off)),
]

def parse_one_hop_fields(b: bytes, off: int, mask: int) -> Tuple[Dict, int]:
    hop = {}
    ptr = off
    for bit, name, size, parser in FIELD_ORDER:
        if mask & bit:
            if ptr + size > len(b):
                # not enough bytes: abort gracefully
                hop[name] = None
                ptr += size
                continue
            if name == 'int_port_ids':
                hop['ingress_port_id'] = read_u16(b, ptr)
                hop['egress_port_id']  = read_u16(b, ptr+2)
            elif name == 'int_q_occupancy':
                hop['q_id'] = b[ptr]
                hop['q_occupancy'] = (b[ptr+1] << 16) | (b[ptr+2] << 8) | b[ptr+3]
            elif name == 'int_level2_port_ids':
                hop['level2_ingress_port_id'] = read_u16(b, ptr)
                hop['level2_egress_port_id'] = read_u16(b, ptr+2)
            else:
                hop[name] = parser(b, ptr) if parser else b[ptr:ptr+size].hex()
            ptr += size
    return hop, ptr

# ---- main report parser --------------------------------------------------
def parse_int_report_packet(packet_bytes: bytes, assume_most_recent_first: bool = True) -> Dict:
    """
    Parse an INT REPORT packet (sink -> collector).
    Returns dict with outer headers, report_fixed_header, inner headers and decoded hop list.
    The parser computes number of hops by: hop_data_words = int_shim.len_words - 3;
      num_hops = hop_data_words // hop_metadata_len
    """
    b = packet_bytes
    off = 0
    result = {}

    # parse outer eth
    outer_eth, off = parse_eth(b, off)
    result['report_eth'] = outer_eth

    # outer IPv4
    report_ipv4, off = parse_ipv4_header(b, off)
    result['report_ipv4'] = report_ipv4

    # outer UDP
    report_udp, off = parse_udp(b, off)
    result['report_udp'] = report_udp

    # report fixed header (16 bytes)
    report_fixed, off = parse_report_fixed_header(b, off)
    result['report_fixed_header'] = report_fixed

    # inner original ethernet
    inner_eth, off = parse_eth(b, off)
    result['inner_eth'] = inner_eth

    # inner IPv4
    inner_ipv4, off = parse_ipv4_header(b, off)
    result['inner_ipv4'] = inner_ipv4

    # inner transport (UDP or TCP)
    if inner_ipv4['protocol'] == 17:  # UDP
        inner_transp, off = parse_udp(b, off)
        result['inner_udp'] = inner_transp
    else:
        # parse minimal TCP header (20 bytes) for offsets
        # only parse ports & dataOffset
        srcp = read_u16(b, off); dstp = read_u16(b, off+2)
        dataOffset = b[off+12] >> 4
        inner_tcp = {'srcPort': srcp, 'dstPort': dstp, 'dataOffset': dataOffset}
        result['inner_tcp'] = inner_tcp
        off = off + dataOffset*4

    # parse int_shim and int_header
    ih, off = parse_int_shim_and_header(b, off)
    if ih is None:
        result['int_shim'] = None
        result['int_header'] = None
        result['hops'] = []
        return result

    result['int_shim'] = ih['int_shim']
    result['int_header'] = ih['int_header']

    # compute number of hop blocks present from shim.len and hop_metadata_len
    shim_len_words = ih['int_shim']['len_words']
    hop_word_len = ih['int_header']['hop_metadata_len']
    if hop_word_len == 0:
        result['hops'] = []
        return result

    hop_data_words = max(0, shim_len_words - 3)    # exclude shim+header words
    num_hops = hop_data_words // hop_word_len
    result['computed_num_hops'] = num_hops
    # mask: use upper byte bits (standard fields)
    mask = ih['int_header']['instruction_mask'] & 0xFF00

    # parse each hop block (blocks are contiguous after int_header)
    hops = []
    hop_bytes_len = hop_word_len * 4
    cur = off
    for i in range(num_hops):
        hop, newptr = parse_one_hop_fields(b, cur, mask)
        hops.append(hop)
        # advance exactly hop_bytes_len (some hops may contain padding)
        cur = cur + hop_bytes_len

    # order: your in-band format usually has most-recent-first; if you prefer oldest-first set flag False
    if not assume_most_recent_first:
        hops = list(reversed(hops))

    result['hops'] = hops
    return result


def handle_udp_packet(pkt):
    """
    Callback for scapy sniff; parses INT report from UDP payload
    """
    print(bytes(pkt))
    if UDP in pkt and pkt[UDP].dport == REPORT_PORT:
        payload = bytes(pkt)
        report = parse_int_report_packet(payload)
        print("\n=== NEW INT REPORT ===")
        print("Report Fixed Header:", report.get('report_fixed_header'))
        print("INT Shim:", report.get('int_shim'))
        print("INT Header:", report.get('int_header'))
        print("Number of Hops:", report.get('computed_num_hops'))
        for i, hop in enumerate(report.get('hops', [])):
            print(f"Hop {i+1}: {hop}")

if __name__ == "__main__":
    print(f"[*] Listening on {IFACE} UDP port {REPORT_PORT} for INT reports...")
    sniff(iface=IFACE, filter=f"udp and dst port {REPORT_PORT}", prn=handle_udp_packet)
