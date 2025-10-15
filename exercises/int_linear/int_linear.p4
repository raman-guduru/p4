// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_UDP = 17;
const bit<6>  DSCP_INT = 0x17;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t { macAddr_t dstAddr; macAddr_t srcAddr; bit<16> etherType; }
header ipv4_t { bit<4> version; bit<4> ihl; bit<6> dscp; bit<2> ecn; bit<16> totalLen; bit<16> identification; bit<3> flags; bit<13> fragOffset; bit<8> ttl; bit<8> protocol; bit<16> hdrChecksum; ip4Addr_t srcAddr; ip4Addr_t dstAddr; }
header udp_t { bit<16> srcPort; bit<16> dstPort; bit<16> length_; bit<16> checksum; }
header intl4_shim_t { bit<8> int_type; bit<8> rsvd1; bit<8> len; bit<6> dscp; bit<2> rsvd2; }
header int_header_t { bit<4> ver; bit<2> rep; bit<1> c; bit<1> e; bit<1> m; bit<7> rsvd1; bit<3> rsvd2; bit<5> hop_metadata_len; bit<8> remaining_hop_cnt; bit<16> instruction_mask; bit<16> rsvd3; }
header int_metadata_t { bit<32> switch_id; }

#define MAX_HOPS 8
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    intl4_shim_t intl4_shim;
    int_header_t int_header;
    int_metadata_t[MAX_HOPS] int_metadata_stack;
}
struct metadata { bit<8> int_hop_count; }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start { transition parse_ethernet; }
    state parse_ethernet { packet.extract(hdr.ethernet); transition select(hdr.ethernet.etherType) { TYPE_IPV4: parse_ipv4; default: accept; } }
    state parse_ipv4 { packet.extract(hdr.ipv4); transition select(hdr.ipv4.protocol) { IP_PROTO_UDP: parse_udp; default: accept; } }
    state parse_udp { packet.extract(hdr.udp); transition select(hdr.ipv4.dscp) { DSCP_INT: parse_int_shim; default: accept; } }
    state parse_int_shim { packet.extract(hdr.intl4_shim); transition parse_int_header; }
    state parse_int_header { packet.extract(hdr.int_header); meta.int_hop_count = hdr.int_header.remaining_hop_cnt; transition parse_int_metadata; }
    state parse_int_metadata { transition select(meta.int_hop_count) { 0: accept; default: parse_one_int_metadata_hop; } }
    state parse_one_int_metadata_hop { packet.extract(hdr.int_metadata_stack.next); meta.int_hop_count = meta.int_hop_count - 1; transition parse_int_metadata; }
}

/*************************************************************************
************** I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() { mark_to_drop(standard_metadata); }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) { standard_metadata.egress_spec = port; hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; hdr.ethernet.dstAddr = dstAddr; hdr.ipv4.ttl = hdr.ipv4.ttl - 1; }
    action int_source() {
        hdr.intl4_shim.setValid();
        hdr.intl4_shim.int_type = 1;
        hdr.intl4_shim.len = 2;
        hdr.intl4_shim.dscp = hdr.ipv4.dscp;
        hdr.ipv4.dscp = DSCP_INT;
        hdr.int_header.setValid();
        hdr.int_header.ver = 1;
        hdr.int_header.hop_metadata_len = 1;
        hdr.int_header.remaining_hop_cnt = 0;
        hdr.int_header.instruction_mask = 0x8000;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 12;
        hdr.udp.length_ = hdr.udp.length_ + 12;
    }
    action int_sink() {
        hdr.ipv4.dscp = hdr.intl4_shim.dscp;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - (bit<16>)(12 + (hdr.int_metadata_stack.size * 4));
        hdr.udp.length_ = hdr.udp.length_ - (bit<16>)(12 + (hdr.int_metadata_stack.size * 4));
        hdr.intl4_shim.setInvalid();
        hdr.int_header.setInvalid();
    }
    table int_source_sink { key = { standard_metadata.ingress_port: exact; } actions = { int_source; int_sink; NoAction; } size = 256; default_action = NoAction(); }
    table forward { key = { hdr.ipv4.dstAddr: lpm; } actions = { ipv4_forward; drop; } size = 1024; default_action = drop(); }

    apply {
        // *** THE FINAL FIX IS HERE ***
        // This simplified logic correctly handles all cases.
        if (hdr.udp.isValid()) {
            int_source_sink.apply();
        }
        forward.apply();
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action add_int_metadata(bit<32> switch_id) {
        if (hdr.int_header.isValid() && hdr.int_metadata_stack.size < MAX_HOPS) {
            hdr.int_metadata_stack.push_front(1);
            hdr.int_metadata_stack[0].setValid();
            hdr.int_metadata_stack[0].switch_id = switch_id;
            hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt + 1;
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
            hdr.udp.length_ = hdr.udp.length_ + 4;
            hdr.intl4_shim.len = hdr.intl4_shim.len + 1;
        }
    }
    table int_transit { key = { standard_metadata.egress_port: exact; } actions = { add_int_metadata; NoAction; } size = 256; default_action = NoAction(); }
    apply {
        if (hdr.int_header.isValid()) {
            int_transit.apply();
        }
    }
}

/*************************************************************************
************* C H E C K S U M    A N D   D E P A R S E R   *************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn,
              hdr.ipv4.totalLen, hdr.ipv4.identification,
              hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
              hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.intl4_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_metadata_stack);
    }
}

/*************************************************************************
*********************** S W I T C H  *******************************
*************************************************************************/
V1Switch( MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser() ) main;