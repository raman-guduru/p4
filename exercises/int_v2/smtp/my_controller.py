#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

def write_l3_rule(p4info_helper, sw, dst_ip_addr, dst_eth_addr, src_eth_addr, port):
    """
    Installs a forwarding rule for the given destination IP address.
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.l3_forward.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dst_addr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.l3_forward.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "srcAddr": src_eth_addr,
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] L3 Rule: {dst_ip_addr}/32 -> port {port}")


def write_transit_rule(p4info_helper, sw, node_id):
    """
    Installs a default INT transit rule.
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.process_int_transit.tb_int_insert",
        default_action=True,
        action_name="MyEgress.process_int_transit.init_metadata",
        action_params={
            "node_id": node_id
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Transit Rule: node_id {node_id}")


def write_source_rules(p4info_helper, sw, dst_ip, hop_count):
    """
    Installs INT source rules for TCP traffic.
    """
    # 1. Activate INT source on ingress port 1
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.process_int_source_sink.tb_set_source",
        match_fields={
            "standard_metadata.ingress_port": 1
        },
        action_name="MyIngress.process_int_source_sink.int_set_source",
        action_params={})
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Source Rule: Activating on port 1")

    # 2. Configure INT headers for TCP traffic to the destination
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.process_int_source.tb_int_source",
        match_fields={
            "hdr.ipv4.dst_addr": (dst_ip, 32)
        },
        action_name="MyIngress.process_int_source.int_source",
        action_params={
            "hop_metadata_len": 11,
            "remaining_hop_cnt": hop_count,
            "ins_mask0003": 15,
            "ins_mask0407": 15
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Source Rule: Applying INT to TCP flow for {dst_ip}")


def write_sink_rules(p4info_helper, sw, report_dst_ip, report_dst_mac, my_report_mac):
    """
    Installs INT sink rules.
    """
    # 1. Activate sink on egress port 2 (towards h2)
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.process_int_source_sink.tb_set_sink",
        match_fields={
            "standard_metadata.egress_port": 2
        },
        action_name="MyIngress.process_int_source_sink.int_set_sink",
        action_params={})
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Sink Rule: Activating on egress port 2")

    # Make the report source IP dynamic, placing it in the h_report subnet.
    report_src_ip = report_dst_ip.rsplit('.', 1)[0] + ".254"

    # 2. Configure report generation
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.process_int_report.tb_generate_report",
        default_action=True,
        action_name="MyEgress.process_int_report.do_report_encapsulation",
        action_params={
            "src_mac": my_report_mac,
            "mon_mac": report_dst_mac,
            "src_ip": report_src_ip,
            "mon_ip": report_dst_ip,
            "src_port": 6666,
            "mon_port": 24576
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Sink Rule: Configuring report to {report_dst_ip}")


def write_clone_session(p4info_helper, sw, egress_port):
    """
    Writes the clone session entry for the INT report.
    """
    clone_session_id = 500
    clone_entry = p4info_helper.buildCloneSessionEntry(
        clone_session_id,
        replicas=[{ "egress_port": egress_port, "instance": 1 }],
        # For E2E clones, this specifies how many bytes of the original packet to
        # include. 0 would mean none. We set it high to get the full packet.
        packet_length_bytes=0
    )
    sw.WritePREEntry(clone_entry)
    print(f"    [{sw.name}] Clone Session: ID {clone_session_id} -> port {egress_port}")


def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    print(f"--- Starting controller for FIXED 5-switch linear topology ---")

    # --- Hardcoded constants for 10-switch topology ---
    # Hosts
    h1_ip = "10.0.1.1"; h1_mac = "08:00:00:00:01:11"
    h2_ip = "10.0.5.5"; h2_mac = "08:00:00:00:05:05"
    h_report_ip = "10.0.6.6"; h_report_mac = "08:00:00:00:06:06"

    # Switch port MACs (Format: 08:00:00:00:[switch_num]:[port_num])
    # These MUST match the ARP entries in topology.json
    s1_p1_mac = "08:00:00:00:01:01"; s1_p2_mac = "08:00:00:00:01:02"
    s2_p1_mac = "08:00:00:00:02:01"; s2_p2_mac = "08:00:00:00:02:02"
    s3_p1_mac = "08:00:00:00:03:01"; s3_p2_mac = "08:00:00:00:03:02"
    s4_p1_mac = "08:00:00:00:04:01"; s4_p2_mac = "08:00:00:00:04:02"
    s5_p1_mac = "08:00:00:00:05:01"; s5_p2_mac = "08:00:00:00:05:02"; s5_p3_mac = "08:00:00:00:05:03"

    try:
        # Create switch connections
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection('s1', '127.0.0.1:50051', 0)
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection('s2', '127.0.0.1:50052', 1)
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection('s3', '127.0.0.1:50053', 2)
        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection('s4', '127.0.0.1:50054', 3)
        s5 = p4runtime_lib.bmv2.Bmv2SwitchConnection('s5', '127.0.0.1:50055', 4)
        switches = [s1, s2, s3, s4, s5]

        # Mastership + P4 program installation
        for sw in switches:
            sw.MasterArbitrationUpdate()
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)

        # --- s1 Rules (Source) ---
        print("\n--- Configuring s1 (node_id 1) ---")
        write_l3_rule(p4info_helper, s1, h1_ip, h1_mac, s1_p1_mac, 1) # To h1
        write_l3_rule(p4info_helper, s1, h2_ip, s2_p1_mac, s1_p2_mac, 2) # To s2
        write_transit_rule(p4info_helper, s1, node_id=1)
        write_source_rules(p4info_helper, s1, dst_ip=h2_ip, hop_count=5)

        # --- s2 Rules (Transit) ---
        print("\n--- Configuring s2 (node_id 2) ---")
        write_l3_rule(p4info_helper, s2, h1_ip, s1_p2_mac, s2_p1_mac, 1) # To s1
        write_l3_rule(p4info_helper, s2, h2_ip, s3_p1_mac, s2_p2_mac, 2) # To s3
        write_transit_rule(p4info_helper, s2, node_id=2)

        # --- s3 Rules (Transit) ---
        print("\n--- Configuring s3 (node_id 3) ---")
        write_l3_rule(p4info_helper, s3, h1_ip, s2_p2_mac, s3_p1_mac, 1) # To s2
        write_l3_rule(p4info_helper, s3, h2_ip, s4_p1_mac, s3_p2_mac, 2) # To s4
        write_transit_rule(p4info_helper, s3, node_id=3)

        # --- s4 Rules (Transit) ---
        print("\n--- Configuring s4 (node_id 4) ---")
        write_l3_rule(p4info_helper, s4, h1_ip, s3_p2_mac, s4_p1_mac, 1) # To s3
        write_l3_rule(p4info_helper, s4, h2_ip, s5_p1_mac, s4_p2_mac, 2) # To s5 (sink)
        write_transit_rule(p4info_helper, s4, node_id=4)

        # --- s5 Rules (Sink) ---
        print("\n--- Configuring s5 (node_id 5) ---")
        write_l3_rule(p4info_helper, s5, h1_ip, s4_p2_mac, s5_p1_mac, 1) # To s4
        write_l3_rule(p4info_helper, s5, h2_ip, h2_mac, s5_p2_mac, 2) # To h2
        write_l3_rule(p4info_helper, s5, h_report_ip, h_report_mac, s5_p3_mac, 3) # To h_report
        write_transit_rule(p4info_helper, s5, node_id=5)
        write_sink_rules(p4info_helper, s5, report_dst_ip=h_report_ip, report_dst_mac=h_report_mac, my_report_mac=s5_p3_mac)
        write_clone_session(p4info_helper, s5, egress_port=3)

        print("\n--- All switches configured successfully! ---")

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        print("gRPC Error:", e)
    finally:
        ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    # Arguments are unchanged
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/int_md.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/int_md.json')
    args = parser.parse_args()

    if not os.path.exists('logs'):
        os.makedirs('logs')

    if not os.path.exists(args.p4info):
        parser.print_help()
        print(f"\np4info file not found: {args.p4info}\nHave you run 'make'?")
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print(f"\nBMv2 JSON file not found: {args.bmv2_json}\nHave you run 'make'?")
        parser.exit(1)

    main(args.p4info, args.bmv2_json)