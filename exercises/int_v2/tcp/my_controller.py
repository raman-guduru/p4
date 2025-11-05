#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import os
import sys
from time import sleep

import grpc
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
            "hdr.ipv4.dst_addr": (dst_ip, 32),
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

    report_src_ip = f"10.0.4.254"

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
        # The P4 program uses clone_e2e, which clones the packet *after* egress processing.
        packet_length_bytes=0  # 0 means do not truncate
    )
    sw.WritePREEntry(clone_entry)
    print(f"    [{sw.name}] Clone Session: ID {clone_session_id} -> port {egress_port}")


def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    print(f"--- Starting controller for 3-switch linear topology ---")

    # Hardcoded topology constants
    h1_ip = "10.0.1.1"; h1_mac = "08:00:00:00:01:11"
    h2_ip = "10.0.3.3"; h2_mac = "08:00:00:00:03:03"
    h_report_ip = "10.0.4.4"; h_report_mac = "08:00:00:00:04:44"

    s1_mac_p1 = "08:00:00:00:01:00" # To h1
    s1_mac_p2 = "08:00:00:00:01:00" # To s2

    s2_mac_p1 = "08:00:00:00:02:00" # To s1
    s2_mac_p2 = "08:00:00:00:02:00" # To s3

    s3_mac_p1 = "08:00:00:00:03:00" # To s2
    s3_mac_p2 = "08:00:00:00:03:00" # To h2
    s3_mac_p3 = "08:00:00:00:04:00" # To h_report

    try:
        # Create switch connections
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(name='s1', address='127.0.0.1:50051', device_id=0, proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(name='s2', address='127.0.0.1:50052', device_id=1, proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(name='s3', address='127.0.0.1:50053', device_id=2, proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Mastership + P4 program installation
        s1.MasterArbitrationUpdate(); s2.MasterArbitrationUpdate(); s3.MasterArbitrationUpdate()
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)

        # --- s1 Rules (Source) ---
        print("\n--- Configuring s1 (node_id 1) ---")
        # L3 Forwarding
        write_l3_rule(p4info_helper, s1, dst_ip_addr=h1_ip, dst_eth_addr=h1_mac, src_eth_addr=s1_mac_p1, port=1)
        write_l3_rule(p4info_helper, s1, dst_ip_addr=h2_ip, dst_eth_addr=s2_mac_p1, src_eth_addr=s1_mac_p2, port=2)
        # INT Rules
        write_transit_rule(p4info_helper, s1, node_id=1)
        write_source_rules(p4info_helper, s1, dst_ip=h2_ip, hop_count=3)

        # --- s2 Rules (Transit) ---
        print("\n--- Configuring s2 (node_id 2) ---")
        # L3 Forwarding
        write_l3_rule(p4info_helper, s2, dst_ip_addr=h1_ip, dst_eth_addr=s1_mac_p2, src_eth_addr=s2_mac_p1, port=1)
        write_l3_rule(p4info_helper, s2, dst_ip_addr=h2_ip, dst_eth_addr=s3_mac_p1, src_eth_addr=s2_mac_p2, port=2)
        # INT Rules
        write_transit_rule(p4info_helper, s2, node_id=2)

        # --- s3 Rules (Sink) ---
        print("\n--- Configuring s3 (node_id 3) ---")
        # L3 Forwarding
        write_l3_rule(p4info_helper, s3, dst_ip_addr=h1_ip, dst_eth_addr=s2_mac_p2, src_eth_addr=s3_mac_p1, port=1)
        write_l3_rule(p4info_helper, s3, dst_ip_addr=h2_ip, dst_eth_addr=h2_mac, src_eth_addr=s3_mac_p2, port=2)
        write_l3_rule(p4info_helper, s3, dst_ip_addr=h_report_ip, dst_eth_addr=h_report_mac, src_eth_addr=s3_mac_p3, port=3)
        # INT Rules
        write_transit_rule(p4info_helper, s3, node_id=3)
        write_sink_rules(p4info_helper, s3, report_dst_ip=h_report_ip, report_dst_mac=h_report_mac, my_report_mac=s3_mac_p3)
        write_clone_session(p4info_helper, s3, egress_port=3)

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