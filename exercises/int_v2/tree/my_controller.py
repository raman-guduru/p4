#!/usr/bin/env python3
import argparse
import os
import sys
import traceback

script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(script_dir, '../../../utils'))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

# --- P4Runtime Helper Functions from other exercises ---
def write_l3_rule(p4info_helper, sw, dst_ip_addr, prefix_len,
                  dst_eth_addr, src_eth_addr, egress_port):
    """
    Writes a forwarding rule to the l3_forward.ipv4_lpm table
    """
    table_entry = p4info_helper.buildTableEntry(  # FIX: Was build_table_entry
        table_name="MyIngress.l3_forward.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dst_addr": (dst_ip_addr, prefix_len)
        },
        action_name="MyIngress.l3_forward.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "srcAddr": src_eth_addr,
            "port": egress_port
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] L3 Rule: {dst_ip_addr}/{prefix_len} -> port {egress_port}")

def write_transit_rule(p4info_helper, sw, node_id):
    """
    Writes the default transit rule to tb_int_insert
    """
    table_entry = p4info_helper.buildTableEntry(  # FIX: Was build_table_entry
        table_name="MyEgress.process_int_transit.tb_int_insert",
        default_action=True,
        action_name="MyEgress.process_int_transit.init_metadata",
        action_params={
            "node_id": node_id
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Transit Rule: node_id {node_id}")

def write_source_rules(p4info_helper, sw, h2_ip, hop_count):
    """
    Writes the INT source rules
    """
    # 1. tb_set_source: Activate INT on ingress port 1
    table_entry = p4info_helper.buildTableEntry(  # FIX: Was build_table_entry
        table_name="MyIngress.process_int_source_sink.tb_set_source",
        match_fields={
            "standard_metadata.ingress_port": 1
        },
        action_name="MyIngress.process_int_source_sink.int_set_source",
        action_params={})
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Source Rule: Activating on port 1")

    # 2. tb_int_source: Configure INT headers for traffic to h2
    table_entry = p4info_helper.buildTableEntry(  # FIX: Was build_table_entry
        table_name="MyIngress.process_int_source.tb_int_source",
        match_fields={
            "hdr.ipv4.dst_addr": (h2_ip, 32)
        },
        action_name="MyIngress.process_int_source.int_source",
        action_params={
            "hop_metadata_len": 11,
            "remaining_hop_cnt": hop_count,
            "ins_mask0003": 15,
            "ins_mask0407": 15
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Source Rule: Configuring headers for {h2_ip}")

def write_sink_rules(p4info_helper, sw, h_report_ip, h_report_mac, my_report_mac):
    """
    Writes the INT sink rules
    """
    # 1. tb_set_sink: Activate sink on egress port 2
    table_entry = p4info_helper.buildTableEntry(  # FIX: Was build_table_entry
        table_name="MyIngress.process_int_source_sink.tb_set_sink",
        match_fields={
            "standard_metadata.egress_port": 2
        },
        action_name="MyIngress.process_int_source_sink.int_set_sink",
        action_params={})
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Sink Rule: Activating on port 2")

    # 2. tb_generate_report: Configure the report packet encapsulation
    table_entry = p4info_helper.buildTableEntry(  # FIX: Was build_table_entry
        table_name="MyEgress.process_int_report.tb_generate_report",
        default_action=True,
        action_name="MyEgress.process_int_report.do_report_encapsulation",
        action_params={
            "src_mac": my_report_mac,
            "mon_mac": h_report_mac,
            "src_ip": h_report_ip.rsplit('.', 1)[0] + '.1', # e.g., 10.0.36.1
            "mon_ip": h_report_ip,
            "src_port": 6666,
            "mon_port": 24576
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Sink Rule: Configuring report to {h_report_ip}")

def write_clone_session(p4info_helper, sw, egress_port): # FIX: Added p4info_helper
    """
    Writes the clone session entry for the INT report
    """
    clone_session_id = 500 # From your headers.p4
    
    # FIX: Use buildCloneSessionEntry as shown in example
    # The '0' for packet_length_bytes means do not truncate.
    clone_entry = p4info_helper.buildCloneSessionEntry(clone_session_id,
                                                       replicas=[{ "egress_port": egress_port, "instance": 1 }],
                                                       packet_length_bytes=0)
    
    sw.WritePREEntry(clone_entry) # FIX: Use WritePREEntry
    print(f"    [{sw.name}] Clone Session: ID {clone_session_id} -> port {egress_port}")

def main(p4info_file_path, bmv2_json_file):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    # Host and gateway MACs from topology.json
    hosts = {
        'h1': {'ip': '10.0.1.1', 'mac': '08:00:00:00:01:11', 'gw_mac': '08:00:00:00:01:00'},
        'h2': {'ip': '10.0.2.2', 'mac': '08:00:00:00:02:22', 'gw_mac': '08:00:00:00:02:00'},
        'h3': {'ip': '10.0.3.3', 'mac': '08:00:00:00:03:33', 'gw_mac': '08:00:00:00:03:00'},
        'h4': {'ip': '10.0.4.4', 'mac': '08:00:00:00:04:44', 'gw_mac': '08:00:00:00:04:00'}
    }

    # Port mapping based on topology.json
    # s1: p1->s2, p2->s3
    # s2: p1->s1, p2->s4, p3->s5
    # s3: p1->s1, p2->s6, p3->s7
    # s4: p1->s2, p3->h1
    # s5: p1->s2, p3->h2
    # s6: p1->s3, p3->h3
    # s7: p1->s3, p3->h4

    switches = {}
    try:
        # Create switch connections
        s_conns = [p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=f's{i}', address=f'127.0.0.1:{50050+i}', device_id=i-1,
            proto_dump_file=f'logs/s{i}-p4runtime-requests.txt'
        ) for i in range(1, 8)]

        # Program the switches
        for sw in s_conns:
            print(f"\n--- Configuring {sw.name} ---")
            sw.MasterArbitrationUpdate()
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_json_file)
            print(f"    [{sw.name}] Installed P4 Program")
            switches[sw.name] = sw

        # --- s1 (Root) ---
        s1 = switches['s1']
        write_transit_rule(p4info_helper, s1, 1)
        # To h1, h2 (via s2)
        write_l3_rule(p4info_helper, s1, hosts['h1']['ip'], 32, "00:00:00:02:01:00", "00:00:00:01:02:00", 1)
        write_l3_rule(p4info_helper, s1, hosts['h2']['ip'], 32, "00:00:00:02:01:00", "00:00:00:01:02:00", 1)
        # To h3, h4 (via s3)
        write_l3_rule(p4info_helper, s1, hosts['h3']['ip'], 32, "00:00:00:03:01:00", "00:00:00:01:03:00", 2)
        write_l3_rule(p4info_helper, s1, hosts['h4']['ip'], 32, "00:00:00:03:01:00", "00:00:00:01:03:00", 2)

        # --- s2 (Agg) ---
        s2 = switches['s2']
        write_transit_rule(p4info_helper, s2, 2)
        # To h1 (via s4)
        write_l3_rule(p4info_helper, s2, hosts['h1']['ip'], 32, "00:00:00:04:01:00", "00:00:00:02:04:00", 2)
        # To h2 (via s5)
        write_l3_rule(p4info_helper, s2, hosts['h2']['ip'], 32, "00:00:00:05:01:00", "00:00:00:02:05:00", 3)
        # To h3, h4 (via s1)
        write_l3_rule(p4info_helper, s2, hosts['h3']['ip'], 32, "00:00:00:01:02:00", "00:00:00:02:01:00", 1)
        write_l3_rule(p4info_helper, s2, hosts['h4']['ip'], 32, "00:00:00:01:02:00", "00:00:00:02:01:00", 1)

        # --- s3 (Agg) ---
        s3 = switches['s3']
        write_transit_rule(p4info_helper, s3, 3)
        # To h3 (via s6)
        write_l3_rule(p4info_helper, s3, hosts['h3']['ip'], 32, "00:00:00:06:01:00", "00:00:00:03:06:00", 2)
        # To h4 (via s7)
        write_l3_rule(p4info_helper, s3, hosts['h4']['ip'], 32, "00:00:00:07:01:00", "00:00:00:03:07:00", 3)
        # To h1, h2 (via s1)
        write_l3_rule(p4info_helper, s3, hosts['h1']['ip'], 32, "00:00:00:01:03:00", "00:00:00:03:01:00", 1)
        write_l3_rule(p4info_helper, s3, hosts['h2']['ip'], 32, "00:00:00:01:03:00", "00:00:00:03:01:00", 1)

        # --- s4 (Leaf) ---
        s4 = switches['s4']
        write_transit_rule(p4info_helper, s4, 4)
        write_l3_rule(p4info_helper, s4, hosts['h1']['ip'], 32, hosts['h1']['mac'], hosts['h1']['gw_mac'], 3) # To h1
        # Uplink to s2
        write_l3_rule(p4info_helper, s4, hosts['h2']['ip'], 32, "00:00:00:02:04:00", "00:00:00:04:01:00", 1)
        write_l3_rule(p4info_helper, s4, hosts['h3']['ip'], 32, "00:00:00:02:04:00", "00:00:00:04:01:00", 1)
        write_l3_rule(p4info_helper, s4, hosts['h4']['ip'], 32, "00:00:00:02:04:00", "00:00:00:04:01:00", 1)
        write_source_rules(p4info_helper, s4, "10.0.0.0", 3) # Dummy IP, hop count
        write_sink_rules(p4info_helper, s4, hosts['h1']['ip'], hosts['h1']['mac'], hosts['h1']['gw_mac'])
        write_clone_session(p4info_helper, s4, egress_port=3)

        # --- s5 (Leaf) ---
        s5 = switches['s5']
        write_transit_rule(p4info_helper, s5, 5)
        write_l3_rule(p4info_helper, s5, hosts['h2']['ip'], 32, hosts['h2']['mac'], hosts['h2']['gw_mac'], 3) # To h2
        # Uplink to s2
        write_l3_rule(p4info_helper, s5, hosts['h1']['ip'], 32, "00:00:00:02:05:00", "00:00:00:05:01:00", 1)
        write_l3_rule(p4info_helper, s5, hosts['h3']['ip'], 32, "00:00:00:02:05:00", "00:00:00:05:01:00", 1)
        write_l3_rule(p4info_helper, s5, hosts['h4']['ip'], 32, "00:00:00:02:05:00", "00:00:00:05:01:00", 1)
        write_source_rules(p4info_helper, s5, "10.0.0.0", 3)
        write_sink_rules(p4info_helper, s5, hosts['h2']['ip'], hosts['h2']['mac'], hosts['h2']['gw_mac'])
        write_clone_session(p4info_helper, s5, egress_port=3)

        # --- s6 (Leaf) ---
        s6 = switches['s6']
        write_transit_rule(p4info_helper, s6, 6)
        write_l3_rule(p4info_helper, s6, hosts['h3']['ip'], 32, hosts['h3']['mac'], hosts['h3']['gw_mac'], 3) # To h3
        # Uplink to s3
        write_l3_rule(p4info_helper, s6, hosts['h1']['ip'], 32, "00:00:00:03:06:00", "00:00:00:06:01:00", 1)
        write_l3_rule(p4info_helper, s6, hosts['h2']['ip'], 32, "00:00:00:03:06:00", "00:00:00:06:01:00", 1)
        write_l3_rule(p4info_helper, s6, hosts['h4']['ip'], 32, "00:00:00:03:06:00", "00:00:00:06:01:00", 1)
        write_source_rules(p4info_helper, s6, "10.0.0.0", 3)
        write_sink_rules(p4info_helper, s6, hosts['h3']['ip'], hosts['h3']['mac'], hosts['h3']['gw_mac'])
        write_clone_session(p4info_helper, s6, egress_port=3)

        # --- s7 (Leaf) ---
        s7 = switches['s7']
        write_transit_rule(p4info_helper, s7, 7)
        write_l3_rule(p4info_helper, s7, hosts['h4']['ip'], 32, hosts['h4']['mac'], hosts['h4']['gw_mac'], 3) # To h4
        # Uplink to s3
        write_l3_rule(p4info_helper, s7, hosts['h1']['ip'], 32, "00:00:00:03:07:00", "00:00:00:07:01:00", 1)
        write_l3_rule(p4info_helper, s7, hosts['h2']['ip'], 32, "00:00:00:03:07:00", "00:00:00:07:01:00", 1)
        write_l3_rule(p4info_helper, s7, hosts['h3']['ip'], 32, "00:00:00:03:07:00", "00:00:00:07:01:00", 1)
        write_source_rules(p4info_helper, s7, "10.0.0.0", 3)
        write_sink_rules(p4info_helper, s7, hosts['h4']['ip'], hosts['h4']['mac'], hosts['h4']['gw_mac'])
        write_clone_session(p4info_helper, s7, egress_port=3)

        print("\n--- All switches configured! ---")

    except KeyboardInterrupt:
        print(" Shutting down.")
    except Exception as e:
        print(f"\nAn error occurred:")
        traceback.print_exc()
    finally:
        ShutdownAllSwitchConnections()
        print("Controller shut down.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller for Tree Topology')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, required=False,
                        default='build/int_md.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, required=False,
                        default='build/int_md.json')
    args = parser.parse_args()

    if not os.path.exists('logs'):
        os.makedirs('logs')

    if not os.path.exists(args.p4info):
        parser.error(f"p4info file not found: {args.p4info}")
    if not os.path.exists(args.bmv2_json):
        parser.error(f"BMv2 JSON file not found: {args.bmv2_json}")

    main(args.p4info, args.bmv2_json)