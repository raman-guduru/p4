#!/usr/bin/env python3
import argparse
import os
import sys
import traceback

# Add the utils directory to the path
script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(script_dir, '../../../utils'))

import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4.v1 import p4runtime_pb2

# --- P4Runtime Helper Functions ---
# (These are identical to your previous controller, I'm including them
# for completeness. No changes to helpers are needed.)

def write_l3_rule(p4info_helper, sw, dst_ip_addr, prefix_len,
                  dst_eth_addr, src_eth_addr, egress_port):
    table_entry = p4info_helper.buildTableEntry(
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
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.process_int_transit.tb_int_insert",
        default_action=True,
        action_name="MyEgress.process_int_transit.init_metadata",
        action_params={
            "node_id": node_id
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Transit Rule: node_id {node_id}")

def write_source_port_activation(p4info_helper, sw, ingress_port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.process_int_source_sink.tb_set_source",
        match_fields={
            "standard_metadata.ingress_port": ingress_port
        },
        action_name="MyIngress.process_int_source_sink.int_set_source",
        action_params={})
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Source Rule: Activating on port {ingress_port}")

def write_source_flow_rule(p4info_helper, sw, h_dst_ip, hop_count):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.process_int_source.tb_int_source",
        match_fields={
            "hdr.ipv4.dst_addr": (h_dst_ip, 32)
        },
        action_name="MyIngress.process_int_source.int_source",
        action_params={
            "hop_metadata_len": 11,
            "remaining_hop_cnt": hop_count,
            "ins_mask0003": 15,
            "ins_mask0407": 15
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Source Rule: Applying INT to flow for {h_dst_ip}")

def write_sink_rules(p4info_helper, sw, sink_port, h_report_ip, h_report_mac, my_report_mac):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.process_int_source_sink.tb_set_sink",
        match_fields={
            "standard_metadata.egress_port": sink_port
        },
        action_name="MyIngress.process_int_source_sink.int_set_sink",
        action_params={})
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Sink Rule: Activating on port {sink_port}")

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.process_int_report.tb_generate_report",
        default_action=True,
        action_name="MyEgress.process_int_report.do_report_encapsulation",
        action_params={
            "src_mac": my_report_mac,
            "mon_mac": h_report_mac,
            "src_ip": "10.0.2.10", # Gateway IP from topology file
            "mon_ip": h_report_ip,
            "src_port": 6666,
            "mon_port": 24576
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Sink Rule: Configuring report to {h_report_ip}")

def write_clone_session(p4info_helper, sw, egress_port):
    clone_session_id = 500 #
    replicas = [
        { "egress_port": egress_port, "instance": 1 }
    ]
    clone_entry = p4info_helper.buildCloneSessionEntry(
        clone_session_id,
        replicas,
        0  # 0 means do not truncate
    )
    sw.WritePREEntry(clone_entry)
    print(f"    [{sw.name}] Clone Session: ID {clone_session_id} -> port {egress_port}")

# --- Main ---
def main(p4info_file, bmv2_json_file):
    
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file)

    print(f"--- Starting controller for 2-Switch INCAST topology ---")
    
    h_dst_ip = "10.0.2.4"
    h_report_ip = "10.0.2.5"

    switches = {}
    try:
        # --- Connect to s1 and s2 ---
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        
        switches = {'s1': s1, 's2': s2}
        
        # --- Program s1 (Source/Aggregator) ---
        print(f"\n--- Configuring s1 (node_id 1) ---")
        s1.MasterArbitrationUpdate()
        print(f"    [s1] Asserted mastership")
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_json_file)
        print(f"    [s1] Installed P4 Program")
        write_transit_rule(p4info_helper, s1, node_id=1)
    
        # L3 Forwarding Rules for s1
        for i in range(1, 21):
            write_l3_rule(p4info_helper, s1, f"10.0.1.{i}", 32, f"08:00:00:00:01:{i:02x}", "08:00:00:00:01:00", i)
        # Send traffic for h_dst and h_report to s2 (port 21)
        write_l3_rule(p4info_helper, s1, h_dst_ip, 32, "00:00:00:02:01:00", "00:00:00:01:02:00", 21) # to s2
        write_l3_rule(p4info_helper, s1, h_report_ip, 32, "00:00:00:02:01:00", "00:00:00:01:02:00", 21) # to s2

        # INT Source Rules for s1
        for i in range(1, 21):
            write_source_port_activation(p4info_helper, s1, ingress_port=i)
        write_source_flow_rule(p4info_helper, s1, h_dst_ip=h_dst_ip, hop_count=2) # 2 hops (s1, s2)

        # --- Program s2 (Sink) ---
        print(f"\n--- Configuring s2 (node_id 2) ---")
        s2.MasterArbitrationUpdate()
        print(f"    [s2] Asserted mastership")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_json_file)
        print(f"    [s2] Installed P4 Program")
        write_transit_rule(p4info_helper, s2, node_id=2)
        
        # L3 Forwarding Rules for s2
        write_l3_rule(p4info_helper, s2, h_dst_ip, 32, "08:00:00:00:02:44", "08:00:00:00:02:00", 2) # to h_dst
        write_l3_rule(p4info_helper, s2, h_report_ip, 32, "08:00:00:00:02:55", "08:00:00:00:02:00", 3) # to h_report
        
        # INT Sink Rules for s2
        write_sink_rules(p4info_helper, s2, sink_port=2,
                         h_report_ip=h_report_ip, h_report_mac="08:00:00:00:02:55",
                         my_report_mac="08:00:00:00:02:00")
        write_clone_session(p4info_helper, s2, egress_port=3)
        
        print("\n--- Corrected 'incast' topology configured successfully! ---")

    except KeyboardInterrupt:
        print(" Shutting down.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        traceback.print_exc()
    finally:
        for sw in switches.values():
            sw.shutdown()
        print("Controller shut down.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller for 2-Switch Incast Topo')
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