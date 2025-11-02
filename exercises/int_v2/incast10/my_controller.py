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
# (These are identical to the ones that worked for you before)

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
            "src_ip": h_report_ip.rsplit('.', 1)[0] + '.10', # e.g., 10.0.21.10
            "mon_ip": h_report_ip,
            "src_port": 6666,
            "mon_port": 24576
        })
    sw.WriteTableEntry(table_entry)
    print(f"    [{sw.name}] INT Sink Rule: Configuring report to {h_report_ip}")

def write_clone_session(p4info_helper, sw, egress_port):
    clone_session_id = 500
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

def connect_switches(p4info_helper, bmv2_json_file, sw_names):
    switches = {}
    print("Connecting to switches...")
    try:
        for i, sw_name in enumerate(sw_names):
            device_id = i
            port = 50051 + device_id
            sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=sw_name,
                address=f'127.0.0.1:{port}',
                device_id=device_id,
                proto_dump_file=f'logs/{sw_name}-p4runtime-requests.txt')
            
            sw.MasterArbitrationUpdate()
            print(f"    [{sw_name}] Asserted mastership")

            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_json_file)
            print(f"    [{sw_name}] Installed P4 Program")
            switches[sw_name] = sw
    except Exception as e:
        print(f"\nAn error occurred while connecting to {sw_name} (ID {device_id} at port {port}):")
        print(e)
        print("Please ensure 'sudo mn -c' was run and Mininet is running.")
        for sw in switches.values():
            sw.shutdown()
        sys.exit(1)
        
    return switches

# --- Main ---
def main(p4info_file, bmv2_json_file):
    
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file)
    sw_names = [f's{i}' for i in range(1, 13)] # s1 through s12
    
    print(f"--- Starting controller for INCAST-10 topology ---")

    h_dst_ip = "10.0.20.20"
    h_report_ip = "10.0.21.21"

    switches = {}
    try:
        switches = connect_switches(p4info_helper, bmv2_json_file, sw_names)

        # --- Program s1 through s10 (Sources) ---
        for node_id in range(1, 11):
            sw = switches[f's{node_id}']
            host_ip = f"10.0.{node_id}.{node_id}"
            host_mac = f"08:00:00:00:{node_id:02X}:{node_id:02X}"
            gw_mac = f"08:00:00:00:{node_id:02X}:00"
            
            print(f"\n--- Configuring s{node_id} (Source) ---")
            write_transit_rule(p4info_helper, sw, node_id)
            
            # Rule for local host -> port 1
            write_l3_rule(p4info_helper, sw, host_ip, 32, host_mac, gw_mac, 1)
            # Rule for h_dst -> port 2 (to s11)
            write_l3_rule(p4info_helper, sw, h_dst_ip, 32, 
                          f"00:00:00:0B:{node_id:02X}:00",  # s11's MAC for sX
                          f"00:00:00:{node_id:02X}:0B:00",  # sX's MAC for s11
                          2)
            
            # Activate INT on port 1 for traffic to h_dst
            write_source_port_activation(p4info_helper, sw, ingress_port=1)
            write_source_flow_rule(p4info_helper, sw, h_dst_ip=h_dst_ip, hop_count=3) # Hops: sX, s11, s12

        # --- Program s11 (Bottleneck/Aggregator) ---
        s11 = switches['s11']
        print(f"\n--- Configuring s11 (Bottleneck) ---")
        write_transit_rule(p4info_helper, s11, node_id=11)
        
        # Rule for h_dst -> port 11 (to s12)
        write_l3_rule(p4info_helper, s11, h_dst_ip, 32, 
                      "00:00:00:0C:0B:00",  # s12's MAC
                      "00:00:00:0B:0C:00",  # s11's MAC
                      11)
        # Rules for h_report -> port 11 (to s12)
        write_l3_rule(p4info_helper, s11, h_report_ip, 32, 
                      "00:00:00:0C:0B:00",  # s12's MAC
                      "00:00:00:0B:0C:00",  # s11's MAC
                      11)
        
        # Add return paths for h1-h10
        for node_id in range(1, 11):
            host_ip = f"10.0.{node_id}.{node_id}"
            write_l3_rule(p4info_helper, s11, host_ip, 32,
                          f"00:00:00:{node_id:02X}:0B:00",  # sX's MAC
                          f"00:00:00:0B:{node_id:02X}:00",  # s11's MAC
                          node_id) # Port is the node_id (e.g., s1 is on p1, s2 on p2)
                          
        # --- Program s12 (Sink) ---
        s12 = switches['s12']
        print(f"\n--- Configuring s12 (Sink) ---")
        write_transit_rule(p4info_helper, s12, node_id=12)
        
        # L3 Rules for final destinations
        write_l3_rule(p4info_helper, s12, h_dst_ip, 32, 
                      "08:00:00:00:20:20", "08:00:00:00:20:00", 2) # to h_dst
        write_l3_rule(p4info_helper, s12, h_report_ip, 32, 
                      "08:00:00:00:21:21", "08:00:00:00:21:00", 3) # to h_report
        
        # INT Sink Rules
        write_sink_rules(p4info_helper, s12, sink_port=2,
                         h_report_ip=h_report_ip, h_report_mac="08:00:00:00:21:21",
                         my_report_mac="08:00:00:00:21:00")
        write_clone_session(p4info_helper, s12, egress_port=3)
        
        print(f"\n--- 'incast-10' topology configured successfully! ---")

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
    parser = argparse.ArgumentParser(description='P4Runtime Controller for Incast-10 Topo')
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