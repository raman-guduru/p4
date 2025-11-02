#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep

# Assuming 'utils' is in your PYTHONPATH
# If not, you may need:
script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(script_dir, '../../../utils'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4.v1 import p4runtime_pb2

# --- Helper Functions to Write P4Runtime Rules ---

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

# --- Main Controller Logic ---

def main(p4info_file, bmv2_json_file, topo_size):
    
    # 1. Instantiate a P4Info helper
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file)

    print(f"--- Starting controller for {topo_size}-switch linear topology ---")

    # 2. Define topology constants (This section is unchanged)
    try:
        N = int(topo_size)
        if N < 2:
            print("Error: Topology size must be at least 2")
            sys.exit(1)
            
        h1_ip = "10.0.1.1"
        h1_mac = "08:00:00:00:01:11"
        s1_mac_for_h1 = "08:00:00:00:01:00"
        
        h2_ip = f"10.0.{N}.{N}"
        h2_mac = f"08:00:00:00:{N:02X}:{N:02X}"
        sN_mac_for_h2 = f"08:00:00:00:{N:02X}:00"

        h_report_ip = f"10.0.{N+1}.{N+1}"
        h_report_mac = f"08:00:00:00:{N+1:02X}:{N+1:02X}"
        sN_mac_for_h_report = f"08:00:00:00:{N+1:02X}:00"
        
    except ValueError:
        print(f"Invalid topology size: {topo_size}")
        sys.exit(1)


    switches = []
    try:
        # 3. Create switch connections (This section is unchanged)
        print("Connecting to switches...")
        for i in range(1, N + 1):
            device_id = i - 1
            port = 50051 + device_id
            sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=f's{i}',
                address=f'127.0.0.1:{port}',
                device_id=device_id,
                proto_dump_file=f'logs/s{i}-p4runtime-requests.txt')
            switches.append(sw)

        # 4. Program all switches
        for i, sw in enumerate(switches):
            node_id = i + 1
            print(f"\n--- Configuring {sw.name} (node_id {node_id}) ---")

            # Send master arbitration update
            sw.MasterArbitrationUpdate()
            print(f"    [{sw.name}] Asserted mastership")

            # Install the P4 program on the switch
            sw.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           bmv2_json_file_path=bmv2_json_file)
            print(f"    [{sw.name}] Installed P4 Program")

            # Write the default INT transit rule (all switches are transit)
            write_transit_rule(p4info_helper, sw, node_id)
            
            # --- Write L3 Forwarding Rules ---
            
            # Rule for h1 (10.0.1.1) -> port 1
            if node_id == 1:
                write_l3_rule(p4info_helper, sw, h1_ip, 32,
                              h1_mac, s1_mac_for_h1, 1)
            else:
                write_l3_rule(p4info_helper, sw, h1_ip, 32,
                              f"00:00:00:{node_id-1:02X}:{node_id:02X}:00", # s(N-1)'s MAC
                              f"00:00:00:{node_id:02X}:{node_id-1:02X}:00", # s(N)'s MAC
                              1)

            # Rule for h2 (e.g., 10.0.3.3) -> port 2
            if node_id == N:
                write_l3_rule(p4info_helper, sw, h2_ip, 32,
                              h2_mac, sN_mac_for_h2, 2)
            else:
                write_l3_rule(p4info_helper, sw, h2_ip, 32,
                              f"00:00:00:{node_id+1:02X}:{node_id:02X}:00", # s(N+1)'s MAC
                              f"00:00:00:{node_id:02X}:{node_id+1:02X}:00", # s(N)'s MAC
                              2)

            # --- Special rules for Source (s1) ---
            if node_id == 1:
                write_source_rules(p4info_helper, sw, h2_ip, N)

            # --- Special rules for Sink (sN) ---
            if node_id == N:
                # Rule for h_report -> port 3
                write_l3_rule(p4info_helper, sw, h_report_ip, 32,
                              h_report_mac, sN_mac_for_h_report, 3)
                
                # Sink and Report rules
                write_sink_rules(p4info_helper, sw, h_report_ip,
                                 h_report_mac, sN_mac_for_h_report)
                
                # Clone session
                write_clone_session(p4info_helper, sw, 3) # Pass p4info_helper
        
        print("\n--- All switches configured successfully! ---")

    except KeyboardInterrupt:
        print(" Shutting down.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        print("Please check that p4runtime_lib is in your PYTHONPATH")
        print("and that the Bmv2 switches are running.")
    finally:
        for sw in switches:
            sw.shutdown()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller for INT_v2')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, required=False, 
                        default='build/int_md.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, required=False, 
                        default='build/int_md.json')
    parser.add_argument('--topo-size', help='Number of switches in the linear topology',
                        type=int, required=True)
    args = parser.parse_args()

    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    if not os.path.exists(args.p4info):
        parser.error(f"p4info file not found: {args.p4info}")
    if not os.path.exists(args.bmv2_json):
        parser.error(f"BMv2 JSON file not found: {args.bmv2_json}")

    main(args.p4info, args.bmv2_json, args.topo_size)