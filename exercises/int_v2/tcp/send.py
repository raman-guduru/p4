#!/usr/bin/env python3
import socket
import sys
import time

def send_tcp_packets(dest_ip, dest_port, message, count):
    """
    Connects to a TCP server and sends a number of messages.
    """
    try:
        # Create a TCP/IP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the connection attempt (e.g., 5 seconds)
            s.settimeout(30)
 
            # Connect the socket to the port where the server is listening
            server_address = (dest_ip, dest_port)
            print(f"Connecting to {dest_ip} on port {dest_port}...")
            s.connect(server_address)
            print("Connection established (SYN/SYN-ACK/ACK complete).")

            # Loop to send multiple data packets
            for i in range(count):
                packet_message = f"{message} (Packet {i + 1}/{count})"
                print(f"Sending data: '{packet_message}'")
                s.sendall(packet_message.encode('utf-8'))
                # Small delay to ensure packets are sent separately
                time.sleep(0.2)

            print(f"\nSuccessfully sent {count} packets.")

    except ConnectionRefusedError:
        print(f"Error: Connection refused. Is the receiver script running on {dest_ip}?")
    except socket.timeout:
        print(f"Error: Connection timed out. The host {dest_ip} is unreachable.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # From topology.json, h2 has IP 10.0.5.5 for a 5-switch topology
    dest_ip = "10.0.5.5"
    dest_port = 9999
    packet_count = 10
    default_message = "This is a test TCP packet for P4 INT from h1."
 
    # Allow custom message from command line
    if len(sys.argv) > 1:
        message = ' '.join(sys.argv[1:])
    else:
        message = default_message
 
    send_tcp_packets(dest_ip, dest_port, message, packet_count)