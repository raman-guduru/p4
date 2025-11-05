#!/usr/bin/env python3
import sys
import time
import requests # Use the requests library for making HTTP calls

def send_http_requests(dest_ip, dest_port, message, count):
    """
    Connects to an HTTP server and sends a number of POST requests.
    """
    # NOTE: The 'requests' library might need to be installed if it's not in
    # your environment. You can typically install it with:
    # pip install requests
    
    url = f"http://{dest_ip}:{dest_port}/"
    print(f"Will send {count} POST requests to {url}")

    # Loop to send multiple POST requests
    for i in range(count):
        body = f"{message} (Packet {i + 1}/{count})"
        try:
            print(f"Sending POST request with body: '{body}'")
            # The requests library handles connection, headers, and sending the data.
            response = requests.post(url, data=body, timeout=5)
            response.raise_for_status() # Raises an exception for bad status codes (4xx or 5xx)
            # Small delay to ensure requests are sent as separate TCP segments
            time.sleep(0.2)
        except requests.exceptions.RequestException as e:
            print(f"\nAn error occurred: {e}")
            print("Stopping the sender script.")
            break
    else: # This 'else' belongs to the 'for' loop, runs if the loop completes without 'break'
        print(f"\nSuccessfully sent {count} packets.")


if __name__ == "__main__":
    # From topology.json, h2 has IP 10.0.5.5 for a 5-switch topology
    dest_ip = "10.0.5.5"
    dest_port = 9999
    packet_count = 10
    default_message = "This is a test HTTP packet for P4 INT from h1."
 
    # Allow custom message from command line
    if len(sys.argv) > 1:
        message = ' '.join(sys.argv[1:])
    else:
        message = default_message
 
    send_http_requests(dest_ip, dest_port, message, packet_count)