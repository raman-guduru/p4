#!/usr/bin/env python3
import sys
import time
import ftplib
from io import BytesIO

def send_ftp_files(dest_ip, dest_port, message, count):
    """
    Connects to an FTP server and uploads a number of files.
    """
    print(f"Will send {count} files via FTP to {dest_ip}:{dest_port}")

    # Loop to send multiple files
    for i in range(count):
        body = f"{message} (Packet {i + 1}/{count})"
        filename = f"p4_int_test_{i + 1}.txt"

        try:
            print(f"Uploading file {i + 1}/{count} ({filename}) with content: '{body}'")
            # Each connection is made inside the loop to ensure a new TCP session,
            # which is useful for network-level testing.
            with ftplib.FTP() as ftp:
                ftp.connect(dest_ip, dest_port, timeout=10)
                # For this exercise, we use anonymous login.
                ftp.login() # user='anonymous', passwd=''

                # Use BytesIO to treat the string as a file for upload
                file_obj = BytesIO(body.encode('utf-8'))
                ftp.storbinary(f"STOR {filename}", file_obj)

            # Small delay to allow network to process each packet individually
            time.sleep(0.2)
        except (*ftplib.all_errors, ConnectionRefusedError, OSError) as e:
            print(f"\nAn error occurred: {e}")
            print("Stopping the sender script.")
            break
    else: # This 'else' belongs to the 'for' loop, runs if the loop completes without 'break'
        print(f"\nSuccessfully uploaded {count} files.")


if __name__ == "__main__":
    # From topology.json, h2 has IP 10.0.5.5 for a 5-switch topology
    dest_ip = "10.0.5.5"
    dest_port = 21  # Standard FTP port
    packet_count = 10
    default_message = "This is a test FTP packet for P4 INT from h1."
 
    if len(sys.argv) > 1:
        message = ' '.join(sys.argv[1:])
    else:
        message = default_message
 
    send_ftp_files(dest_ip, dest_port, message, packet_count)