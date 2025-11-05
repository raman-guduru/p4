#!/usr/bin/env python3
import sys
import time
import smtplib
from email.message import EmailMessage

def send_smtp_emails(dest_ip, dest_port, message, count):
    """
    Connects to an SMTP server and sends a number of emails.
    """
    print(f"Will send {count} emails to {dest_ip}:{dest_port}")

    # Loop to send multiple emails
    for i in range(count):
        # Create the email message
        msg = EmailMessage()
        msg['Subject'] = f"P4 INT Test Email ({i + 1}/{count})"
        msg['From'] = "h1@p4.org"
        msg['To'] = "h2@p4.org"
        body = f"{message} (Packet {i + 1}/{count})"
        msg.set_content(body)

        try:
            print(f"Sending email {i + 1}/{count} with body: '{body}'")
            # Each connection is made inside the loop to ensure a new TCP session,
            # which is useful for network-level testing.
            with smtplib.SMTP(dest_ip, dest_port, timeout=10) as server:
                # For this exercise, we don't need to log in.
                # The server is expected to be a simple open relay for testing.
                server.send_message(msg)

            # Small delay to allow network to process each packet individually
            time.sleep(0.2)
        except (smtplib.SMTPException, ConnectionRefusedError, OSError) as e:
            print(f"\nAn error occurred: {e}")
            print("Stopping the sender script.")
            break
    else: # This 'else' belongs to the 'for' loop, runs if the loop completes without 'break'
        print(f"\nSuccessfully sent {count} emails.")


if __name__ == "__main__":
    # From topology.json, h2 has IP 10.0.5.5 for a 5-switch topology
    dest_ip = "10.0.5.5"
    dest_port = 25  # Standard SMTP port
    packet_count = 10
    default_message = "This is a test SMTP packet for P4 INT from h1."
 
    if len(sys.argv) > 1:
        message = ' '.join(sys.argv[1:])
    else:
        message = default_message
 
    send_smtp_emails(dest_ip, dest_port, message, packet_count)