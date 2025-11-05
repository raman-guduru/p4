#!/usr/bin/env python3
import asyncio
from aiosmtpd.controller import Controller
from time import sleep
from email import message_from_bytes

# NOTE: The 'aiosmtpd' library might need to be installed if it's not in
# your environment. You can typically install it with:
# pip install aiosmtpd

class SimpleSMTPHandler:
    """A simple handler that processes incoming emails and prints them."""

    async def handle_DATA(self, server, session, envelope):
        """Handle the email data after the DATA command."""
        print(f"\n--- Received email from {session.peer[0]} ---")
        print(f"From: {envelope.mail_from}")
        print(f"To: {', '.join(envelope.rcpt_tos)}")

        # Decode the full message content
        message = message_from_bytes(envelope.content)
        print(f"Subject: {message.get('subject')}")

        # Extract the plain text body
        body = ""
        if message.is_multipart():
            for part in message.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                # Find the plain text part which is not an attachment
                if ctype == 'text/plain' and 'attachment' not in cdispo:
                    body = part.get_payload(decode=True).decode('utf-8')
                    break
        else:
            # Not a multipart message, just get the payload
            body = message.get_payload(decode=True).decode('utf-8')

        print(f"Message Body: '{body}'")
        print("------------------------------------")

        # A '250 OK' response is required by the SMTP protocol on success
        return '250 OK'

if __name__ == "__main__":
    # Listen on all available interfaces
    listen_ip = "0.0.0.0"
    listen_port = 25  # Standard SMTP port

    controller = Controller(SimpleSMTPHandler(), hostname=listen_ip, port=listen_port)
    print(f"Starting basic SMTP server on {listen_ip}:{listen_port}...")
    controller.start()
    print("Server started. Press Ctrl+C to stop.")
    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
    finally:
        controller.stop()