#!/usr/bin/env python3
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import os

# NOTE: The 'pyftpdlib' library might need to be installed if it's not in
# your environment. You can typically install it with:
# pip install pyftpdlib

class SimpleFTPHandler(FTPHandler):
    """A simple handler that processes file uploads and prints their content."""

    def on_file_received(self, file_path):
        """Handle the file after it has been uploaded."""
        try:
            with open(file_path, 'r') as f:
                content = f.read()

            print(f"\n--- Received file from {self.remote_ip} ---")
            print(f"File Name: {os.path.basename(file_path)}")
            print(f"File Content: '{content}'")
            print("------------------------------------")

            # Clean up the received file
            os.remove(file_path)

        except Exception as e:
            print(f"Error processing received file: {e}")

if __name__ == "__main__":
    # Listen on all available interfaces
    listen_ip = "0.0.0.0"
    listen_port = 21  # Standard FTP port

    # Set up a dummy authorizer for anonymous access
    authorizer = DummyAuthorizer()
    # Allow anonymous user with read/write permissions to the current directory
    authorizer.add_anonymous(os.getcwd(), perm='elradfmw')

    handler = SimpleFTPHandler
    handler.authorizer = authorizer

    server = FTPServer((listen_ip, listen_port), handler)
    print(f"Starting basic FTP server on {listen_ip}:{listen_port}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
        server.close_all()