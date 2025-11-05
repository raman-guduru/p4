#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import time

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    """A simple request handler that processes POST requests."""

    def do_POST(self):
        """Handle incoming POST requests."""
        try:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            message = body.decode('utf-8')

            print(f"\n--- Received POST from {self.client_address[0]} ---")
            print(f"Path: {self.path}")
            print(f"Message Body: '{message}'")
            print("------------------------------------")

            # Send a 200 OK response
            self.send_response(200)
            self.end_headers()

        except Exception as e:
            print(f"Error handling POST request: {e}")
            self.send_error(500, "Internal Server Error")

    def log_message(self, format, *args):
        # Optional: Override to quiet down the default logging
        # For this exercise, we'll just print a simpler connection message.
        # The default implementation logs every single request line.
        return

if __name__ == "__main__":
    # Listen on all available interfaces
    listen_ip = "0.0.0.0"
    listen_port = 9999

    httpd = HTTPServer((listen_ip, listen_port), SimpleHTTPRequestHandler)
    print(f"Starting basic HTTP server on {listen_ip}:{listen_port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
        httpd.server_close()