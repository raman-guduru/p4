#!/usr/bin/env python3
import socket

def start_tcp_server(listen_ip, listen_port):
    """
    Starts a TCP server to listen for and receive one message.
    """
    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind the socket to the address and port
        server_address = (listen_ip, listen_port)
        s.bind(server_address)

        # Listen for incoming connections
        s.listen(1)
        print(f"Listening for connections on {listen_ip}:{listen_port}...")

        while True:
            # Wait for a connection
            connection, client_address = s.accept()
            with connection:
                print(f"Connection from {client_address}")

                # Loop to receive all data from this single connection
                # until the client closes it.
                while True:
                    data = connection.recv(1024)
                    if data:
                        message = data.decode('utf-8')
                        print(f"Received message: '{message}'")
                    else:
                        # An empty data string means the client has closed the connection
                        print(f"Client {client_address} closed the connection.")
                        break

if __name__ == "__main__":
    # Listen on all available interfaces on h2
    listen_ip = "0.0.0.0"
    listen_port = 9999

    start_tcp_server(listen_ip, listen_port)