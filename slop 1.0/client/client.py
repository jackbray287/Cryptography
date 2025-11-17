# Client Application for SiFT Protocol

import socket
import os
import sys
from siftprotocols.login import LoginProtocol
from siftprotocols.cmd import CommandsProtocol
from siftprotocols.upl import UploadProtocol
from siftprotocols.dnl import DownloadProtocol

class SiFTClient:
    def __init__(self, server_address, server_port):
        self.server_address = server_address
        self.server_port = server_port
        self.socket = None
        self.login_protocol = LoginProtocol(self)
        self.commands_protocol = CommandsProtocol(self)
        self.upload_protocol = UploadProtocol(self)
        self.download_protocol = DownloadProtocol(self)

    def connect_to_server(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_address, self.server_port))
        print(f"Connected to server at {self.server_address}:{self.server_port}")

    def close_connection(self):
        if self.socket:
            self.socket.close()
            print("Connection closed.")

    def run(self):
        try:
            self.connect_to_server()
            self.login_protocol.authenticate_user()
            while True:
                command = input("Enter command (or 'exit' to quit): ")
                if command.lower() == 'exit':
                    break
                self.commands_protocol.send_command(command)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.close_connection()

if __name__ == "__main__":
    server_address = 'localhost'  # Change to your server address
    server_port = 5150  # Default port for SiFT
    client = SiFTClient(server_address, server_port)
    client.run()