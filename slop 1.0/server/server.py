import socket
import threading
import os
from siftprotocols.login import LoginProtocol
from siftprotocols.cmd import CommandsProtocol
from siftprotocols.upl import UploadProtocol
from siftprotocols.dnl import DownloadProtocol
from siftprotocols.mtp import MessageTransferProtocol

class SiFTServer:
    def __init__(self, host='0.0.0.0', port=5150):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.users = self.load_users()

    def load_users(self):
        users = {}
        with open('users.txt', 'r') as f:
            for line in f:
                username, password_hash = line.strip().split(':')
                users[username] = password_hash
        return users

    def handle_client(self, client_socket):
        try:
            # Handle login
            login_protocol = LoginProtocol(client_socket, self.users)
            login_protocol.handle_login()

            # Handle commands
            commands_protocol = CommandsProtocol(client_socket)
            commands_protocol.handle_commands()

        finally:
            client_socket.close()

    def start(self):
        print(f'Server listening on {self.host}:{self.port}')
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f'Accepted connection from {addr}')
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

if __name__ == '__main__':
    server = SiFTServer()
    server.start()