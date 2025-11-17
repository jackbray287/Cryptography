# Contents of /sift-v1/sift-v1/client/siftprotocols/upl.py

"""
This file manages the upload protocol for transferring files from the client to the server.
"""

import os
import socket
import json
from .mtp import MTP

class UploadProtocol:
    def __init__(self, server_address, port):
        self.server_address = server_address
        self.port = port
        self.mtp = MTP(server_address, port)

    def upload_file(self, file_path):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"The file {file_path} does not exist.")

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Send upload request
        self.mtp.send_message({
            "command": "upl",
            "file_name": file_name,
            "file_size": file_size
        })

        # Open the file and send it in chunks
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(1024)  # Read in 1KB chunks
                if not chunk:
                    break
                self.mtp.send_message(chunk)

        # Send a final message indicating the end of the upload
        self.mtp.send_message({"command": "end_upload", "file_name": file_name})

    def receive_upload_response(self):
        response = self.mtp.receive_message()
        return response
