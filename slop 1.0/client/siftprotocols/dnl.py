# dnl.py

# This file manages the download protocol for retrieving files from the server to the client.

import os
import json
from siftprotocols.mtp import MTP

class DownloadProtocol:
    def __init__(self, client_socket, transfer_key):
        self.client_socket = client_socket
        self.transfer_key = transfer_key
        self.mtp = MTP(client_socket, transfer_key)

    def download_file(self, filename):
        # Prepare the download request
        request = {
            "command": "dnl",
            "filename": filename
        }
        self.mtp.send_message(request)

        # Receive the response
        response = self.mtp.receive_message()
        if response.get("status") == "success":
            file_data = response.get("data")
            self.save_file(filename, file_data)
        else:
            print("Download failed:", response.get("error"))

    def save_file(self, filename, data):
        with open(filename, 'wb') as file:
            file.write(data)
        print(f"File '{filename}' downloaded successfully.")

# Example usage (to be removed or commented out in production):
# if __name__ == "__main__":
#     client_socket = ...  # Obtain the client socket
#     transfer_key = ...   # Obtain the transfer key
#     downloader = DownloadProtocol(client_socket, transfer_key)
#     downloader.download_file("example.txt")  # Replace with the desired filename