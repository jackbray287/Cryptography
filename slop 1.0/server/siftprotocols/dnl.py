# dnl.py

# This file is intentionally left blank.

# DownloadProtocol helper for SiFT v1.0 (server-side)

import os
from Crypto.Hash import SHA256

class DownloadProtocolError(Exception):
    def __init__(self, msg):
        self.msg = msg

class DownloadProtocol:
    def __init__(self):
        self.DEBUG = True
        self.size_fragment = 1024

    def prepare_download(self, filepath):
        if not os.path.exists(filepath):
            raise DownloadProtocolError('File does not exist')
        if not os.path.isfile(filepath):
            raise DownloadProtocolError('Path is not a file')
        try:
            hash_fn = SHA256.new()
            with open(filepath, 'rb') as f:
                data = f.read()
                hash_fn.update(data)
            return {
                'file_bytes': data,
                'file_size': len(data),
                'file_hash': hash_fn.digest()
            }
        except Exception as e:
            raise DownloadProtocolError('Unable to read file for download: ' + str(e))

    def save_download(self, filepath, file_bytes, expected_hash=None):
        try:
            hash_fn = SHA256.new()
            hash_fn.update(file_bytes)
            computed = hash_fn.digest()
            if expected_hash is not None and computed != expected_hash:
                raise DownloadProtocolError('Hash mismatch while saving download')
            parent = os.path.dirname(filepath)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            with open(filepath, 'wb') as f:
                f.write(file_bytes)
            return {'file_size': len(file_bytes), 'file_hash': computed}
        except DownloadProtocolError:
            raise
        except Exception as e:
            raise DownloadProtocolError('Unable to save file: ' + str(e))