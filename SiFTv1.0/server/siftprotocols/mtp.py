# Contents of /sift-v1/sift-v1/server/siftprotocols/mtp.py

import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

class MTP:
    def __init__(self, key):
        self.key = key
        self.sequence_number = 0

    def encrypt(self, plaintext):
        self.sequence_number += 1
        nonce = get_random_bytes(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(pad(plaintext.encode(), AES.block_size))
        return {
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'sequence_number': self.sequence_number
        }

    def decrypt(self, message):
        nonce = base64.b64decode(message['nonce'])
        ciphertext = base64.b64decode(message['ciphertext'])
        tag = base64.b64decode(message['tag'])
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
        return plaintext.decode()

    def create_message(self, payload):
        return self.encrypt(payload)

    def parse_message(self, message):
        return self.decrypt(message)