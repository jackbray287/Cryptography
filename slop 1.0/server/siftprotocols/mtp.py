# Contents of /sift-v1/sift-v1/server/siftprotocols/mtp.py

import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

class MTP:
    def __init__(self, key):
        # key: bytes (AES key)
        self.key = key
        self.sequence_number = 0

    def encrypt(self, plaintext):
        # accepts str or bytes, returns a JSON-serializable dict
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext

        # increment sequence number and include it in the message
        self.sequence_number += 1
        nonce = get_random_bytes(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'sequence_number': self.sequence_number
        }

    def decrypt(self, message):
        # message is dict with base64 fields and sequence_number
        nonce = base64.b64decode(message['nonce'])
        ciphertext = base64.b64decode(message['ciphertext'])
        tag = base64.b64decode(message['tag'])
        seq = int(message.get('sequence_number', 0))

        # replay/ordering protection: require strictly increasing sequence numbers
        if seq <= self.sequence_number:
            raise ValueError('Replay or out-of-order message detected (sequence_number)')

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            raise ValueError('Decryption failed or authentication tag mismatch: ' + str(e))

        # accept the sequence number
        self.sequence_number = seq

        # return decoded string if possible, otherwise bytes
        try:
            return plaintext_bytes.decode('utf-8')
        except Exception:
            return plaintext_bytes

    # convenience wrappers kept for compatibility
    def create_message(self, payload):
        return self.encrypt(payload)

    def parse_message(self, message):
        return self.decrypt(message)