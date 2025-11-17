# Contents of /sift-v1/sift-v1/client/siftprotocols/login.py

import time
import hashlib
import os
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF

class LoginProtocol:
    def __init__(self, server_public_key_path):
        self.server_public_key = self.load_public_key(server_public_key_path)

    def load_public_key(self, path):
        with open(path, 'rb') as key_file:
            return RSA.import_key(key_file.read())

    def generate_client_random(self):
        return get_random_bytes(16)

    def create_login_request(self, username, password):
        timestamp = str(time.time_ns())
        client_random = self.generate_client_random().hex()
        payload = f"{timestamp}\n{username}\n{password}\n{client_random}"
        request_hash = hashlib.sha256(payload.encode()).hexdigest()
        return payload, request_hash

    def encrypt_payload(self, payload, temporary_key):
        cipher = AES.new(temporary_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(payload.encode())
        return cipher.nonce + ciphertext + tag

    def send_login_request(self, username, password):
        payload, request_hash = self.create_login_request(username, password)
        temporary_key = get_random_bytes(32)
        encrypted_payload = self.encrypt_payload(payload, temporary_key)
        etk = self.server_public_key.encrypt(temporary_key, None)[0]
        return encrypted_payload, etk, request_hash

    def verify_login_response(self, response, expected_request_hash):
        response_hash, server_random = response.split('\n')
        if response_hash != expected_request_hash:
            raise ValueError("Invalid response hash")
        return server_random

    def derive_final_key(self, client_random, server_random, request_hash):
        initial_key_material = client_random + server_random
        return HKDF(initial_key_material, 32, hashlib.sha256, request_hash.encode())