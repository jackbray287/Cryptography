# Contents of /sift-v1/sift-v1/server/siftprotocols/login.py

import time
import hashlib
import os
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF

class LoginProtocol:
    def __init__(self, server_private_key, user_db):
        # server_private_key: Crypto.PublicKey.RSA.RsaKey (private)
        # user_db: dict mapping username -> {'password_hash': <hex str>, ...}
        self.server_private_key = server_private_key
        self.user_db = user_db

    def generate_client_random(self):
        return get_random_bytes(16)

    def handle_login_request(self, login_request):
        # login_request: plaintext string "timestamp\nusername\npassword\nclient_random_hex"
        try:
            timestamp, username, password, client_random = self.parse_login_request(login_request)
        except Exception:
            return None  # malformed request

        if not self.is_timestamp_valid(timestamp):
            return None  # Invalid timestamp

        if not self.authenticate_user(username, password):
            return None  # Authentication failed

        server_random = self.generate_client_random()
        request_hash = self.compute_request_hash(login_request)

        response_payload = f"{request_hash}\n{server_random.hex()}"
        signed_response = self.encrypt_response(response_payload)
        # return a JSON string containing signed payload and server_random for the client
        return signed_response

    def parse_login_request(self, login_request):
        parts = login_request.split('\n')
        if len(parts) < 4:
            raise ValueError('Malformed login request')
        timestamp = int(parts[0])
        username = parts[1]
        password = parts[2]
        client_random = bytes.fromhex(parts[3])
        return timestamp, username, password, client_random

    def is_timestamp_valid(self, timestamp):
        current_time = time.time_ns()
        # accept +-1 second window
        return (current_time - 1_000_000_000) < timestamp < (current_time + 1_000_000_000)

    def authenticate_user(self, username, password):
        if username not in self.user_db:
            return False
        stored_password_hash = self.user_db[username].get('password_hash')
        return self.hash_password(password) == stored_password_hash

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def compute_request_hash(self, login_request):
        return hashlib.sha256(login_request.encode('utf-8')).hexdigest()

    def encrypt_response(self, response_payload):
        # Sign the response payload with server private RSA key and return JSON string:
        # {"payload": "<payload>", "signature": "<base64(sig)>"}
        payload_bytes = response_payload.encode('utf-8')
        h = SHA256.new(payload_bytes)
        signer = pkcs1_15.new(self.server_private_key)
        signature = signer.sign(h)
        msg = {
            'payload': response_payload,
            'signature': base64.b64encode(signature).decode('utf-8')
        }
        return json.dumps(msg)

    def derive_final_key(self, client_random, server_random, request_hash):
        # Derive a 32-byte symmetric key using HKDF
        master = (client_random if isinstance(client_random, bytes) else bytes.fromhex(client_random)) + \
                 (server_random if isinstance(server_random, bytes) else bytes.fromhex(server_random))
        salt = request_hash.encode('utf-8')
        return HKDF(master, 32, salt, hashlib.sha256)

# This file is intended to handle the login protocol for the SiFT v1.0 project.