#python3

import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket, is_server=False, rsa_public_key=None, rsa_private_key=None):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'

		 # header fields: ver (2) | typ (2) | len (2) | sqn (2) | rnd (6) | rsv (2)
        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2

		# AES-GCM tag size
        self.size_mac = 12
        # RSA key size is 2048 bits -> 256 byte ciphertext for tk
        self.size_etk = 256

		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.is_server = is_server
        self.rsa_public_key = rsa_public_key    # used on client to encrypt tk
        self.rsa_private_key = rsa_private_key  # used on server to decrypt tk

        # AES-GCM transfer key (temporary tk for login,
        # then final transfer key after HKDF)
        self.transfer_key = None

        # message sequence numbers
        self.send_sqn = 1   # next sqn to send
        self.recv_sqn = 0   # last sqn received

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		
		len_bytes = msg_hdr[i:i+self.size_msg_hdr_len]
        parsed_msg_hdr['len'] = int.from_bytes(len_bytes, byteorder='big')
        i += self.size_msg_hdr_len

        sqn_bytes = msg_hdr[i:i+self.size_msg_hdr_sqn]
        parsed_msg_hdr['sqn'] = int.from_bytes(sqn_bytes, byteorder='big')
        i += self.size_msg_hdr_sqn

        parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
        parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]

        return parsed_msg_hdr

	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received

	def _make_nonce(self, sqn_int, rnd_bytes):
        # nonce = sqn (2 bytes big-endian) || rnd (6 bytes) => 8-byte nonce
        return sqn_int.to_bytes(2, byteorder='big') + rnd_bytes

	# receives and parses message, returns msg_type and *decrypted* payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = parsed_msg_hdr['len']
        sqn = parsed_msg_hdr['sqn']
        rnd = parsed_msg_hdr['rnd']

		# replay protection: sqn must be strictly increasing
        if sqn <= self.recv_sqn:
            raise SiFT_MTP_Error('Replay or out-of-order message detected')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')
	
		msg_type = parsed_msg_hdr['typ']
        nonce = self.make_nonce(sqn, rnd)

        # NEW: login_req is special: epd||mac||etk, only server should handle it
        if msg_type == self.type_login_req:
            if not self.is_server:
                raise SiFT_MTP_Error('Client received login_req unexpectedly')

            if len(msg_body) < self.size_mac + self.size_etk:
                raise SiFT_MTP_Error('login_req body too short')

            epd_len = len(msg_body) - self.size_mac - self.size_etk
            epd = msg_body[:epd_len]
            mac = msg_body[epd_len:epd_len + self.size_mac]
            etk = msg_body[epd_len + self.size_mac:]

            if self.rsa_private_key is None:
                raise SiFT_MTP_Error('RSA private key not set on server')

            rsa_cipher = PKCS1_OAEP.new(self.rsa_private_key, hashAlgo=SHA256)
            try:
                tk = rsa_cipher.decrypt(etk)
            except ValueError:
                raise SiFT_MTP_Error('RSA decryption of temporary key failed')

            if len(tk) != 32:
                raise SiFT_MTP_Error('Temporary key has invalid length')

            cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce)
            cipher.update(msg_hdr)
            try:
                msg_payload = cipher.decrypt_and_verify(epd, mac)
            except ValueError:
                raise SiFT_MTP_Error('MAC verification failed in login_req')

            # store temporary key so login_res can use it
            self.transfer_key = tk

        else:
            # NEW: all other messages use current transfer_key
            if self.transfer_key is None:
                raise SiFT_MTP_Error('Transfer key not set for decrypting message')

            if len(msg_body) < self.size_mac:
                raise SiFT_MTP_Error('Message body too short')

            epd = msg_body[:-self.size_mac]
            mac = msg_body[-self.size_mac:]

            cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce)
            cipher.update(msg_hdr)
            try:
                msg_payload = cipher.decrypt_and_verify(epd, mac)
            except ValueError:
                raise SiFT_MTP_Error('MAC verification failed')

        # NEW: update last received sequence number
        self.recv_sqn = sqn

        return msg_type, msg_payload

	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')

	# NEW: setter for final transfer key after HKDF in login protocol
    def set_transfer_key(self, key_bytes):
        if len(key_bytes) != 32:
            raise SiFT_MTP_Error('Transfer key must be 32 bytes')
        self.transfer_key = key_bytes

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		
		# NEW: compute sqn, rnd, rsv
        sqn = self.send_sqn
        rnd = get_random_bytes(self.size_msg_hdr_rnd)
        rsv = b'\x00\x00'

		# login_req is special: client sends epd||mac||etk using a fresh tk
        if msg_type == self.type_login_req:
            if self.is_server:
                raise SiFT_MTP_Error('Server should not send login_req')

            # fresh temporary key tk for login messages
            tk = get_random_bytes(32)

            if self.rsa_public_key is None:
                raise SiFT_MTP_Error('RSA public key not set on client')

            # total length = header + payload + mac + etk
            msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac + self.size_etk
            msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
            sqn_bytes = sqn.to_bytes(self.size_msg_hdr_sqn, byteorder='big')

            msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + sqn_bytes + rnd + rsv

            nonce = self.make_nonce(sqn, rnd)
            cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce)
            cipher.update(msg_hdr)
            epd, mac = cipher.encrypt_and_digest(msg_payload)

            # RSA-OAEP encrypt tk -> etk
            rsa_cipher = PKCS1_OAEP.new(self.rsa_public_key, hashAlgo=SHA256)
            etk = rsa_cipher.encrypt(tk)

            msg_body = epd + mac + etk

            # store tk as current transfer key so client can decrypt login_res
            self.transfer_key = tk

        else:
            # all other messages: encrypt with current transfer_key
            if self.transfer_key is None:
                raise SiFT_MTP_Error('Transfer key not set for sending message')

            msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac
            msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
            sqn_bytes = sqn.to_bytes(self.size_msg_hdr_sqn, byteorder='big')

            msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + sqn_bytes + rnd + rsv

            nonce = self.make_nonce(sqn, rnd)
            cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce)
            cipher.update(msg_hdr)
            epd, mac = cipher.encrypt_and_digest(msg_payload)

            msg_body = epd + mac

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg_hdr + msg_payload)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

		self.send_sqn += 1