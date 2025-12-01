#python3

import time
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error


class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None
        self.size_key = 32   # 32 bytes = 256-bit transfer/session key
        self.ts_window = 120   # seconds allowed drift 
        self.ts_window_ns = self.ts_window * 1_000_000_000


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users

    def derive_session_key(self, tk, info):
        # HKDF with request_hash as salt, no additional context
        session_key = HKDF(
            master=tk,
            key_len=self.size_key,
            salt=info,
            hashmod=SHA256,
            context=b''
        )
        return session_key

    # builds a login request from a dictionary
    def build_login_req(self, login_req_struct):

        # Format: <timestamp>\n<username>\n<password>\n<client_random>
        login_req_str = str(login_req_struct['timestamp'])
        login_req_str += self.delimiter + login_req_struct['username'] 
        login_req_str += self.delimiter + login_req_struct['password'] 
        login_req_str += self.delimiter + login_req_struct['client_random'].hex()
        return login_req_str.encode(self.coding)


    # parses a login request into a dictionary
    def parse_login_req(self, login_req):

        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        login_req_struct = {}
        login_req_struct['timestamp'] = int(login_req_fields[0])
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = bytes.fromhex(login_req_fields[3])
        return login_req_struct


    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):

        # Format: <request_hash>\n<server_random>
        login_res_str = login_res_struct['request_hash'].hex() 
        login_res_str += self.delimiter + login_res_struct['server_random'].hex()
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        login_res_struct['server_random'] = bytes.fromhex(login_res_fields[1])
        return login_res_struct


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False


    # handles login process (to be used by the server)
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        login_req_struct = self.parse_login_req(msg_payload)

        now = time.time_ns()
        ts = login_req_struct['timestamp']
        if abs(now - ts) > self.ts_window_ns:
            raise SiFT_LOGIN_Error(f'Timestamp check failed (now={now}, ts={ts})')
        if self.DEBUG:
            print("[DEBUG] timestamp =", login_req_struct['timestamp'])

        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unkown user attempted to log in')

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        login_res_struct['server_random'] = get_random_bytes(16)
        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # sending login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # Derive final transfer key: HKDF(client_random||server_random, salt=request_hash)
        if self.mtp.transfer_key is not None:
            key_material = login_req_struct['client_random'] + login_res_struct['server_random']
            session_key = self.derive_session_key(key_material, request_hash)
            self.mtp.set_transfer_key(session_key)
            if self.DEBUG:
                print("[CHECK] server final_tk =", session_key.hex())
                print("[CHECK] server mtp.transfer_key =", self.mtp.transfer_key.hex())
        else:
            raise SiFT_LOGIN_Error('Temporary transfer key not set after receiving login request')
        
        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG 

        return login_req_struct['username']


    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):

        # building a login request
        login_req_struct = {}
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        login_req_struct['timestamp'] = time.time_ns()
        login_req_struct['client_random'] = get_random_bytes(16)
        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(msg_payload)

        # checking request_hash receiveid in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')

        # Derive final transfer key: HKDF(client_random||server_random, salt=request_hash)
        if self.mtp.transfer_key is not None:
            key_material = login_req_struct['client_random'] + login_res_struct['server_random']
            session_key = self.derive_session_key(key_material, request_hash)
            self.mtp.set_transfer_key(session_key)
            if self.DEBUG:
                print("[CHECK] client final_tk =", session_key.hex())
                print("[CHECK] client mtp.transfer_key =", self.mtp.transfer_key.hex())
        else:
            # This should not happen if send_msg for login_req worked correctly
            raise SiFT_LOGIN_Error('Temporary transfer key not set after sending login request')
        
