# python3
import sys, threading, socket, getpass
# /-------------------------------------------------------------
import os                            # NEW
from Crypto.PublicKey import RSA     # NEW
# -------------------------------------------------------------\

# Add client package directory to sys.path so the fixed client/siftprotocols is used
server_dir = os.path.dirname(os.path.abspath(__file__))
client_pkg = os.path.normpath(os.path.join(server_dir, '..', 'client'))
if client_pkg not in sys.path:
    sys.path.insert(0, client_pkg)

from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from siftprotocols.siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error
from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error

class Server:
    def __init__(self):
        # ------------------------ CONFIG -----------------------------
        self.server_usersfile = 'users.txt' 
        self.server_usersfile_coding = 'utf-8'
        self.server_usersfile_rec_delimiter = '\n'
        self.server_usersfile_fld_delimiter = ':'
        self.server_rootdir = './users/'
        self.server_ip = socket.gethostbyname('localhost')
        # self.server_ip = socket.gethostbyname(socket.gethostname())
        self.server_port = 5150
        # -------------------------------------------------------------

        base_dir = os.path.dirname(os.path.abspath(__file__))
        priv_path = os.path.join(base_dir, "server_private.pem")
        try:
            with open(priv_path, "rb") as f:
                self.server_private_key = RSA.import_key(f.read())
        except FileNotFoundError:
            print(f"[FATAL] RSA private key not found at {priv_path}")
            print("        Generate it first (e.g. with genkeys.py) and retry.")
            sys.exit(1)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(5)
        print('Listening on ' + self.server_ip + ':' + str(self.server_port))
        self.accept_connections()


    def load_users(self, usersfile):
        users = {}
        with open(usersfile, 'rb') as f:
            allrecords = f.read().decode(self.server_usersfile_coding)
        records = allrecords.split(self.server_usersfile_rec_delimiter)
        for r in records:
            if not r:      # ADDED
                continue
            fields = r.split(self.server_usersfile_fld_delimiter)
            username = fields[0]
            usr_struct = {}
            usr_struct['pwdhash'] = bytes.fromhex(fields[1])
            usr_struct['icount'] = int(fields[2])
            usr_struct['salt'] = bytes.fromhex(fields[3])
            usr_struct['rootdir'] = fields[4]
            users[username] = usr_struct
        return users


    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, addr, )).start()


    def handle_client(self, client_socket, addr):
        print('New client on ' + addr[0] + ':' + str(addr[1]))

        mtp = SiFT_MTP(client_socket,
                       is_server=True,
                       rsa_private_key=self.server_private_key)
                       
        loginp = SiFT_LOGIN(mtp, is_server=True)

        users = self.load_users(self.server_usersfile)
        loginp.set_server_users(users)

        try:
            user = loginp.handle_login_server()
        except SiFT_LOGIN_Error as e:
            print('SiFT_LOGIN_Error: ' + e.err_msg)
            print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
            client_socket.close()
            return

        cmdp = SiFT_CMD(mtp)
        cmdp.set_server_rootdir(self.server_rootdir)
        cmdp.set_user_rootdir(users[user]['rootdir'])

        while True:
            try:
                cmdp.receive_command()
            except SiFT_CMD_Error as e:
                print('SiFT_CMD_Error: ' + e.err_msg)
                print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
                client_socket.close()
                return


# main
if __name__ == '__main__':
    server = Server()
