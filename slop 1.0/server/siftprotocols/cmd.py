# Contents of /sift-v1/sift-v1/server/siftprotocols/cmd.py

"""
This file implements the Commands Protocol for the SiFT v1.0 protocol.
It mirrors the behaviour of the v0.5 SiFT_CMD implementation but exposes
a simpler method set suitable for the v1.0 codebase.
"""

import os
from Crypto.Hash import SHA256

class CommandsProtocol:
    def __init__(self):
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.cmd_pwd = 'pwd'
        self.cmd_lst = 'lst'
        self.cmd_chd = 'chd'
        self.cmd_mkd = 'mkd'
        self.cmd_del = 'del'
        self.cmd_upl = 'upl'
        self.cmd_dnl = 'dnl'
        self.commands = (self.cmd_pwd, self.cmd_lst, self.cmd_chd,
                         self.cmd_mkd, self.cmd_del,
                         self.cmd_upl, self.cmd_dnl)
        self.res_success = 'success'
        self.res_failure = 'failure'
        self.res_accept = 'accept'
        self.res_reject = 'reject'
        # --------- STATE ------------
        self.server_rootdir = None
        self.user_rootdir = None
        self.current_dir = []
        self.filesize_limit = 2**16

    def set_server_rootdir(self, server_rootdir):
        self.server_rootdir = server_rootdir

    def set_user_rootdir(self, user_rootdir):
        self.user_rootdir = user_rootdir
        if self.DEBUG:
            print('User root directory is set to ' + str(self.user_rootdir))

    def set_filesize_limit(self, limit):
        self.filesize_limit = limit

    def check_fdname(self, fdname):
        if not fdname:
            return False
        if fdname[0] == '.':
            return False
        for c in fdname:
            if not c.isalnum():
                if c not in ('-', '_', '.'):
                    return False
        return True

    def _cwd_path(self):
        if not self.server_rootdir or not self.user_rootdir:
            return None
        # ensure trailing slashes are normalized
        root = self.server_rootdir.rstrip('/') + '/'
        user = self.user_rootdir.strip('/')
        if user:
            user = user.rstrip('/') + '/'
        base = root + user
        rel = '/'.join(self.current_dir)
        if rel:
            return base + rel
        return base.rstrip('/')

    # process a single command (high-level entry)
    def process_command(self, command, params=None):
        if command not in self.commands:
            return {'result': self.res_failure, 'reason': 'Unknown command'}

        if command == self.cmd_pwd:
            return {'result': self.res_success, 'cwd': self.pwd()}

        if command == self.cmd_lst:
            return self.lst()

        if command == self.cmd_chd:
            return self.chd(params)

        if command == self.cmd_mkd:
            return self.mkd(params)

        if command == self.cmd_del:
            return self.del_file(params)

        if command == self.cmd_upl:
            # params can be either metadata {'filename','filesize','filehash'} for pre-check
            # or full upload dict containing 'file_bytes' to write the file immediately.
            return self.upl(params)

        if command == self.cmd_dnl:
            # params expected to be filename string; returns accept/reject and file info on accept
            return self.dnl(params)

    # returns current working directory as string
    def pwd(self):
        return '/'.join(self.current_dir) + '/'

    # list current directory contents
    def lst(self):
        path = self._cwd_path()
        if not path:
            return {'result': self.res_failure, 'reason': 'Server/user root not configured'}
        if not os.path.exists(path):
            return {'result': self.res_failure, 'reason': 'Operation failed due to local error on server'}
        dirlist_str = ''
        try:
            with os.scandir(path) as dirlist:
                for f in dirlist:
                    if not f.name.startswith('.'):
                        if f.is_file():
                            dirlist_str += f.name + '\n'
                        elif f.is_dir():
                            dirlist_str += f.name + '/\n'
            if dirlist_str.endswith('\n'):
                dirlist_str = dirlist_str[:-1]
        except Exception:
            return {'result': self.res_failure, 'reason': 'Operation failed due to local error on server'}
        return {'result': self.res_success, 'listing': dirlist_str}

    # change directory; params expected to be a single dirname string
    def chd(self, params):
        dirname = params
        if dirname == '..':
            if not self.current_dir:
                return {'result': self.res_failure, 'reason': 'Cannot change to directory outside of the user root directory'}
            parent_path = self._cwd_path().rsplit('/', 1)[0]
            if not os.path.exists(parent_path):
                return {'result': self.res_failure, 'reason': 'Directory does not exist'}
            self.current_dir = self.current_dir[:-1]
            return {'result': self.res_success}
        else:
            if not self.check_fdname(dirname):
                return {'result': self.res_failure, 'reason': 'Directory name is empty, starts with . or contains unsupported characters'}
            path = self._cwd_path()
            if path is None:
                return {'result': self.res_failure, 'reason': 'Server/user root not configured'}
            # build candidate path
            if path.endswith('/'):
                cand = path + dirname
            else:
                cand = path + '/' + dirname
            if not os.path.exists(cand):
                return {'result': self.res_failure, 'reason': 'Directory does not exist'}
            self.current_dir.append(dirname)
            return {'result': self.res_success}

    # make directory; params expected to be a single dirname string
    def mkd(self, params):
        dirname = params
        if not self.check_fdname(dirname):
            return {'result': self.res_failure, 'reason': 'Directory name is empty, starts with . or contains unsupported characters'}
        path = self._cwd_path()
        if path is None:
            return {'result': self.res_failure, 'reason': 'Server/user root not configured'}
        if path.endswith('/'):
            cand = path + dirname
        else:
            cand = path + '/' + dirname
        if os.path.exists(cand):
            return {'result': self.res_failure, 'reason': 'Directory already exists'}
        try:
            os.mkdir(cand)
        except Exception:
            return {'result': self.res_failure, 'reason': 'Creating directory failed'}
        return {'result': self.res_success}

    # delete file or directory; params expected to be filename string
    def del_file(self, params):
        fdname = params
        if not self.check_fdname(fdname):
            return {'result': self.res_failure, 'reason': 'File name or directory name is empty, starts with . or contains unsupported characters'}
        path = self._cwd_path()
        if path is None:
            return {'result': self.res_failure, 'reason': 'Server/user root not configured'}
        if path.endswith('/'):
            cand = path + fdname
        else:
            cand = path + '/' + fdname
        if not os.path.exists(cand):
            return {'result': self.res_failure, 'reason': 'File or directory does not exist'}
        try:
            if os.path.isdir(cand):
                os.rmdir(cand)
            elif os.path.isfile(cand):
                os.remove(cand)
            else:
                return {'result': self.res_failure, 'reason': 'Object is not a file or directory'}
        except Exception:
            return {'result': self.res_failure, 'reason': 'Removing file/directory failed'}
        return {'result': self.res_success}

    # upload handling: two modes:
    # 1) params is metadata dict {'filename','filesize','filehash'} -> pre-check (accept/reject)
    # 2) params is dict with 'filename' and 'file_bytes' -> write file and verify hash
    def upl(self, params):
        # pre-check mode: params = {'filename','filesize','filehash'}
        if isinstance(params, dict) and 'file_bytes' not in params:
            filename = params.get('filename')
            filesize = params.get('filesize')
            if not self.check_fdname(filename):
                return {'result': self.res_reject, 'reason': 'File name is empty, starts with . or contains unsupported characters'}
            if filesize is None or filesize > self.filesize_limit:
                return {'result': self.res_reject, 'reason': 'File to be uploaded is too large'}
            # accept (caller will send the bytes separately)
            return {'result': self.res_accept}

        # write mode: params = {'filename','file_bytes'}
        if isinstance(params, dict) and 'file_bytes' in params:
            filename = params.get('filename')
            file_bytes = params.get('file_bytes')
            if not self.check_fdname(filename):
                return {'result': self.res_failure, 'reason': 'File name is invalid'}
            path = self._cwd_path()
            if path is None or not os.path.exists(path):
                return {'result': self.res_failure, 'reason': 'Operation failed due to local error on server'}
            if path.endswith('/'):
                filepath = path + filename
            else:
                filepath = path + '/' + filename
            # write file and compute hash
            try:
                hash_fn = SHA256.new()
                hash_fn.update(file_bytes)
                with open(filepath, 'wb') as f:
                    f.write(file_bytes)
                file_hash = hash_fn.digest()
                file_size = len(file_bytes)
            except Exception:
                return {'result': self.res_failure, 'reason': 'Writing uploaded file failed'}
            return {'result': self.res_success, 'file_size': file_size, 'file_hash': file_hash}
        return {'result': self.res_failure, 'reason': 'Invalid upload parameters'}

    # download handling: params expected to be filename string
    # returns {'result':'accept', 'file_size':..., 'file_hash':..., 'file_bytes':...} on success
    def dnl(self, params):
        filename = params
        if not self.check_fdname(filename):
            return {'result': self.res_reject, 'reason': 'File name is empty, starts with . or contains unsupported characters'}
        path = self._cwd_path()
        if path is None:
            return {'result': self.res_reject, 'reason': 'Server/user root not configured'}
        if path.endswith('/'):
            filepath = path + filename
        else:
            filepath = path + '/' + filename
        if not os.path.exists(filepath):
            return {'result': self.res_reject, 'reason': 'File or directory does not exist'}
        if not os.path.isfile(filepath):
            return {'result': self.res_reject, 'reason': 'Only file download is supported'}
        try:
            hash_fn = SHA256.new()
            with open(filepath, 'rb') as f:
                data = f.read()
                hash_fn.update(data)
            file_hash = hash_fn.digest()
            file_size = len(data)
            return {'result': self.res_accept, 'file_size': file_size, 'file_hash': file_hash, 'file_bytes': data}
        except Exception:
            return {'result': self.res_reject, 'reason': 'Operation failed due to local error on server'}