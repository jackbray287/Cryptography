class UploadProtocol:
    def __init__(self, connection):
        # connection may be any object — network I/O is left to caller
        self.connection = connection
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.size_fragment = 1024

    def get_file_metadata(self, file_path):
        # returns (file_size:int, file_hash:bytes)
        import os
        from Crypto.Hash import SHA256
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            raise FileNotFoundError('File not found')
        hash_fn = SHA256.new()
        size = 0
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.size_fragment)
                if not chunk:
                    break
                size += len(chunk)
                hash_fn.update(chunk)
        return size, hash_fn.digest()

    def stream_file(self, file_path):
        # generator that yields (chunk_bytes, is_final:bool)
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.size_fragment)
                if not chunk:
                    break
                # peek to know if this is final
                next_byte = f.peek(1) if hasattr(f, 'peek') else None
                # we can't reliably peek for plain file objects; instead decide by len(chunk)
                is_final = len(chunk) < self.size_fragment
                yield chunk, is_final

    def write_file_from_chunks(self, file_path, chunks_iterable):
        # chunks_iterable yields bytes chunks; writes them to file_path and returns (size, hash)
        import os
        from Crypto.Hash import SHA256
        parent = os.path.dirname(file_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        hash_fn = SHA256.new()
        total = 0
        with open(file_path, 'wb') as f:
            for chunk in chunks_iterable:
                if isinstance(chunk, tuple):
                    # accommodate (chunk, is_final) shape
                    chunk = chunk[0]
                f.write(chunk)
                total += len(chunk)
                hash_fn.update(chunk)
        return total, hash_fn.digest()

    # builds an upload response from a dictionary (v0.5 format)
    def build_upload_res(self, upl_res_struct):
        upl_res_str = upl_res_struct['file_hash'].hex()
        upl_res_str += self.delimiter + str(upl_res_struct['file_size'])
        return upl_res_str.encode(self.coding)

    # parses an upload response into a dictionary (v0.5 format)
    def parse_upload_res(self, upl_res):
        upl_res_fields = upl_res.decode(self.coding).split(self.delimiter)
        upl_res_struct = {}
        upl_res_struct['file_hash'] = bytes.fromhex(upl_res_fields[0])
        upl_res_struct['file_size'] = int(upl_res_fields[1])
        return upl_res_struct

    def upload_file(self, file_path):
        # convenience: compute metadata; actual send should be done by caller using stream_file()
        size, file_hash = self.get_file_metadata(file_path)
        return {'file_size': size, 'file_hash': file_hash}

    def receive_file(self, file_name):
        # placeholder: writing should be done by caller by passing chunks into write_file_from_chunks
        raise NotImplementedError('receive_file is transport-specific; use write_file_from_chunks with incoming chunks')

    def handle_upload(self, file_path):
        # Handle the upload process: returns metadata and leaves transfer to caller
        return self.upload_file(file_path)

    def handle_receive(self, file_name):
        return self.receive_file(file_name)