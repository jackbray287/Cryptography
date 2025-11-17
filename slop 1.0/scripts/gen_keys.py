import os
from Crypto.PublicKey import RSA

def generate_keys():
    # Generate an RSA key pair
    key = RSA.generate(2048)
    
    # Save the private key
    private_key_path = os.path.join('server', 'keys', 'server_key.pem')
    with open(private_key_path, 'wb') as private_file:
        private_file.write(key.export_key(format='PEM'))
    
    # Save the public key
    public_key_path = os.path.join('client', 'keys', 'server_public.pem')
    with open(public_key_path, 'wb') as public_file:
        public_file.write(key.publickey().export_key(format='PEM'))

if __name__ == "__main__":
    generate_keys()