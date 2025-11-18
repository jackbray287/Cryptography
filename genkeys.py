#!/usr/bin/env python3

from Crypto.PublicKey import RSA
import os

def main():
    # 1) Generate 2048-bit RSA keypair
    key = RSA.generate(2048)

    private_pem = key.export_key()               # bytes
    public_pem = key.publickey().export_key()    # bytes

    # 2) Paths – adjust if your folder layout differs
    base = os.path.dirname(os.path.abspath(__file__))
    server_priv_path = os.path.join(base, "SiFTv1.0", "server", "server_private.pem")
    client_pub_path  = os.path.join(base, "SiFTv1.0", "client", "server_public.pem")

    # 3) Write files
    os.makedirs(os.path.dirname(server_priv_path), exist_ok=True)
    os.makedirs(os.path.dirname(client_pub_path), exist_ok=True)

    with open(server_priv_path, "wb") as f:
        f.write(private_pem)

    with open(client_pub_path, "wb") as f:
        f.write(public_pem)

    print("Wrote:")
    print("  ", server_priv_path)
    print("  ", client_pub_path)

if __name__ == "__main__":
    main()