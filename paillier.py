import random
from phe import paillier
import os

def generate_paillier_keys():
    public_key, private_key = paillier.generate_paillier_keypair()
    with open("paillier_public_key.txt", "w") as pub_file:
        pub_file.write(str(public_key.n))
    with open("paillier_private_key.txt", "w") as priv_file:
        priv_file.write(f"{private_key.p},{private_key.q}")
    print("[INFO] Paillier keys generated successfully.")
    return public_key, private_key

def load_paillier_keys():
    if not (os.path.exists("paillier_public_key.txt") and os.path.exists("paillier_private_key.txt")):
        print("[INFO] Paillier keys not found. Generating new ones...")
        return generate_paillier_keys()

    with open("paillier_public_key.txt", "r") as pub_file:
        n = int(pub_file.read())
        public_key = paillier.PaillierPublicKey(n)

    with open("paillier_private_key.txt", "r") as priv_file:
        p, q = map(int, priv_file.read().split(","))
        private_key = paillier.PaillierPrivateKey(public_key, p, q)

    return public_key, private_key

def paillier_encrypt(public_key, plaintext):
    return public_key.encrypt(plaintext)

def paillier_decrypt(private_key, public_key, encrypted_data):
    encrypted_number = paillier.EncryptedNumber(public_key, encrypted_data)
    return private_key.decrypt(encrypted_number)