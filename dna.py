import rsa
from Crypto.Cipher import AES
import os

binary_to_dna = {'00': 'A', '01': 'T', '10': 'C', '11': 'G'}
dna_to_binary = {v: k for k, v in binary_to_dna.items()}

def binary_to_dna_seq(binary_data):
    return ''.join(binary_to_dna[binary_data[i:i + 2]] for i in range(0, len(binary_data), 2))

def dna_to_binary_seq(dna_data):
    return ''.join(dna_to_binary[d] for d in dna_data)

def to_binary(data):
    binary = bin(data)[2:]
    return binary.zfill(8 * ((len(binary) + 7) // 8))

def from_binary(binary_data):
    return int(binary_data, 2)

def dna_encrypt(data):
    binary_data = to_binary(int(data))
    return binary_to_dna_seq(binary_data)

def dna_decrypt(dna_data):
    binary_data = dna_to_binary_seq(dna_data)
    return from_binary(binary_data)

def generate_aes_key():
    return os.urandom(32)

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce + ciphertext

def aes_decrypt(encrypted_data, key):
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

def generate_rsa_keys():
    public_key, private_key = rsa.newkeys(4096)
    with open("rsa_public_key.pem", "wb") as pub_file:
        pub_file.write(public_key.save_pkcs1("PEM")) 
    with open("rsa_private_key.pem", "wb") as priv_file:
        priv_file.write(private_key.save_pkcs1("PEM"))
    print("[INFO] RSA keys generated successfully.")
    return public_key, private_key

def load_rsa_keys():
    if not (os.path.exists("rsa_public_key.pem") and os.path.exists("rsa_private_key.pem")):
        print("[INFO] RSA keys not found. Generating new ones...")
        return generate_rsa_keys()

    with open("rsa_public_key.pem", "rb") as pub_file:
        public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
    with open("rsa_private_key.pem", "rb") as priv_file:
        private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())

    return public_key, private_key

def rsa_encrypt(public_key, data):
    return rsa.encrypt(data, public_key)

def rsa_decrypt(private_key, encrypted_data):
    return rsa.decrypt(encrypted_data, private_key)