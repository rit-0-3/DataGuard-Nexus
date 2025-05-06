import time
from paillier import load_rsa_keys, rsa_encrypt, rsa_decrypt
from dna import generate_aes_key

def main():
    # RSA Key Generation
    start = time.time()
    rsa_public_key, rsa_private_key = load_rsa_keys()
    rsa_keygen_time = time.time() - start

    # AES Key Generation
    start = time.time()
    aes_key = generate_aes_key()
    aes_keygen_time = time.time() - start

    # RSA Encryption of AES Key
    start = time.time()
    rsa_encrypted_key = rsa_encrypt(rsa_public_key, aes_key)
    rsa_enc_time = time.time() - start

    # RSA Decryption of AES Key
    start = time.time()
    aes_decrypted_key = rsa_decrypt(rsa_private_key, rsa_encrypted_key)
    rsa_dec_time = time.time() - start

    # Output results
    print("\n--- RSA Timing for AES Key Encryption/Decryption ---")
    print(f"RSA Key Generation Time      : {rsa_keygen_time:.6f} seconds")
    print(f"AES Key Generation Time      : {aes_keygen_time:.6f} seconds")
    print(f"RSA Encryption Time (AES Key): {rsa_enc_time:.6f} seconds")
    print(f"RSA Decryption Time (AES Key): {rsa_dec_time:.6f} seconds")

if __name__ == "__main__":
    main()
