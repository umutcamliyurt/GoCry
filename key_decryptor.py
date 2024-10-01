import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

def load_private_key(pem_file):
    """Load RSA private key from PEM file."""
    with open(pem_file, 'rb') as f:
        private_key = RSA.import_key(f.read())
    return private_key

def decrypt_aes_key(encrypted_aes_key_b64, private_key):
    """Decrypt AES key using the RSA private key (with PKCS1 v1.5 padding)."""
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    cipher_rsa = PKCS1_v1_5.new(private_key)
    sentinel = get_random_bytes(16)  # Random bytes for error handling
    aes_key = cipher_rsa.decrypt(encrypted_aes_key, sentinel)

    if aes_key == sentinel:
        raise ValueError("Incorrect decryption.")
    
    return aes_key

def main():
    # Get the path to the RSA private key from user input
    private_key_path = input("Enter the path to your RSA private key (PEM format): ").strip()

    # Get the Base64-encoded AES key from user input
    encrypted_aes_key_b64 = input("Enter the Base64-encoded AES key: ").strip()

    try:
        # Load the RSA private key
        private_key = load_private_key(private_key_path)

        # Decrypt the AES key
        aes_key = decrypt_aes_key(encrypted_aes_key_b64, private_key)

        # Display the decrypted AES key
        print("Decrypted AES Key (in hex):", aes_key.hex())

    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
