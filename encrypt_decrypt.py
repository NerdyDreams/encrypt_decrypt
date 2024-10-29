import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Define the encryption key and initialization vector (IV)
key = os.urandom(32)  # 256-bit key for AES-256
iv = os.urandom(16)   # 128-bit IV for AES

def encrypt_aes_cbc(plaintext, key, iv):
    # Pad the plaintext
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded plaintext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Convert ciphertext to HEX and Base64
    ciphertext_hex = ciphertext.hex()
    ciphertext_base64 = base64.b64encode(ciphertext).decode()

    return ciphertext, ciphertext_hex, ciphertext_base64

def decrypt_aes_cbc(ciphertext, key, iv):
    # Decrypt the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()

# Encrypt the plaintext
plaintext = "Welcome to Lagos"
ciphertext, ciphertext_hex, ciphertext_base64 = encrypt_aes_cbc(plaintext, key, iv)

print("Encrypted (HEX):", ciphertext_hex)
print("Encrypted (Base64):", ciphertext_base64)

# Decrypt from HEX
ciphertext_from_hex = bytes.fromhex(ciphertext_hex)
decrypted_text_from_hex = decrypt_aes_cbc(ciphertext_from_hex, key, iv)
print("Decrypted from HEX:", decrypted_text_from_hex)

# Decrypt from Base64
ciphertext_from_base64 = base64.b64decode(ciphertext_base64)
decrypted_text_from_base64 = decrypt_aes_cbc(ciphertext_from_base64, key, iv)
print("Decrypted from Base64:", decrypted_text_from_base64)
