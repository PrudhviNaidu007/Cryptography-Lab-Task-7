from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
import os
import matplotlib.pyplot as plt
import numpy as np

def generate_ecc_key(curve):

    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_aes_key(aes_key, public_key):
    shared_key = public_key.public_numbers().x.to_bytes(32, 'big')
    aes_key_encrypted = bytes([a ^ b for a, b in zip(aes_key, shared_key[:len(aes_key)])])
    return aes_key_encrypted

def decrypt_aes_key(aes_key_encrypted, private_key):
    shared_key = private_key.public_key().public_numbers().x.to_bytes(32, 'big')
    aes_key = bytes([a ^ b for a, b in zip(aes_key_encrypted, shared_key[:len(aes_key_encrypted)])])
    return aes_key

def encrypt_message(message, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    pad_len = 16 - (len(message) % 16)
    padded_message = message + " " * pad_len
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(ciphertext, aes_key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return decrypted_message.strip().decode()

def plot_curve(a, b, p, title, x_limit=1000):
    points = []
    for x in range(x_limit):
        rhs = (x**3 + a*x + b) % p
        for y in range(0, x_limit):
            if (y*y) % p == rhs:
                points.append((x, y))
    if points:
        x_vals, y_vals = zip(*points)
        plt.scatter(x_vals, y_vals, s=5, color='blue')
    plt.title(title)
    plt.xlabel("x")
    plt.ylabel("y")
    plt.grid(True)

def main():
    message = "Hell0 SRM AP"
    
    private_key_1, public_key_1 = generate_ecc_key(ec.SECP256R1())
    private_key_2, public_key_2 = generate_ecc_key(ec.SECP256K1())
    
    aes_key = os.urandom(16)
    
    aes_key_encrypted_1 = encrypt_aes_key(aes_key, public_key_1)
    aes_key_encrypted_2 = encrypt_aes_key(aes_key, public_key_2)
    
    ciphertext = encrypt_message(message, aes_key)
    
    decrypted_aes_key_1 = decrypt_aes_key(aes_key_encrypted_1, private_key_1)
    decrypted_aes_key_2 = decrypt_aes_key(aes_key_encrypted_2, private_key_2)
    
    decrypted_message_1 = decrypt_message(ciphertext, decrypted_aes_key_1)
    decrypted_message_2 = decrypt_message(ciphertext, decrypted_aes_key_2)
    
    print("Original Message:", message)
    print("Decrypted Message (Curve 1 - secp256r1):", decrypted_message_1)
    print("Decrypted Message (Curve 2 - secp256k1):", decrypted_message_2)

    a_k1 = -3
    b_k1 = 7
    a_r1 = -3
    b_r1 = 4105836372515214219659623119953979731041094027254150191941
    
    p_demo = 1009
    
    plt.figure(figsize=(12, 5))
    plt.subplot(1, 2, 1)
    plot_curve(a_k1, b_k1, p_demo, "Demo Plot: Curve secp256k1 (mod 1009)")
    
    plt.subplot(1, 2, 2)
    plot_curve(a_r1, b_r1 % p_demo, p_demo, "Demo Plot: Curve secp256r1 (mod 1009)")
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()
