from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json

class ECCManager:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    def get_public_key(self):
        return self.private_key.public_key()

    def generate_shared_secret(self, peer_public_key):
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_secret)
        return derived_key

    def encrypt_data(self, key, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(data) + encryptor.finalize()

    def decrypt_data(self, key, encrypted_data):
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data[16:]) + decryptor.finalize()
