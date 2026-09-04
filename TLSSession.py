import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class TLSSession:
    """Simula canale sicuro TLS tra Client e Idp"""
    def __init__(self, session_key: bytes):
        self.session_key=session_key

    def send_encrypted(self, plaintext: bytes)-> tuple[bytes,bytes]:
        """cifra i dati applicativi su canale TLS usando AES_CTR"""
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.session_key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce, ciphertext

    def receive_encrypted(self, nonce: bytes, ciphertext:bytes)->bytes:
        """Decifra i dati applicativi ricevuti"""
        cipher = Cipher(algorithms.AES(self.session_key),modes.CTR(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)+decryptor.finalize()
    
    
    