import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class TLSSession:
    """Simula canale sicuro TLS tra Client e Idp"""
    def __init__(self, chiave_sessione: bytes):
        self.chiave_sessione=chiave_sessione

    def invia_cifrato(self, plaintext: bytes)-> tuple[bytes,bytes]:
        """cifra i dati applicativi su canale TLS usando AES_CTR"""
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.chiave_sessione), modes.CTR(nonce))
        cifratore = cipher.encryptor()
        ciphertext = cifratore.update(plaintext) + cifratore.finalize()
        return nonce, ciphertext

    def ricevi_cifrato(self, nonce: bytes, ciphertext:bytes)->bytes:
        """Decifra i dati applicativi ricevuti"""
        cipher = Cipher(algorithms.AES(self.chiave_sessione),modes.CTR(nonce))
        decifratore = cipher.decryptor()
        return decifratore.update(ciphertext)+decifratore.finalize()


    
    