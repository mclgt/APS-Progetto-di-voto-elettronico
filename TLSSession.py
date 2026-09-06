import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class TLSSession:
    """Simula canale sicuro TLS tra Client e Idp"""
    def __init__(self, chiave_sessione: bytes):
        self.chiave_sessione=chiave_sessione
        self.aesgcm =AESGCM(self.chiave_sessione)

    def invia_cifrato(self, plaintext: bytes)-> tuple[bytes,bytes]:
        """cifra i dati applicativi su canale TLS usando AES_CTR"""
        nonce = os.urandom(16)
        ciphertext = self.aesgcm.encrypt(nonce,plaintext, None)
        return nonce, ciphertext

    def ricevi_cifrato(self, nonce: bytes, ciphertext:bytes)->bytes:
        """Decifra i dati applicativi ricevuti"""
        return self.aesgcm.decrypt(nonce, ciphertext, None)


    
    