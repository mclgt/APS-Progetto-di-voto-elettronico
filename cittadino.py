import os
import json
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat. primitives import hashes
from cryptography.hazmat.primitives import serialization

class Cittadino: 
    def __init__(self, cf):
        self.cf=cf
        self.sk_eff=None
        self.pk_eff=None
        self.token_voto=None
        self.t_sign=None #pacchetto ricevuto dall'IdP

    def generate_eff_keys(self):
        """Genera una coppia di chiavi effimere prima di reindirizzarsi all'IdP"""
        self.sk_eff=rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.pk_eff=self.sk_eff.public_key()
        return self.pk_eff

    def get_pk_eff_pem(self)->bytes:
        """Restituisce la chiave pubblica effimera in formato PEM"""
        return self.pk_eff.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def receive_token(self, t_sign:dict): 
        """Riceve da IdP il la struttura firmata: 
            Tsign=SignSkIdP(Token ||Pkeff) scambiata tramite l'Authorization Code su
            un canale TLS"""
        required={"token_voto", "pk_eff_pem", "signature"}
        if not required.issubset(t_sign):
            raise ValueError(f"Tsign incompleto: attesi i campi {required}")
        self.t_sign = t_sign
        self.token_voto = t_sign["token_voto"]

    @staticmethod
    def one_hot_encode(choice_idx: int, n_options: int)->bytes: 
        """Traduce la preferenza in un vettore binario di n opzioni"""
        if not (0<= choice_idx < n_options):
            raise ValueError(f"Indice della preferenza non valido: {choice_idx}")
        vector=bytearray(n_options)
        vector[choice_idx]=1
        return bytes(vector)

    def encode_vote(self, choice_idx:int, n_options:int)->bytes: 
        one_hot=self.one_hot_encode(choice_idx, n_options)
        #Si aggiunge un padding randomico
        padding=secrets.token_bytes(32)
        return one_hot + b'||' + padding

    @staticmethod
    def encrypt_vote(M:bytes,pk_glob:rsa.RSAPublicKey)->dict: 
        """Cifratura ibrida: chiave di sessione cifrata con RSA-OAEP e payload cifrato con
        tecnica simmetrica. La modalità è analoga a quella usata tra Ente e Scrutinatore """ 
        session_key=secrets.token_bytes(32)
        k_enc=pk_glob.encrypt(
            session_key, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm=AESGCM(session_key)
        nonce= secrets.token_bytes(12)
        c_vote=aesgcm.encrypt(nonce, M, None)
        return{
            "k_enc": k_enc.hex(), 
            "nonce": nonce.hex(), 
            "c_vote": c_vote.hex()
        }
    

                   
    def build_package(self, choice_idx:int, n_options:int, pk_glob:rsa.RSAPublicKey)->bytes: 
        """Costruisce il pacchetto P:{Votocifrato, Tsigm, firma_eff} da inviari ai comuni limitrofi. 
        La firma è relativa alla concatenazione del votocifrato e del token con la chiave privata effimera"""
        if self.sk_eff is None:
            raise RuntimeError("Chiavi effimere non generate: chiamare generate_ephemeral_keys()")
        if self.t_sign is None:
            raise RuntimeError("Token non ricevuto dall'IdP: chiamare receive_token()")
        M=self.encode_vote(choice_idx, n_options)
        encrypted_vote=self.encrypt_vote(M, pk_glob)
        enc_vote_bytes=json.dumps(encrypted_vote, sort_keys=True).encode("utf-8")
        t_sign_bytes=json.dumps(self.t_sign, sort_keys=True).encode("utf-8")
        sign_payload=enc_vote_bytes+ b"||"+t_sign_bytes
        signature=self.sk_eff.sign(
            sign_payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        package={
            "encrypted_vote": encrypted_vote, 
            "t_sign":self.t_sign, 
            "signature":signature.hex()
        }
        return json.dumps(package).encode("utf-8")