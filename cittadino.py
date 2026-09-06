import os
import json
import secrets
import hashlib
from datetime import datetime
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
        self.t_firma=None #pacchetto ricevuto dall'IdP

    def genera_chiavi_effimere(self):
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

    def ricevi_token(self, t_firma:dict): 
        """Riceve da IdP il la struttura firmata: 
            Tsign=SignSkIdP(Token ||Pkeff) scambiata tramite l'Authorization Code su un canale TLS"""
        richiesti={"token_voto", "pk_eff_pem", "firma"}
        if not richiesti.issubset(t_firma):
            raise ValueError(f"Tsign incompleto: attesi i campi {richiesti}")
        self.t_firma = t_firma
        self.token_voto = t_firma["token_voto"]

    @staticmethod
    def codifica_one_hot(indice_scelta: int, n_opzioni: int)->bytes: 
        """Traduce la preferenza in un vettore binario di n opzioni"""
        if not (0<= indice_scelta < n_opzioni):
            raise ValueError(f"Indice della preferenza non valido: {indice_scelta}")
        vettore=bytearray(n_opzioni)
        vettore[indice_scelta]=1
        return bytes(vettore)

    def codifica_voto(self, indice_scelta:int, n_opzioni:int)->bytes: 
        one_hot=self.codifica_one_hot(indice_scelta, n_opzioni)
        #Si aggiunge un padding randomico
        padding=secrets.token_bytes(32)
        return one_hot + b'||' + padding

    @staticmethod
    def cifra_voto(M:bytes,pk_glob:rsa.RSAPublicKey)->dict: 
        """Cifratura ibrida: chiave di sessione cifrata con RSA-OAEP e payload cifrato con
        tecnica simmetrica. La modalità è analoga a quella usata tra Ente e Scrutinatore """ 
        chiave_sessione=secrets.token_bytes(32)
        c_cifr=pk_glob.encrypt(
            chiave_sessione, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm=AESGCM(chiave_sessione)
        nonce= secrets.token_bytes(12)
        c_voto=aesgcm.encrypt(nonce, M, None)
        return{
            "c_cifr": c_cifr.hex(), 
            "nonce": nonce.hex(), 
            "c_voto": c_voto.hex()
        }
    

                   
    def costruisci_pacchetto(self, indice_scelta:int, n_opzioni:int, pk_glob:rsa.RSAPublicKey)->bytes: 
        """Costruisce il pacchetto P:{Votocifrato, Tsigm, firma_eff} da inviari ai comuni limitrofi. 
        La firma è relativa alla concatenazione del votocifrato e del token con la chiave privata effimera"""
        if self.sk_eff is None:
            raise RuntimeError("Chiavi effimere non generate: chiamare generate_ephemeral_keys()")
        if self.t_firma is None:
            raise RuntimeError("Token non ricevuto dall'IdP: chiamare ricevi_token()")
        M=self.codifica_voto(indice_scelta, n_opzioni)
        voto_cifrato=self.cifra_voto(M, pk_glob)
        c_voto_bytes=json.dumps(voto_cifrato, sort_keys=True).encode("utf-8")
        t_firma_bytes=json.dumps(self.t_firma, sort_keys=True).encode("utf-8")
        firma_payload=c_voto_bytes+ b"||"+t_firma_bytes
        firma=self.sk_eff.sign(
            firma_payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        pacchetto={
            "voto_cifrato": voto_cifrato, 
            "t_firma":self.t_firma, 
            "firma":firma.hex()
        }
        return json.dumps(pacchetto).encode("utf-8")

    def ricevi_token_hash(self):
        """Calcola l'identificativo anonimo mostrato nella bacheca"""
        if not hasattr(self, 'token_voto') or not self.token_voto: 
            return ""
        return hashlib.sha256(str(self.token_voto).encode()).hexdigest()[:32]+"..."
