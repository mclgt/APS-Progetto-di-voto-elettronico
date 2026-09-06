import os
import json
from TLSSession import TLSSession
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class IdentityProvider:
    def __init__(self):
        """Creazione coppia di chiavi pubblica/privata per l'Identity Provider."""
        self.sk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.pk = self.sk.public_key() 
        #Registro degli aventi diritto al voto
        self.registro = {
            "RSSMRA85M01H501Z": {"maggiorenne": True, "diritto_voto": True},
            "RDDFA85M01H501ZH": {"maggiorenne": True, "diritto_voto": True},
            "VRDLGI90A01F205X": {"maggiorenne": True, "diritto_voto": True},
            "BNCLRA08T41H501Y": {"maggiorenne": False, "diritto_voto": False},
            "NROFNC75B02F205W": {"maggiorenne": True, "diritto_voto": False}
        }
        #Registro per garantire univocità dei voti
        self.votanti_registrati = set()
        #Tabella temporanea per gli authorization code
        self._authorization_codes = {}

    def get_pk(self) -> bytes:
        return self.pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def richiesta_authorization_code(self, codice_fiscale: str, pk_eff:bytes)->str:
        """Verifica requisiti anagrafici e marcatura antifrode"""
        if codice_fiscale not in self.registro:
            raise ValueError("Autenticazione fallita: utente non censito.")
        stato_utente = self.registro[codice_fiscale]
        if not stato_utente["maggiorenne"] or not stato_utente["diritto_voto"]:
            raise PermissionError("Accesso negato: Requisiti elettorali non soddisfatti.")
        #Controllo unicità del lettore
        if codice_fiscale in self.votanti_registrati:
            raise PermissionError("Tentativo di frode: Elettore già registrato per il voto.")
        self.votanti_registrati.add(codice_fiscale)
        #Generazione dell'authorization code temporaneo
        auth_code=os.urandom(16).hex()
        self._authorization_codes[auth_code]=pk_eff
        return auth_code

    def scambia_codice_token(self,sessione_tls: TLSSession, richiesta_cifrata: tuple[bytes, bytes])->tuple[bytes,bytes]:
        """Scambio del codice sul canale TLS e rilascio di token voto e Tsign"""
        nonce, ciphertext = richiesta_cifrata
        richiesta_bytes=sessione_tls.ricevi_cifrato(nonce,ciphertext)
        dati_richiesta=json.loads(richiesta_bytes.decode("utf-8"))
        auth_code=dati_richiesta.get("auth_code")
        if auth_code not in self._authorization_codes:
            raise PermissionError("Authorization code non valido")
        pk_eff=self._authorization_codes.pop(auth_code)
        token_voto = os.urandom(16).hex()
        #Costruzione del pacchetto t_firma
        payload=f"{token_voto} ||".encode("utf-8")+pk_eff
        #Firma RSA
        firma=self.sk.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        payload_risposta = {
            "token_voto": token_voto,
            "pk_eff": pk_eff.decode("utf-8"),
            "firma": firma.hex(),
        }
        #Risposta cifrata su canale TLS
        return sessione_tls.invia_cifrato(
            json.dumps(payload_risposta).encode("utf-8")
        )