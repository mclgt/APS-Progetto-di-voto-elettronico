import os
import json
from TLSSession import TLSSession
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class IdentityProvider:
    def __init__(self):
        """Creazione coppia di chiavi pubblica/privata per l'Identity Provider."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key() 

        """Registro degli aventi diritto al voto"""
        self._registry = {
            "RSSMRA85M01H501Z": {"maggiorenne": True, "diritto_voto": True},
            "VRDLGI90A01F205X": {"maggiorenne": True, "diritto_voto": True},
            "BNCLRA08T41H501Y": {"maggiorenne": False, "diritto_voto": False},
            "NROFNC75B02F205W": {"maggiorenne": True, "diritto_voto": False}
        }

        """Registro per garantire univocità dei voti"""
        self._voted_voters = set()

        """Tabella temporanea per gli authorization code"""
        self._authorization_codes = {}

    def get_public_key(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def request_authorization_code(self, fiscal_code: str, pk_eff:bytes)->str:
        """Verifica requisiti anagrafici e marcatura antifrode"""
        if fiscal_code not in self._registry:
            raise ValueError("Autenticazione fallita: utente non censito.")
        user_status = self._registry[fiscal_code]
        if not user_status["maggiorenne"] or not user_status["diritto_voto"]:
            raise PermissionError("Accesso negato: Requisiti elettorali non soddisfatti.")

        """Controllo unicità del lettore"""
        if fiscal_code in self._voted_voters:
            raise PermissionError("Tentativo di frode: Elettore già registrato per il voto.")
        self._voted_voters.add(fiscal_code)
        """Generazione dell'authorization code temporaneo"""
        auth_code=os.urandom(16).hex()
        self._authorization_codes[auth_code]=pk_eff
        return auth_code

    def exchange_code_for_token(self,tls_session: TLSSession, encrypted_req: tuple[bytes, bytes])->tuple[bytes,bytes]:
        """Scambio del codice sul canale TLS e rilascio di token voto e Tsign"""
        nonce, ciphertext = encrypted_req
        req_bytes=tls_session.receive_encrypted(nonce,ciphertext)
        req_data=json.loads(req_bytes.decode("utf-8"))
        auth_code=req_data.get("auth_code")

        if auth_code not in self._authorization_codes:
            raise PermissionError("Authorization code non valido")

        pk_eff=self._authorization_codes.pop(auth_code)

        token_voto = os.urandom(16).hex()

        """Costruzione di T_sign"""
        payload=f"{token_voto} ||".encode("utf-8")+pk_eff

        """Firma RSA"""
        signature=self.private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        response_payload = {
            "token_voto": token_voto,
            "pk_eff": pk_eff.decode("utf-8"),
            "signature": signature.hex(),
        }

        "Risposta cifrata su canale TLS"
        return tls_session.send_encrypted(
            json.dumps(response_payload).encode("utf-8")
        )