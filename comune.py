import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

class Comune:
    """Inizializza l'autorità comunale (Resource Server).
    Contiene chiave pubblica dell'IdP, il registro per il tracciamento
    dei token utilizzati e il registro locale dei pacchetti che hanno
    superato i controlli"""
    def __init__(self, idp_public_key: rsa.RSAPublicKey):
        self.pk_idp=idp_public_key
        self.used_tokens=set()
        self.validated_vote=[]

    def _sign_verify_idp(self, t_sign: dict)->bool:
        """Valida la firma digitale apposta dall'IdP sul 
        payload formato da (token_voto||pk_eff)"""
        token_voto=t_sign.get("token_voto")
        pk_eff=t_sign.get("pk_eff_pem")
        sign_hex=t_sign.get("signature")

        if not (token_voto and pk_eff and sign_hex):
            return False

        """Ricostruzione del payload atteso dall'Identity Provider"""
        expected_payload=f"{token_voto} ||".encode("utf-8")+pk_eff.encode("utf-8")
        sign_bytes=bytes.fromhex(sign_hex)

        try:
            self.pk_idp.verify(
                sign_bytes,
                expected_payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def _eff_sign_verify(self, encrypted_vote: dict, t_sign: dict, sign_hex:str)->bool:
        """Verifica la firma apposta con la chiave privata effimera sul payload
        formato da (voto_cifrato||t_sign)"""
        pk_eff_str=t_sign.get("pk_eff_pem")
        if not pk_eff_str:
            return False
        try:
            """caricamento della chiave pubblica effimera nel formato PEM"""
            pk_eff=serialization.load_pem_public_key(pk_eff_str.encode("utf-8"))

            """Ricostruzione del payload serializzato"""
            enc_vote_bytes=json.dumps(encrypted_vote, sort_keys=True).encode("utf-8")
            t_sign_bytes=json.dumps(t_sign, sort_keys=True).encode("utf-8")
            sign_payload=enc_vote_bytes+b"||"+t_sign_bytes

            sign_bytes=bytes.fromhex(sign_hex)

            pk_eff.verify(
                sign_bytes,
                sign_payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def valida_pacchetto_voto(self, package_bytes: bytes)->tuple[bool,str,dict]:
        """Riceve il pacchetto del cittadino ed esegue l'intera catena di validazione:
        1. deserializzazione del pacchetto
        2. verifica autenticità del token (firma idp)
        3. verifica univocità del voto
        4. verifica autenticità del votante anonimo
        """
        try:
            package = json.loads(package_bytes.decode("utf-8"))
        except Exception:
            return False, "Formato pacchetto non valido: JSON corrotto", {}

        encrypted_vote = package.get("encrypted_vote")
        t_sign = package.get("t_sign")
        signature_eff = package.get("signature")

        if not (encrypted_vote and t_sign and signature_eff):
            return False, "Pacchetto incompleto: campi obbligatori mancanti", {}

        token_voto=t_sign.get("token_voto")

        if not self._sign_verify_idp(t_sign):
            return False, "Verifica fallita: Firma dell'IdP non valida", {}

        if token_voto in self.used_tokens:
            return False, "Tentativo di frode: Token di voto già utilizzato", {}

        if not self._eff_sign_verify(encrypted_vote,t_sign,signature_eff):
            return False, "Verifica fallita: firma con chiave effimera non valida", {}

        self.used_tokens.add(token_voto)

        scheda_validata={
            "token_voto": token_voto,
            "encrypted_vote": encrypted_vote,
            "t_sign": t_sign
        }
        self.validated_vote.append(scheda_validata)

        return True, "Pacchetto validato con successo", scheda_validata
    