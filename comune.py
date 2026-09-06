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
        self.tokens_usati=set()
        self.voti_validi=[]

    def verifica_firma_idp(self, t_firma: dict)->bool:
        """Valida la firma digitale apposta dall'IdP sul 
        payload formato da (token_voto||pk_eff)"""
        token_voto=t_firma.get("token_voto")
        pk_eff=t_firma.get("pk_eff_pem")
        firma_hex=t_firma.get("firma")
        if not (token_voto and pk_eff and firma_hex):
            return False
        #Ricostruzione del payload atteso dall'Identity Provider
        payload_atteso=f"{token_voto} ||".encode("utf-8")+pk_eff.encode("utf-8")
        firma_bytes=bytes.fromhex(firma_hex)
        try:
            self.pk_idp.verify(
                firma_bytes,
                payload_atteso,
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

    def verifica_firma_eff(self, voto_cifrato: dict, t_firma: dict, firma_hex:str)->bool:
        """Verifica la firma apposta con la chiave privata effimera sul payload
        formato da (voto_cifrato||t_firma)"""
        pk_eff_str=t_firma.get("pk_eff_pem")
        if not pk_eff_str:
            return False
        try:
            #Caricamento della chiave pubblica effimera nel formato PEM
            pk_eff=serialization.load_pem_public_key(pk_eff_str.encode("utf-8"))
            #Ricostruzione del payload serializzato
            c_voto_bytes=json.dumps(voto_cifrato, sort_keys=True).encode("utf-8")
            t_firma_bytes=json.dumps(t_firma, sort_keys=True).encode("utf-8")
            firma_payload=c_voto_bytes+b"||"+t_firma_bytes
            firma_bytes=bytes.fromhex(firma_hex)
            pk_eff.verify(
                firma_bytes,
                firma_payload,
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

    def valida_pacchetto_voto(self, byte_pacchetto: bytes)->tuple[bool,str,dict]:
        """Riceve il pacchetto del cittadino ed esegue l'intera catena di validazione:
        1. deserializzazione del pacchetto
        2. verifica autenticità del token (firma idp)
        3. verifica univocità del voto
        4. verifica autenticità del votante anonimo
        """
        try:
            package = json.loads(byte_pacchetto.decode("utf-8"))
        except Exception:
            return False, "Formato pacchetto non valido: JSON corrotto", {}

        voto_cifrato = package.get("voto_cifrato")
        t_firma = package.get("t_firma")
        firma_eff = package.get("firma")
        if not (voto_cifrato and t_firma and firma_eff):
            return False, "Pacchetto incompleto: campi obbligatori mancanti", {}
        #Si verifica se la firma dell'IdP è valida
        token_voto=t_firma.get("token_voto")
        if not self.verifica_firma_idp(t_firma):
            return False, "Verifica fallita: Firma dell'IdP non valida", {}
        #Si verifica se il voto è stato già registrato dal comune per quel token
        if token_voto in self.tokens_usati:
            return False, "Tentativo di frode: Token di voto già utilizzato", {}
        #Si verifica se la firma effimera coincide con quella da cui il messaggio è arrivato
        if not self.verifica_firma_eff(voto_cifrato,t_firma,firma_eff):
            return False, "Verifica fallita: firma con chiave effimera non valida", {}
        #si segnala il token del voto ricevuto come usato
        self.tokens_usati.add(token_voto)
        scheda_validata={
            "token_voto": token_voto,
            "voto_cifrato": voto_cifrato,
            "t_firma": t_firma
        }
        self.voti_validi.append(scheda_validata)
        return True, "Pacchetto validato con successo", scheda_validata
    