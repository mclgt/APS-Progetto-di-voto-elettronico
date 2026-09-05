import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes 
import secrets

"""Nello schema di distribuzione della chiave privata è necessario operare su 
un campo primo Z_p in cui p sia maggiore del segreto da frammentare d 
(per evitare l'alterazione del segreto facendo mod p).
Si richiedono quindi numeri primi di grandi dimensioni, in questo caso 2049 bit,
 per garantire la sicurezza della frammentazione. 
La formula indica il più grande numero primo rappresentabile con 2048 bit, 1381 è il numero
trovato tramite i test di primalità."""
PRIME_2048 = (1 << 2048) -1381 

class EnteNazionale:
    def __init__(self, ente_id="GLOBAL"): 
        self.id=ente_id
        #Coppia di chiavi registrata nella PKI servono per firmare i pacchetti certificando l'identità dell'ente
        self.sk = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.pk = self.sk.public_key()
        self.revoked_tokens=set() #insieme dei token invalidati


    def get_pk_pem(self)->bytes:
        """Restituisce la chiave pubblica in formato PEM"""
        return self.pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def generate_election_key(self): 
        """Genera la chiave pubblica e privata a 2048 bit per le elezioni. La chiave privata 
         viene usata solo per cifrare i voti e viene distrutta dopo la distribuzione dei frammenti"""
        sk_global=rsa.generate_private_key(
            public_exponent=65537, #valori standard per RSA
            key_size=2048,
        )
        pk_global=sk_global.public_key()
        pem_pk_global= pk_global.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return sk_global, pem_pk_global

    @staticmethod
    def split_secret(secret_int, t, n, prime=PRIME_2048):
        """Divide un segreto (esponente di di sk) in n parti, richiedendo almeno t parti per ricostruirlo: 
        - Il segreto è rappresentato come un intero ed è il termine noto
        - Gli altri coefficienti (t-1) sono generati casualmente tra 0 e prime-1
        La struttura shares associerà a ciascun scrutinatore un indice (da 1 a n) e il valore del frammento calcolato
        """
        coefficients = [secret_int] + [secrets.randbelow(prime) for _ in range(t - 1)]
        shares = []
        #Si assegna un indica da 1 a n a ciascuno scrutinatore e si calcola il valore 
        # del frammento usando il polinomio generato dai coefficienti e poi facendo modulo prime
        for i in range(1, n + 1):
            val=0
            for power, coeff in enumerate(coefficients):
                val = (val + coeff * pow(i, power, prime)) % prime  
            shares.append((i, val))
        return shares

    #Preparazione del pacchetto signcryption per gli scrutinatori
    def create_signcryption_package(self,share_point: tuple, scrutineer_id,  scrutineer_pk: rsa.RSAPublicKey)->bytes: 
        """La funzione implementa il protocollo di Singcryption per la distribuzine sicura dei 
        frammenti della chiave privata globale dell'ente nazionale agli scrutinatori.
        - La funzione prende in input il frammento della chiave privata (share_point),
        l'identità dello scrutinatore destinatario (scrutineer_id) e la chiave pubblica dello scrutinatore (scrutineer_pk).
        - La funzione restituisce un pacchetto cifrato e firmato (bytes) da inviare allo scrutinatore."""
        
        idx, share_val=share_point
        #Serializzazione del dato del frammento
        share_bytes=json.dumps({'idx': idx, 'share_val': share_val}).encode('utf-8') #estrae la coppia indice - valore del polinomio lo serializza in bytes il dizionario
        #Aggiunta dell'id del destinatario della firma
        sign_payload=share_bytes + b"||"+scrutineer_id.encode("utf-8")
        signature=self.sk.sign(
            sign_payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        #Aggiunta identità del mittente nella firma
        inner_block=json.dumps({
            "sender": self.id, 
            "share": share_bytes.decode("utf-8"),
            "signature": signature.hex()
        }).encode("utf-8")
        #cifratura con la chiave pubbblica dello scrutinatore (RSA-OAEP)
        session_key=secrets.token_bytes(32)  #session key simmetrica (ibrido)
        ciphered_session_key=scrutineer_pk.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm=AESGCM(session_key)
        nonce=secrets.token_bytes(12)  #Nonce per AES-GCM
        ciphered_inner_block=aesgcm.encrypt(nonce, inner_block, None)
        #Creazione del pacchetto finale- tutto trasformato in esadecimale per la serializzazione
        package={
            "enc_key": ciphered_session_key.hex(), 
            "nonce": nonce.hex(),
            "ciphertext": ciphered_inner_block.hex()   
        }
        return json.dumps(package).encode("utf-8")

    def setup_election(self, scrutineeers_pk:dict):
        """Setup dell'elezione:
          1 generazione delle chiavi per l'elezione
          2 frmamentazione dell'esponente privato della chiave 
          3. invio del pacchetto signcryption
          4. distruzione della chiave skglob dalla memoria 
          Restituisce anche il modulo n 
          necessari agli scrutinatori per poter riscotruire la chiave privata RSA in fase di spoglio"""
        n_scrutineers= len(scrutineeers_pk)
        t_treshold= (n_scrutineers//2)+1
        sk_glob, pem_pk_glob=self.generate_election_key()
        #Si estrae l'esponente privato di Sk_glob per frammentarlo
        d_secret= sk_glob.private_numbers().d
        global_n=sk_glob.public_key().public_numbers().n
        shares=self.split_secret(d_secret, t_treshold, n_scrutineers)
        packages={}
        for idx, (s_id, pk_scrut) in enumerate(scrutineeers_pk.items()):
            share_point=shares[idx]
            package=self.create_signcryption_package(share_point, s_id, pk_scrut)
            packages[s_id]=package
        #distruzione della chiave privata dalla memoria dell'ente
        del sk_glob
        del d_secret
        return pem_pk_glob, global_n, packages

    def resolve_dispute(self, dispute_package, blockchain_list, idp_pk:rsa.RSAPublicKey): 
        """Valida la contestazione dell'elettore e rilascia un nuovo token se
          e solo se il vecchio voto non è presente in bacheca"""
        try: 
            t_sign=dispute_package["t_sign"]
            statement=dispute_package["statement"]
            eff_sign= bytes.fromhex(dispute_package["eff_signature"])
            token=statement["token"]
            pk_eff_pem=t_sign.get("pk_eff_pem")
            idp_sig = bytes.fromhex(t_sign["signature"])
            #verifica della validità della firma dell'IdP sul Token
            payload_idp=f"{token} ||".encode("utf-8")
            idp_pk.verify(
                idp_sig,
                payload_idp,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256()
            )
            #verifica che chi contesta possieda la chiave effimera contenuta nel pacchetto dell'idp
            pk_eff=serialization.load_pem_public_key(pk_eff_pem.encode("utf-8"))
            statement_bytes=json.dumps(statement, sort_keys=True).encode("utf-8")
            pk_eff.verify(
                eff_sign,
                statement_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            #si verifica se il token è stato già revocato
            if token in self.revoked_tokens:
                return False,None,"Contestazione respinta: il token è stato già revocato"
            #si verifica sulla blockchain se il voto è realmente mancante
            token_hash=hashlib.sha256(str(token).encode()).hexdigest()[:32]+"..."
            vote_found= any(b.get("token_hash")==token_hash for b in blockchain_list)
            if vote_found: 
                return False, None, f"Contestazione respinta: il voto è registrato in bacheca"
            #altrimenti la contestazione viene accettata
            self.revoked_tokens.add(token)
            new_token=os.urandom(16).hex()
            new_payload=f"{new_token}||".encode("utf-8")+pk_eff_pem.encode("utf-8")
            new_signature=self.sk.sign(
                new_payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            new_t_sign = {
                "token": new_token,
                "token_voto": new_token,
                "pk_eff_pem": pk_eff_pem,
                "signature": new_signature.hex(),
                "recovered_by": self.id
            }
            return True, new_t_sign, f"Contestazione ACCOLTA: Il vecchio token  è stato revocato. Emesso nuovo token di voto."

        except Exception as e:
            return False, None, f"Errore durante l'elaborazione della contestazione"