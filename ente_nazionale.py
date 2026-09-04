import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes 
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