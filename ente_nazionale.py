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

    def get_pk_pem(self)->bytes:
        """Restituisce la chiave pubblica in formato PEM"""
        return self.pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def genera_chiavi_elezione(self): 
        """Genera la chiave pubblica e privata a 2048 bit per le elezioni. La chiave privata 
         viene usata solo per cifrare i voti e viene distrutta dopo la distribuzione dei frammenti"""
        sk_globale=rsa.generate_private_key(
            public_exponent=65537, #valori standard per RSA
            key_size=2048,
        )
        pk_globale=sk_globale.public_key()
        pem_pk_globale= pk_globale.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return sk_globale, pem_pk_globale

    @staticmethod
    def frammenta_segreto(segreto_int, t, n, primo=PRIME_2048):
        """Divide un segreto (esponente di di sk) in n parti, richiedendo almeno t parti per ricostruirlo: 
        - Il segreto è rappresentato come un intero ed è il termine noto
        - Gli altri coefficienti (t-1) sono generati casualmente tra 0 e primo-1
        La struttura frammenti associerà a ciascun scrutinatore un indice (da 1 a n) e il valore del frammento calcolato
        """
        coefficienti = [segreto_int] + [secrets.randbelow(primo) for _ in range(t - 1)]
        frammenti = []
        #Si assegna un indica da 1 a n a ciascuno scrutinatore e si calcola il valore 
        # del frammento usando il polinomio generato dai coefficienti e poi facendo modulo primo
        for i in range(1, n + 1):
            val=0
            for pot, coeff in enumerate(coefficienti):
                val = (val + coeff * pow(i, pot, primo)) % primo  
            frammenti.append((i, val))
        return frammenti

    #Preparazione del pacchetto signcryption per gli scrutinatori
    def crea_pacchetto_signcryption(self,frammento_punto: tuple, id_scrutinatore,  pk_scrutinatore: rsa.RSAPublicKey)->bytes: 
        """La funzione implementa il protocollo di Singcryption per la distribuzine sicura dei 
        frammenti della chiave privata globale dell'ente nazionale agli scrutinatori.
        - La funzione prende in input il frammento della chiave privata (frammento_punto),
        l'identità dello scrutinatore destinatario (id_scrutinatore) e la chiave pubblica dello scrutinatore (pk_scrutinatore).
        - La funzione restituisce un pacchetto cifrato e firmato (bytes) da inviare allo scrutinatore."""
        
        idx, valore_frammento=frammento_punto
        #Serializzazione del dato del frammento
        frammento_bytes=json.dumps({'idx': idx, 'valore_frammento': valore_frammento}).encode('utf-8') #estrae la coppia indice - valore del polinomio lo serializza in bytes il dizionario
        #Aggiunta dell'id del destinatario della firma
        firma_payload=frammento_bytes + b"||"+id_scrutinatore.encode("utf-8")
        firma=self.sk.sign(
            firma_payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        #Aggiunta identità del mittente nella firma
        blocco_interno=json.dumps({
            "sender": self.id, 
            "share": frammento_bytes.decode("utf-8"),
            "firma": firma.hex()
        }).encode("utf-8")
        #cifratura con la chiave pubbblica dello scrutinatore (RSA-OAEP)
        session_key=secrets.token_bytes(32)  #session key simmetrica (ibrido)
        ciphered_session_key=pk_scrutinatore.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm=AESGCM(session_key)
        nonce=secrets.token_bytes(12)  #Nonce per AES-GCM
        blocco_interno_cifrato=aesgcm.encrypt(nonce, blocco_interno, None)
        #Creazione del pacchetto finale- tutto trasformato in esadecimale per la serializzazione
        pacchetto={
            "chiave_cifrata": ciphered_session_key.hex(), 
            "nonce": nonce.hex(),
            "ciphertext": blocco_interno_cifrato.hex()   
        }
        return json.dumps(pacchetto).encode("utf-8")

    def setup_elezione(self, pk_scrutinatori:dict):
        """Setup dell'elezione:
          1 generazione delle chiavi per l'elezione
          2 frmamentazione dell'esponente privato della chiave 
          3. invio del pacchetto signcryption
          4. distruzione della chiave skglob dalla memoria 
          Restituisce anche il modulo n 
          necessari agli scrutinatori per poter riscotruire la chiave privata RSA in fase di spoglio"""
        num_scrutinatori= len(pk_scrutinatori)
        t_treshold= (num_scrutinatori//2)+1
        sk_glob, pem_pk_glob=self.genera_chiavi_elezione()
        #Si estrae l'esponente privato di Sk_glob per frammentarlo
        segreto_d= sk_glob.private_numbers().d
        n_globale=sk_glob.public_key().public_numbers().n
        frammenti=self.frammenta_segreto(segreto_d, t_treshold, num_scrutinatori)
        pacchetti={}
        for idx, (s_id, pk_scrut) in enumerate(pk_scrutinatori.items()):
            frammento_punto=frammenti[idx]
            pacchetto=self.crea_pacchetto_signcryption(frammento_punto, s_id, pk_scrut)
            pacchetti[s_id]=pacchetto
        #distruzione della chiave privata dalla memoria dell'ente
        del sk_glob
        del segreto_d
        return pem_pk_glob, n_globale, pacchetti

    

   