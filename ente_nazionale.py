import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes 
import secrets


def generate_global_key():
    """ Genera una coppia di chiavi RSA per l'ente nazionale: 
     - Le chiavi risultano essere difficili da ricavare grazie alla dimensione a 2048 bit e all'esponente standard
     - La chiave pubblica viene serializzata in formato PEM per essere condivisa anche con sistemi esterni (ad esempio Ganache)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537, #valori standard per RSA
        key_size=2048,
    )
    public_key=private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pem_public_key


"""Nello schema di distribuzione della chiave privata è necessario operare su 
un campo primo Z_p in cui p sia maggiore del segreto da frammentare d 
(per evitare l'alterazione del segreto facendo mod p).
Si richiedono quindi numeri primi di grandi dimensioni, in questo caso 2049 bit,
 per garantire la sicurezza della frammentazione. 
La formula indica il più grande numero primo rappresentabile con 2048 bit, 1381 è il numero
trovato tramite i test di primalità."""
PRIME_2048 = (1 << 2048) -1381 

def split_secret(secret_int, t, n, prime=PRIME_2048):
    """Divide un segreto in n parti, richiedendo almeno t parti per ricostruirlo: 
      - Il segreto è rappresentato come un intero (ad esempio l'esponente privato della chiave RSA) 
        ed è il termine noto
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
def create_signcryption_package( share_point: tuple, scrutineer_id, global_id, global_sk: rsa.RSAPrivateKey, scrutineer_pk: rsa.RSAPublicKey)->bytes: 
    """La funzione implementa il protocollo di Singcryption per la distribuzine sicura dei 
    frammenti della chiave privata globale dell'ente nazionale agli scrutinatori.
    - La funzione prende in input il frammento della chiave privata (share_point),
      l'identità dello scrutinatore destinatario (scrutineer_id),
      l'identità dell'ente nazionale (global_id), 
      la chiave privata globale dell'ente (global_sk) e la chiave pubblica dello scrutinatore (scrutineer_pk).
      - La funzione restituisce un pacchetto cifrato e firmato (bytes) da inviare allo scrutinatore."""
    
    idx, share_val=share_point
    #Serializzazione del dato del frammento
    share_bytes=json.dumps({'idx': idx, 'share_val': share_val}).encode('utf-8') #estrae la coppia indice - valore del polinomio lo serializza in bytes il dizionario
    #Aggiunta dell'id del destinatario della firma
    sign_payload=share_bytes + b"||"+scrutineer_id.encode("utf-8")
    signature=global_sk.sign(
        sign_payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    #Aggiunta identità del mittente nella firma
    inner_block=json.dumps({
        "sender": global_id, 
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

def setup_election(n_scrutineers, scrutineeers_pk:dict, global_sk, global_id="GLOBAL"):
    """Setup dell'elezione: generazione chiave globale e distribuzione dei frammenti agli scrutinatori"""
    sk_glob, pem_pk_glob=generate_global_key()
    #Si estrae l'esponente privato di Sk_glob per frammentarlo
    d_secret= sk_glob.private_numbers().d
    t_treshold= (n_scrutineers//2)+1
    shares=split_secret(d_secret, t_treshold, n_scrutineers)
    packages={}
    for idx, (s_id, pk_scrut) in enumerate(scrutineeers_pk.items()):
        share_point=shares[idx]
        package=create_signcryption_package(share_point, s_id, global_id, global_sk, pk_scrut)
        packages[s_id]=package
    #distruzione della chiave privata dalla memoria dell'ente
    del sk_glob
    del d_secret
    return pem_pk_glob, packages