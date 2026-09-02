import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat. primitives import hashes
from cryptography.hazmat.primitives import serialization

def prepare_vote(pk_glob_pem, token_idp, vote): 
    """Prepara e cifra il voto del cittadino sfruttando la chiave pubblica globale dell'ente nazionale e il token di identità del cittadino fornito dall'idp"""
    #Prelevamento della chiave pubblica globale 
    global_public_key=serialization.load_pem_public_key(pk_glob_pem)
    #Si generano le chiavi effimere per la sessione di voto
    eff_private_key=rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048
    )
    eff_public_key=eff_private_key.public_key()
    #Generazione nonce per padding casuale (OAEP)
    nonce=os.urandom(16)
    plaintext=vote.encode('utf-8') + b'||' +nonce
    ciphervote=global_public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #Firma del voto cifrato e del token di identità con la chiave privata effimera
    to_sign=ciphervote+token_idp
    signature=eff_private_key.sign(
        to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    #Preparazione del pacchetto dati da inviare
    data={
        'ciphervote': ciphervote,
        'token_idp': token_idp,
        'eff_public_key_pem': eff_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        'signature': signature
    }
    return data
