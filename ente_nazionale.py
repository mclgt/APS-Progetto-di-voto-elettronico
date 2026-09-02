from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

"""L'ente nazionale genera la chiave pubblica globale con cui tutti i cittadini cifreranno il voto"""

def generate_global_key():
    #Generazione chiave privata globale con valori standard
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key=private_key.public_key()
    #Serializzazione della chiave pubblica in un formato leggibile in modo che  anche i sistemi esterni possano usarla (ganache)
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pem_public_key



