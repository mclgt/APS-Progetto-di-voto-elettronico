import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

PRIME_2048 = (1 << 2048) - 1381 #numero per la frammentazione del segreto

class Scrutinatore:
    def __init__(self, scrutineer_id):
        self.scrutineer_id = scrutineer_id
        self.sk= rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.pk= self.sk.public_key()
        self.share_point =None #tupla ricevuta dall'ente nazionale

    def receive_verify_package(self, package, ente_pk: rsa.RSAPublicKey, expected_ente_id="GLOBAL"):
        """Decifra il pacchetto ibrido ed esegue l'autenticazione"""
        package = json.loads(package.decode("utf-8"))
        ciphered_session_key = bytes.fromhex(package["enc_key"])
        nonce = bytes.fromhex(package["nonce"])
        ciphertext=bytes.fromhex(package["ciphertext"])
        #Decifra la session key simmetrica tramite RSA-OAEPù
        session_key = self.sk.decrypt(
            ciphered_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #decifra il blocco interno simmetrico
        aesgcm = AESGCM(session_key)
        decrypted_inner_block = aesgcm.decrypt(nonce, ciphertext, None)
        inner_block=json.loads(decrypted_inner_block.decode("utf-8"))
        #verifica dell'identità del mittente
        if inner_block["sender"] != expected_ente_id:
            raise ValueError("Identità del mittente non corrispondente")
        #verifica della firma
        share_bytes = inner_block["share"].encode("utf-8")
        signature = bytes.fromhex(inner_block["signature"])
        # ricostruzione del plaintext per la verifica della firma
        expected_payload = share_bytes + b"||" + self.scrutineer_id.encode("utf-8")
        ente_pk.verify(
            signature,
            expected_payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        #Se tutto è valido, si salva il frammento 
        share_data= json.loads(inner_block["share"])
        self.share_point=(share_data["idx"], share_data["share_val"])
        return True

    @staticmethod
    def reconstruct_global_sk(shares_subset, prime=PRIME_2048):
        """Ricostruisce la chiave privata globale dell'ente nazionale a partire dai frammenti ricevuti"""
        secret=0
        k=len(shares_subset)
        for j in range(k): 
            xj,yj=shares_subset[j]
            num=1
            den=1
            for m in range(k): 
                if(m==j): 
                    continue    
                xm, _=shares_subset[m]
                num=(num*(-xm))%prime
                den=(den*(xj-xm))%prime
            inv_den=pow(den, -1, prime)
            lagrange_basis=(num*inv_den)%prime
            secret=(secret+yj*lagrange_basis)%prime
        return secret

    #manca la somma e lo spoglio dei voti
