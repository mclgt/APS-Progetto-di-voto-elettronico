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
        #Formula dell'interpolazione di lagrange
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

    @staticmethod
    def decrypt_single_vote(encrypted_vote_dict, reconstructed_d, global_n)->list: 
        """Decifra una scheda elettorale: 
            1. Recupera i fattori primi p, q 
            2. Istanza la chiave privata dell'Ente
            3. Decifratura chiave di sessione con RSE-OAEP
            4. Decifratura simmetrica del payload con AES-GCM usando la chiave di sessione 
            inviata tramite RSA
            5. Rimozione del padding casuale e recupero del valore di voto"""
        p, q = rsa.rsa_recover_prime_factors(global_n, 65537, reconstructed_d)
        dmp1 = rsa.rsa_crt_dmp1(reconstructed_d, p)
        dmq1 = rsa.rsa_crt_dmq1(reconstructed_d, q)
        iqmp = rsa.rsa_crt_iqmp(p, q)
        #ricostruzione delle chiave privata RSA dell'Ente 
        private_numbers=rsa.RSAPrivateNumbers(
            p=p,q=q,d=reconstructed_d, 
            dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
            public_numbers=rsa.RSAPublicNumbers(e=65537, n=global_n)
        )
        private_key= private_numbers.private_key()
        k_enc=bytes.fromhex(encrypted_vote_dict["k_enc"])
        nonce=bytes.fromhex(encrypted_vote_dict["nonce"])
        c_vote=bytes.fromhex(encrypted_vote_dict["c_vote"])
       #decifrare la chiave di sessione simmetrica tramite RSA-OAEP
        session_key = private_key.decrypt(
            k_enc,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #decifratura payload
        aesgcm=AESGCM(session_key)
        decrypted_payload=aesgcm.decrypt(nonce, c_vote, None)
        clean_payload=decrypted_payload.split(b"||")[0]
        return json.loads(clean_payload.decode("utf-8"))


    def compute_vote(self, encrypted_votes, quorum_shares, global_n, party_list)->dict: 
        """Esegue lo spoglio del voto: 
        1. Ricostruisce d tramite t frammenti
        2. Decifra ogni scheda e aggrega le preferenze
        3. Determina il partito vincitore
        4. Firma il verdetto con la sua chiave privata"""
        reconstructed_d=self.reconstruct_global_sk(quorum_shares)
        tally={party:0 for party in party_list} #conteggio per ogni partito
        for enc_ballot in encrypted_votes: 
            one_hot_vector=self.decrypt_single_vote(enc_ballot, reconstructed_d, global_n)
            for idx, bit in enumerate(one_hot_vector): 
                if bit == 1: 
                    tally[party_list[idx]]+=1
                    break
        winner=max(tally, key=tally.get)
        verdict={
            "scrutineer_id": self.scrutineer_id,
            "tally":tally,
            "winner": winner
        }
        verdict_bytes=json.dumps(verdict, sort_keys=True).encode("utf-8")
        verdict_signature=self.sk.sign(
            verdict_bytes, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return{
            "verdict": verdict,
            "signature": verdict_signature.hex()
        }
