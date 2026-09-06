import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

PRIME_2048 = (1 << 2048) - 1381 #numero per la frammentazione del segreto

class Scrutinatore:
    def __init__(self, id_scrutinatore):
        self.id_scrutinatore = id_scrutinatore
        self.sk= rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.pk= self.sk.public_key()
        self.frammento =None #tupla ricevuta dall'ente nazionale

    def ricevi_verifica_pacchetto(self, pacchetto, ente_pk: rsa.RSAPublicKey, id_ente_atteso="GLOBAL"):
        """Decifra il pacchetto ibrido ed esegue l'autenticazione"""
        pacchetto = json.loads(pacchetto.decode("utf-8"))
        chiave_sessione_cifrata = bytes.fromhex(pacchetto["chiave_cifrata"])
        nonce = bytes.fromhex(pacchetto["nonce"])
        ciphertext=bytes.fromhex(pacchetto["ciphertext"])
        #Decifra la session key simmetrica tramite RSA-OAEPù
        chiave_sessione = self.sk.decrypt(
            chiave_sessione_cifrata,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #decifra il blocco interno simmetrico
        aesgcm = AESGCM(chiave_sessione)
        blocco_interno_decifrato = aesgcm.decrypt(nonce, ciphertext, None)
        blocco_interno=json.loads(blocco_interno_decifrato.decode("utf-8"))
        #verifica dell'identità del mittente
        if blocco_interno["sender"] != id_ente_atteso:
            raise ValueError("Identità del mittente non corrispondente")
        #verifica della firma
        bytes_frammento = blocco_interno["share"].encode("utf-8")
        firma = bytes.fromhex(blocco_interno["firma"])
        # ricostruzione del plaintext per la verifica della firma
        payload_atteso = bytes_frammento + b"||" + self.id_scrutinatore.encode("utf-8")
        ente_pk.verify(
            firma,
            payload_atteso,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        #Se tutto è valido, si salva il frammento 
        dati_frammento= json.loads(blocco_interno["share"])
        self.frammento=(dati_frammento["idx"], dati_frammento["valore_frammento"])
        return True

    @staticmethod
    def ricostruisci_sk_globale(sottoinsieme_frammenti, prime=PRIME_2048):
        """Ricostruisce la chiave privata globale dell'ente nazionale a partire dai frammenti ricevuti"""
        segreto=0
        k=len(sottoinsieme_frammenti)
        #Formula dell'interpolazione di lagrange
        for j in range(k): 
            xj,yj=sottoinsieme_frammenti[j]
            num=1
            den=1
            for m in range(k): 
                if(m==j): 
                    continue    
                xm, _=sottoinsieme_frammenti[m]
                num=(num*(-xm))%prime
                den=(den*(xj-xm))%prime
            inv_den=pow(den, -1, prime)
            base_lagrange=(num*inv_den)%prime
            segreto=(segreto+yj*base_lagrange)%prime 
        return segreto

    @staticmethod
    def decifra_singolo_voto(voto_cifrato_dict, d_ricostruito, n_globale)->list: 
        """Decifra una scheda elettorale: 
            1. Recupera i fattori primi p, q 
            2. Istanza la chiave privata dell'Ente
            3. Decifratura chiave di sessione con RSE-OAEP
            4. Decifratura simmetrica del payload con AES-GCM usando la chiave di sessione 
            inviata tramite RSA
            5. Rimozione del padding casuale e recupero del valore di voto"""
        try:
            p, q = rsa.rsa_recover_prime_factors(n_globale, 65537, d_ricostruito)
            dmp1 = rsa.rsa_crt_dmp1(d_ricostruito, p)
            dmq1 = rsa.rsa_crt_dmq1(d_ricostruito, q)
            iqmp = rsa.rsa_crt_iqmp(p, q)
            #ricostruzione delle chiave privata RSA dell'Ente 
            private_numbers=rsa.RSAPrivateNumbers(
                p=p,q=q,d=d_ricostruito, 
                dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
                public_numbers=rsa.RSAPublicNumbers(e=65537, n=n_globale)
            )
            private_key= private_numbers.private_key()
            c_cifr=bytes.fromhex(voto_cifrato_dict["c_cifr"])
            nonce=bytes.fromhex(voto_cifrato_dict["nonce"])
            c_voto=bytes.fromhex(voto_cifrato_dict["c_voto"])
        #decifrare la chiave di sessione simmetrica tramite RSA-OAEP
            chiave_sessione = private_key.decrypt(
                c_cifr,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            #decifratura payload
            aesgcm=AESGCM(chiave_sessione)
            decrypted_payload=aesgcm.decrypt(nonce, c_voto, None)
            clean_payload=decrypted_payload.split(b"||")[0]
            return list(clean_payload)
        except Exception as e:
            print(f"[DEBUG ERRORE DECR] Fallimento su scheda specifica: {str(e)}")
            raise e


    def calcola_voto(self, voti_cifrati, frammenti_quorum, n_globale, lista_partiti)->dict: 
        """Esegue lo spoglio del voto: 
        1. Ricostruisce d tramite t frammenti
        2. Decifra ogni scheda e aggrega le preferenze
        3. Determina il partito vincitore
        4. Firma il verdetto con la sua chiave privata"""
        d_ricostruito=self.ricostruisci_sk_globale(frammenti_quorum)
        conteggio={partito:0 for partito in lista_partiti} #conteggio per ogni partito
        for scheda_cifrata in voti_cifrati: 
            vettore_one_hot=self.decifra_singolo_voto(scheda_cifrata, d_ricostruito, n_globale)
            for idx, bit in enumerate(vettore_one_hot): 
                if bit == 1: 
                    conteggio[lista_partiti[idx]]+=1
                    break
        vincitore=max(conteggio, key=conteggio.get)
        verdetto={
            "id_scrutinatore": self.id_scrutinatore,
            "conteggio":conteggio,
            "vincitore": vincitore
        }
        bytes_verdetto=json.dumps(verdetto, sort_keys=True).encode("utf-8")
        verdetto_firmaature=self.sk.sign(
            bytes_verdetto, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return{
            "verdetto": verdetto,
            "firma": verdetto_firmaature.hex()
        }
