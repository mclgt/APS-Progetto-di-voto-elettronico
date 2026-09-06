import json 
import hashlib
from typing import List, Tuple, Dict, Any

class MerkleTree:
    def __init__ (self, schede_validate: List[Dict[str, Any]]):
        """Costruisce un Merkle Tree a partire dall'elenco delle schede
        validate. Ogni elemento di schede validate deve contenere un voto
        cifrato e un token di voto"""
        self.schede = schede_validate
        self.livelli: List[List[bytes]] = []
        #Calcolo hash delle foglie
        foglie = [self.hash_leaf(s["voto_cifrato"], s["token_voto"]) for s in self.schede]

        if foglie:
            self._build_tree(foglie)

    @staticmethod
    def hash_leaf(voto_cifrato: dict, token_voto: str)->bytes:
        """Calcola l'hash crittografico del nodo foglia combinando
        la serializzazione canonica del voto cifrato e il token 
        univoco"""
        enc_voto_bytes = json.dumps(voto_cifrato,sort_keys=True).encode("utf-8")
        payload = enc_voto_bytes+b"||"+token_voto.encode("utf-8")
        return hashlib.sha256(payload).digest()

    @staticmethod
    def hash_pair(sinistra: bytes, destra: bytes)->bytes:
        """"
        Calcola l'hash genitore a partire dalla concatenazione
        dei due nodi figli
        """
        return hashlib.sha256(sinistra+destra).digest()

    def _build_tree(self, foglie:List[bytes]):
        """
        Costruisce ricorsivamente tutti i livelli dell'albero fino alla radice.
        Se un livello ha un numero dispari di nodi, duplica l'ultimo nodo
        """
        livello_corrente = foglie
        self.livelli.append(livello_corrente)

        while len(livello_corrente)>1:
            next_livello: List[bytes] = []
            n = len(livello_corrente)

            for i in range(0, n, 2):
                sinistra=livello_corrente[i]
                destra = livello_corrente[i+1] if (i+1<n) else sinistra 
                genitore = self.hash_pair(sinistra, destra)
                next_livello.append(genitore)

            livello_corrente= next_livello
            self.livelli.append(livello_corrente)

    def get_root(self)->str:
        """
        Restituisce la root del merkle tree in formato stringa
        esadecimale. Se l'albero è vuoto, restituisce una stringa vuota.
        """

        if not self.livelli or not self.livelli[-1]:
            return ""
        return self.livelli[-1][0].hex()

    def get_proof(self, indice: int)->List[Tuple[str,str]]:
        """
        Genera cammino di autenticazione per la foglia all'indice
        specificato. Restituisce una lista di tuple.
        """
        if not self.livelli or indice < 0 or indice >= len(self.livelli[0]):
            raise IndexError("Indice di foglia non valido")

        proof:List[Tuple[str,str]] = []
        curr_idx = indice
        #Itera per tutti i livelli tranne l'ultimo
        for livello in self.livelli[:-1]:
            n = len(livello)
            if curr_idx % 2 == 0:
                #nodo corrente è sinistro: il fratello è a destra
                idx_fratello = curr_idx + 1 if curr_idx + 1 < n else curr_idx
                lato = "R"
            else:
                #nodo corrente è destro: il fratello è a sinistra
                idx_fratello = curr_idx -1
                lato = "L"
            hash_fratello = livello[idx_fratello].hex()
            proof.append((hash_fratello, lato))
            #Risale all'indice del genitore nel livello superiore
            curr_idx = curr_idx // 2
        return proof

    @staticmethod
    def verify_proof(hash_foglia_hex: str, proof: List[Tuple[str,str]], hex_radice_atteso: str)->bool:
        """
        Funzione di verifica pubblica eseguibile dal cittadino:
        Ricalcola la radice partedo dall'hash della propria foglia e dai nodi fratelli.
        """
        corrente = bytes.fromhex(hash_foglia_hex)
        for hex_fratello, lato in proof:
            fratello = bytes.fromhex(hex_fratello)
            if lato == "L":
                corrente = hashlib.sha256(fratello+corrente).digest()
            else:
                corrente = hashlib.sha256(corrente+fratello).digest()
        return corrente.hex() == hex_radice_atteso