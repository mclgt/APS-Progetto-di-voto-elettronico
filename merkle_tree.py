import json 
import hashlib
from typing import List, Tuple, Dict, Any

class MerkleTree:
    def __init__ (self, schede_validate: List[Dict[str, Any]]):
        """Costruisce un Merkle Tree a partire dall'elenco delle schede
        validate. Ogni elemento di schede validate deve contenere un voto
        cifrato e un token di voto"""
        self.schede = schede_validate
        self.levels: List[List[bytes]] = []

        #Calcolo hash delle foglie
        leaves = [self.hash_leaf(s["encrypted_vote"], s["token_vote"]) for s in self.schede]

        if leaves:
            self._build_tree(leaves)

    @staticmethod
    def hash_leaf(encrypted_vote: dict, token_vote: str)->bytes:
        """Calcola l'hash crittografico del nodo foglia combinando
        la serializzazione canonica del voto cifrato e il token 
        univoco"""
        enc_vote_bytes = json.dumps(encrypted_vote,sort_keys=True).encode("utf-8")
        payload = enc_vote_bytes+b"||"+token_vote.encode("utf-8")
        return hashlib.sha256(payload).digest()

    @staticmethod
    def hash_pair(left: bytes, right: bytes)->bytes:
        """"
        Calcola l'hash genitore a partire dalla concatenazione
        dei due nodi figli
        """
        return hashlib.sha256(left+right).digest()

    def _build_tree(self, leaves:List[bytes]):
        """
        Costruisce ricorsivamente tutti i livelli dell'albero fino alla radice.
        Se un livello ha un numero dispari di nodi, duplica l'ultimo nodo"""
        current_level = leaves
        self.levels.append(current_level)

        while len(current_level)>1:
            next_level: List[bytes] = []
            n = len(current_level)

            for i in range(0, n, 2):
                left=current_level[i]
                right = current_level[i+1] if (i+1<n) else left 
                parent = self.hash_pair(left, right)
                next_level.append(parent)

            current_level= next_level
            self.levels.append(current_level)

    def get_root(self)->str:
        """
        Restituisce la root del merkle tree in formato stringa
        esadecimale. Se l'albero è vuoto, restituisce una stringa vuota."""

        if not self.levels or not self.levels[-1]:
            return ""
        return self.levels[-1][0].hex()

    def get_proof(self, index: int)->List[Tuple[str,str]]:
        """
        Genera cammino di autenticazione per la foglia all'indice
        specificato. Restituisce una lista di tuple.
        """
        if not self.levels or index < 0 or index >= len(self.levels[0]):
            raise IndexError("Indice di foglia non valido")

        proof:List[Tuple[str,str]] = []
        curr_idx = index

        #Itera per tutti i livelli tranne l'ultimo
        for level in self.levels[:-1]:
            n = len(level)
            if curr_idx % 2 == 0:
                #nodo corrente è sinistro: il fratello è a destra
                sibling_idx = curr_idx + 1 if curr_idx + 1 < n else curr_idx
                direction = "R"
            else:
                #nodo corrente è destro: il fratello è a sinistra
                sibling_idx = curr_idx -1
                direction = "L"

            sibling_hash = level[sibling_idx].hex()
            proof.append((sibling_hash, direction))
            #Risale all'indice del genitore nel livello superiore
            curr_idx = curr_idx // 2
        return proof

    @staticmethod
    def verify_proof(leaf_hash_hex: str, proof: List[Tuple[str,str]], expected_root_hex: str)->bool:
        """
        Funzione di verifica pubblica eseguibile dal cittadino:
        Ricalcola la radice partedo dall'hash della propria foglia e dai nodi fratelli.
        """
        current = bytes.fromhex(leaf_hash_hex)

        for sibling_hex, direction in proof:
            sibling = bytes.fromhex(sibling_hex)
            if direction == "L":
                current = hashlib.sha256(sibling+current).digest()
            else:
                current = hashlib.sha256(current+sibling).digest()

        return current.hex() == expected_root_hex