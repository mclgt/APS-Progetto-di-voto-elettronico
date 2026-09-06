import json
import hashlib
from web3 import Web3
from comune import Comune
from merkle_tree import MerkleTree

class ComuneBlockchainService:
    def __init__(self, istanza_comune: Comune, rcp_url: str = "http://127.0.0.1:7545"):
        """
        Servizio del comune che connette la logica crittografica a Ganache.
        Contiene un'istanza della classe comune già inizializzata con la PK dell'IdP e un ednpoint RPC del nodo Ganache locale. 
        """
        self.comune=istanza_comune
        self.w3=Web3(Web3.HTTPProvider(rcp_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Impossibile connettersi al nodo Ganache")
        #Seleziona il primo account di Ganache come indirizzo istituzionale del Comune
        self.indirizzo_comune = self.w3.eth.accounts[0]
        self.w3.eth.default_account = self.indirizzo_comune
        #struttura interna per mantenere merkle tree aggiornato
        self.merkle_tree: MerkleTree = None

    def sottometti_e_registra_voto(self, bytes_pacchetto: bytes)->tuple[bool, str, dict]:
        """
        1. Valida crittograficamente il pacchetto tramite il Comune
        2. Aggiorna i merkle tree includendo la nuova scheda
        3. Costruisce e invia la transazone verso Ganache con il payload dei dati
        4. Restituisce al cittadino la ricevuta crittografica per la verifica individuale
        """
        valido, msg, scheda = self.comune.valida_pacchetto_voto(bytes_pacchetto)
        if not valido:
            return False, msg, {}
        self.merkle_tree = MerkleTree(self.comune.voti_validi)
        merkle_root_attuale = self.merkle_tree.get_root()
        indice_scheda = len(self.comune.voti_validi)-1
        merkle_proof = self.merkle_tree.get_proof(indice_scheda)
        #calcolo hash anonimo del token per il riferimento pubblico
        token_hash = hashlib.sha256(scheda["token_voto"].encode("utf-8")).hexdigest()
        dati_transazione = {
            "token_hash": token_hash,
            "voto_cifrato": scheda["voto_cifrato"],
            "merkle_root": merkle_root_attuale
        }
        payload_bytes_grezzi = json.dumps(dati_transazione, sort_keys=True).encode("utf-8")
        dati_payload_hex = "0x"+payload_bytes_grezzi.hex()
        tx_dict = {
            "from": self.indirizzo_comune,
            "to": self.indirizzo_comune,
            "value": 0,
            "data": dati_payload_hex,
            "gas": 300000,
            "gasPrice": self.w3.eth.gas_price
        }
        tx_hash = self.w3.eth.send_transaction(tx_dict)
        ricevuta = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        ricevuta_cittadino = {
            "tx_hash": ricevuta.transactionHash.hex(),
            "block_number": ricevuta.blockNumber,
            "token_hash": token_hash,
            "leaf_index": indice_scheda,
            "leaf_hash": MerkleTree.hash_leaf(scheda["voto_cifrato"], scheda["token_voto"]).hex(),
            "merkle_proof": merkle_proof,
            "merkle_root": merkle_root_attuale
        }
        return True, "Voto registrato con successo sulla Blockchain di Ganache.", ricevuta_cittadino


class BachecaPubblica:
    def __init__(self, rcp_url: str = "http://127.0.0.1:7545"):
        """Interfaccia in sola lettura per cittadini e osservatori elettorali.
        Interroga direttamente la blockchain locale per mostrare i voti cifrati.
        """
        self.w3 = Web3(Web3.HTTPProvider(rcp_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Impossibile collegarsi alla bacheca pubblica")

    def recupera_voti_pubblicati(self)->list[dict]:
        """
        Scansiona i blocchi della blockchain a partire dal blocco 1
        fino al più recente, estraendo i dati di voto memorizzati nel 
        payload esadecimale della transizione
        """
        voti_bacheca = []
        ultimo_blocco = self.w3.eth.block_number
        for blocco_idx in range (1, ultimo_blocco+1):
            blocco = self.w3.eth.get_block(blocco_idx, full_transactions=True)
            for tx in blocco.transactions:
                input_grezzo = tx.get("input", "")
                #Se la transazione trasporta un payload di dati valido
                if input_grezzo and input_grezzo!="0x"and input_grezzo != b"0x":
                    try:
                        if isinstance(input_grezzo, (bytes, bytearray)):
                            hex_str = input_grezzo.hex()
                        else:
                            hex_str = input_grezzo[2:] if input_grezzo.startswith("0x") else input_grezzo

                        if not hex_str:
                            continue

                        json_bytes = bytes.fromhex(hex_str)
                        payload_dict = json.loads(json_bytes.decode("utf-8"))
                        voti_bacheca.append({
                            "tx_hash": tx.hash.hex(),
                            "block_number": blocco_idx,
                            "from": tx["from"],
                            "token_hash":payload_dict.get("token_hash"),
                            "voto_cifrato":payload_dict.get("voto_cifrato"),
                            "merkle_root": payload_dict.get("merkle_root")
                        })
                    except Exception:
                        #Ignora transazioni che non rispettano le codifiche previste
                        continue
        return voti_bacheca


    def recupera_root_da_tx(self, tx_hash: str) -> dict:
        """Legge UNA SOLA transazione (O(1)), non scansiona tutta la chain."""
        try:
            tx = self.w3.eth.get_transaction(tx_hash)
        except Exception:
            raise ValueError("Transazione non trovata sulla blockchain")
        input_grezzo = tx.get("input", "")
        if not input_grezzo or input_grezzo == "0x":
            raise ValueError("La transazione non contiene un payload di voto")
        if isinstance(input_grezzo, (bytes, bytearray)):
            hex_str = input_grezzo.hex()
        else:
            hex_str = input_grezzo[2:] if input_grezzo.startswith("0x") else input_grezzo

        if not hex_str:
            raise ValueError("La transazione non contiene un payload di voto")

        try:
            json_bytes = bytes.fromhex(hex_str)
            payload_dict = json.loads(json_bytes.decode("utf-8"))
        except Exception:
            raise ValueError("Payload della transazione non decodificabile")

        if "merkle_root" not in payload_dict:
            raise ValueError("Payload della transazione privo di merkle_root")
        return payload_dict

    def esegui_verifica_individuale(self, ricevuta:dict)-> tuple[bool, str]:
        """
        Permette a qualunque cittaino di testare la propria ricevuta crittografica:
        risale all'albero calcolando gli hash a coppie e verifica se corrisponde alla 
        merkle root pubblica.
        """
        tx_hash=ricevuta["tx_hash"]
        hash_foglia_hex=ricevuta["leaf_hash"]
        proof=ricevuta["merkle_proof"]
        try:
            payload = self.recupera_root_da_tx(tx_hash)
        except ValueError as e:
            return False, str(e)
        merkle_root=payload["merkle_root"]
        esito= MerkleTree.verify_proof(hash_foglia_hex, proof, merkle_root)
        if esito:
            return True, "Voto confermato: incluso nel registro e coerente con la root pubblicata su blockchain."
        else:
            return False, "Verifica fallita: la scheda non risulta inclusa nella root pubblicata, oppure la ricevuta è stata alterata."
