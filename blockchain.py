import json
import hashlib
from web3 import Web3
from comune import Comune
from merkle_tree import MerkleTree

class ComuneBlockchainService:
    def __init__(self, comune_instance: Comune, rcp_url: str = "http://127.0.0.1:7545"):
        """
        Servizio del comune che connette la logica crittografica a Ganache.
        Contiene un'istanza della classe comune già inizializzata con la PK dell'IdP e un ednpoint RPC del nodo Ganache locale. 
        """
        self.comune=comune_instance
        self.w3=Web3(Web3.HTTPProvider(rcp_url))

        if not self.w3.is_connected():
            raise ConnectionError(f"Impossibile connettersi al nodo Ganache")

        #Seleziona il primo account di Ganache come indirizzo istituzionale del Comune
        self.comune_address = self.w3.eth.accounts[0]
        self.w3.eth.default_account = self.comune_address

        #struttura interna per mantenere merkle tree aggiornato
        self.merkle_tree: MerkleTree = None

    def sottometti_e_registra_voto(self, package_bytes: bytes)->tuple[bool, str, dict]:
        """
        1. Valida crittograficamente il pacchetto tramite il Comune
        2. Aggiorna i merkle tree includendo la nuova scheda
        3. Costruisce e invia la transazone verso Ganache con il payload dei dati
        4. Restituisce al cittadino la ricevuta crittografica per la verifica individuale
        """
        #1
        valido, msg, scheda = self.comune.valida_pacchetto_voto(package_bytes)
        if not valido:
            return False, msg, {}

        #2
        self.merkle_tree = MerkleTree(self.comune.validated_vote)
        merkle_root_attuale = self.merkle_tree.get_root()
        indice_scheda = len(self.comune.validated_vote)-1
        merkle_proof = self.merkle_tree.get_proof(indice_scheda)

        #calcolo hash anonimo del token per il riferimento pubblico
        token_hash = hashlib.sha256(scheda["token_vote"].encode("utf-8")).hexdigest()

        #3
        dati_transazione = {
            "token_hash": token_hash,
            "encrypted_vote": scheda["encrypted_vote"],
            "merkle_root": merkle_root_attuale
        }
        raw_payload_bytes = json.dumps(dati_transazione, sort_keys=True).encode("utf-8")
        hex_data_payload = "0x"+raw_payload_bytes.hex()

        #4
        tx_dict = {
            "from": self.comune_address,
            "to": self.comune_address,
            "value": 0,
            "data": hex_data_payload,
            "gas": 300000,
            "gasPrice": self.w3.eth.gas_price
        }

        tx_hash = self.w3.eth.send_transaction(tx_dict)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        ricevuta_cittadino = {
            "tx_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "token_hash": token_hash,
            "leaf_index": indice_scheda,
            "leaf_hash": MerkleTree.hash_leaf(scheda["encrypted_vote"], scheda["token_vote"]).hex(),
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
        latest_block = self.w3.eth.block_number

        for blk_idx in range (1, latest_block+1):
            blocco = self.w3.eth.get_block(blk_idx, full_transactions=True)
            for tx in blocco.transactions:
                raw_input = tx.get("input", "")
                #Se la transazione trasporta un payload di dati valido
                if raw_input and raw_input!="0x":
                    try:
                        hex_str = raw_input.replace("0x","")
                        json_bytes = bytes.fromhex(hex_str)
                        payload_dict = json.loads(json_bytes.decode("utf-8"))

                        voti_bacheca.append({
                            "tx_hash": tx.hash.hex(),
                            "block_number": blk_idx,
                            "from": tx["from"],
                            "token_hash":payload_dict.get("token_hash"),
                            "encrypted_vote":payload_dict.get("encrypted_vote"),
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

        raw_input = tx.get("input", "")
        if not raw_input or raw_input == "0x":
            raise ValueError("La transazione non contiene un payload di voto")
        if isinstance(raw_input, (bytes, bytearray)):
            hex_str = raw_input.hex()
        else:
            hex_str = raw_input[2:] if raw_input.startswith("0x") else raw_input

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
        leaf_hash_hex=ricevuta["leaf_hash"]
        proof=ricevuta["merkle_proof"]
        try:
            payload = self.recupera_root_da_tx(tx_hash)
        except ValueError as e:
            return False, str(e)
        merkle_root=payload["merkle_root"]
        esito= MerkleTree.verify_proof(leaf_hash_hex, proof, merkle_root)
        if esito:
            return True, "Voto confermato: incluso nel registro e coerente con la root pubblicata su blockchain."
        else:
            return False, "Verifica fallita: la scheda non risulta inclusa nella root pubblicata, oppure la ricevuta è stata alterata."
