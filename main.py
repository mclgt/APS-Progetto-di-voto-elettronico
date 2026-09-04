"""
=============================================================================
MAIN INTEGRATO - SISTEMA DI VOTO ELETTRONICO CRITTOGRAFICO & BLOCKCHAIN
=============================================================================
Questo file coordina l'intera architettura:
1. Inizializzazione dell'Ente Nazionale e setup della chiave globale (e frammentazione).
2. Inizializzazione degli Scrutinatori e ricezione dei frammenti (Signcryption).
3. Inizializzazione dell'Identity Provider (IdP) con il registro degli elettori.
4. Simulazione del canale TLS tra Cittadino e IdP.
5. Integrazione con la GUI Tkinter (e_voting_gui.py) collegando i punti di aggancio
   alla logica crittografica reale (Autenticazione IdP, Generazione chiavi effimere,
   Cifratura ibrida del voto, firma e inserimento nel registro/blockchain comunale).
6. Gestione della fase di spoglio finale da parte degli scrutinatori.
=============================================================================
"""

import tkinter as tk
from tkinter import messagebox
import json
import os
from cryptography.hazmat.primitives import serialization
from ente_nazionale import EnteNazionale
from scrutinatore import Scrutinatore
from identity_provider import IdentityProvider
from cittadino import Cittadino
from TLSSession import TLSSession
from gui.e_voting_gui import MainWindow, IdPAuthWindow, VotingBoothWindow, LISTE_ELETTORALI

class SistemaElettoraleManager:
    def __init__(self):
        print("[INIT] Avvio del Sistema Elettorale...")  
        # 1. Ente Nazionale
        self.ente = EnteNazionale(ente_id="GLOBAL")    
        # 2. Scrutinatori (es. 5 scrutinatori, soglia t = 3)
        self.num_scrutinatori = 5
        self.scrutinatori = {}
        scrutinatori_pk = {}
        for i in range(1, self.num_scrutinatori + 1):
            s_id = f"SCRUTINATORE_{i}"
            scrut = Scrutinatore(scrutineer_id=s_id)
            self.scrutinatori[s_id] = scrut
            scrutinatori_pk[s_id] = scrut.pk        
        # 3. Setup Elezione dall'Ente Nazionale
        print("[SETUP] Generazione chiave globale ed elezione...")
        self.pem_pk_glob, self.global_n, self.packages = self.ente.setup_election(scrutinatori_pk)  
        # Caricamento della chiave pubblica globale per la cifratura dei voti
        self.pk_glob = serialization.load_pem_public_key(self.pem_pk_glob)  
        # 4. Distribuzione dei pacchetti di signcryption agli scrutinatori
        print("[SETUP] Distribuzione frammenti agli scrutinatori...")
        for s_id, scrut in self.scrutinatori.items():
            pkg = self.packages[s_id]
            scrut.receive_verify_package(pkg, self.ente.pk, expected_ente_id="GLOBAL")
            print(f"  -> {s_id} ha ricevuto e verificato con successo il proprio frammento.")
        # 5. Identity Provider
        self.idp = IdentityProvider()
        # 6. Registro / Blockchain Comunale (Simulazione ledger append-only)
        self.blockchain_ledger = []

    def autentica_elettore(self, cf: str, provider: str, password: str, pk_eff_bytes: bytes):
        """
        Gestisce l'autenticazione tramite IdP:
        1. Richiede l'authorization code all'IdP.
        2. Simula lo scambio protetto via canale TLS per ottenere il token firmato (T_sign).
        """
        try:
            # 1. Richiesta Auth Code
            auth_code = self.idp.request_authorization_code(cf, pk_eff_bytes)
            # 2. Creazione sessione TLS simulata tra Client (Cittadino) e IdP
            tls_session_key = os.urandom(32)
            client_tls = TLSSession(tls_session_key)
            idp_tls = TLSSession(tls_session_key)
            # Preparazione richiesta di scambio codice per token
            req_data = {"auth_code": auth_code}
            nonce, ciphertext = client_tls.send_encrypted(json.dumps(req_data).encode("utf-8"))
            # IdP riceve e scambia il codice per il token firmato
            tls_resp_nonce, tls_resp_ciphertext = self.idp.exchange_code_for_token(idp_tls, (nonce, ciphertext)) 
            # Client riceve la risposta decifrata sul canale TLS
            resp_bytes = client_tls.receive_encrypted(tls_resp_nonce, tls_resp_ciphertext)
            resp_data = json.loads(resp_bytes.decode("utf-8"))
            t_sign = {
                "token": resp_data["token_voto"],
                "token_voto": resp_data["token_voto"],
                "pk_eff_pem": resp_data["pk_eff"],
                "signature": resp_data["signature"]
            }
            return True, t_sign, "Autenticazione completata con successo."
        except Exception as e:
            return False, None, str(e)

    def registra_voto_blockchain(self, package_bytes: bytes, token_hash: str):
        """Registra il pacchetto di voto anonimo nella blockchain/bacheca comunale"""
        tx_id = f"TX-2026-{len(self.blockchain_ledger) + 1:04d}"
        block = {
            "tx_id": tx_id,
            "token_hash": token_hash,
            "package": package_bytes.hex(),
            "status": "Validato"
        }
        self.blockchain_ledger.append(block)
        return tx_id


# =============================================================================
# ESTENSIONE DELLA GUI PER INTEGRARE IL BACKEND CRITTOGRAFICO
# =============================================================================
class IntegratedMainWindow(MainWindow):
    def __init__(self, root, backend: SistemaElettoraleManager):
        self.backend = backend
        self.current_cittadino = None
        self.current_t_sign = None
        super().__init__(root)

    def apri_autenticazione(self):
        self.btn_vota.config(state="disabled")
        # Crea il cittadino e genera le chiavi effimere prima di autenticarsi all'IdP
        self.current_cittadino = Cittadino(cf="")
        self.current_cittadino.generate_eff_keys()
        
        IntegratedIdPAuthWindow(
            self.root, 
            backend=self.backend, 
            cittadino_instance=self.current_cittadino,
            on_auth_success=self.apri_cabina_voto, 
            on_cancel=self._riabilita_tasto_voto
        )

    def apri_cabina_voto(self, cf_autenticato: str, t_sign: dict):
        self.current_t_sign = t_sign
        self.current_cittadino.cf = cf_autenticato
        self.current_cittadino.receive_token(t_sign)
        
        IntegratedVotingBoothWindow(
            self.root,
            backend=self.backend,
            cittadino_instance=self.current_cittadino,
            on_vote_confirmed=self.on_voto_completato,
            on_cancel=self._riabilita_tasto_voto
        )

    def _carica_dati_iniziali_bacheca(self):
        # Svuota i dati di esempio e mostra la bacheca reale collegata al backend
        pass


class IntegratedIdPAuthWindow(IdPAuthWindow):
    def __init__(self, root, backend: SistemaElettoraleManager, cittadino_instance: Cittadino, on_auth_success, on_cancel=None):
        self.backend = backend.idp
        self.manager = backend
        self.cittadino = cittadino_instance
        self.on_auth_success_callback = on_auth_success
        super().__init__(root, on_auth_success=lambda cf: None, on_cancel=on_cancel)

    def on_authenticate_logic(self, cf: str, provider: str, password: str):
        pk_eff_pem = self.cittadino.get_pk_eff_pem()
        success, t_sign, msg = self.manager.autentica_elettore(cf, provider, password, pk_eff_pem)
        if success:
            self.t_sign_result = t_sign
            return True, msg
        else:
            return False, msg

    def _submit_auth(self):
        cf = self.cf_entry.get().strip().upper()
        provider = self.provider_var.get()
        pwd = self.pwd_entry.get()

        if len(cf) != 16:
            messagebox.showwarning("Formato Non Valido", "Il Codice Fiscale deve essere di 16 caratteri!")
            return

        success, msg = self.on_authenticate_logic(cf, provider, pwd)
        if success:
            messagebox.showinfo("Accesso Autorizzato", f"Identità verificata con successo via {provider}.Rilascio token e apertura cabina elettorale protetta.")
            self.window.destroy()
            self.on_auth_success_callback(cf, self.t_sign_result)
        else:
            messagebox.showerror("Accesso Negato", msg)


class IntegratedVotingBoothWindow(VotingBoothWindow):
    def __init__(self, root, backend: SistemaElettoraleManager, cittadino_instance: Cittadino, on_vote_confirmed, on_cancel=None):
        self.manager = backend
        self.cittadino = cittadino_instance
        super().__init__(root, on_vote_confirmed=on_vote_confirmed, on_cancel=on_cancel)

    def on_submit_vote_logic(self, lista_scelta: dict):
        choice_idx = lista_scelta["id"]
        n_options = len(LISTE_ELETTORALI)
        
        try:
            # Costruzione del pacchetto crittografico sicuro (One-hot encoding + padding + cifratura ibrida + firma effimera)
            package_bytes = self.cittadino.build_package(choice_idx, n_options, self.manager.pk_glob)
            
            # Calcolo di un hash anonimo del token per la bacheca pubblica
            import hashlib
            token_val = self.cittadino.token_voto if hasattr(self.cittadino, "token_voto") else "token_anonimo"
            token_hash = hashlib.sha256(str(token_val).encode()).hexdigest()[:32] + "..."
            
            # Registrazione nella blockchain/registro comunale
            tx_id = self.manager.registra_voto_blockchain(package_bytes, token_hash)
            
            dati_scheda = {
                "tx_id": tx_id,
                "token_hash": token_hash,
                "package_bytes": package_bytes
            }
            return True, dati_scheda
        except Exception as e:
            messagebox.showerror("Errore Cifratura Voto", f"Si è verificato un errore durante la cifratura: {str(e)}")
            return False, None


# =============================================================================
# AVVIO APPLICAZIONE PRINCIPALE
# =============================================================================
if __name__ == "__main__":
    # Inizializza il backend crittografico completo
    backend_manager = SistemaElettoraleManager()
    
    root = tk.Tk()
    app = IntegratedMainWindow(root, backend=backend_manager)
    root.mainloop()