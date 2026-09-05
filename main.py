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
6. Autorità Comunale: Doppia verifica crittografica sequenziale (Firma IdP + Firma effimera)
7. Generazione Merkle Tree, registrazione su Ganache (Web3) e Bacheca Pubblica append_only.
8. Gestione della fase di spoglio finale da parte degli scrutinatori.
=============================================================================
"""

import tkinter as tk
from tkinter import messagebox
import json
import os

from web3 import Web3
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from ente_nazionale import EnteNazionale
from scrutinatore import Scrutinatore
from identity_provider import IdentityProvider
from cittadino import Cittadino
from TLSSession import TLSSession
from comune import Comune
from blockchain import ComuneBlockchainService, BachecaPubblica
from merkle_tree import MerkleTree
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
        self.comune = Comune(idp_public_key=self.idp.public_key)
        self.blockchain = ComuneBlockchainService(self.comune)
        self.bacheca = BachecaPubblica()

    def autentica_elettore(self, cf: str, provider: str, pk_eff_bytes: bytes):
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
                "token": resp_data["token_vote"],
                "token_vote": resp_data["token_vote"],
                "pk_eff_pem": resp_data["pk_eff"],
                "signature": resp_data["signature"]
            }
            return True, t_sign, "Autenticazione completata con successo."
        except Exception as e:
            return False, None, str(e)

    def processa_contestazione(self, dispute_package): 
        """Inoltra la richiesta di contestazione all'Ente"""
        return self.ente.resolve_dispute(
            dispute_package=dispute_package, 
            blockchain_list=self.blockchain_ledger, 
            idp_pk=self.idp.public_key
        )


# =============================================================================
# ESTENSIONE DELLA GUI PER INTEGRARE IL BACKEND CRITTOGRAFICO
# =============================================================================
class IntegratedMainWindow(MainWindow):
    def __init__(self, root, backend: SistemaElettoraleManager):
        self.backend = backend
        self.current_cittadino = None
        self.current_t_sign = None
        self.current_ricevuta= None
        super().__init__(root)
        self.aggiungi_pulsante_contestazione()
        self.aggiungi_pulsante_verifica_voto()
        self._carica_dati_iniziali_bacheca()

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

    def on_voto_completato(self, dati_scheda: dict):
        self.current_ricevuta=dati_scheda.get("ricevuta")
        super().on_voto_completato(dati_scheda)
        self._carica_dati_iniziali_bacheca()

    def _carica_dati_iniziali_bacheca(self):
        """
        Legge direttamente i blocchi dalla blockchain tramite la Bacheca Pubblica
        """
        try:
            for item in self.tree_bacheca.get_children():
                self.tree_bacheca.delete(item)
            voti = self.backend.bacheca.recupera_voti_pubblicati()
            for v in voti:
                tx_short = v["tx_hash"][:16] + "..."
                token_h_short = v["token_hash"][:24] + "..." if v.get("token_hash") else "N/A"
                merkle_short = v["merkle_root"][:24] + "..." if v.get("merkle_root") else "N/A"
                self.tree_bacheca.insert("","end",values=(tx_short, token_h_short, merkle_short,f"Blocco #{v['block_number']}"))
        except Exception:
            pass

    def aggiungi_pulsante_contestazione(self):
        dispute_frame = tk.Frame(self.root, bg="#0F172A", padx=24, pady=4)
        dispute_frame.pack(fill="x", side="bottom")
        # Aggiunta pulsante di contestazione nella schermata principale
        btn_dispute = tk.Button(
            dispute_frame,
            text="NON TROVI IL TUO VOTO? CONTESTA",
            font=("Helvetica", 9, "bold"),
            bg="#DC2626",
            fg="#FFFFFF",
            activebackground="#B91C1C",
            activeforeground="#FFFFFF",
            padx=12,
            pady=6,
            relief="flat",
            cursor="hand2",
            command=self.avvia_procedura_contestazione
        )
        btn_dispute.pack(side="right")

    def aggiungi_pulsante_verifica_voto(self):
        btn_verifica = tk.Button(
            self.root,
            text="VERIFICA IL MIO VOTO",
            font=("Helvetica", 9, "bold"),
            bg="#16A34A",
            fg="#FFFFFF",
            command=self.verifica_mio_voto
        )
        btn_verifica.pack(side="right", padx=8, pady=4)
        
    def avvia_procedura_contestazione(self): 
        """Permette al cittafino di verificare e contestare la mancata pubblicazione"""
        if not self.current_cittadino or not getattr(self.current_cittadino, 'token_vote', None): 
            messagebox.showwarning(
                "Nessuna Sessione", 
                "nessun voto espresso in memoria in questa sessione"
            )
            return 
        token_hash=self.current_cittadino.get_token_hash()
        confirmation=messagebox.askyesno(
            "Verifica e contestazione Voto", f"Il tuo identificativo anonimo è:\n{token_hash}\n\n" "Se  non compare nella tabella, confermi l'invio della contestazione all'ente nazionale?"
        )
        if not confirmation: 
            return
        try: 
            dispute_pack=self.current_cittadino.generate_dispute_package()
            success, new_t_sign, msg= self.backend.processa_contestazione(dispute_pack)
            if success: 
                messagebox.showinfo("Esito Contestazione: Accolta\nVerrai reindirizzato alla cabina per votare di nuovo")
                self.current_cittadino.reset_revote(new_t_sign)
                self.apri_cabina_voto(self.current_cittadino.cf, new_t_sign)
            else:
                messagebox.showerror("Esito Contestazione: Respinta", msg)
        except Exception as e: 
            messagebox.showerror("Errore", "Impossibile generare la contestazione")

    def verifica_mio_voto(self):
        if not self.current_ricevuta:
            messagebox.showwarning(
                "Nessuna Ricevuta",
                "Non hai ancora una ricevuta di voto in questa sessione."
            )
            return

        esito, msg = self.backend.bacheca.esegui_verifica_individuale(self.current_ricevuta)
        if esito:
            messagebox.showinfo("Voto Verificato", msg)
        else:
            messagebox.showerror("Verifica Fallita", msg)


class IntegratedIdPAuthWindow(IdPAuthWindow):
    def __init__(self, root, backend: SistemaElettoraleManager, cittadino_instance: Cittadino, on_auth_success, on_cancel=None):
        self.backend = backend.idp
        self.manager = backend
        self.cittadino = cittadino_instance
        self.on_auth_success_callback = on_auth_success
        super().__init__(root, on_auth_success=lambda cf: None, on_cancel=on_cancel)

    def on_authenticate_logic(self, cf: str, provider: str):
        pk_eff_pem = self.cittadino.get_pk_eff_pem()
        success, t_sign, msg = self.manager.autentica_elettore(cf, provider, pk_eff_pem)
        if success:
            self.t_sign_result = t_sign
            return True, msg
        else:
            return False, msg

    def _submit_auth(self):
        cf = self.cf_entry.get().strip().upper()
        provider = self.provider_var.get()
        if len(cf) != 16:
            messagebox.showwarning("Formato Non Valido", "Il Codice Fiscale deve essere di 16 caratteri!")
            return
        success, msg = self.on_authenticate_logic(cf, provider)
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
            success, msg, ricevuta = self.manager.blockchain.sottometti_e_registra_voto(package_bytes)
            if not success:
                messagebox.showerror("Errore validazione comune", msg)
                return False, None
            
            dati_scheda = {
                "tx_id": ricevuta["tx_hash"][:18]+"...",
                "token_hash": ricevuta["token_hash"][:24]+"...",
                "package_bytes": package_bytes,
                "ricevuta": ricevuta
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