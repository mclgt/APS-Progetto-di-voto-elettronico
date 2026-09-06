"""
Questo file coordina l'architettura:
1. Inizializzazione dell'Ente Nazionale e setup della chiave globale (e frammentazione).
2. Inizializzazione degli Scrutinatori e ricezione dei frammenti (Signcryption).
3. Inizializzazione dell'Identity Provider (IdP) con il registro degli elettori.
4. Simulazione del canale TLS tra Cittadino e IdP.
5. Integrazione con la GUI collegando i punti l'interfacccia alla logica
  (Autenticazione IdP, Generazione chiavi effimere, Cifratura ibrida del voto, 
  firma e inserimento nel registro/blockchain comunale).
6. Autorità Comunale: Doppia verifica crittografica sequenziale (Firma IdP + Firma effimera)
7. Generazione Merkle Tree, registrazione su Ganache (Web3) e Bacheca Pubblica append_only.
8. Gestione della fase di spoglio finale da parte degli scrutinatori.
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
from gui.e_voting_gui import MainWindow, IdPAuthWindow, FinestraVoto, LISTE_ELETTORALI

class SistemaElettoraleManager:
    def __init__(self):
        print("Avvio del Sistema...")  
        #  Instanziazione dell' Ente Nazionale
        self.ente = EnteNazionale(ente_id="GLOBAL")    
        # Instanziazione Scrutinatori (5 scrutinatori, soglia t = 3)
        self.num_scrutinatori = 5
        self.scrutinatori = {}
        scrutinatori_pk = {}
        for i in range(1, self.num_scrutinatori + 1):
            s_id = f"SCRUTINATORE_{i}"
            scrut = Scrutinatore(id_scrutinatore=s_id)
            self.scrutinatori[s_id] = scrut
            scrutinatori_pk[s_id] = scrut.pk        
        # Configurazione da parte dell'Ente nazionale
        print("Generazione chiave globale di elezione...")
        self.pem_pk_glob, self.n_globale, self.pacchetti = self.ente.setup_elezione(scrutinatori_pk)  
        # Caricamento della chiave pubblica globale per la cifratura dei voti
        self.pk_glob = serialization.load_pem_public_key(self.pem_pk_glob)  
        # Distribuzione dei frammenti della chiave privata
        print("Distribuzione frammenti agli scrutinatori...")
        for s_id, scrut in self.scrutinatori.items():
            pacchetto = self.pacchetti[s_id]
            scrut.ricevi_verifica_pacchetto(pacchetto, self.ente.pk, id_ente_atteso="GLOBAL")
            print(f"  -> {s_id} ha ricevuto e verificato con successo il proprio frammento.")
        #Istanziazione Identity Provider
        self.idp = IdentityProvider()
        # Istanziazione Bacheca Pubblica e Blockchain
        self.comune = Comune(idp_public_key=self.idp.pk)
        self.blockchain = ComuneBlockchainService(self.comune)
        self.bacheca = BachecaPubblica() #per leggere i voti
        

    def autentica_elettore(self, cf: str, provider: str, pk_eff_bytes: bytes):
        """
        Gestisce l'autenticazione tramite IdP:
        1. Richiede l'authorization code all'IdP.
        2. Simula lo scambio protetto via canale TLS per ottenere il token firmato (t_firma).
        """
        try:
            #Richiesta Authorization Code
            auth_code = self.idp.richiesta_authorization_code(cf, pk_eff_bytes)
            #Creazione della sessione TLS simulata tra il Cittadino e l'IdP
            chiave_sessione_tls = os.urandom(32)
            cittadino_tls = TLSSession(chiave_sessione_tls)
            idp_tls = TLSSession(chiave_sessione_tls)
            # Preparazione richiesta di scambio codice per token
            dati_richiesta = {"auth_code": auth_code}
            nonce, ciphertext = cittadino_tls.invia_cifrato(json.dumps(dati_richiesta).encode("utf-8"))
            # IdP riceve e scambia il codice per il token firmato
            tls_resp_nonce, tls_resp_ciphertext = self.idp.scambia_codice_token(idp_tls, (nonce, ciphertext)) 
            # Client riceve la risposta decifrata sul canale TLS
            resp_bytes = cittadino_tls.ricevi_cifrato(tls_resp_nonce, tls_resp_ciphertext)
            resp_data = json.loads(resp_bytes.decode("utf-8"))
            t_firma = {
                "token": resp_data["token_voto"],
                "token_voto": resp_data["token_voto"],
                "pk_eff_pem": resp_data["pk_eff"],
                "firma": resp_data["firma"]
            }
            return True, t_firma, "Autenticazione completata con successo."
        except Exception as e:
            return False, None, str(e)


#Estensione GUI (da spostare)
class FinesttraMainIntergrata(MainWindow):
    def __init__(self, root, backend: SistemaElettoraleManager):
        self.backend = backend
        self.current_cittadino = None
        self.current_t_firma = None
        self.current_ricevuta= None
        super().__init__(root)
        self.aggiungi_pulsante_verifica_voto()
        self.aggiungi_pulsante_spoglio()
        self._carica_dati_iniziali_bacheca()

    def aggiungi_pulsante_spoglio(self):
        """Aggiunge il pulsante per aprire la finestra di spoglio e chiusura elezioni"""
        btn_spoglio = tk.Button(
            self.root,
            text="TERMINA ELEZIONI & SPOGLIO",
            font=("Helvetica", 9, "bold"),
            bg="#7C3AED",
            fg="#FFFFFF",
            activebackground="#6D28D9",
            activeforeground="#FFFFFF",
            padx=10,
            pady=4,
            relief="flat",
            cursor="hand2",
            command=self.apri_finestra_spoglio
        )
        btn_spoglio.pack(side="right", padx=8, pady=4)

    def apri_finestra_spoglio(self):
        """Apre la finestra parallela per la gestione dello scrutinio"""
        FinestraScrutinio(self.root, backend=self.backend)

    def apri_autenticazione(self):
        self.btn_vota.config(state="disabled")
        # Crea il cittadino e genera le chiavi effimere prima di autenticarsi all'IdP
        self.current_cittadino = Cittadino(cf="")
        self.current_cittadino.genera_chiavi_effimere()
        
        FinestraIdpAuthIntegrata(
            self.root, 
            backend=self.backend, 
            istanza_cittadino=self.current_cittadino,
            on_auth_success=self.apri_cabina_voto, 
            on_cancellazione=self._riabilita_tasto_voto
        )

    def apri_cabina_voto(self, cf_autenticato: str, t_firma: dict):
        self.current_t_firma = t_firma
        self.current_cittadino.cf = cf_autenticato
        self.current_cittadino.ricevi_token(t_firma)
        
        FinestraVotoIntegrata(
            self.root,
            backend=self.backend,
            istanza_cittadino=self.current_cittadino,
            on_voto_confermato=self.on_voto_completato,
            on_cancellazione=self._riabilita_tasto_voto
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
            for el in self.tree.get_children():
                self.tree.delete(el)
            voti = self.backend.bacheca.recupera_voti_pubblicati()
            for v in voti:
                tx_corto = v["tx_hash"][:16] + "..."
                token_h_corto = v["token_hash"][:24] + "..." if v.get("token_hash") else "N/A"
                merkle_corto = v["merkle_root"][:24] + "..." if v.get("merkle_root") else "N/A"
                self.tree.insert("","end",values=(tx_corto, token_h_corto, merkle_corto,f"Blocco #{v['block_number']}"))
        except Exception:
            pass


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


class FinestraIdpAuthIntegrata(IdPAuthWindow):
    def __init__(self, root, backend: SistemaElettoraleManager, istanza_cittadino: Cittadino, on_auth_success, on_cancellazione=None):
        self.backend = backend.idp
        self.manager = backend
        self.cittadino = istanza_cittadino
        self.on_auth_success_callback = on_auth_success
        super().__init__(root, on_auth_success=lambda cf: None, on_cancellazione=on_cancellazione)

    def on_authenticate_logic(self, cf: str, provider: str):
        pk_eff_pem = self.cittadino.get_pk_eff_pem()
        success, t_firma, msg = self.manager.autentica_elettore(cf, provider, pk_eff_pem)
        if success:
            self.t_firma_result = t_firma
            return True, msg
        else:
            return False, msg

    def sottometti_auth(self):
        cf = self.cf_entry.get().strip().upper()
        provider = self.provider_var.get()
        if len(cf) != 16:
            messagebox.showwarning("Formato Non Valido", "Il Codice Fiscale deve essere di 16 caratteri!")
            return
        success, msg = self.on_authenticate_logic(cf, provider)
        if success:
            messagebox.showinfo("Accesso Autorizzato", f"Identità verificata con successo via {provider}.Rilascio token e apertura cabina elettorale protetta.")
            self.window.destroy()
            self.on_auth_success_callback(cf, self.t_firma_result)
        else:
            messagebox.showerror("Accesso Negato", msg)


class FinestraVotoIntegrata(FinestraVoto):
    def __init__(self, root, backend: SistemaElettoraleManager, istanza_cittadino: Cittadino, on_voto_confermato, on_cancellazione=None):
        self.manager = backend
        self.cittadino = istanza_cittadino
        super().__init__(root, on_voto_confermato=on_voto_confermato, on_cancellazione=on_cancellazione)

    def on_sottometti_voto_logica(self, lista_scelta: dict):
        indice_scelta = lista_scelta["id"]
        n_opzioni = len(LISTE_ELETTORALI)
        try:
            # Costruzione del pacchetto crittografico sicuro (One-hot encoding + padding + cifratura ibrida + firma effimera)
            byte_pacchetto = self.cittadino.costruisci_pacchetto(indice_scelta, n_opzioni, self.manager.pk_glob)
            # Calcolo di un hash anonimo del token per la bacheca pubblica
            success, msg, ricevuta = self.manager.blockchain.sottometti_e_registra_voto(byte_pacchetto)
            if not success:
                messagebox.showerror("Errore validazione comune", msg)
                return False, None
            dati_scheda = {
                "tx_id": ricevuta["tx_hash"][:18]+"...",
                "token_hash": ricevuta["token_hash"][:24]+"...",
                "byte_pacchetto": byte_pacchetto,
                "ricevuta": ricevuta
            }
            return True, dati_scheda
        except Exception as e:
            messagebox.showerror("Errore Cifratura Voto", f"Si è verificato un errore durante la cifratura: {str(e)}")
            return False, None


class FinestraScrutinio: 
    """
    Finestra parallela per la gestione della chiusura delle elezioni e lo spoglio crittografico.
    Permette agli scrutinatori di ricostruire la chiave e proclamare il vincitore
    """
    def __init__(self, root, backend: SistemaElettoraleManager): 
        self.root=root
        self.backend=backend
        self.window= tk.Toplevel(self.root)
        self.window.title("Spoglio Elettorale e Scrutinio")
        self.window.geometry("700x550")
        self.window.configure(bg="#0F172A")
        self.window.resizable(False, False)
        self.window.transient(self.root)
        self.window.grab_set()
        self.costruisci_ui()

    def costruisci_ui(self): 
        header = tk.Frame(self.window, bg="#1E293B", padx=20, pady=16)
        header.pack(fill="x")
        lbl_title = tk.Label(header, text=" GESTIONE CHIUSURA SEGPI E SPOGLIO CRITTOGRAFICO", 
                             font=("Helvetica", 11, "bold"), fg="#38BDF8", bg="#1E293B")
        lbl_title.pack(anchor="w")
        lbl_sub = tk.Label(header, text="Richiede il raggiungimento del quorum degli scrutinatori (t >= 3 su 5).", 
                           font=("Helvetica", 9), fg="#94A3B8", bg="#1E293B")
        lbl_sub.pack(anchor="w", pady=(2, 0))
        body = tk.Frame(self.window, bg="#FFFFFF", padx=20, pady=20)
        body.pack(fill="both", expand=True, padx=20, pady=16)
        tk.Label(body, text="Stato del Registro Blockchain:", font=("Helvetica", 10, "bold"), 
                 fg="#0F172A", bg="#FFFFFF").pack(anchor="w", pady=(0, 4))
        # Text box per log e risultati
        self.txt_log = tk.Text(body, height=15, font=("Courier", 9), bg="#F1F5F9", fg="#0F172A", relief="solid", bd=1)
        self.txt_log.pack(fill="both", expand=True, pady=(0, 14))
        self.txt_log.insert("end", "Sistema pronto per la chiusura delle urne e l'avvio dello spoglio distribuito.\n")
        self.txt_log.config(state="disabled")
        btn_frame = tk.Frame(body, bg="#FFFFFF")
        btn_frame.pack(fill="x")
        btn_esegui_spoglio = tk.Button(
            btn_frame,
            text="TERMINA ELEZIONI ED ESEGUI SPOGLIO",
            font=("Helvetica", 10, "bold"),
            bg="#2563EB",
            fg="#FFFFFF",
            activebackground="#1D4ED8",
            activeforeground="#FFFFFF",
            padx=16,
            pady=10,
            relief="flat",
            cursor="hand2",
            command=self.avvia_procedura_spoglio
        )
        btn_esegui_spoglio.pack(side="left")
        btn_chiudi = tk.Button(
            btn_frame,
            text="Chiudi Finestra",
            font=("Helvetica", 10),
            bg="#64748B",
            fg="#FFFFFF",
            relief="flat",
            padx=12,
            pady=10,
            command=self.window.destroy
        )
        btn_chiudi.pack(side="right")

    def _log(self,msg:str):
        self.txt_log.config(state="normal")
        self.txt_log.insert("end", f"{msg}\n")
        self.txt_log.see("end")
        self.txt_log.config(state="disabled")

    def avvia_procedura_spoglio(self): 
        self._log("\n--AVVIO SPOGLIO--")
        try: 
            #Recupero dei voti cifrati dalla blockchain tramite bacheca pubblica
            voti_grezzi=self.backend.bacheca.recupera_voti_pubblicati()
            if not voti_grezzi: 
                messagebox.showwarning("Nessun Voto", "Non ci sono voti registrati da scrutinare!")
                return
            voti_cifrati=[v["voto_cifrato"] for v in voti_grezzi]
            #Raccolta frammenti degli scrutinatori
            scrutinatori_attivi=list(self.backend.scrutinatori.values())[:3] #prelievo degli scrutinatori per il quorum
            frammenti_quorum=[s.frammento for s in scrutinatori_attivi if s.frammento is not None]
            if len(frammenti_quorum)<3: 
                messagebox.showerror("Errore quorum", "numero insufficiente di frammenti")
                return
            #Esecuzione spoglio con il primo scrutinatore
            coordinatore=scrutinatori_attivi[0]
            lista_partiti=["Movimento Progresso & Futuro", "Alleanza Ecologista & Territorio", "Unione Civica per la Libertà", "Polo Popolare Democratico"]
            verdetto_dict=coordinatore.calcola_voto(
                voti_cifrati=[v["voto_cifrato"]for v in voti_grezzi], 
                frammenti_quorum=frammenti_quorum, 
                n_globale=self.backend.n_globale, 
                lista_partiti=lista_partiti
            )
            verdetto=verdetto_dict["verdetto"]
            vincitore=verdetto["vincitore"]
            conteggio=verdetto["conteggio"]
            self._log("\n--- RISULTATO FINALE DELLO SCRUTINIO ---")
            self._log(f"PARTITO VINCITORE: {vincitore}")
            self._log("Conteggio dettagliato voti:")
            for partito, voti in conteggio.items():
                self._log(f"   • {partito}: {voti} voti")
            messagebox.showinfo(
                "Elezioni Terminate - Vincitore Eletto",
                f"Lo spoglio si è concluso con successo!\n\nIl partito vincitore è:\n {vincitore}"
            )

        except Exception as e:
            self._log(f"[ERRORE CRitico] Fallimento durante lo spoglio: {str(e)}")
            messagebox.showerror("Errore Spoglio")



# Avvio applicazione principale
if __name__ == "__main__":
    # Inizializza il backend crittografico completo
    backend_manager = SistemaElettoraleManager()
    
    root = tk.Tk()
    app = FinesttraMainIntergrata(root, backend=backend_manager)
    root.mainloop()