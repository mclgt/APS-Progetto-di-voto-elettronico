
"""
Flusso applicativo richiesto:
  1. SCHERMATA PRINCIPALE (MainWindow):
     - Contiene la Bacheca Pubblica dei Voti (tabella append-only con le schede registrate).
     - Contiene il pulsante principale per avviare la procedura di voto.
  2. SCHERMATA DI AUTENTICAZIONE IdP (IdPAuthWindow):
     - Finestra separata per inserimento Codice Fiscale, Provider SPID/CIE e password.
     - In caso di successo, avvia la cabina di voto.
  3. SCHERMATA CABINA ELETTORALE (FinestraVoto):
     - Scheda elettorale a lista chiusa per la selezione della preferenza.
     - Una volta confermato il voto, chiude la cabina e ritorna alla Schermata
       Principale, aggiornando la bacheca pubblica con la nuova scheda anonima.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

#dati di default per le liste elettorali
LISTE_ELETTORALI = [
    {"id": 0, "sigla": "FUTURO", "nome": "Movimento Progresso & Futuro", "capolista": "Prof.ssa Elena Bianchi", "colore": "#2563EB"},
    {"id": 1, "sigla": "ECO", "nome": "Alleanza Ecologista & Territorio", "capolista": "Dott. Marco Verdi", "colore": "#059669"},
    {"id": 2, "sigla": "LIB", "nome": "Unione Civica per la Libertà", "capolista": "Avv. Roberto Ferrari", "colore": "#D97706"},
    {"id": 3, "sigla": "SOV", "nome": "Polo Popolare Democratico", "capolista": "Ing. Chiara De Luca", "colore": "#DC2626"},
]


#schermata principale
class MainWindow:
    """
    Schermata Principale dell'applicazione.
    - Mostra la Bacheca Pubblica dei voti già registrati.
    - Contiene il pulsante per avviare il processo di autenticazione e voto.
    - Si aggiorna automaticamente al termine di ogni votazione.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Comune - Bacheca Pubblica del Voto Elettronico")
        self.root.geometry("820x620")
        self.root.configure(bg="#0F172A")
        self.root.minsize(700, 500)
        # Contatore voti
        self.voti_registrati = []
        self.costruisci_ui()
        self._carica_dati_iniziali_bacheca()

    def costruisci_ui(self):
        # 1. Header Istituzionale
        header = tk.Frame(self.root, bg="#1E293B", padx=24, pady=18)
        header.pack(fill="x")
        lbl_inst = tk.Label(header, text="REPUBBLICA ITALIANA • SERVIZIO ELETTORALE COMUNALE", 
                            font=("Helvetica", 9, "bold"), fg="#38BDF8", bg="#1E293B")
        lbl_inst.pack(anchor="w")
        title_box = tk.Frame(header, bg="#1E293B")
        title_box.pack(fill="x", pady=(4, 0))

        lbl_title = tk.Label(title_box, text="Bacheca Pubblica delle Schede Elettorali", 
                             font=("Helvetica", 16, "bold"), fg="#FFFFFF", bg="#1E293B")
        lbl_title.pack(side="left")
        # 2. Barra di Controllo con Azione Voto
        action_bar = tk.Frame(self.root, bg="#0F172A", padx=24, pady=16)
        action_bar.pack(fill="x")
        desc_text = (
            "Clicca sul pulsante a destra per autenticarti con Codice Fiscale ed esprimere il tuo voto."
        )
        lbl_desc = tk.Label(action_bar, text=desc_text, font=("Helvetica", 9), 
                            fg="#94A3B8", bg="#0F172A", justify="left")
        lbl_desc.pack(side="left")
        # Pulsante principale: avvia autenticazione
        self.btn_vota = tk.Button(
            action_bar,
            text="VOTA ORA (Accedi con SPID/CIE)",
            font=("Helvetica", 11, "bold"),
            bg="#0284C7",
            fg="#FFFFFF",
            activebackground="#0369A1",
            activeforeground="#FFFFFF",
            padx=18,
            pady=10,
            relief="flat",
            cursor="hand2",
            command=self.apri_autenticazione
        )
        self.btn_vota.pack(side="right")
        # 3. Contenitore Tabella Bacheca Pubblica
        board_frame = tk.Frame(self.root, bg="#1E293B", padx=16, pady=16, 
                               highlightthickness=1, highlightbackground="#334155")
        board_frame.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        # Intestazione tabella
        table_header = tk.Frame(board_frame, bg="#1E293B")
        table_header.pack(fill="x", pady=(0, 8))
        lbl_tbl = tk.Label(table_header, text="ELENCO SCHEDE ACQUISITE NEL REGISTRO", 
                           font=("Helvetica", 10, "bold"), fg="#E2E8F0", bg="#1E293B")
        lbl_tbl.pack(side="left")
        self.lbl_count = tk.Label(table_header, text="Totale Schede: 0", 
                                  font=("Helvetica", 9, "bold"), fg="#38BDF8", bg="#1E293B")
        self.lbl_count.pack(side="right")
        # Configurazione Treeview (Tabella)
        columns = ("tx_id", "timestamp", "token_hash", "stato")
        self.tree = ttk.Treeview(board_frame, columns=columns, show="headings", height=12)
        self.tree.heading("tx_id", text="ID Transazione")
        self.tree.heading("timestamp", text="Data e Ora")
        self.tree.heading("token_hash", text="Identificativo Anonimo / Token Hash")
        self.tree.heading("stato", text="Stato Acquisizione")
        self.tree.column("tx_id", width=140, anchor="center")
        self.tree.column("timestamp", width=150, anchor="center")
        self.tree.column("token_hash", width=300, anchor="w")
        self.tree.column("stato", width=130, anchor="center")
        # Scrollbar per la tabella
        scrollbar = ttk.Scrollbar(board_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def apri_autenticazione(self):
        """Apre la finestra separata di autenticazione IdP."""
        # Disabilita temporaneamente il tasto vota per evitare doppie aperture
        self.btn_vota.config(state="disabled")
        IdPAuthWindow(self.root, on_auth_success=self.apri_cabina_voto, on_cancellazione=self._riabilita_tasto_voto)

    def apri_cabina_voto(self, cf_autenticato: str):
        """Chiamata dopo l'autenticazione; apre la cabina elettorale."""
        FinestraVoto(self.root, on_voto_confermato=self.on_voto_completato, on_cancellazione=self._riabilita_tasto_voto)

    def on_voto_completato(self, dati_scheda: dict):
        """Chiamata al termine dell'espressione del voto.
        Torna alla schermata principale e aggiorna la bacheca pubblica!
        """
        # Creazione riga bacheca pubblica (completamente anonima)
        tx_id = dati_scheda.get("tx_id", f"TX-2026-000{len(self.voti_registrati) + 1}")
        ora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        identificativo_anonimo = dati_scheda.get("token_hash", f"hash_{ora.replace(' ', '_')}")
        stato = "Validato"
        self.aggiungi_voto_in_bacheca(tx_id, ora, identificativo_anonimo, stato)
        self._riabilita_tasto_voto()
        # Feedback visivo all'utente sulla schermata principale
        messagebox.showinfo(
            "Procedura Conclusa",
            f"Sei tornato alla Schermata Principale.\n\n"
            f"La tua scheda è stata registrata nella Bacheca Pubblica con identificativo:\n{tx_id}"
        )

    def aggiungi_voto_in_bacheca(self, tx_id, timestamp, token_hash, stato):
        """Inserisce una nuova riga nella tabella della bacheca."""
        self.voti_registrati.append({"tx_id": tx_id, "time": timestamp, "hash": token_hash, "status": stato})
        self.tree.insert("", "end", values=(tx_id, timestamp, token_hash, stato))
        self.lbl_count.config(text=f"Totale Schede: {len(self.voti_registrati)}")

    def _riabilita_tasto_voto(self):
        self.btn_vota.config(state="normal")



# SCHERMATA DI AUTENTICAZIONE IdP (CODICE FISCALE & SPID/CIE)
class IdPAuthWindow:
    """
    Finestra Modale di Autenticazione Separata.
    Riceve il Codice Fiscale dell'utente e convalida le credenziali.
    """
    def __init__(self, root, on_auth_success, on_cancellazione=None):
        self.root = root
        self.on_auth_success = on_auth_success
        self.on_cancellazione = on_cancellazione
        self.window = tk.Toplevel(self.root)
        self.window.title("Portale IdP - Autenticazione SPID / CIE")
        self.window.geometry("520x640")
        self.window.configure(bg="#F8FAFC")
        self.window.resizable(False, False)
        self.window.transient(self.root)
        self.window.grab_set()  # Rende la finestra modale
        self.window.protocol("WM_DELETE_WINDOW", self.on_chiusura)
        self.costruisci_ui()

    def costruisci_ui(self):
        # Header istituzionale
        header = tk.Frame(self.window, bg="#0F172A", padx=20, pady=16)
        header.pack(fill="x")
        lbl_top = tk.Label(header, text="REPUBBLICA ITALIANA • MINISTERO DELL'INTERNO", 
                           font=("Helvetica", 8, "bold"), fg="#94A3B8", bg="#0F172A")
        lbl_top.pack(anchor="w")
        lbl_title = tk.Label(header, text="Portale Unico di Autenticazione IdP", 
                             font=("Helvetica", 13, "bold"), fg="#FFFFFF", bg="#0F172A")
        lbl_title.pack(anchor="w", pady=(2, 0))
        # Card del form
        card = tk.Frame(self.window, bg="#FFFFFF", padx=24, pady=20, 
                        highlightthickness=1, highlightbackground="#E2E8F0")
        card.pack(fill="both", expand=True, padx=20, pady=20)
        # Selettore Provider
        tk.Label(card, text="SELEZIONA IDENTITY PROVIDER:", font=("Helvetica", 9, "bold"), 
                 fg="#334155", bg="#FFFFFF").pack(anchor="w", pady=(0, 4))     
        self.provider_var = tk.StringVar(value="PosteID")
        providers = ["PosteID", "Aruba ID", "InfoCert ID", "CIE ID (Carta d'Identità)"]
        combo = ttk.Combobox(card, textvariable=self.provider_var, values=providers, 
                             state="readonly", font=("Helvetica", 10))
        combo.pack(fill="x", pady=(0, 16))
        # Campo Codice Fiscale
        tk.Label(card, text="CODICE FISCALE DELL'ELETTORE (16 caratteri):", 
                 font=("Helvetica", 9, "bold"), fg="#334155", bg="#FFFFFF").pack(anchor="w", pady=(0, 4)) 
        self.cf_entry = tk.Entry(card, font=("Courier", 13, "bold"), fg="#0F172A", 
                                 bg="#F1F5F9", relief="solid", bd=1)
        self.cf_entry.pack(fill="x", ipady=6, pady=(0, 4))
        lbl_hint = tk.Label(card, text="Inserisci il codice fiscale per verificare il diritto al voto.", 
                            font=("Helvetica", 8), fg="#64748B", bg="#FFFFFF")
        lbl_hint.pack(anchor="w", pady=(0, 16))
        # Box informativo
        info_frame = tk.Frame(card, bg="#F0FDF4", padx=12, pady=10, 
                              highlightthickness=1, highlightbackground="#BBF7D0")
        info_frame.pack(fill="x", pady=(0, 20))
        # Pulsante Autenticazione
        btn_auth = tk.Button(card, text="AUTENTICATI ED ENTRA IN CABINA", 
                             bg="#0284C7", fg="#FFFFFF", activebackground="#0369A1", 
                             activeforeground="#FFFFFF", font=("Helvetica", 11, "bold"), 
                             relief="flat", cursor="hand2", command=self.sottometti_auth)
        btn_auth.pack(fill="x", ipady=8)
        # Pulsante Annulla
        btn_cancel = tk.Button(card, text="Annulla e Torna alla Bacheca", 
                               font=("Helvetica", 9), fg="#64748B", bg="#FFFFFF", 
                               relief="flat", command=self.on_chiusura)
        btn_cancel.pack(pady=(10, 0))

    def sottometti_auth(self):
        cf = self.cf_entry.get().strip().upper()
        provider = self.provider_var.get()
        pwd = self.pwd_entry.get()
        if len(cf) != 16:
            messagebox.showwarning("Formato Non Valido", "Il Codice Fiscale deve essere di 16 caratteri!")
            return
        success, msg = self.on_logica_autenticazione(cf, provider, pwd)
        if success:
            messagebox.showinfo("Accesso Autorizzato", f"Identità verificata con successo via {provider}.\nSi apre la cabina elettorale.")
            self.window.destroy()
            self.on_auth_success(cf)
        else:
            messagebox.showerror("Accesso Negato", msg)

    def on_logica_autenticazione(self, cf: str):
        """
            Effettua il controllo dei dati
        """
        if len(cf) == 16:
            return True, "Autenticato con successo"
        return False, "Codice Fiscale non valido"

    def on_chiusura(self):
        self.window.destroy()
        if self.on_cancellazione:
            self.on_cancellazione()



# 3. SCHERMATA CABINA ELETTORALE DIGITALE (ACQUISIZIONE VOTO)
class FinestraVoto:
    """
    Finestra della Cabina Elettorale (separata e disaccoppiata).
    - L'elettore seleziona la preferenza per una delle liste chiuse.
    - Alla conferma, restituisce i dati del voto e si chiude,
      riportando l'utente alla Bacheca Principale.
    """
    def __init__(self, root, on_voto_confermato, on_cancellazione=None):
        self.root = root
        self.on_voto_confermato = on_voto_confermato
        self.on_cancellazione = on_cancellazione
        self.window = tk.Toplevel(self.root)
        self.window.title("Cabina Elettorale Digitale - Repubblica Italiana")
        self.window.geometry("680x720")
        self.window.configure(bg="#0F172A")
        self.window.resizable(False, False)
        self.window.transient(self.root)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self.on_chiusura)
        self.lista_selezionata_id = tk.IntVar(value=-1)
        self.costruisci_ui()

    def costruisci_ui(self):
        # 1. Header Cabina
        top_bar = tk.Frame(self.window, bg="#1E293B", padx=20, pady=16)
        top_bar.pack(fill="x")
        lbl_shield = tk.Label(top_bar, text="CABINA ELETTORALE DIGITALE (DISACCOPPIATA)", 
                              font=("Helvetica", 11, "bold"), fg="#38BDF8", bg="#1E293B")
        lbl_shield.pack(anchor="w")
        lbl_sub = tk.Label(top_bar, text="Ambiente di voto protetto: nessun dato anagrafico o Codice Fiscale presente.", 
                           font=("Helvetica", 9), fg="#94A3B8", bg="#1E293B")
        lbl_sub.pack(anchor="w", pady=(2, 0))
        # 2. Scheda Elettorale
        ballot_frame = tk.Frame(self.window, bg="#FFFFFF", padx=24, pady=20)
        ballot_frame.pack(fill="both", expand=True, padx=20, pady=16)
        lbl_title = tk.Label(ballot_frame, text="ELEZIONI DELLA CAMERA DEI DEPUTATI", 
                             font=("Georgia", 14, "bold"), fg="#0F172A", bg="#FFFFFF")
        lbl_title.pack(pady=(0, 2))
        lbl_desc = tk.Label(ballot_frame, text="Scheda Elettorale a Lista Chiusa (seleziona un'unica preferenza):", 
                            font=("Helvetica", 9), fg="#64748B", bg="#FFFFFF")
        lbl_desc.pack(pady=(0, 14))
        # 3. Lista opzioni partiti
        list_container = tk.Frame(ballot_frame, bg="#F8FAFC", padx=10, pady=10, 
                                  relief="solid", bd=1)
        list_container.pack(fill="both", expand=True)
        for p in LISTE_ELETTORALI:
            row = tk.Frame(list_container, bg="#FFFFFF", padx=12, pady=10, 
                           highlightthickness=1, highlightbackground="#E2E8F0")
            row.pack(fill="x", pady=4)
            rb = tk.Radiobutton(
                row,
                variable=self.lista_selezionata_id,
                value=p["id"],
                bg="#FFFFFF",
                activebackground="#FFFFFF",
                font=("Helvetica", 11, "bold"),
                fg="#0F172A",
                command=self.on_cambio_selezione
            )
            rb.pack(side="left", padx=(0, 8))

            badge = tk.Label(row, text=p["sigla"], font=("Helvetica", 9, "bold"), 
                             fg="#FFFFFF", bg=p["colore"], padx=8, pady=4)
            badge.pack(side="left", padx=(0, 12))

            info = tk.Frame(row, bg="#FFFFFF")
            info.pack(side="left", fill="x", expand=True)

            lbl_name = tk.Label(info, text=p["nome"], font=("Helvetica", 10, "bold"), 
                                fg="#0F172A", bg="#FFFFFF")
            lbl_name.pack(anchor="w")

            lbl_cap = tk.Label(info, text=f"Capolista: {p['capolista']}", 
                               font=("Helvetica", 8), fg="#64748B", bg="#FFFFFF")
            lbl_cap.pack(anchor="w")

        # 4. Azioni e Invio Voto
        action_bar = tk.Frame(ballot_frame, bg="#FFFFFF", pady=10)
        action_bar.pack(fill="x", pady=(12, 0))

        self.lbl_selected_summary = tk.Label(action_bar, text="Nessuna lista selezionata", 
                                             font=("Helvetica", 9, "italic"), fg="#64748B", bg="#FFFFFF")
        self.lbl_selected_summary.pack(anchor="w", pady=(0, 8))

        btn_box = tk.Frame(action_bar, bg="#FFFFFF")
        btn_box.pack(fill="x")

        btn_cancel = tk.Button(btn_box, text="Annulla e Torna", font=("Helvetica", 10), 
                               command=self.on_chiusura, bg="#F1F5F9", relief="flat", padx=12, pady=6)
        btn_cancel.pack(side="left")

        btn_confirm = tk.Button(btn_box, text="CONFERMA ED INVIA VOTO", 
                                font=("Helvetica", 10, "bold"), bg="#10B981", fg="#FFFFFF", 
                                activebackground="#059669", activeforeground="#FFFFFF", 
                                relief="flat", cursor="hand2", padx=16, pady=8, 
                                command=self.sottometti_voto)
        btn_confirm.pack(side="right")

    def on_cambio_selezione(self):
        sel_id = self.lista_selezionata_id.get()
        scelto = next((p for p in LISTE_ELETTORALI if p["id"] == sel_id), None)
        if scelto:
            self.lbl_selected_summary.config(
                text=f"Lista Selezionata: [{scelto['sigla']}] {scelto['nome']}", 
                fg="#0F172A", font=("Helvetica", 9, "bold")
            )

    def sottometti_voto(self):
        sel_id = self.lista_selezionata_id.get()
        if sel_id < 0:
            messagebox.showwarning("Nessuna Selezione", "Seleziona una lista prima di inviare la scheda!")
            return

        scelto = next((p for p in LISTE_ELETTORALI if p["id"] == sel_id), None)
        conferma = messagebox.askyesno(
            "Conferma Espressione Voto",
            f"Stai per esprimere il voto per:\n\n[{scelto['sigla']}] {scelto['nome']}\n\nConfermi l'invio?"
        )
        if not conferma:
            return

        esito, dati_scheda = self.on_sottometti_voto_logica(scelto)
        if esito:
            self.window.destroy()
            # Ritorna alla Schermata Principale passando i dati anonimi
            self.on_voto_confermato(dati_scheda)

    def on_sottometti_voto_logica(self, lista_scelta: dict):
        """
        Richiama l'algoritmo di voto
        """
        id_fittizio = f"TX-2026-{lista_scelta['sigla']}-987"
        token_hash_fittizio = f"sha256_{lista_scelta['sigla']}_mock_token_leaf"
        return True, {"tx_id": id_fittizio, "token_hash": token_hash_fittizio}

    def on_chiusura(self):
        self.window.destroy()
        if self.on_cancellazione:
            self.on_cancellazione()


# AVVIO APPLICAZIONE
if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()
