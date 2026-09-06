## Sistema di voto elettronico sicuro basato su blockchain e cifratura ibrida
Progetto sviluppato per il corso di Algoritmi e Protocolli per la Sicurezza (A.A. 2025-2026)
### Autrici del progetto
- Beatrice Rebecca
- Gaeta Michela
### Panoramica del progetto
Il progetto implementa un prototipo di software in Python per la gestione sicura di un'elezione parlamentare a lista chiusa. L'architettura cerca di trovare le migliore scelte per garantire un compromesso tra la segretezza del voto, l'unicità e l'integrità.
Il codice è organizzato in una struttura ad oggetti orientata alla separazione delle responsabilità: 
-  `ente_nazionale.py `: Autorità di configurazione iniziale. Genera la coppia di chiavi globali per l'elezione e frammenta l'esponente privato usando uno schema a soglia basato sui polinomi. Distribuisce i frammenti agli scrutinatori mediante Signcryption per prevenire attacchi di re-inoltro.
-  `scrutinatore.py `: Ciascuno riceve e verifica il proprio frammento protetto. Al termine delle votazioni, un quorum di $t$ scrutinatori collabora tramite Interpolazione di Lagrange per ricostruire la chiave privata globale e decifrare le schede.
- `identity_provider.py `:Entità fidata indipendente. Verifica l'identità e i requisiti di voto degli elettori, bloccando tentativi di voto multiplo mediante un registro. Rilascia un token monouso associato alla chiave pubblica effimera del cittadino firmato.
-  `cittadino.py `: Genera un coppia di chiavi effimere locali, riceve il token tramite una sessione TLS simulata, codifica il proprio voto in One-Hot Encoding con padding casuale, applica una cifratura ibrida (AES-CGM con RSA-OAEP) e firma il pacchetto finale.
-  `comune.py ` e classe Resource Server in  `blockchain.py `:  Verifica la doppia firma e l'unicità del token. In caso di successo, iscrive il voto su una blockchain locale (Ganache) sottoforma di una transazione e calcola il Merkle Tree.
-  Bacheca Pubblica  in `blockchain.py ` e  `merkle_tree.py `: Interfaccia che consente a chiunque di ispezionare i blocchi e ai singoli cittadini di verificare il singolo voto tramite l'uso di prove di Merkle senza compromettere la segretezza del voto.

### Librerie usate: 
Il progetto richiede Python3.x e utilizza le seguente librerie: 
-  `cryptography ` per la gestione delle primitive simmetriche e asimmetriche e per le funzioni di hash
-  `web3` per comunicare con Ganache (nodo locale)
- `tkinter` per l'interfaccia grafica
