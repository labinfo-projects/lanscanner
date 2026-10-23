# 🔍 LAN Scanner

Uno scanner di rete locale veloce e multipiattaforma scritto in Rust.

A differenza dei tradizionali scanner basati su ping che richiedono privilegi di `root` o `Amministratore` per aprire socket ICMP raw, questo strumento utilizza una tecnica di **TCP Port Sweep**. Questo gli permette di essere eseguito interamente nello spazio utente (user-space) aggirando efficacemente i blocchi ICMP dei firewall di base.

## ✨ Caratteristiche

* **Estremamente Veloce e Multithread:** Utilizza `rayon` per la scansione parallela, sfruttando al massimo i core della tua CPU per analizzare intere sottoreti in pochi secondi.

* **Multipiattaforma:** Funziona perfettamente su Windows, macOS e Linux senza dipendenze specifiche legate al sistema operativo.

* **Nessun Permesso di Root Richiesto:** Sfrutta i timeout di connessione TCP e l'analisi dei pacchetti RST (tramite gli errori di tipo `ConnectionRefused`) per rilevare in modo affidabile la presenza degli host.

* **OS Fingerprinting:** Cerca di dedurre il tipo di dispositivo bersaglio (Windows, Linux/macOS, IoT/Web) in base alle porte trovate aperte.

* **Reverse DNS Lookup:** Risolve in modo asincrono i nomi di dominio (hostname) per gli IP che risultano attivi.

* **Timeout Configurabile:** Adattabile dinamicamente a connessioni cablate aziendali (ultra-veloci) o reti Wi-Fi/IoT (più lente a rispondere) tramite il flag `-t`.

* **CLI Elegante:** Sviluppato utilizzando `clap` per un'interfaccia a riga di comando standard e intuitiva, e `indicatif` per una barra di avanzamento fluida e thread-safe.

## 🚀 Installazione

### Prerequisiti

È necessario avere installata la toolchain di Rust. Se non l'hai ancora configurata, puoi scaricarla da [rustup.rs](https://rustup.rs/).

### Compilazione dai sorgenti

Clona la repository e compila il progetto in modalità `release` per ottenere le massime prestazioni:

```bash
git clone https://github.com/labinfo-projects/lanscanner.git
cd lanscanner
cargo build --release
```

Il binario compilato sarà disponibile al percorso `target/release/lanscanner` (oppure `lanscanner.exe` su sistemi Windows).

## 💻 Utilizzo

Avvia lo scanner fornendo la sottorete di destinazione utilizzando la notazione CIDR.

```bash
# Utilizzo di base (timeout di default: 500ms)
./target/release/lanscanner 192.168.1.0/24

# Scansione rapida (es. Rete Ethernet molto veloce, timeout 100ms)
./target/release/lanscanner 192.168.1.0/24 -t 100

# Mostra il menu di aiuto
./target/release/lanscanner --help
```

### Esempio di Output

```text
Avvio scansione intelligente sulla rete 192.168.1.0/24...
[00:00:01] ########################################     256/256 IP (00:00:00) Completato!

=== Risultati Scansione ===
Trovati 4 host attivi:

192.168.1.1      | router.local              | Probabile Linux/macOS/Router (SSH aperto)
192.168.1.5      | DESKTOP-X7B.local         | Probabile PC Windows (SMB/RPC aperto)
192.168.1.20     | raspberrypi.local         | Probabile Linux/macOS/Router (SSH aperto)
192.168.1.100    | Sconosciuto               | Dispositivo Attivo (Porte blindate/Firewall)
```

## 🛠️ Dettagli Tecnici

Questo scanner tenta di connettersi a una lista predefinita di porte comuni (`22`, `80`, `135`, `445`) impostando un timeout configurabile (di default **500ms**, modificabile con il parametro `-t`). 

* Se la connessione viene accettata (`Ok`), significa che la porta è aperta.
* Se la connessione viene attivamente rifiutata dal kernel remoto (`ConnectionRefused`), significa che la macchina host è accesa e raggiungibile dalla rete, anche se la porta interrogata è chiusa. Questa particolarità tecnica garantisce un metodo di rilevamento altamente accurato senza dover ricorrere all'invio di pacchetti ICMP raw.

### Dipendenze

* [`clap`](https://crates.io/crates/clap) - Parsing e gestione degli argomenti da riga di comando.
* [`rayon`](https://crates.io/crates/rayon) - Gestione del parallelismo e del multithreading.
* [`indicatif`](https://crates.io/crates/indicatif) - Rendering della barra di avanzamento a terminale.
* [`ipnet`](https://crates.io/crates/ipnet) - Gestione sicura dei tipi di rete IPv4/IPv6 e calcolo degli indirizzi.
* [`dns-lookup`](https://crates.io/crates/dns-lookup) - Wrapper per la risoluzione DNS nativa del sistema operativo.

## 📄 Licenza

Questo progetto è distribuito sotto licenza **GNU General Public License v3.0**. Consulta il file [LICENSE](https://github.com/labinfo-projects/lanscanner/blob/main/LICENSE) per ulteriori dettagli.
