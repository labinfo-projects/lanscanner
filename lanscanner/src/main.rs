//     println!("\nLAN SCANNER (c)Giorgio Ruffa 2026\n\nAvvio scansione sulla rete {}...", args.cidr);
use clap::Parser;
use dns_lookup::lookup_addr;
use indicatif::{ProgressBar, ProgressStyle};
use ipnet::Ipv4Net;
use rayon::prelude::*;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

const PORTS_TO_CHECK: &[u16] = &[22, 80, 135, 445];

#[derive(Parser, Debug)]
#[command(
    name = "lan_scanner",
    author = "Giorgio Ruffa", // Aggiornato con il tuo nome
    version = "1.0.0",
    about = "Uno scanner di rete locale con fingerprinting OS e DNS\n(c)Giorgio Ruffa 2026"
)]
struct Args {
    /// La sottorete da scansionare in formato CIDR (es. 192.168.1.0/24)
    cidr: Ipv4Net,

    /// Timeout in millisecondi per ogni connessione TCP
    #[arg(short, long, default_value_t = 500)]
    timeout: u64,
}

/// Struttura per memorizzare le informazioni dettagliate dell'host trovato
struct ActiveHost {
    ip: IpAddr,
    hostname: String,
    details: &'static str,
}

fn main() {
    let args = Args::parse();
    // Convertiamo il parametro numerico in una struct Duration di Rust
    let tcp_timeout = Duration::from_millis(args.timeout);

    println!("\nLAN SCANNER (c)Giorgio Ruffa 2026\n\nAvvio scansione intelligente sulla rete {}...", args.cidr);
    
    let hosts: Vec<IpAddr> = args.cidr.hosts().map(IpAddr::V4).collect();
    let pb = ProgressBar::new(hosts.len() as u64);
    
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} IP ({eta}) {msg}",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb.set_message("Scansione e risoluzione DNS...");

    // filter_map è idiomatico in Rust per filtrare e trasformare i dati in un colpo solo.
    let mut active_hosts: Vec<ActiveHost> = hosts
        .into_par_iter()
        .filter_map(|ip| {
            // Controlla se l'host è vivo, passando il timeout configurabile
            let result = check_host(ip, tcp_timeout);
            
            // Avanziamo la progress bar per ogni IP elaborato, vivo o morto che sia
            pb.inc(1);
            
            // Se check_host restituisce Some(details), mappiamo i dati nella struct
            result.map(|details| {
                // Risoluzione Reverse DNS (eseguita nei thread paralleli!)
                // Usiamo unwrap_or_else per gestire l'errore senza andare in panic se l'IP non ha un nome
                let hostname = lookup_addr(&ip).unwrap_or_else(|_| "Sconosciuto".to_string());
                
                ActiveHost { ip, hostname, details }
            })
        })
        .collect();

    pb.finish_with_message("Completato!");

    // Ordiniamo la lista per IP
    active_hosts.sort_by_key(|h| h.ip);

    println!("\n=== Risultati Scansione ===");
    if active_hosts.is_empty() {
        println!("Nessun host attivo rilevato.");
    } else {
        println!("Trovati {} host attivi:\n", active_hosts.len());
        // Formattazione allineata per una lettura pulita
        for host in active_hosts {
            println!(
                "{:<16} | {:<25} | {}", 
                host.ip.to_string(), 
                host.hostname, 
                host.details
            );
        }
    }
}

/// Tenta di connettersi. Restituisce `Some` con la deduzione del dispositivo se vivo, `None` se morto.
fn check_host(ip: IpAddr, timeout: Duration) -> Option<&'static str> {
    let mut is_alive = false;

    for &port in PORTS_TO_CHECK {
        let addr = SocketAddr::new(ip, port);
        match TcpStream::connect_timeout(&addr, timeout) {
            // Se la porta è aperta, la usiamo per fare "fingerprinting"
            Ok(_) => return Some(guess_device_from_port(port)),
            Err(e) => {
                // Se la connessione è attivamente rifiutata (RST packet), 
                // la macchina esiste fisicamente ma la porta è chiusa dal firewall.
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    is_alive = true; 
                    // Non facciamo return qui: continuiamo il ciclo per vedere 
                    // se c'è un'altra porta effettivamente aperta per identificarlo.
                }
            }
        }
    }

    if is_alive {
        Some("Dispositivo Attivo (Porte blindate/Firewall)")
    } else {
        None
    }
}

/// Restituisce una deduzione statica basata sulla porta aperta trovata.
fn guess_device_from_port(port: u16) -> &'static str {
    match port {
        22 => "Probabile Linux/macOS/Router (SSH aperto)",
        135 | 445 => "Probabile PC Windows (SMB/RPC aperto)",
        80 => "Web Server o Dispositivo IoT (HTTP aperto)",
        _ => "Dispositivo generico (Porta anomala)",
    }
}
