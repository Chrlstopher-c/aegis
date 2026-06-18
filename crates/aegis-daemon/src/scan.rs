//! Thread de scan YARA on-access. Reçoit des requêtes de scan depuis le pipeline
//! (hors du chemin d'ingestion fanotify, pour ne jamais retarder l'acquittement
//! kernel), scanne le fichier, journalise tout verdict et — sur signature exacte
//! (confiance 1.0) — met le fichier en quarantaine immédiatement.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use aegis_core::{Severity, StreamMessage, Verdict};
use aegis_detection::YaraEngine;
use aegis_response::Quarantine;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

/// Requête de scan : fichier à analyser + identifiant de l'événement déclencheur.
pub struct ScanRequest {
    pub path: String,
    pub event_id: u128,
}

/// Démarre le thread de scan et retourne le canal d'émission des requêtes. Les
/// verdicts produits sont poussés sur `bus` (UI) en plus d'être journalisés.
pub fn spawn(
    engine: YaraEngine,
    quarantine: Quarantine,
    bus: broadcast::Sender<StreamMessage>,
) -> Sender<ScanRequest> {
    let (tx, rx) = std::sync::mpsc::channel::<ScanRequest>();
    thread::Builder::new()
        .name("aegis-yara".into())
        .spawn(move || run(rx, engine, quarantine, bus))
        .expect("démarrage du thread de scan YARA");
    tx
}

fn run(
    rx: Receiver<ScanRequest>,
    engine: YaraEngine,
    quarantine: Quarantine,
    bus: broadcast::Sender<StreamMessage>,
) {
    info!("thread de scan YARA prêt");
    while let Ok(req) = rx.recv() {
        match engine.scan_file(&req.path, req.event_id) {
            Ok(verdicts) => {
                for verdict in verdicts {
                    handle_verdict(&verdict, &req.path, &quarantine, &bus);
                }
            }
            Err(err) => warn!(path = %req.path, %err, "scan YARA échoué"),
        }
    }
}

fn handle_verdict(
    verdict: &Verdict,
    path: &str,
    quarantine: &Quarantine,
    bus: &broadcast::Sender<StreamMessage>,
) {
    info!(
        engine = ?verdict.engine,
        severity = ?verdict.severity,
        category = ?verdict.category,
        mitre = ?verdict.mitre,
        title = %verdict.title,
        path,
        "VERDICT"
    );
    let _ = bus.send(StreamMessage::Verdict(verdict.clone()));
    // Signature exacte ≥ High → isolation immédiate, même en mode detection.
    if verdict.severity >= Severity::High {
        match quarantine.quarantine(path, &verdict.title) {
            Ok(entry) => info!(id = %entry.id, path, "menace mise en quarantaine"),
            Err(err) => error!(path, %err, "quarantaine impossible"),
        }
    }
}

/// Emplacement du store de quarantaine (root → `/var/lib/aegis`, sinon repli).
pub fn quarantine_dir() -> PathBuf {
    // SAFETY: geteuid est toujours sûr.
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from("/var/lib/aegis/quarantine");
    }
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("aegis/quarantine")
}
