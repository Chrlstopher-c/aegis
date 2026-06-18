//! Thread de scan YARA on-access. Reçoit des requêtes de scan depuis le pipeline
//! (hors du chemin d'ingestion fanotify, pour ne jamais retarder l'acquittement
//! kernel), scanne le fichier, et délègue chaque verdict à l'`Enforcer` (policy
//! + application). Le verdict de signature porte l'action de quarantaine.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use aegis_detection::YaraEngine;
use tracing::{info, warn};

use crate::enforce::{Enforcer, Subject};

/// Requête de scan : fichier à analyser + identifiant de l'événement déclencheur
/// + contexte du process (pour une éventuelle décision différée).
pub struct ScanRequest {
    pub path: String,
    pub event_id: u128,
    pub subject: Subject,
}

/// Démarre le thread de scan et retourne le canal d'émission des requêtes.
pub fn spawn(engine: YaraEngine, enforcer: Enforcer) -> Sender<ScanRequest> {
    let (tx, rx) = std::sync::mpsc::channel::<ScanRequest>();
    thread::Builder::new()
        .name("aegis-yara".into())
        .spawn(move || run(rx, engine, enforcer))
        .expect("démarrage du thread de scan YARA");
    tx
}

fn run(rx: Receiver<ScanRequest>, engine: YaraEngine, enforcer: Enforcer) {
    info!("thread de scan YARA prêt");
    while let Ok(req) = rx.recv() {
        match engine.scan_file(&req.path, req.event_id) {
            Ok(verdicts) => {
                for verdict in verdicts {
                    enforcer.handle(&verdict, &req.subject);
                }
            }
            Err(err) => warn!(path = %req.path, %err, "scan YARA échoué"),
        }
    }
}

/// Répertoire de données du daemon (root → `/var/lib/aegis`, sinon repli XDG).
pub fn data_dir() -> PathBuf {
    // SAFETY: geteuid est toujours sûr.
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from("/var/lib/aegis");
    }
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("aegis")
}

/// Emplacement du store de quarantaine.
pub fn quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}
