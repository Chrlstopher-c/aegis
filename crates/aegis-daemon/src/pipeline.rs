//! Boucle d'ingestion : consomme les événements normalisés des capteurs, écarte
//! le bruit système (exécutions en lecture seule), journalise le flux pertinent
//! et déclenche un scan YARA on-access sur les exécutions issues de zones
//! inscriptibles. Rediffuse les événements pertinents aux clients du socket.

use std::sync::mpsc::Sender;

use aegis_core::{EventEnvelope, EventPayload};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info};

use crate::scan::ScanRequest;
use crate::zones::is_hot_exec;

/// Draine le canal capteurs jusqu'à sa fermeture. Les exécutions en zone chaude
/// sont loggées, diffusées et envoyées au scanner ; le reste est ignoré (trace).
pub async fn ingest(
    mut rx: mpsc::UnboundedReceiver<EventEnvelope>,
    bus: broadcast::Sender<EventEnvelope>,
    scan_tx: Sender<ScanRequest>,
) {
    while let Some(event) = rx.recv().await {
        if !is_relevant(&event) {
            debug!(source = ?event.source, "événement non pertinent ignoré");
            continue;
        }
        log_event(&event);
        if let EventPayload::File(file) = &event.payload {
            let _ = scan_tx.send(ScanRequest {
                path: file.path.clone(),
                event_id: event.event_id,
            });
        }
        let _ = bus.send(event); // échoue seulement sans abonné : ignoré
    }
    info!("canal d'ingestion fermé, arrêt de la boucle");
}

/// Filtre le bruit : seules les exécutions issues d'une zone inscriptible passent.
fn is_relevant(event: &EventEnvelope) -> bool {
    match &event.payload {
        EventPayload::File(file) => is_hot_exec(&file.path),
        EventPayload::Exec(exec) => exec.from_writable_dir,
        _ => true, // mmap/priv/net : toujours pertinents (Lot 3)
    }
}

fn log_event(event: &EventEnvelope) {
    match &event.payload {
        EventPayload::Exec(exec) => info!(
            source = ?event.source,
            pid = event.process.pid,
            exe = %event.process.exe_path,
            from_writable = exec.from_writable_dir,
            "exec"
        ),
        EventPayload::File(file) => info!(
            source = ?event.source,
            pid = event.process.pid,
            exe = %event.process.exe_path,
            path = %file.path,
            op = ?file.op,
            "exec (fanotify)"
        ),
        other => debug!(source = ?event.source, payload = ?other, "événement"),
    }
}
