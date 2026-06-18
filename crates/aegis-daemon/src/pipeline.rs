//! Boucle d'ingestion : consomme les événements normalisés des capteurs, les
//! journalise (livrable Lot 1 : flux temps réel en logs) et les rediffuse sur le
//! bus broadcast pour les clients du socket. La détection/policy se branche ici
//! au Lot 2 (entre la réception et la diffusion).

use aegis_core::{EventEnvelope, EventPayload};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info};

/// Draine le canal capteurs jusqu'à sa fermeture. `bus` rediffuse aux clients.
pub async fn ingest(
    mut rx: mpsc::UnboundedReceiver<EventEnvelope>,
    bus: broadcast::Sender<EventEnvelope>,
) {
    while let Some(event) = rx.recv().await {
        log_event(&event);
        // Échoue seulement si aucun abonné : sans intérêt, on ignore.
        let _ = bus.send(event);
    }
    info!("canal d'ingestion fermé, arrêt de la boucle");
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
