//! Boucle d'ingestion : consomme les événements normalisés des capteurs, écarte
//! le bruit système (exécutions en lecture seule), journalise le flux pertinent
//! et déclenche un scan YARA on-access sur les exécutions issues de zones
//! inscriptibles. Rediffuse les événements pertinents aux clients du socket.

use std::sync::mpsc::Sender;

use aegis_core::{Action, EventEnvelope, EventPayload, FileOp, StreamMessage, Verdict};
use aegis_detection::{CanaryWatch, ExecHeuristics};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info};

use crate::scan::ScanRequest;
use crate::zones::is_hot_exec;

/// Draine le canal capteurs jusqu'à sa fermeture. Priorité au comportemental
/// (canari touché → kill immédiat) ; sinon, les exécutions en zone chaude sont
/// loggées, diffusées et envoyées au scanner. Le reste est ignoré. Événements
/// pertinents et verdicts sont poussés sur le bus (UI).
pub async fn ingest(
    mut rx: mpsc::UnboundedReceiver<EventEnvelope>,
    bus: broadcast::Sender<StreamMessage>,
    scan_tx: Sender<ScanRequest>,
    canary_watch: CanaryWatch,
) {
    while let Some(event) = rx.recv().await {
        // 1. Comportemental prioritaire : un canari modifié = ransomware certain.
        if let Some(verdict) = canary_watch.evaluate(&event) {
            enforce(&verdict, &bus);
            let _ = bus.send(StreamMessage::Event(event));
            continue;
        }
        // 2. Flux d'exécution filtré par zone → scan signatures.
        if !is_relevant(&event) {
            debug!(source = ?event.source, "événement non pertinent ignoré");
            continue;
        }
        log_event(&event);
        // Heuristiques exec (reverse shell, zone inscriptible) en plus du scan.
        if let Some(verdict) = ExecHeuristics::evaluate(&event) {
            enforce(&verdict, &bus);
        }
        if let EventPayload::File(file) = &event.payload {
            if matches!(file.op, FileOp::OpenExec) {
                let _ = scan_tx.send(ScanRequest {
                    path: file.path.clone(),
                    event_id: event.event_id,
                });
            }
        }
        let _ = bus.send(StreamMessage::Event(event)); // échoue sans abonné : ignoré
    }
    info!("canal d'ingestion fermé, arrêt de la boucle");
}

/// Journalise un verdict comportemental, le pousse à l'UI et applique l'action.
fn enforce(verdict: &Verdict, bus: &broadcast::Sender<StreamMessage>) {
    info!(
        engine = ?verdict.engine,
        severity = ?verdict.severity,
        mitre = ?verdict.mitre,
        title = %verdict.title,
        "VERDICT"
    );
    let _ = bus.send(StreamMessage::Verdict(verdict.clone()));
    if let Action::Kill { pid } = verdict.recommended_action {
        match aegis_response::kill_process(pid) {
            Ok(()) => info!(pid, "process neutralisé"),
            Err(err) => error!(pid, %err, "neutralisation impossible"),
        }
    }
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
