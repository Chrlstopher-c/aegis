//! Boucle d'ingestion : consomme les événements normalisés des capteurs, écarte
//! le bruit système (exécutions en lecture seule), journalise le flux pertinent
//! et déclenche un scan YARA on-access sur les exécutions issues de zones
//! inscriptibles. Rediffuse les événements pertinents aux clients du socket.

use std::sync::mpsc::Sender;
use std::sync::Arc;

use aegis_core::{EventEnvelope, EventPayload, FileOp, ProcessCtx, StreamMessage};
use aegis_detection::{CanaryWatch, CredentialWatch, ExecHeuristics};
use aegis_response::ExclusionStore;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info};

use crate::enforce::{Enforcer, Subject};
use crate::scan::ScanRequest;
use crate::zones::is_hot_exec;

/// Contexte d'arbitrage à partir du process déclencheur.
fn subject_of(ctx: &ProcessCtx) -> Subject {
    Subject { exe_path: ctx.exe_path.clone(), pid: ctx.pid, comm: ctx.comm.clone() }
}

/// Draine le canal capteurs jusqu'à sa fermeture. Priorité au comportemental
/// (canari touché → décision policy immédiate) ; sinon, les exécutions en zone
/// chaude sont loggées, diffusées et envoyées au scanner. Le reste est ignoré.
/// Un process couvert par une exclusion court-circuite toute détection.
pub async fn ingest(
    mut rx: mpsc::UnboundedReceiver<EventEnvelope>,
    bus: broadcast::Sender<StreamMessage>,
    scan_tx: Sender<ScanRequest>,
    canary_watch: CanaryWatch,
    enforcer: Enforcer,
    exclusions: Arc<ExclusionStore>,
) {
    while let Some(event) = rx.recv().await {
        // 0. Allowlist : process explicitement autorisé → aucune détection.
        if exclusions.is_excluded(&event.process) {
            debug!(exe = %event.process.exe_path, "autorisé par exclusion");
            let _ = bus.send(StreamMessage::Event(event));
            continue;
        }
        let subject = subject_of(&event.process);
        // 1. Comportemental prioritaire : un canari modifié = ransomware certain.
        if let Some(verdict) = canary_watch.evaluate(&event) {
            enforcer.handle(&verdict, &subject);
            let _ = bus.send(StreamMessage::Event(event));
            continue;
        }
        // 1bis. FIM credential : lecture d'un fichier sensible surveillé.
        if let Some(verdict) = CredentialWatch::evaluate(&event) {
            enforcer.handle(&verdict, &subject);
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
            enforcer.handle(&verdict, &subject);
        }
        if let EventPayload::File(file) = &event.payload {
            if matches!(file.op, FileOp::OpenExec) {
                let _ = scan_tx.send(ScanRequest {
                    path: file.path.clone(),
                    event_id: event.event_id,
                    subject: subject.clone(),
                });
            }
        }
        let _ = bus.send(StreamMessage::Event(event)); // échoue sans abonné : ignoré
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
