//! Sonde fanotify : capte les exécutions (`FAN_OPEN_EXEC_PERM`) en temps réel
//! sur les filesystems montés. Mode detection ⇒ réponse `FAN_ALLOW` immédiate
//! (avant le timeout kernel, contrainte dure). Tourne sur un thread dédié car
//! `read_events` est bloquant ; émet des `EventEnvelope` vers le daemon.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::thread;

use aegis_core::{
    EventEnvelope, EventPayload, EventSource, FileEvent, FileOp, ProcessCtx, SCHEMA_VERSION,
};
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyEvent, FanotifyResponse, InitFlags, MarkFlags, MaskFlags,
    Response,
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info, warn};
use ulid::Ulid;

use crate::proc::process_ctx;

/// Filesystems marqués. Couvre la racine + les tmpfs chauds (montages séparés).
const MARKED_MOUNTS: &[&str] = &["/", "/tmp", "/dev/shm"];

/// Erreur d'initialisation d'une sonde.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("init fanotify (CAP_SYS_ADMIN requis ?) : {0}")]
    Init(#[source] nix::Error),
    #[error("démarrage du thread fanotify : {0}")]
    Thread(#[source] std::io::Error),
}

/// Initialise fanotify, pose les marques d'exécution et lance la boucle de
/// capture sur un thread dédié. Nécessite `CAP_SYS_ADMIN`.
pub fn spawn(tx: UnboundedSender<EventEnvelope>) -> Result<(), ProbeError> {
    let fan = Fanotify::init(
        InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC,
        EventFFlags::O_RDONLY,
    )
    .map_err(ProbeError::Init)?;

    let mask = MaskFlags::FAN_OPEN_EXEC_PERM;
    let flags = MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_FILESYSTEM;
    for mount in MARKED_MOUNTS {
        if let Err(err) = fan.mark(flags, mask, None, Some(*mount)) {
            warn!(mount, %err, "marque fanotify ignorée");
        }
    }

    thread::Builder::new()
        .name("aegis-fanotify".into())
        .spawn(move || run_loop(fan, tx))
        .map_err(ProbeError::Thread)?;
    Ok(())
}

fn run_loop(fan: Fanotify, tx: UnboundedSender<EventEnvelope>) {
    info!(mounts = ?MARKED_MOUNTS, "sonde fanotify active (FAN_OPEN_EXEC_PERM)");
    loop {
        match fan.read_events() {
            // Phase 1 : acquitter tout le batch immédiatement (chemin bloquant,
            // sous timeout kernel). Phase 2 : enrichir hors du chemin critique.
            Ok(events) => {
                let captured = acknowledge_batch(&fan, &events);
                for (pid, path) in captured {
                    let envelope = envelope_for(process_ctx(pid, &path), path);
                    if tx.send(envelope).is_err() {
                        warn!("canal d'ingestion fermé, événement perdu");
                    }
                }
            }
            Err(err) => error!(%err, "lecture des événements fanotify"),
        }
    }
}

/// Répond `ALLOW` à chaque événement et retourne `(pid, path)` pour enrichissement.
fn acknowledge_batch(fan: &Fanotify, events: &[FanotifyEvent]) -> Vec<(u32, String)> {
    let mut captured = Vec::with_capacity(events.len());
    for event in events {
        let Some(fd) = event.fd() else { continue };
        let path = read_fd_path(fd);
        if let Err(err) = fan.write_response(FanotifyResponse::new(fd, Response::FAN_ALLOW)) {
            error!(%err, "réponse fanotify (ALLOW)");
        }
        captured.push((event.pid().max(0) as u32, path));
    }
    captured
}

fn envelope_for(process: ProcessCtx, path: String) -> EventEnvelope {
    EventEnvelope {
        schema_version: SCHEMA_VERSION,
        event_id: Ulid::new().0,
        ts: monotonic_ns(),
        source: EventSource::Fanotify,
        process,
        payload: EventPayload::File(FileEvent {
            path,
            op: FileOp::OpenExec,
            blocking: true,
            response_token: None,
        }),
    }
}

fn read_fd_path(fd: BorrowedFd) -> String {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Horodatage monotone en nanosecondes (`CLOCK_MONOTONIC`).
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts est un buffer valide passé à clock_gettime.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + ts.tv_nsec as u64
}
