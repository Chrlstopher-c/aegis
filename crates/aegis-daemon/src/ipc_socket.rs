//! Socket Unix local : diffuse le flux d'événements (JSON, une ligne par
//! événement) aux clients abonnés. C'est le canal que l'UI consommera (Lot 4).
//! Chemin `/run/aegis/aegis.sock` si root, repli `$XDG_RUNTIME_DIR/aegis.sock`.

use std::path::PathBuf;

use aegis_core::EventEnvelope;
use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Détermine le chemin du socket selon les privilèges courants.
fn socket_path() -> PathBuf {
    // SAFETY: geteuid est toujours sûr.
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        return PathBuf::from("/run/aegis/aegis.sock");
    }
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("aegis.sock")
}

/// Lie le socket et sert chaque client connecté (lecture seule du flux).
pub async fn serve(bus: broadcast::Sender<EventEnvelope>) -> Result<()> {
    let path = socket_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("création du dossier socket {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(&path); // socket résiduel d'un run précédent
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind du socket {}", path.display()))?;
    info!(socket = %path.display(), "socket Unix prêt");

    loop {
        let (stream, _addr) = listener.accept().await.context("accept socket")?;
        let rx = bus.subscribe();
        tokio::spawn(async move {
            if let Err(err) = serve_client(stream, rx).await {
                debug!(%err, "client socket déconnecté");
            }
        });
    }
}

async fn serve_client(
    mut stream: UnixStream,
    mut rx: broadcast::Receiver<EventEnvelope>,
) -> Result<()> {
    loop {
        match rx.recv().await {
            Ok(event) => {
                let mut line = serde_json::to_string(&event)?;
                line.push('\n');
                stream.write_all(line.as_bytes()).await?;
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "client lent, événements sautés");
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}
