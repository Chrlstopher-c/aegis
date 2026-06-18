//! Point d'entrée du daemon Aegis. Assemble le pipeline temps réel :
//! capteurs (aegis-probes) → ingestion → (à venir) détection/policy/réponse,
//! avec diffusion du flux d'événements aux clients via un socket Unix.

mod ipc_socket;
mod pipeline;

use aegis_core::EventEnvelope;
use anyhow::Result;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    info!(
        schema_version = aegis_core::SCHEMA_VERSION,
        "aegis-daemon démarré (Lot 1 — capteurs + ingestion)"
    );

    // Capteurs → ingestion (mpsc), ingestion → clients socket (broadcast).
    let (event_tx, event_rx) = mpsc::unbounded_channel::<EventEnvelope>();
    let (bus_tx, _) = broadcast::channel::<EventEnvelope>(1024);

    aegis_probes::spawn_fanotify(event_tx)?;

    let socket_bus = bus_tx.clone();
    tokio::spawn(async move {
        if let Err(err) = ipc_socket::serve(socket_bus).await {
            error!(%err, "serveur socket Unix arrêté");
        }
    });

    // Bloque jusqu'à fermeture du canal (capteurs morts).
    pipeline::ingest(event_rx, bus_tx).await;
    Ok(())
}
