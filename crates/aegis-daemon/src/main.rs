//! Point d'entrée du daemon Aegis. Assemble le pipeline temps réel :
//! capteurs (aegis-probes) → ingestion → (à venir) détection/policy/réponse,
//! avec diffusion du flux d'événements aux clients via un socket Unix.

mod ipc_socket;
mod pipeline;
mod scan;
mod zones;

use aegis_core::EventEnvelope;
use aegis_detection::YaraEngine;
use aegis_response::Quarantine;
use anyhow::{Context, Result};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

/// Répertoire des règles YARA, surchargé par `AEGIS_RULES_DIR`.
fn rules_dir() -> String {
    std::env::var("AEGIS_RULES_DIR").unwrap_or_else(|_| "rules".to_string())
}

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
        "aegis-daemon démarré (Lot 2 — capteurs + détection signatures)"
    );

    // Moteur de signatures + store de quarantaine + thread de scan.
    let engine = YaraEngine::from_dir(rules_dir())
        .with_context(|| format!("compilation des règles ({})", rules_dir()))?;
    let quarantine = Quarantine::open(scan::quarantine_dir())
        .context("ouverture du store de quarantaine")?;
    let scan_tx = scan::spawn(engine, quarantine);

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
    pipeline::ingest(event_rx, bus_tx, scan_tx).await;
    Ok(())
}
