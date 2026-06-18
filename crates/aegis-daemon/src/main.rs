//! Point d'entrée du daemon Aegis. Assemble le pipeline temps réel :
//! capteurs → corrélation → détection → policy → réponse + bridge UI.
//! Lot 0 : amorce du runtime tokio et du logging. Le pipeline est câblé au Lot 1.

use anyhow::Result;
use tracing::info;

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
        "aegis-daemon démarré (Lot 0 — pipeline non câblé)"
    );
    Ok(())
}
