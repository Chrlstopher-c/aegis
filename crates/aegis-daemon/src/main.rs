//! Point d'entrée du daemon Aegis. Assemble le pipeline temps réel :
//! capteurs (aegis-probes) → ingestion → détection/réponse, avec diffusion du
//! flux (événements + verdicts) aux clients via un socket Unix et un bridge
//! WebSocket localhost (consommé par l'UI).

mod command;
mod demo;
mod enforce;
mod ipc_socket;
mod pipeline;
mod policy;
mod scan;
mod ws_bridge;
mod zones;

use std::sync::Arc;

use aegis_core::{EventEnvelope, StreamMessage};
use aegis_detection::{CanaryWatch, YaraEngine};
use aegis_response::Quarantine;
use anyhow::{Context, Result};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

use crate::enforce::Enforcer;
use crate::policy::PolicyEngine;

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
        "aegis-daemon démarré (Lot 4 — capteurs + détection + bridge UI)"
    );

    // Bus de diffusion (événements + verdicts) vers les clients (socket + WS).
    let (bus_tx, _) = broadcast::channel::<StreamMessage>(1024);

    // Policy engine (réponse graduée) + store de quarantaine + enforcer partagé.
    let policy = Arc::new(PolicyEngine::with_defaults());
    let quarantine = Arc::new(
        Quarantine::open(scan::quarantine_dir()).context("ouverture du store de quarantaine")?,
    );
    let enforcer = Enforcer::new(policy.clone(), quarantine.clone(), bus_tx.clone());

    // Moteur de signatures + thread de scan (délègue ses verdicts à l'enforcer).
    let engine = YaraEngine::from_dir(rules_dir())
        .with_context(|| format!("compilation des règles ({})", rules_dir()))?;
    let scan_tx = scan::spawn(engine, enforcer.clone());

    // Anti-ransomware : déploiement des canaris + surveillance.
    let canaries = aegis_probes::deploy_canaries(&aegis_probes::default_canary_zones());
    let canary_watch = CanaryWatch::new(canaries.clone());

    // Capteurs → ingestion (mpsc). Si fanotify échoue (pas de CAP_SYS_ADMIN), on
    // démarre en mode dégradé : pas de capteurs, mais l'UI et le bridge restent
    // servis. Le daemon ne doit jamais mourir parce qu'un capteur manque.
    let sensitive = aegis_probes::default_sensitive_files();
    let (event_tx, event_rx) = mpsc::unbounded_channel::<EventEnvelope>();
    if let Err(err) = aegis_probes::spawn_fanotify(event_tx, &canaries, &sensitive) {
        error!(%err, "capteurs fanotify indisponibles — mode dégradé (sans détection temps réel)");
    }

    // Diffusion : socket Unix + bridge WebSocket localhost.
    let socket_bus = bus_tx.clone();
    tokio::spawn(async move {
        if let Err(err) = ipc_socket::serve(socket_bus).await {
            error!(%err, "serveur socket Unix arrêté");
        }
    });
    let ws_bus = bus_tx.clone();
    let control = ws_bridge::Control { policy: policy.clone(), quarantine: quarantine.clone() };
    tokio::spawn(async move {
        if let Err(err) = ws_bridge::serve(ws_bus, control).await {
            error!(%err, "bridge WebSocket arrêté");
        }
    });

    // Mode démo : flux synthétique pour valider l'UI sans privilèges.
    if std::env::args().any(|a| a == "--demo") {
        info!("mode démo actif — flux synthétique injecté");
        let demo_bus = bus_tx.clone();
        tokio::spawn(demo::run(demo_bus));
    }

    // Ingestion en tâche ; le daemon vit jusqu'à un signal d'arrêt (et survit au
    // mode dégradé où l'ingestion se termine faute de capteurs).
    tokio::spawn(pipeline::ingest(event_rx, bus_tx, scan_tx, canary_watch, enforcer));

    tokio::signal::ctrl_c().await.ok();
    info!("signal d'arrêt reçu, arrêt du daemon");
    Ok(())
}
