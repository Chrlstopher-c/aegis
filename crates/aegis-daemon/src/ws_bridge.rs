//! Bridge WebSocket localhost : réexpose le flux temps réel (événements +
//! verdicts) en JSON et reçoit les commandes de contrôle UI → daemon. Liaison
//! sur `127.0.0.1` uniquement, aucun port exposé au réseau (invariant
//! souveraineté/sécurité). L'UI demande, le daemon arbitre et applique.

use std::sync::Arc;

use aegis_core::{Command, StreamMessage};
use aegis_response::Quarantine;
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::policy::PolicyEngine;

/// Adresse d'écoute du bridge, surchargée par `AEGIS_WS_ADDR`. Localhost only.
fn ws_addr() -> String {
    std::env::var("AEGIS_WS_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string())
}

/// Contexte de contrôle partagé avec les clients (commandes UI → daemon).
#[derive(Clone)]
pub struct Control {
    pub policy: Arc<PolicyEngine>,
    pub quarantine: Arc<Quarantine>,
}

/// Lance le bridge WebSocket et sert chaque client (flux sortant + commandes).
pub async fn serve(bus: broadcast::Sender<StreamMessage>, control: Control) -> Result<()> {
    let addr = ws_addr();
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind WebSocket {addr}"))?;
    info!(addr = %addr, "bridge WebSocket prêt");

    loop {
        let (stream, peer) = listener.accept().await.context("accept WebSocket")?;
        let rx = bus.subscribe();
        let control = control.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_client(stream, rx, control).await {
                debug!(%peer, %err, "client WebSocket déconnecté");
            }
        });
    }
}

async fn serve_client(
    stream: TcpStream,
    mut rx: broadcast::Receiver<StreamMessage>,
    control: Control,
) -> Result<()> {
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .context("handshake WebSocket")?;
    let (mut sink, mut source) = ws.split();

    loop {
        tokio::select! {
            // Flux sortant : événements + verdicts → client.
            msg = rx.recv() => match msg {
                Ok(msg) => sink.send(Message::Text(serde_json::to_string(&msg)?)).await?,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(skipped = n, "client WebSocket lent, messages sautés");
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
            // Flux entrant : commandes de contrôle ← client.
            incoming = source.next() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    let result = dispatch_command(&text, &control);
                    sink.send(Message::Text(serde_json::to_string(&result)?)).await?;
                }
                Some(Ok(Message::Close(_))) | None => return Ok(()),
                Some(Ok(_)) => {} // ping/pong/binaire ignorés
                Some(Err(err)) => return Err(err.into()),
            },
        }
    }
}

fn dispatch_command(text: &str, control: &Control) -> aegis_core::CommandResult {
    match serde_json::from_str::<Command>(text) {
        Ok(cmd) => crate::command::handle(cmd, &control.policy, &control.quarantine),
        Err(err) => aegis_core::CommandResult {
            ok: false,
            error: Some(format!("commande illisible : {err}")),
            data: None,
        },
    }
}
