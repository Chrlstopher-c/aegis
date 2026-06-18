//! Bridge WebSocket localhost : réexpose le flux temps réel (événements +
//! verdicts) en JSON aux clients UI. Lecture seule pour le Lot 4 (le contrôle
//! UI→daemon via `Command` viendra au Lot 5). Liaison sur `127.0.0.1` uniquement,
//! aucun port exposé au réseau (invariant souveraineté/sécurité).

use aegis_core::StreamMessage;
use anyhow::{Context, Result};
use futures_util::SinkExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

/// Adresse d'écoute du bridge, surchargée par `AEGIS_WS_ADDR`. Localhost only.
fn ws_addr() -> String {
    std::env::var("AEGIS_WS_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_string())
}

/// Lance le bridge WebSocket et sert chaque client connecté (flux JSON).
pub async fn serve(bus: broadcast::Sender<StreamMessage>) -> Result<()> {
    let addr = ws_addr();
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind WebSocket {addr}"))?;
    info!(addr = %addr, "bridge WebSocket prêt");

    loop {
        let (stream, peer) = listener.accept().await.context("accept WebSocket")?;
        let rx = bus.subscribe();
        tokio::spawn(async move {
            if let Err(err) = serve_client(stream, rx).await {
                debug!(%peer, %err, "client WebSocket déconnecté");
            }
        });
    }
}

async fn serve_client(
    stream: TcpStream,
    mut rx: broadcast::Receiver<StreamMessage>,
) -> Result<()> {
    let mut ws = tokio_tungstenite::accept_async(stream)
        .await
        .context("handshake WebSocket")?;
    loop {
        match rx.recv().await {
            Ok(msg) => {
                let json = serde_json::to_string(&msg)?;
                ws.send(Message::Text(json)).await?;
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "client WebSocket lent, messages sautés");
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}
