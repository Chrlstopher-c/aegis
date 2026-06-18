//! Message du flux temps réel daemon → UI. Le daemon pousse en continu
//! événements (filtrés) et verdicts sur le même canal ; `StreamMessage` est
//! l'enveloppe qui les distingue côté client.

use serde::{Deserialize, Serialize};

use crate::events::EventEnvelope;
use crate::verdict::Verdict;

/// Élément du flux poussé vers l'UI. Sérialisé en JSON sur le bridge WebSocket
/// (champ `type` discriminant : `"event"` ou `"verdict"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StreamMessage {
    Event(EventEnvelope),
    Verdict(Verdict),
}
