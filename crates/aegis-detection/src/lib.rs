//! Moteurs de détection. Consomment des `EventEnvelope`, produisent des
//! `Verdict`. Aucune action n'est appliquée ici (frontière `detection` → jamais
//! `response`). YARA, comportemental et corrélation arriveront au Lot 2/3.

use aegis_core::{EventEnvelope, Verdict};

/// Contrat commun des moteurs de détection.
pub trait DetectionEngine {
    /// Évalue un événement et retourne un verdict éventuel.
    fn evaluate(&self, event: &EventEnvelope) -> Option<Verdict>;
}
