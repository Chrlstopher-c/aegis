//! Application des actions décidées par le daemon (quarantaine, kill, isolation,
//! restauration). Ne détecte rien : reçoit une `Action` et l'exécute. Implémenté
//! au Lot 2 (quarantaine) puis Lot 3/5 (kill, isolation graduée).

use aegis_core::Action;

/// Erreur lors de l'application d'une action de réponse.
#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
    #[error("action non encore implémentée : {0:?}")]
    NotImplemented(Action),
}

/// Applique une action de réponse. Stub : sera câblé au Lot 2.
pub fn apply(action: Action) -> Result<(), ResponseError> {
    Err(ResponseError::NotImplemented(action))
}
