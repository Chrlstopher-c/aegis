//! Application des actions décidées par le daemon. Ne détecte rien : reçoit une
//! `Action` (ou une commande directe) et l'exécute. Lot 2 : quarantaine +
//! restauration. Kill/isolation graduée au Lot 3/5.

mod quarantine;

pub use quarantine::{Quarantine, QuarantineEntry, QuarantineError};
