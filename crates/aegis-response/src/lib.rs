//! Application des actions décidées par le daemon. Ne détecte rien : reçoit une
//! `Action` (ou une commande directe) et l'exécute. Lot 2 : quarantaine +
//! restauration. Kill/isolation graduée au Lot 3/5.

mod exclusions;
mod kill;
mod pending;
mod quarantine;

pub use exclusions::{ExclusionEntry, ExclusionStore};
pub use kill::{isolate_process, kill_process, KillError};
pub use pending::{PendingDecision, PendingStore};
pub use quarantine::{Quarantine, QuarantineEntry, QuarantineError};
