//! Traitement des commandes UI → daemon. L'UI ne fait que demander : le daemon
//! arbitre et applique. Couvre le contrôle du mode de protection, le kill/
//! quarantaine/restauration à la demande. Le scan on-demand est journalisé pour
//! l'instant (câblage au thread de scan en évolution).

use std::sync::Arc;

use aegis_core::{Command, CommandResult, ModeScope};
use aegis_response::Quarantine;
use tracing::{info, warn};

use crate::policy::PolicyEngine;

/// Exécute une commande et retourne son résultat. Toute commande mutante est
/// journalisée (cf. policy-model.md).
pub fn handle(cmd: Command, policy: &Arc<PolicyEngine>, quarantine: &Arc<Quarantine>) -> CommandResult {
    match cmd {
        Command::SetMode { scope, mode } => {
            match scope {
                ModeScope::Global => policy.set_global(mode),
                ModeScope::Category(cat) => policy.set_category(cat, Some(mode)),
            }
            info!(?scope, ?mode, "mode de protection modifié");
            ok()
        }
        Command::KillProcess { pid } => match aegis_response::kill_process(pid) {
            Ok(()) => ok(),
            Err(err) => err_result(err.to_string()),
        },
        Command::Quarantine { path } => match quarantine.quarantine(&path, "commande UI") {
            Ok(entry) => ok_with(serde_json::json!({ "id": entry.id })),
            Err(err) => err_result(err.to_string()),
        },
        Command::Restore { quarantine_id } => match quarantine.restore(&quarantine_id) {
            Ok(_) => ok(),
            Err(err) => err_result(err.to_string()),
        },
        Command::ListQuarantine => match quarantine.list() {
            Ok(entries) => match serde_json::to_value(&entries) {
                Ok(data) => ok_with(data),
                Err(err) => err_result(err.to_string()),
            },
            Err(err) => err_result(err.to_string()),
        },
        Command::PurgeQuarantine { quarantine_id } => match quarantine.purge(&quarantine_id) {
            Ok(()) => ok(),
            Err(err) => err_result(err.to_string()),
        },
        other => {
            warn!(?other, "commande non encore implémentée");
            err_result("commande non implémentée".into())
        }
    }
}

fn ok() -> CommandResult {
    CommandResult { ok: true, error: None, data: None }
}

fn ok_with(data: serde_json::Value) -> CommandResult {
    CommandResult { ok: true, error: None, data: Some(data) }
}

fn err_result(error: String) -> CommandResult {
    CommandResult { ok: false, error: Some(error), data: None }
}
