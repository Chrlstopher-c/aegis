//! Traitement des commandes UI → daemon. L'UI ne fait que demander : le daemon
//! arbitre et applique. Couvre le contrôle du mode de protection, le kill/
//! quarantaine/restauration à la demande. Le scan on-demand est journalisé pour
//! l'instant (câblage au thread de scan en évolution).

use aegis_core::{Command, CommandResult, ModeScope};
use tracing::{info, warn};

use crate::ws_bridge::Control;

/// Exécute une commande et retourne son résultat. Toute commande mutante est
/// journalisée (cf. policy-model.md).
pub fn handle(cmd: Command, ctl: &Control) -> CommandResult {
    match cmd {
        Command::SetMode { scope, mode } => {
            match scope {
                ModeScope::Global => ctl.policy.set_global(mode),
                ModeScope::Category(cat) => ctl.policy.set_category(cat, Some(mode)),
            }
            info!(?scope, ?mode, "mode de protection modifié");
            ok()
        }
        Command::KillProcess { pid } => match aegis_response::kill_process(pid) {
            Ok(()) => ok(),
            Err(err) => err_result(err.to_string()),
        },
        Command::Quarantine { path } => match ctl.quarantine.quarantine(&path, "commande UI") {
            Ok(entry) => ok_with(serde_json::json!({ "id": entry.id })),
            Err(err) => err_result(err.to_string()),
        },
        Command::Restore { quarantine_id } => match ctl.quarantine.restore(&quarantine_id) {
            Ok(_) => ok(),
            Err(err) => err_result(err.to_string()),
        },
        Command::ListQuarantine => match ctl.quarantine.list() {
            Ok(entries) => to_data(&entries),
            Err(err) => err_result(err.to_string()),
        },
        Command::PurgeQuarantine { quarantine_id } => match ctl.quarantine.purge(&quarantine_id) {
            Ok(()) => ok(),
            Err(err) => err_result(err.to_string()),
        },
        Command::AddExclusion { kind, value, reason } => match ctl.exclusions.add(kind, value, reason) {
            Ok(entry) => ok_with(serde_json::json!({ "id": entry.id })),
            Err(err) => err_result(err.to_string()),
        },
        Command::RemoveExclusion { id } => match ctl.exclusions.remove(&id) {
            Ok(()) => ok(),
            Err(err) => err_result(err.to_string()),
        },
        Command::ListExclusions => to_data(&ctl.exclusions.list()),
        Command::ListPending => to_data(&ctl.pending.list()),
        Command::DismissPending { pending_id } => match ctl.pending.dismiss(&pending_id) {
            Ok(()) => ok(),
            Err(err) => err_result(err.to_string()),
        },
        other => {
            warn!(?other, "commande non encore implémentée");
            err_result("commande non implémentée".into())
        }
    }
}

/// Sérialise une valeur en `data` JSON, ou retourne une erreur de sérialisation.
fn to_data<T: serde::Serialize>(value: &T) -> CommandResult {
    match serde_json::to_value(value) {
        Ok(data) => ok_with(data),
        Err(err) => err_result(err.to_string()),
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
