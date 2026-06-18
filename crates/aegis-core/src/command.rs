//! Commandes : UI → daemon. L'UI demande, le daemon décide et applique.

use serde::{Deserialize, Serialize};

use crate::verdict::ThreatCategory;

/// Cible d'un changement de mode de protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModeScope {
    Global,
    Category(ThreatCategory),
}

/// Mode de protection : observer ou bloquer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionMode {
    Detection,
    Prevention,
}

/// Critère d'une exclusion (allowlist).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExclusionKind {
    Path,
    Hash,
    Process,
}

/// Commande émise par l'UI vers le daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    SetMode { scope: ModeScope, mode: ProtectionMode },
    ScanOnDemand { path: String, recursive: bool },
    ScanMemory { pid: u32 },
    Quarantine { path: String },
    Restore { quarantine_id: String },
    KillProcess { pid: u32 },
    AddExclusion { kind: ExclusionKind, value: String, reason: String },
    RemoveExclusion { id: String },
    /// Feedback faux positif → exclusion suggérée.
    AckVerdict { event_id: u128 },
}

/// Réponse du daemon à une commande. `data` porte un JSON libre selon la commande.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}
