//! Contexte process commun, porté par chaque événement.

use serde::{Deserialize, Serialize};

/// Contexte d'un process au moment d'un événement. `container_id` est `None`
/// quand le process tourne sur l'hôte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCtx {
    pub pid: u32,
    pub ppid: u32,
    pub tgid: u32,
    pub exe_path: String,
    pub comm: String,
    pub cmdline: String,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    /// Bitmask des capabilities effectives.
    pub caps_effective: u64,
    pub cgroup_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
}
