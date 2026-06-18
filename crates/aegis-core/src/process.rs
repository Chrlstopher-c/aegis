//! Contexte process commun, porté par chaque événement.

use serde::{Deserialize, Serialize};

/// Nature de l'application racine à laquelle un process est rattaché. Donne le
/// registre de lecture côté UI (une app de bureau vs un service système).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppKind {
    /// App de bureau lancée via son `.desktop` (scope `app-*`).
    Desktop,
    /// Activité issue d'un émulateur de terminal (dev, shell).
    Terminal,
    /// Service systemd (`*.service`).
    Service,
    /// Process système hors session utilisateur (`system.slice`, conteneur).
    System,
    /// Rattachement indéterminé.
    Unknown,
}

/// Attribution d'un process à l'application « parente » lisible par un humain
/// (Claude Code, Discord, Netflix…), pour rendre le flux compréhensible. Déduite
/// du cgroup et de la chaîne d'ancêtres au moment de l'événement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppAttribution {
    /// Nom lisible de l'application racine.
    pub name: String,
    pub kind: AppKind,
    /// PID du process de tête identifié comme l'application.
    pub root_pid: u32,
}

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
    /// Application racine attribuée (corrélation lisible). `None` si indéterminée.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<AppAttribution>,
}
