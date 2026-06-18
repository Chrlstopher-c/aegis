//! Contrat IPC d'Aegis — source de vérité unique des messages échangés.
//!
//! Trois familles : événements (kernel → daemon), verdicts (detection → daemon
//! → UI), commandes (UI → daemon). Sérialisation interne bincode, JSON sur le
//! bridge WebSocket. Aucune logique métier ici : uniquement des types.

mod command;
mod events;
mod process;
mod verdict;

pub use command::{Command, CommandResult, ExclusionKind, ModeScope, ProtectionMode};
pub use events::{EventEnvelope, EventPayload, EventSource, ExecEvent, FileEvent, FileOp, MmapBacking, MmapEvent, NetEvent, NetProto, PrivEvent};
pub use process::ProcessCtx;
pub use verdict::{Action, Engine, Severity, ThreatCategory, Verdict};

/// Version du schéma IPC. Incrémentée à tout changement incompatible.
/// Un client de version différente est rejeté proprement par le daemon.
pub const SCHEMA_VERSION: u16 = 1;
