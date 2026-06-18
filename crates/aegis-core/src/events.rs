//! Événements kernel → daemon. Enveloppe commune + payloads typés par source.

use serde::{Deserialize, Serialize};

use crate::process::ProcessCtx;

/// Origine kernel d'un événement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    ExecveProbe,
    Fanotify,
    MmapLsm,
    PrivLsm,
    NetConnect,
}

/// Enveloppe commune à tout événement remonté au daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub schema_version: u16,
    /// Identifiant unique (ULID encodé en u128).
    pub event_id: u128,
    /// Horodatage monotone, nanosecondes depuis l'epoch.
    pub ts: u64,
    pub source: EventSource,
    pub process: ProcessCtx,
    pub payload: EventPayload,
}

/// Charge utile spécifique à la source de l'événement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EventPayload {
    Exec(ExecEvent),
    File(FileEvent),
    Mmap(MmapEvent),
    Priv(PrivEvent),
    Net(NetEvent),
}

/// Exécution d'un binaire (eBPF `bprm_check`/`execve`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_inline: Option<String>,
    /// Le binaire provient d'un répertoire inscriptible (`/tmp`, world-writable…).
    pub from_writable_dir: bool,
}

/// Opération fichier observée par fanotify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOp {
    OpenExec,
    Read,
    Write,
    Rename,
    Create,
    Unlink,
}

/// Accès fichier (fanotify). `blocking: true` ⇒ le kernel attend un verdict
/// (`response_token`) avant le timeout, sous peine de blocage système.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: String,
    pub op: FileOp,
    pub blocking: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_token: Option<u64>,
}

/// Origine d'un mapping mémoire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmapBacking {
    Anon,
    File,
}

/// Mapping mémoire (eBPF `security_mmap_file`). `prot_wx: true` ⇒ W+X (fileless).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmapEvent {
    pub prot_wx: bool,
    pub backing: MmapBacking,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Changement de privilèges (eBPF `security_capset`/setuid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivEvent {
    pub from_uid: u32,
    pub to_uid: u32,
    /// Capabilities ajoutées (bitmask).
    pub caps_delta: u64,
}

/// Protocole de transport d'une connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetProto {
    Tcp,
    Udp,
}

/// Connexion sortante (eBPF `security_socket_connect`). `resolved: false` ⇒
/// pas de résolution DNS préalable (IP en dur, signal C2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEvent {
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: NetProto,
    pub resolved: bool,
}
