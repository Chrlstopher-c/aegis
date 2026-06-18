//! Verdicts : detection → daemon → UI. Le moteur juge, il n'agit pas.

use serde::{Deserialize, Serialize};

/// Moteur ayant produit le verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Engine {
    Yara,
    Behavioral,
    Ransomware,
    Heuristic,
    Fim,
}

/// Niveau de sévérité, ordonné (Info < … < Critical).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Catégorie de menace, alignée sur les tactiques MITRE ATT&CK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// TA0002
    Execution,
    /// TA0003
    Persistence,
    /// TA0004
    PrivilegeEscalation,
    /// TA0005
    DefenseEvasion,
    /// TA0006
    CredentialAccess,
    /// TA0011
    CommandAndControl,
    /// TA0040 — anti-ransomware
    Impact,
    /// Signatures (transverse)
    Signature,
}

/// Action recommandée par le moteur (le daemon décide de l'appliquer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Log,
    Notify,
    Quarantine { path: String },
    Isolate { pid: u32 },
    Kill { pid: u32 },
}

/// Verdict émis sur un événement déclencheur.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub schema_version: u16,
    /// Événement à l'origine du verdict.
    pub event_id: u128,
    pub engine: Engine,
    pub severity: Severity,
    pub category: ThreatCategory,
    /// Techniques MITRE, ex. `["T1059.004", "T1486"]`.
    pub mitre: Vec<String>,
    /// Confiance dans le verdict, 0.0–1.0.
    pub confidence: f32,
    pub title: String,
    pub detail: String,
    pub recommended_action: Action,
}
