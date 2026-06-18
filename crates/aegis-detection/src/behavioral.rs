//! Détection comportementale. Première brique (Lot 3) : surveillance des canaris.
//! Toute écriture sur un fichier leurre est, par construction, illégitime —
//! signal quasi-certain d'un ransomware en cours de chiffrement de masse. Le
//! verdict est `Critical` et recommande la neutralisation immédiate du process.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use aegis_core::{
    Action, Engine, EventEnvelope, EventPayload, FileOp, Severity, ThreatCategory, Verdict,
    SCHEMA_VERSION,
};

/// Surveillance des canaris : connaît l'ensemble des chemins leurres déployés.
pub struct CanaryWatch {
    canaries: HashSet<PathBuf>,
}

impl CanaryWatch {
    /// Construit la surveillance à partir des chemins de canaris déployés.
    pub fn new(canaries: impl IntoIterator<Item = PathBuf>) -> Self {
        Self { canaries: canaries.into_iter().collect() }
    }

    /// Évalue un événement. Retourne un verdict si une écriture frappe un canari.
    pub fn evaluate(&self, event: &EventEnvelope) -> Option<Verdict> {
        let EventPayload::File(file) = &event.payload else { return None };
        if !matches!(file.op, FileOp::Write) {
            return None;
        }
        if !self.is_canary(&file.path) {
            return None;
        }
        Some(self.ransomware_verdict(event, &file.path))
    }

    fn is_canary(&self, path: &str) -> bool {
        self.canaries.contains(Path::new(path))
    }

    fn ransomware_verdict(&self, event: &EventEnvelope, canary: &str) -> Verdict {
        let pid = event.process.pid;
        Verdict {
            schema_version: SCHEMA_VERSION,
            event_id: event.event_id,
            engine: Engine::Ransomware,
            severity: Severity::Critical,
            category: ThreatCategory::Impact,
            mitre: vec!["T1486".to_string()],
            confidence: 0.99,
            title: format!("Canari modifié par {} (pid {pid})", event.process.comm),
            detail: format!(
                "Écriture sur le fichier leurre {canary} — chiffrement de masse probable, \
                 neutralisation immédiate."
            ),
            recommended_action: Action::Kill { pid },
        }
    }
}
