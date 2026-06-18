//! File des décisions en attente : menaces de sévérité moyenne laissées passer
//! (non bloquées) que l'utilisateur doit arbitrer dans l'UI — quarantaine, kill,
//! ou autorisation. Persistée pour survivre à un redémarrage ; le kill devient
//! alors best-effort (le pid peut avoir disparu), quarantaine/autorisation restent valides.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use aegis_core::Verdict;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ulid::Ulid;

use crate::quarantine::QuarantineError;

/// Une décision en attente : un verdict notifié, son contexte d'action, non encore arbitré.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDecision {
    pub id: String,
    pub verdict: Verdict,
    /// Chemin de l'exécutable du process incriminé (pour quarantaine/exclusion).
    pub exe_path: String,
    /// Process incriminé (pour kill ; peut ne plus exister après reboot).
    pub pid: u32,
    pub comm: String,
    pub created_at_ns: u64,
}

/// Store des décisions en attente : fichier JSON, chargé en mémoire, persisté à chaque mutation.
pub struct PendingStore {
    path: PathBuf,
    entries: RwLock<Vec<PendingDecision>>,
}

impl PendingStore {
    /// Ouvre (ou crée) le store, en chargeant l'existant.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, QuarantineError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let entries = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        Ok(Self { path, entries: RwLock::new(entries) })
    }

    /// Enregistre une décision en attente. Retourne son identifiant.
    pub fn push(&self, verdict: Verdict, exe_path: String, pid: u32, comm: String) -> Result<PendingDecision, QuarantineError> {
        let entry = PendingDecision {
            id: Ulid::new().to_string(),
            verdict,
            exe_path,
            pid,
            comm,
            created_at_ns: now_ns(),
        };
        {
            let mut guard = self.entries.write().unwrap();
            guard.push(entry.clone());
            self.persist(&guard)?;
        }
        info!(id = %entry.id, "décision en attente enregistrée");
        Ok(entry)
    }

    /// Retire une décision arbitrée (après quarantaine/kill/autorisation).
    pub fn dismiss(&self, id: &str) -> Result<(), QuarantineError> {
        let mut guard = self.entries.write().unwrap();
        let before = guard.len();
        guard.retain(|e| e.id != id);
        if guard.len() == before {
            return Err(QuarantineError::NotFound(id.to_string()));
        }
        self.persist(&guard)?;
        info!(id, "décision en attente arbitrée");
        Ok(())
    }

    /// Liste les décisions en attente.
    pub fn list(&self) -> Vec<PendingDecision> {
        self.entries.read().unwrap().clone()
    }

    fn persist(&self, entries: &[PendingDecision]) -> Result<(), QuarantineError> {
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(entries)?)?;
        if let Err(err) = fs::rename(&tmp, &self.path) {
            warn!(%err, "persistance pending : rename échoué");
            return Err(QuarantineError::from(err));
        }
        Ok(())
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}
