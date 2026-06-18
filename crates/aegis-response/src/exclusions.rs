//! Allowlist persistante : ce que l'utilisateur a explicitement autorisé. Une
//! entrée correspondante court-circuite toute détection en amont (le process
//! n'est même pas jugé). Sert le cas « c'est mon application, ne la bloque
//! jamais » — faux positif comme vrai positif assumé.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use aegis_core::{ExclusionKind, ProcessCtx};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ulid::Ulid;

use crate::quarantine::QuarantineError;

/// Une exclusion : un critère (chemin, hash, process) que l'utilisateur autorise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionEntry {
    pub id: String,
    pub kind: ExclusionKind,
    pub value: String,
    pub reason: String,
    pub created_at_ns: u64,
}

impl ExclusionEntry {
    /// Vrai si ce process correspond à l'exclusion. Le hash est ignoré ici
    /// (calculé au scan, non disponible au niveau process) — géré côté scanner.
    fn matches(&self, ctx: &ProcessCtx) -> bool {
        match self.kind {
            ExclusionKind::Path => self.value == ctx.exe_path,
            ExclusionKind::Process => self.value == ctx.comm,
            ExclusionKind::Hash => false,
        }
    }
}

/// Store d'exclusions : un fichier JSON unique, chargé en mémoire et persisté à
/// chaque mutation. Lecture concurrente fréquente (chaque événement), écriture rare.
pub struct ExclusionStore {
    path: PathBuf,
    entries: RwLock<Vec<ExclusionEntry>>,
}

impl ExclusionStore {
    /// Ouvre (ou crée) le store au chemin donné, en chargeant l'existant.
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

    /// Vrai si un process est couvert par une exclusion (→ aucune détection).
    pub fn is_excluded(&self, ctx: &ProcessCtx) -> bool {
        self.entries.read().unwrap().iter().any(|e| e.matches(ctx))
    }

    /// Ajoute une exclusion et persiste. Retourne l'entrée créée.
    pub fn add(&self, kind: ExclusionKind, value: String, reason: String) -> Result<ExclusionEntry, QuarantineError> {
        let entry = ExclusionEntry {
            id: Ulid::new().to_string(),
            kind,
            value,
            reason,
            created_at_ns: now_ns(),
        };
        {
            let mut guard = self.entries.write().unwrap();
            guard.push(entry.clone());
            self.persist(&guard)?;
        }
        info!(id = %entry.id, kind = ?entry.kind, value = %entry.value, "exclusion ajoutée");
        Ok(entry)
    }

    /// Retire une exclusion par identifiant et persiste.
    pub fn remove(&self, id: &str) -> Result<(), QuarantineError> {
        let mut guard = self.entries.write().unwrap();
        let before = guard.len();
        guard.retain(|e| e.id != id);
        if guard.len() == before {
            return Err(QuarantineError::NotFound(id.to_string()));
        }
        self.persist(&guard)?;
        info!(id, "exclusion retirée");
        Ok(())
    }

    /// Liste les exclusions actuelles.
    pub fn list(&self) -> Vec<ExclusionEntry> {
        self.entries.read().unwrap().clone()
    }

    fn persist(&self, entries: &[ExclusionEntry]) -> Result<(), QuarantineError> {
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(entries)?)?;
        if let Err(err) = fs::rename(&tmp, &self.path) {
            warn!(%err, "persistance exclusions : rename échoué");
            return Err(QuarantineError::from(err));
        }
        Ok(())
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}
