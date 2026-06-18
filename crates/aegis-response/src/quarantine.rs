//! Quarantaine : isole un fichier malveillant hors de portée d'exécution, en
//! conserve les métadonnées d'origine, et permet sa restauration. Le fichier
//! mis en quarantaine perd ses bits d'exécution et est rangé sous un store dédié.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use ulid::Ulid;

/// Erreur d'une opération de quarantaine.
#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    #[error("entrée de quarantaine introuvable : {0}")]
    NotFound(String),
    #[error("E/S quarantaine : {0}")]
    Io(#[from] std::io::Error),
    #[error("métadonnées quarantaine : {0}")]
    Meta(#[from] serde_json::Error),
}

/// Métadonnées d'un fichier mis en quarantaine, persistées à côté du blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub original_mode: u32,
    pub quarantined_at_ns: u64,
    pub reason: String,
}

/// Store de quarantaine : un répertoire contenant `<id>.bin` + `<id>.json`.
pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    /// Ouvre (ou crée) le store de quarantaine au chemin donné.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, QuarantineError> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Déplace `path` en quarantaine. Retourne l'entrée créée.
    pub fn quarantine(&self, path: impl AsRef<Path>, reason: &str) -> Result<QuarantineEntry, QuarantineError> {
        use std::os::unix::fs::PermissionsExt;
        let path = path.as_ref();
        let id = Ulid::new().to_string();
        let mode = fs::metadata(path)?.permissions().mode();

        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.display().to_string(),
            original_mode: mode,
            quarantined_at_ns: now_ns(),
            reason: reason.to_string(),
        };

        let blob = self.dir.join(format!("{id}.bin"));
        move_file(path, &blob)?;
        // Retirer tout bit d'exécution sur le blob isolé.
        fs::set_permissions(&blob, fs::Permissions::from_mode(0o600))?;
        fs::write(self.dir.join(format!("{id}.json")), serde_json::to_vec_pretty(&entry)?)?;

        info!(id = %entry.id, original = %entry.original_path, "fichier mis en quarantaine");
        Ok(entry)
    }

    /// Restaure une entrée à son emplacement d'origine, avec son mode initial.
    pub fn restore(&self, id: &str) -> Result<QuarantineEntry, QuarantineError> {
        use std::os::unix::fs::PermissionsExt;
        let meta_path = self.dir.join(format!("{id}.json"));
        if !meta_path.exists() {
            return Err(QuarantineError::NotFound(id.to_string()));
        }
        let entry: QuarantineEntry = serde_json::from_slice(&fs::read(&meta_path)?)?;
        let blob = self.dir.join(format!("{id}.bin"));

        move_file(&blob, &entry.original_path)?;
        fs::set_permissions(&entry.original_path, fs::Permissions::from_mode(entry.original_mode))?;
        fs::remove_file(&meta_path)?;
        info!(id, original = %entry.original_path, "fichier restauré depuis la quarantaine");
        Ok(entry)
    }

    /// Supprime définitivement une entrée de quarantaine (blob + métadonnées).
    /// Action destructive volontaire : ne porte que sur un fichier déjà isolé,
    /// jamais déclenchée automatiquement (toujours sur demande explicite UI).
    pub fn purge(&self, id: &str) -> Result<(), QuarantineError> {
        let meta_path = self.dir.join(format!("{id}.json"));
        if !meta_path.exists() {
            return Err(QuarantineError::NotFound(id.to_string()));
        }
        let blob = self.dir.join(format!("{id}.bin"));
        let _ = fs::remove_file(&blob);
        fs::remove_file(&meta_path)?;
        info!(id, "entrée de quarantaine supprimée définitivement");
        Ok(())
    }

    /// Liste les entrées actuellement en quarantaine.
    pub fn list(&self) -> Result<Vec<QuarantineEntry>, QuarantineError> {
        let mut entries = Vec::new();
        for dir_entry in fs::read_dir(&self.dir)?.flatten() {
            let path = dir_entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                match fs::read(&path).map_err(QuarantineError::from).and_then(|b| {
                    serde_json::from_slice(&b).map_err(QuarantineError::from)
                }) {
                    Ok(entry) => entries.push(entry),
                    Err(err) => warn!(path = %path.display(), %err, "entrée de quarantaine illisible"),
                }
            }
        }
        Ok(entries)
    }
}

/// Déplace un fichier ; bascule sur copie+suppression si rename cross-device.
fn move_file(from: &Path, to: impl AsRef<Path>) -> Result<(), QuarantineError> {
    let to = to.as_ref();
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(from, to)?;
            fs::remove_file(from)?;
            Ok(())
        }
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
