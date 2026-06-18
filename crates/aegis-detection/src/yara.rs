//! Moteur de signatures yara-x. Compile les règles `.yar` une fois, scanne
//! fichiers et mémoire à la demande, et traduit chaque match en `Verdict`
//! enrichi par les métadonnées de la règle (severity, category, mitre).

use std::fs;
use std::path::Path;

use aegis_core::{Action, Engine, Severity, ThreatCategory, Verdict, SCHEMA_VERSION};
use tracing::{info, warn};
use yara_x::{Compiler, MetaValue, Rule, Rules, Scanner};

/// Erreur du moteur YARA.
#[derive(Debug, thiserror::Error)]
pub enum YaraError {
    #[error("lecture des règles {path} : {source}")]
    ReadRules { path: String, source: std::io::Error },
    #[error("compilation des règles : {0}")]
    Compile(String),
    #[error("scan : {0}")]
    Scan(String),
}

/// Moteur YARA prêt à scanner. Les `Rules` compilées sont partageables entre
/// plusieurs scans séquentiels (un `Scanner` est créé par appel).
pub struct YaraEngine {
    rules: Rules,
}

impl YaraEngine {
    /// Compile tous les fichiers `.yar` d'un répertoire (récursif simple).
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, YaraError> {
        let mut compiler = Compiler::new();
        let mut count = 0usize;
        for path in collect_yar_files(dir.as_ref())? {
            let src = fs::read_to_string(&path).map_err(|source| YaraError::ReadRules {
                path: path.display().to_string(),
                source,
            })?;
            compiler
                .add_source(src.as_str())
                .map_err(|e| YaraError::Compile(format!("{}: {e}", path.display())))?;
            count += 1;
        }
        info!(files = count, "règles YARA compilées");
        Ok(Self { rules: compiler.build() })
    }

    /// Scanne un fichier ; retourne un verdict par règle qui matche.
    pub fn scan_file(&self, path: impl AsRef<Path>, event_id: u128) -> Result<Vec<Verdict>, YaraError> {
        let path = path.as_ref();
        let mut scanner = Scanner::new(&self.rules);
        let results = scanner
            .scan_file(path)
            .map_err(|e| YaraError::Scan(e.to_string()))?;
        Ok(results
            .matching_rules()
            .map(|rule| verdict_from_rule(&rule, event_id, Some(path.display().to_string())))
            .collect())
    }

    /// Scanne un buffer mémoire (ex. région `/proc/<pid>/mem`).
    pub fn scan_bytes(&self, data: &[u8], event_id: u128) -> Result<Vec<Verdict>, YaraError> {
        let mut scanner = Scanner::new(&self.rules);
        let results = scanner.scan(data).map_err(|e| YaraError::Scan(e.to_string()))?;
        Ok(results
            .matching_rules()
            .map(|rule| verdict_from_rule(&rule, event_id, None))
            .collect())
    }
}

fn collect_yar_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, YaraError> {
    let mut files = Vec::new();
    let entries = fs::read_dir(dir).map_err(|source| YaraError::ReadRules {
        path: dir.display().to_string(),
        source,
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_yar_files(&path)?);
        } else if path.extension().is_some_and(|e| e == "yar" || e == "yara") {
            files.push(path);
        }
    }
    Ok(files)
}

/// Construit un `Verdict` à partir d'une règle qui a matché et de ses métadonnées.
fn verdict_from_rule(rule: &Rule, event_id: u128, quarantine_path: Option<String>) -> Verdict {
    let mut severity = Severity::Medium;
    let mut category = ThreatCategory::Signature;
    let mut mitre = Vec::new();
    let mut description = String::new();

    for (key, value) in rule.metadata() {
        let MetaValue::String(s) = value else { continue };
        match key {
            "severity" => severity = parse_severity(s),
            "category" => category = parse_category(s),
            "mitre" => mitre = s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
            "description" => description = s.to_string(),
            _ => {}
        }
    }

    let recommended_action = match quarantine_path {
        Some(path) => Action::Quarantine { path },
        None => Action::Notify,
    };

    Verdict {
        schema_version: SCHEMA_VERSION,
        event_id,
        engine: Engine::Yara,
        severity,
        category,
        mitre,
        confidence: 1.0, // signature exacte
        title: format!("Signature YARA : {}", rule.identifier()),
        detail: if description.is_empty() {
            rule.identifier().to_string()
        } else {
            description
        },
        recommended_action,
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "Info" => Severity::Info,
        "Low" => Severity::Low,
        "Medium" => Severity::Medium,
        "High" => Severity::High,
        "Critical" => Severity::Critical,
        other => {
            warn!(value = other, "severity inconnue dans une règle YARA, défaut Medium");
            Severity::Medium
        }
    }
}

fn parse_category(s: &str) -> ThreatCategory {
    match s {
        "Execution" => ThreatCategory::Execution,
        "Persistence" => ThreatCategory::Persistence,
        "PrivilegeEscalation" => ThreatCategory::PrivilegeEscalation,
        "DefenseEvasion" => ThreatCategory::DefenseEvasion,
        "CredentialAccess" => ThreatCategory::CredentialAccess,
        "CommandAndControl" => ThreatCategory::CommandAndControl,
        "Impact" => ThreatCategory::Impact,
        _ => ThreatCategory::Signature,
    }
}
