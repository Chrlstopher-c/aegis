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

/// Préfixes de répertoires inscriptibles d'où une exécution est suspecte.
const WRITABLE_EXEC_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"];

/// Motifs de reverse shell recherchés dans la ligne de commande.
const REVERSE_SHELL_PATTERNS: &[&str] =
    &["/dev/tcp/", "/dev/udp/", "bash -i", "sh -i", "nc -e", "ncat -e", "mkfifo"];

/// Heuristiques sur les exécutions (catégorie Execution / C2 du catalogue).
/// S'appuient sur le flux exec fanotify + `cmdline` issu de `/proc`, sans eBPF.
pub struct ExecHeuristics;

impl ExecHeuristics {
    /// Évalue une exécution. Reverse shell (cmdline) prime sur l'origine du binaire.
    pub fn evaluate(event: &EventEnvelope) -> Option<Verdict> {
        let EventPayload::File(file) = &event.payload else { return None };
        if !matches!(file.op, FileOp::OpenExec) {
            return None;
        }
        if let Some(pattern) = matched_reverse_shell(&event.process.cmdline) {
            return Some(reverse_shell_verdict(event, pattern));
        }
        if is_writable_exec(&file.path) {
            return Some(writable_exec_verdict(event, &file.path));
        }
        None
    }
}

fn matched_reverse_shell(cmdline: &str) -> Option<&'static str> {
    REVERSE_SHELL_PATTERNS.iter().copied().find(|p| cmdline.contains(p))
}

fn is_writable_exec(path: &str) -> bool {
    WRITABLE_EXEC_DIRS.iter().any(|d| path.starts_with(d))
}

fn reverse_shell_verdict(event: &EventEnvelope, pattern: &str) -> Verdict {
    Verdict {
        schema_version: SCHEMA_VERSION,
        event_id: event.event_id,
        engine: Engine::Behavioral,
        severity: Severity::Critical,
        category: ThreatCategory::CommandAndControl,
        mitre: vec!["T1059.004".to_string()],
        confidence: 0.9,
        title: format!("Reverse shell probable ({})", event.process.comm),
        detail: format!("Motif « {pattern} » dans la commande : {}", event.process.cmdline),
        recommended_action: Action::Kill { pid: event.process.pid },
    }
}

fn writable_exec_verdict(event: &EventEnvelope, path: &str) -> Verdict {
    Verdict {
        schema_version: SCHEMA_VERSION,
        event_id: event.event_id,
        engine: Engine::Behavioral,
        severity: Severity::High,
        category: ThreatCategory::Execution,
        mitre: vec!["T1059".to_string()],
        confidence: 0.7,
        title: format!("Exécution depuis une zone inscriptible ({})", event.process.comm),
        detail: format!("Binaire exécuté depuis {path}"),
        recommended_action: Action::Notify,
    }
}

/// Process système légitimement amenés à lire les fichiers d'authentification.
const CRED_READ_ALLOWLIST: &[&str] = &["sshd", "sudo", "su", "login", "passwd", "unix_chkpwd", "systemd"];

/// FIM credential access : lecture d'un fichier sensible surveillé. La sonde ne
/// marque QUE les fichiers sensibles en lecture, donc tout `Read` est un accès
/// credential ; on écarte les lecteurs système légitimes (sshd, sudo…).
pub struct CredentialWatch;

impl CredentialWatch {
    pub fn evaluate(event: &EventEnvelope) -> Option<Verdict> {
        let EventPayload::File(file) = &event.payload else { return None };
        if !matches!(file.op, FileOp::Read) {
            return None;
        }
        if CRED_READ_ALLOWLIST.contains(&event.process.comm.as_str()) {
            return None;
        }
        Some(Verdict {
            schema_version: SCHEMA_VERSION,
            event_id: event.event_id,
            engine: Engine::Fim,
            severity: Severity::High,
            category: ThreatCategory::CredentialAccess,
            mitre: vec!["T1003".to_string()],
            confidence: 0.85,
            title: format!("Lecture de credentials par {}", event.process.comm),
            detail: format!("Accès en lecture au fichier sensible {}", file.path),
            recommended_action: Action::Notify,
        })
    }
}
