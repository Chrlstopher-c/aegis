//! Neutralisation d'un process par signal. Réponse la plus directe à une menace
//! active (ransomware en cours, reverse shell). `SIGKILL` est non interceptable :
//! le process ne peut ni l'ignorer ni le différer, ce qui stoppe la propagation.

use nix::sys::signal::{kill as nix_kill, Signal};
use nix::unistd::Pid;
use tracing::{info, warn};

/// Erreur de neutralisation.
#[derive(Debug, thiserror::Error)]
pub enum KillError {
    #[error("pid invalide : {0}")]
    InvalidPid(u32),
    #[error("envoi du signal au pid {pid} : {source}")]
    Signal { pid: u32, source: nix::Error },
}

/// Tue immédiatement un process (`SIGKILL`). Idempotent : un process déjà mort
/// (`ESRCH`) est traité comme un succès.
pub fn kill_process(pid: u32) -> Result<(), KillError> {
    send(pid, Signal::SIGKILL, "neutralisé (SIGKILL)")
}

/// Gèle un process (`SIGSTOP`) pour investigation, sans le tuer. Isolation légère
/// — le gel cgroup-freezer + coupure des sockets viendra (cf. policy-model.md).
pub fn isolate_process(pid: u32) -> Result<(), KillError> {
    send(pid, Signal::SIGSTOP, "isolé (SIGSTOP, gelé)")
}

fn send(pid: u32, signal: Signal, label: &str) -> Result<(), KillError> {
    if pid == 0 {
        return Err(KillError::InvalidPid(pid));
    }
    match nix_kill(Pid::from_raw(pid as i32), signal) {
        Ok(()) => {
            info!(pid, "process {label}");
            Ok(())
        }
        Err(nix::Error::ESRCH) => {
            warn!(pid, "process déjà terminé");
            Ok(())
        }
        Err(source) => Err(KillError::Signal { pid, source }),
    }
}
