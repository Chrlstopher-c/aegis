//! Application d'une décision de policy. Point unique où le daemon agit sur le
//! système (kill, isolation, quarantaine) — pipeline et thread de scan passent
//! tous deux par ici, ce qui garantit une journalisation et un comportement
//! cohérents. Pousse aussi le verdict sur le bus UI.

use std::sync::Arc;

use aegis_core::{StreamMessage, Verdict};
use aegis_response::{PendingStore, Quarantine};
use tokio::sync::broadcast;
use tracing::{error, info};

use crate::policy::{Decision, PolicyEngine};

/// Contexte du process incriminé, nécessaire pour différer une décision
/// (quarantaine/kill/autorisation ultérieurs par l'utilisateur).
#[derive(Clone)]
pub struct Subject {
    pub exe_path: String,
    pub pid: u32,
    pub comm: String,
}

/// Contexte partagé d'application des décisions.
#[derive(Clone)]
pub struct Enforcer {
    policy: Arc<PolicyEngine>,
    quarantine: Arc<Quarantine>,
    pending: Arc<PendingStore>,
    bus: broadcast::Sender<StreamMessage>,
}

impl Enforcer {
    pub fn new(
        policy: Arc<PolicyEngine>,
        quarantine: Arc<Quarantine>,
        pending: Arc<PendingStore>,
        bus: broadcast::Sender<StreamMessage>,
    ) -> Self {
        Self { policy, quarantine, pending, bus }
    }

    /// Journalise le verdict, le diffuse à l'UI, décide via la policy et applique.
    /// `subject` porte le contexte du process pour une décision différée.
    pub fn handle(&self, verdict: &Verdict, subject: &Subject) {
        info!(
            engine = ?verdict.engine,
            severity = ?verdict.severity,
            category = ?verdict.category,
            mitre = ?verdict.mitre,
            title = %verdict.title,
            "VERDICT"
        );
        let _ = self.bus.send(StreamMessage::Verdict(verdict.clone()));
        self.apply(self.policy.decide(verdict), verdict, subject);
    }

    fn apply(&self, decision: Decision, verdict: &Verdict, subject: &Subject) {
        match decision {
            Decision::Log => {}
            Decision::Notify => info!("notification utilisateur"),
            Decision::Defer => {
                // Laisser passer + inscrire en file d'attente : l'utilisateur
                // arbitrera (quarantaine/kill/autoriser) depuis l'UI.
                match self.pending.push(
                    verdict.clone(),
                    subject.exe_path.clone(),
                    subject.pid,
                    subject.comm.clone(),
                ) {
                    Ok(entry) => info!(id = %entry.id, exe = %subject.exe_path, "décision différée"),
                    Err(err) => error!(%err, "enregistrement de la décision en attente impossible"),
                }
            }
            Decision::Quarantine { path } => match self.quarantine.quarantine(&path, "policy") {
                Ok(entry) => info!(id = %entry.id, path, "mis en quarantaine"),
                Err(err) => error!(path, %err, "quarantaine impossible"),
            },
            Decision::Isolate { pid } => {
                if let Err(err) = aegis_response::isolate_process(pid) {
                    error!(pid, %err, "isolation impossible");
                }
            }
            Decision::Kill { pid } => {
                if let Err(err) = aegis_response::kill_process(pid) {
                    error!(pid, %err, "neutralisation impossible");
                }
            }
        }
    }
}
