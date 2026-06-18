//! Application d'une décision de policy. Point unique où le daemon agit sur le
//! système (kill, isolation, quarantaine) — pipeline et thread de scan passent
//! tous deux par ici, ce qui garantit une journalisation et un comportement
//! cohérents. Pousse aussi le verdict sur le bus UI.

use std::sync::Arc;

use aegis_core::{StreamMessage, Verdict};
use aegis_response::Quarantine;
use tokio::sync::broadcast;
use tracing::{error, info};

use crate::policy::{Decision, PolicyEngine};

/// Contexte partagé d'application des décisions.
#[derive(Clone)]
pub struct Enforcer {
    policy: Arc<PolicyEngine>,
    quarantine: Arc<Quarantine>,
    bus: broadcast::Sender<StreamMessage>,
}

impl Enforcer {
    pub fn new(
        policy: Arc<PolicyEngine>,
        quarantine: Arc<Quarantine>,
        bus: broadcast::Sender<StreamMessage>,
    ) -> Self {
        Self { policy, quarantine, bus }
    }

    /// Journalise le verdict, le diffuse à l'UI, décide via la policy et applique.
    pub fn handle(&self, verdict: &Verdict) {
        info!(
            engine = ?verdict.engine,
            severity = ?verdict.severity,
            category = ?verdict.category,
            mitre = ?verdict.mitre,
            title = %verdict.title,
            "VERDICT"
        );
        let _ = self.bus.send(StreamMessage::Verdict(verdict.clone()));
        self.apply(self.policy.decide(verdict));
    }

    fn apply(&self, decision: Decision) {
        match decision {
            Decision::Log => {}
            Decision::Notify => info!("notification utilisateur"),
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
