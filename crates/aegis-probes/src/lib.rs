//! Capteurs bas niveau : fanotify (exécution + canaris) et, à terme, sondes eBPF.
//! Normalise les événements kernel en `EventEnvelope` (contrat `aegis-core`) et
//! les pousse vers le daemon. Ne décide rien : ni verdict, ni action.

mod canary;
mod fanotify;
mod proc;

pub use canary::{default_zones as default_canary_zones, deploy as deploy_canaries};
pub use fanotify::{spawn as spawn_fanotify, ProbeError};
