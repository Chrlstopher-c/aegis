//! Capteurs bas niveau : fanotify (exécution) et, à terme, sondes eBPF. Normalise
//! les événements kernel en `EventEnvelope` (contrat `aegis-core`) et les pousse
//! vers le daemon. Ne décide rien : ni verdict, ni action.

mod fanotify;
mod proc;

pub use fanotify::{spawn as spawn_fanotify, ProbeError};
