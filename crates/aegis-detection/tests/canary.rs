//! Validation Lot 3 : CanaryWatch produit un verdict ransomware sur écriture canari.

use std::path::PathBuf;

use aegis_core::{
    Action, Engine, EventEnvelope, EventPayload, EventSource, FileEvent, FileOp, ProcessCtx,
    Severity, ThreatCategory, SCHEMA_VERSION,
};
use aegis_detection::CanaryWatch;

fn process() -> ProcessCtx {
    ProcessCtx {
        pid: 4242,
        ppid: 1,
        tgid: 4242,
        exe_path: "/tmp/ransom".into(),
        comm: "ransom".into(),
        cmdline: "ransom".into(),
        uid: 1000,
        euid: 1000,
        gid: 1000,
        caps_effective: 0,
        cgroup_id: 0,
        container_id: None,
    }
}

fn file_event(path: &str, op: FileOp) -> EventEnvelope {
    EventEnvelope {
        schema_version: SCHEMA_VERSION,
        event_id: 1,
        ts: 0,
        source: EventSource::Fanotify,
        process: process(),
        payload: EventPayload::File(FileEvent {
            path: path.into(),
            op,
            blocking: false,
            response_token: None,
        }),
    }
}

#[test]
fn ecriture_canari_declenche_kill_critical() {
    let canary = "/home/u/Documents/0000_aegis_canary.docx";
    let watch = CanaryWatch::new([PathBuf::from(canary)]);

    let verdict = watch
        .evaluate(&file_event(canary, FileOp::Write))
        .expect("un canari modifié doit produire un verdict");

    assert_eq!(verdict.engine, Engine::Ransomware);
    assert_eq!(verdict.severity, Severity::Critical);
    assert_eq!(verdict.category, ThreatCategory::Impact);
    assert!(verdict.mitre.contains(&"T1486".to_string()));
    assert_eq!(verdict.recommended_action, Action::Kill { pid: 4242 });
}

#[test]
fn fichier_non_canari_ou_lecture_ignore() {
    let watch = CanaryWatch::new([PathBuf::from("/home/u/Documents/0000_aegis_canary.docx")]);
    // Fichier ordinaire écrit.
    assert!(watch.evaluate(&file_event("/home/u/notes.txt", FileOp::Write)).is_none());
    // Le canari lui-même, mais en exécution (pas une écriture).
    assert!(watch
        .evaluate(&file_event("/home/u/Documents/0000_aegis_canary.docx", FileOp::OpenExec))
        .is_none());
}
