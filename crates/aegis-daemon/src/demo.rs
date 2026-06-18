//! Générateur de flux synthétique pour démos et validation UI hors root (le mode
//! réel exige `CAP_SYS_ADMIN`). Activé par `--demo`. Injecte périodiquement des
//! événements et des verdicts plausibles sur le bus, sans toucher au système.

use aegis_core::{
    Action, AppAttribution, AppKind, Engine, EventEnvelope, EventPayload, EventSource, FileEvent,
    FileOp, ProcessCtx, Severity, StreamMessage, ThreatCategory, Verdict, SCHEMA_VERSION,
};
use tokio::sync::broadcast;
use tokio::time::{sleep, Duration};

/// Boucle de démo : un événement toutes les ~600 ms, un verdict tous les 5 events.
pub async fn run(bus: broadcast::Sender<StreamMessage>) {
    let samples = sample_execs();
    let mut tick: u64 = 0;
    loop {
        let (comm, path, pid, app) = &samples[(tick as usize) % samples.len()];
        let _ = bus.send(StreamMessage::Event(make_event(*pid, comm, path, app.clone())));
        if tick % 5 == 4 {
            let _ = bus.send(StreamMessage::Verdict(make_verdict(tick)));
        }
        tick += 1;
        sleep(Duration::from_millis(600)).await;
    }
}

fn sample_execs() -> Vec<(&'static str, &'static str, u32, Option<AppAttribution>)> {
    vec![
        ("bash", "/usr/bin/bash", 1201, app("Claude Code", AppKind::Terminal, 1180)),
        ("curl", "/usr/bin/curl", 1318, app("Discord", AppKind::Desktop, 2324)),
        ("dropper", "/tmp/dropper", 4042, app("Chrome", AppKind::Desktop, 109254)),
        ("python3", "/usr/bin/python3", 1555, app("Claude Code", AppKind::Terminal, 1180)),
        ("nc", "/tmp/.x/nc", 4099, None),
        ("cron", "/usr/sbin/cron", 812, app("Cron", AppKind::Service, 812)),
        ("systemd", "/usr/lib/systemd/systemd", 1, app("Système", AppKind::System, 1)),
    ]
}

fn app(name: &str, kind: AppKind, root_pid: u32) -> Option<AppAttribution> {
    Some(AppAttribution { name: name.into(), kind, root_pid })
}

fn make_event(pid: u32, comm: &str, path: &str, app: Option<AppAttribution>) -> EventEnvelope {
    EventEnvelope {
        schema_version: SCHEMA_VERSION,
        event_id: u128::from(pid) << 32 | u128::from(fastrand()),
        ts: 0,
        source: EventSource::Fanotify,
        process: ProcessCtx {
            pid,
            ppid: 1,
            tgid: pid,
            exe_path: path.into(),
            comm: comm.into(),
            cmdline: path.into(),
            uid: 1000,
            euid: 1000,
            gid: 1000,
            caps_effective: 0,
            cgroup_id: 0,
            container_id: None,
            app,
        },
        payload: EventPayload::File(FileEvent {
            path: path.into(),
            op: FileOp::OpenExec,
            blocking: true,
            response_token: None,
        }),
    }
}

fn make_verdict(tick: u64) -> Verdict {
    let table = [
        (Engine::Yara, Severity::High, ThreatCategory::Signature, "T1204", "Signature YARA : eicar_test_file", "Fichier de test EICAR détecté dans /tmp", Action::Quarantine { path: "/tmp/eicar.com".into() }),
        (Engine::Ransomware, Severity::Critical, ThreatCategory::Impact, "T1486", "Canari modifié par crypter", "Chiffrement de masse détecté, process neutralisé", Action::Kill { pid: 4042 }),
        (Engine::Behavioral, Severity::Critical, ThreatCategory::CommandAndControl, "T1059.004", "Reverse shell probable (bash)", "Motif /dev/tcp/ dans la commande", Action::Kill { pid: 1201 }),
        (Engine::Behavioral, Severity::High, ThreatCategory::Execution, "T1059", "Exécution depuis une zone inscriptible (dropper)", "Binaire exécuté depuis /tmp/dropper", Action::Notify),
    ];
    let (engine, severity, category, mitre, title, detail, action) =
        table[(tick as usize / 5) % table.len()].clone();
    Verdict {
        schema_version: SCHEMA_VERSION,
        event_id: u128::from(tick),
        engine,
        severity,
        category,
        mitre: vec![mitre.to_string()],
        confidence: 0.95,
        title: title.into(),
        detail: detail.into(),
        recommended_action: action,
    }
}

/// Petit PRNG déterministe (xorshift) — évite une dépendance pour la démo.
fn fastrand() -> u32 {
    use std::cell::Cell;
    thread_local!(static SEED: Cell<u32> = const { Cell::new(0x9E3779B9) });
    SEED.with(|s| {
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        s.set(x);
        x
    })
}
