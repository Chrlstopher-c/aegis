//! Enrichissement d'un `ProcessCtx` depuis `/proc/<pid>`. Best-effort : un champ
//! illisible (process déjà mort, course) ne fait pas échouer la capture.

use std::fs;

use aegis_core::ProcessCtx;
use tracing::trace;

/// Construit un `ProcessCtx` pour `pid`. `exe_hint` (chemin du binaire issu du fd
/// fanotify) sert de repli si `/proc/<pid>/exe` n'est pas lisible.
pub fn process_ctx(pid: u32, exe_hint: &str) -> ProcessCtx {
    let status = read_status(pid);
    ProcessCtx {
        pid,
        ppid: status.ppid,
        tgid: status.tgid,
        exe_path: read_link(pid, "exe").unwrap_or_else(|| exe_hint.to_string()),
        comm: read_trim(pid, "comm").unwrap_or_default(),
        cmdline: read_cmdline(pid),
        uid: status.uid,
        euid: status.euid,
        gid: status.gid,
        caps_effective: status.caps_effective,
        cgroup_id: 0, // renseigné par la sonde eBPF (cgroup réel), 0 côté fanotify.
        container_id: read_container_id(pid),
        app: crate::attribution::attribute(pid),
    }
}

#[derive(Default)]
struct Status {
    ppid: u32,
    tgid: u32,
    uid: u32,
    euid: u32,
    gid: u32,
    caps_effective: u64,
}

fn read_status(pid: u32) -> Status {
    let mut status = Status::default();
    let raw = match fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(raw) => raw,
        Err(err) => {
            trace!(pid, %err, "lecture /proc/<pid>/status échouée");
            return status;
        }
    };
    for line in raw.lines() {
        parse_status_line(line, &mut status);
    }
    status
}

fn parse_status_line(line: &str, status: &mut Status) {
    let Some((key, val)) = line.split_once(':') else { return };
    let val = val.trim();
    match key {
        "PPid" => status.ppid = val.parse().unwrap_or(0),
        "Tgid" => status.tgid = val.parse().unwrap_or(0),
        // "Uid: real eff saved fs", idem Gid.
        "Uid" => {
            let mut it = val.split_whitespace();
            status.uid = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            status.euid = it.next().and_then(|v| v.parse().ok()).unwrap_or(status.uid);
        }
        "Gid" => status.gid = val.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0),
        "CapEff" => status.caps_effective = u64::from_str_radix(val, 16).unwrap_or(0),
        _ => {}
    }
}

fn read_cmdline(pid: u32) -> String {
    match fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(bytes) => bytes
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s))
            .collect::<Vec<_>>()
            .join(" "),
        Err(err) => {
            trace!(pid, %err, "lecture cmdline échouée");
            String::new()
        }
    }
}

fn read_link(pid: u32, name: &str) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/{name}"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn read_trim(pid: u32, name: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/{name}"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Indice de conteneur best-effort depuis la hiérarchie cgroup.
fn read_container_id(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for marker in ["docker", "containerd", "libpod", "crio"] {
        if let Some(pos) = raw.find(marker) {
            let id: String = raw[pos..].chars().take_while(|c| c.is_alphanumeric()).collect();
            return Some(id);
        }
    }
    None
}
