//! Attribution d'un process à son application « parente » lisible (Claude Code,
//! Discord, Netflix…). Sur un desktop systemd, le signal le plus fiable est le
//! cgroup : une app lancée via son `.desktop` vit dans un scope `app-<nom>.scope`.
//! Quand le scope est générique (session) ou un terminal, on remonte la chaîne
//! d'ancêtres jusqu'à une frontière (manager de session, changement de scope) pour
//! nommer le process de tête. Best-effort : `None` si rien d'exploitable.

use std::fs;

use aegis_core::{AppAttribution, AppKind};

/// Comms de shells : transparents dans l'attribution (on cherche l'app derrière).
const SHELLS: &[&str] = &["sh", "bash", "zsh", "fish", "dash", "ksh", "tcsh"];

/// Binaires « hôtes » génériques : leur basename ne nomme pas l'application (un
/// script node s'appelle `node`). Dans ce cas le `comm` porte le vrai nom logique
/// (ex. `claude`), on le préfère au basename de l'exe.
const RUNTIMES: &[&str] = &[
    "node", "electron", "python", "python3", "python2", "ruby", "java", "perl",
    "deno", "bun", "php", "lua", "wine", "mono", "dotnet", "sh", "bash", "zsh",
    "fish", "dash", "ksh", "tcsh",
];

/// Comms qui marquent une frontière : leur enfant est l'application racine
/// (compositors, gestionnaires de session, display managers, init).
const MANAGERS: &[&str] = &[
    "systemd", "init", "login", "agetty", "Hyprland", "hyprland", "ambxst", "sway",
    "gnome-shell", "plasmashell", "Xorg", "Xwayland", "sddm", "gdm", "lightdm", "ly",
];

const MAX_WALK: usize = 24;

/// Classe du scope cgroup feuille.
enum Leaf {
    App { name: String, pid: u32 },
    Terminal(String),
    Service(String),
    System,
    Session,
}

/// Attribue `pid` à son application racine. Voir module pour la stratégie.
pub fn attribute(pid: u32) -> Option<AppAttribution> {
    let cg = read_cgroup(pid)?;
    match parse_leaf(&cg) {
        Leaf::App { name, pid: root } => {
            Some(app(prettify(&name), AppKind::Desktop, if root != 0 { root } else { pid }))
        }
        Leaf::Service(name) => Some(app(prettify(&name), AppKind::Service, pid)),
        Leaf::System => Some(app("Système".into(), AppKind::System, pid)),
        Leaf::Terminal(term) => Some(walk_terminal(pid, &leaf_segment(&cg), &term)),
        Leaf::Session => Some(walk_session(pid)),
    }
}

fn app(name: String, kind: AppKind, root_pid: u32) -> AppAttribution {
    AppAttribution { name, kind, root_pid }
}

/// Remonte la chaîne tant qu'on reste dans le scope du terminal ; l'application
/// est le premier ancêtre non-shell rencontré en partant du plus haut. À défaut,
/// le terminal lui-même.
fn walk_terminal(pid: u32, term_leaf: &str, term_name: &str) -> AppAttribution {
    let mut chain: Vec<(u32, String)> = Vec::new();
    let mut cur = pid;
    for _ in 0..MAX_WALK {
        let comm = read_comm(cur).unwrap_or_default();
        chain.push((cur, comm));
        let Some(ppid) = read_ppid(cur) else { break };
        if ppid <= 1 || read_cgroup(ppid).map(|c| leaf_segment(&c)) != Some(term_leaf.to_string()) {
            break;
        }
        cur = ppid;
    }
    // chain : du plus profond au plus haut → on prend le plus haut non-shell.
    for (p, comm) in chain.iter().rev() {
        if !is_shell(comm) {
            return app(display_name(*p), AppKind::Terminal, *p);
        }
    }
    app(prettify(term_name), AppKind::Terminal, pid)
}

/// Remonte jusqu'à ce que le parent soit un manager de session, init, ou hors
/// scope : ce process est l'application racine perçue par l'utilisateur.
fn walk_session(pid: u32) -> AppAttribution {
    let mut cur = pid;
    for _ in 0..MAX_WALK {
        let Some(ppid) = read_ppid(cur) else { break };
        if ppid <= 1 {
            break;
        }
        let pcomm = read_comm(ppid).unwrap_or_default();
        if is_manager(&pcomm) {
            break;
        }
        cur = ppid;
    }
    app(display_name(cur), AppKind::Desktop, cur)
}

/// Nom lisible d'un process : basename de l'exe, sauf runtime générique ou numéro
/// de version (→ on retombe sur le `comm`, plus parlant) ; un shell est nommé par
/// le script qu'il exécute. Source générale, sans table d'applications.
fn display_name(pid: u32) -> String {
    let comm = read_comm(pid).unwrap_or_default();
    let exe_base = read_exe_basename(pid);
    let mut base = match exe_base {
        Some(e) if !is_runtime(&e) && !is_version_like(&e) => e,
        _ if !comm.is_empty() => comm.clone(),
        Some(e) => e,
        None => "inconnu".to_string(),
    };
    if is_shell(&base) {
        if let Some(script) = script_basename(pid) {
            base = script;
        }
    }
    prettify_proc(&base)
}

fn parse_leaf(cg: &str) -> Leaf {
    if cg.contains("/system.slice/") && (cg.contains("docker-") || cg.contains("containerd")) {
        return Leaf::System;
    }
    let leaf = leaf_segment(cg);
    if let Some(rest) = leaf.strip_prefix("app-").and_then(|l| l.strip_suffix(".scope")) {
        let (name, pid) = split_trailing_pid(rest);
        return Leaf::App { name: unescape(&name), pid };
    }
    if leaf == "init.scope" {
        return Leaf::System;
    }
    if let Some(name) = leaf.strip_suffix(".service") {
        return Leaf::Service(name.to_string());
    }
    if leaf.starts_with("session-") && leaf.ends_with(".scope") {
        return Leaf::Session;
    }
    if let Some(term) = terminal_name(&leaf) {
        return Leaf::Terminal(term);
    }
    Leaf::Session
}

/// Reconnaît un scope de terminal `<nom>-<num>-<num>.scope` (ex. `kitty-116532-0`).
fn terminal_name(leaf: &str) -> Option<String> {
    let body = leaf.strip_suffix(".scope")?;
    let parts: Vec<&str> = body.split('-').collect();
    if parts.len() < 3 {
        return None;
    }
    let tail_digits = parts[parts.len() - 2..].iter().all(|p| p.chars().all(|c| c.is_ascii_digit()));
    if tail_digits {
        Some(parts[..parts.len() - 2].join("-"))
    } else {
        None
    }
}

/// Sépare un suffixe `-<pid>` numérique du nom (`Chrome-109254` → `Chrome`, 109254).
fn split_trailing_pid(s: &str) -> (String, u32) {
    match s.rsplit_once('-') {
        Some((name, num)) if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) => {
            (name.to_string(), num.parse().unwrap_or(0))
        }
        _ => (s.to_string(), 0),
    }
}

/// Met une majuscule initiale sans toucher au reste (préserve `cli.sh`,
/// `quickshell`, les casses internes). Pour les noms de process, pas d'app-id.
fn prettify_proc(raw: &str) -> String {
    let s = raw.trim();
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => s.to_string(),
    }
}

fn is_runtime(name: &str) -> bool {
    RUNTIMES.contains(&name)
}

/// Vrai si la chaîne n'est qu'une version (`2.1.181`) : un tel basename d'exe ne
/// nomme pas l'application.
fn is_version_like(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Basename de la cible de `/proc/<pid>/exe`.
fn read_exe_basename(pid: u32) -> Option<String> {
    let target = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    target.file_name().map(|n| n.to_string_lossy().into_owned())
}

/// Basename du premier argument « fichier » d'un shell (le script exécuté).
fn script_basename(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let args: Vec<&[u8]> = raw.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
    for arg in args.iter().skip(1) {
        let s = String::from_utf8_lossy(arg);
        if s.starts_with('-') {
            continue;
        }
        let base = s.rsplit('/').next().unwrap_or(&s);
        if !base.is_empty() {
            return Some(base.to_string());
        }
    }
    None
}

/// Rend lisible un identifiant cgroup : reverse-DNS → dernier segment, majuscule.
fn prettify(raw: &str) -> String {
    let base = raw.rsplit('.').next().unwrap_or(raw);
    let base = base.trim();
    if base.is_empty() {
        return raw.to_string();
    }
    let mut chars = base.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => base.to_string(),
    }
}

/// Décode les échappements systemd les plus courants (`\x2d` → `-`).
fn unescape(s: &str) -> String {
    s.replace("\\x2d", "-").replace("\\x40", "@")
}

fn leaf_segment(cg: &str) -> String {
    cg.rsplit('/').next().unwrap_or(cg).to_string()
}

fn is_shell(comm: &str) -> bool {
    SHELLS.contains(&comm)
}

fn is_manager(comm: &str) -> bool {
    MANAGERS.contains(&comm)
}

/// Première ligne de `/proc/<pid>/cgroup`, sans le préfixe `0::`.
fn read_cgroup(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let line = raw.lines().next()?;
    Some(line.rsplit_once("::").map(|(_, p)| p).unwrap_or(line).to_string())
}

fn read_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string())
}

fn read_ppid(pid: u32) -> Option<u32> {
    let raw = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in raw.lines() {
        if let Some(v) = line.strip_prefix("PPid:") {
            return v.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cgroups réels observés sur un desktop systemd (cf. validation terrain).
    #[test]
    fn app_scope_yields_clean_name() {
        let cg = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-com.google.Chrome-109254.scope";
        match parse_leaf(cg) {
            Leaf::App { name, pid } => {
                assert_eq!(prettify(&name), "Chrome");
                assert_eq!(pid, 109254);
            }
            _ => panic!("attendu App"),
        }
        match parse_leaf("/user.slice/.../app.slice/app-netflix-267919.scope") {
            Leaf::App { name, .. } => assert_eq!(prettify(&name), "Netflix"),
            _ => panic!("attendu App"),
        }
    }

    #[test]
    fn terminal_scope_detected() {
        assert!(matches!(
            parse_leaf("/user.slice/user-1000.slice/user@1000.service/kitty-116532-0.scope"),
            Leaf::Terminal(ref t) if t == "kitty"
        ));
    }

    #[test]
    fn session_and_service_classified() {
        assert!(matches!(parse_leaf("/user.slice/user-1000.slice/session-2.scope"), Leaf::Session));
        assert!(matches!(parse_leaf("/system.slice/sshd.service"), Leaf::Service(_)));
        assert!(matches!(
            parse_leaf("/system.slice/docker-abc123.scope"),
            Leaf::System
        ));
    }

    #[test]
    fn prettify_handles_reverse_dns_and_plain() {
        assert_eq!(prettify("org.chromium.Chromium"), "Chromium");
        assert_eq!(prettify("discord"), "Discord");
    }

    #[test]
    fn version_like_distingue_exe_inutile() {
        assert!(is_version_like("2.1.181"));
        assert!(!is_version_like("quickshell"));
        assert!(is_runtime("node"));
        assert!(!is_runtime("quickshell"));
    }

    #[test]
    fn prettify_proc_preserve_extensions_et_casse() {
        // contrairement à prettify (app-id), ne coupe pas sur les points.
        assert_eq!(prettify_proc("cli.sh"), "Cli.sh");
        assert_eq!(prettify_proc("quickshell"), "Quickshell");
    }
}
