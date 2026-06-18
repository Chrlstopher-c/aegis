//! Classification d'un chemin d'exécution. Le filtrage in-kernel viendra avec
//! eBPF ; côté fanotify on filtre en userspace pour ne traiter (log + scan) que
//! les exécutions issues de zones inscriptibles par l'utilisateur — là où un
//! malware se dépose — et ignorer le bruit des binaires système en lecture seule.

/// Préfixes de zones « chaudes » : inscriptibles, surveillées de près.
const HOT_PREFIXES: &[&str] = &[
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    "/home/",
    "/root/",
];

/// Préfixes système en lecture seule : exécutions légitimes, ignorées du flux.
const COLD_PREFIXES: &[&str] = &["/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/"];

/// Une exécution mérite-t-elle traitement (log + scan) ? Vrai si elle provient
/// d'une zone inscriptible. Les chemins système connus sont écartés ; un chemin
/// inconnu est traité par prudence (faux positif de log toléré, pas de menace ratée).
pub fn is_hot_exec(path: &str) -> bool {
    if HOT_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return true;
    }
    if COLD_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::is_hot_exec;

    #[test]
    fn classifie_les_zones() {
        assert!(is_hot_exec("/tmp/payload"));
        assert!(is_hot_exec("/home/user/.cache/x"));
        assert!(!is_hot_exec("/usr/bin/bash"));
        assert!(!is_hot_exec("/lib/ld-linux-x86-64.so.2"));
        assert!(is_hot_exec("/some/unknown/path"));
    }
}
