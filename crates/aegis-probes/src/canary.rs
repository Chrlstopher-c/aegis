//! Fichiers canari (leurres) anti-ransomware. Déposés dans les zones de données,
//! ils ne sont jamais touchés en usage normal : toute modification trahit un
//! chiffrement de masse en cours. Nommés pour être atteints tôt par un ransomware
//! qui parcourt les fichiers (préfixes en début/fin d'ordre alphabétique).

use std::fs;
use std::path::{Path, PathBuf};

use nix::unistd::{chown, Gid, Uid, User};
use tracing::{info, warn};

/// Noms de canaris déposés dans chaque zone. Préfixes `0000`/`zzzz` pour être
/// rencontrés tôt quel que soit le sens de parcours ; extensions « précieuses ».
const CANARY_NAMES: &[&str] = &[
    "0000_aegis_canary.docx",
    "zzzz_aegis_canary.xlsx",
];

const CANARY_CONTENT: &[u8] = b"AEGIS-CANARY - ne pas modifier. Toute ecriture declenche une reponse.\n";

/// Déploie les canaris dans les zones données. Retourne les chemins effectivement
/// créés (à marquer ensuite en fanotify). Best-effort : une zone inaccessible est
/// ignorée avec un warn, pas une erreur fatale.
pub fn deploy(zones: &[PathBuf]) -> Vec<PathBuf> {
    let owner = invoking_owner();
    let mut deployed = Vec::new();
    for zone in zones {
        if let Err(err) = fs::create_dir_all(zone) {
            warn!(zone = %zone.display(), %err, "zone canari inaccessible, ignorée");
            continue;
        }
        for name in CANARY_NAMES {
            let path = zone.join(name);
            match fs::write(&path, CANARY_CONTENT) {
                Ok(()) => {
                    reassign_owner(&path, owner);
                    deployed.push(path);
                }
                Err(err) => warn!(path = %path.display(), %err, "dépôt de canari échoué"),
            }
        }
    }
    info!(count = deployed.len(), "canaris déployés");
    deployed
}

/// uid/gid de l'utilisateur réel derrière `sudo`/systemd. `None` si on tourne déjà
/// sous l'utilisateur cible (les fichiers lui appartiennent alors d'office).
fn invoking_owner() -> Option<(Uid, Gid)> {
    let user = std::env::var("SUDO_USER").ok()?;
    match User::from_name(&user) {
        Ok(Some(u)) => Some((u.uid, u.gid)),
        _ => None,
    }
}

/// Rend un canari déposé en root à son propriétaire réel, sinon il pollue le home
/// en root sous systemd. Best-effort : un échec de `chown` n'invalide pas le canari.
fn reassign_owner(path: &Path, owner: Option<(Uid, Gid)>) {
    let Some((uid, gid)) = owner else { return };
    if let Err(err) = chown(path, Some(uid), Some(gid)) {
        warn!(path = %path.display(), %err, "chown canari échoué");
    }
}

/// Zones canari par défaut. Surchargées par `AEGIS_CANARY_DIRS` (séparées par `:`).
/// Sans configuration, cible les dossiers de données de l'utilisateur invoquant
/// (`SUDO_USER`) puis, à défaut, `$HOME`.
pub fn default_zones() -> Vec<PathBuf> {
    if let Some(raw) = std::env::var_os("AEGIS_CANARY_DIRS") {
        return std::env::split_paths(&raw).collect();
    }
    let home = sudo_user_home().or_else(|| std::env::var_os("HOME").map(PathBuf::from));
    let Some(home) = home else { return Vec::new() };
    ["Documents", "Pictures", "Desktop"]
        .iter()
        .map(|sub| home.join(sub))
        .collect()
}

/// Home de l'utilisateur derrière `sudo`, pour cibler ses données et non `/root`.
fn sudo_user_home() -> Option<PathBuf> {
    let user = std::env::var("SUDO_USER").ok()?;
    let home = PathBuf::from("/home").join(&user);
    home.exists().then_some(home)
}
