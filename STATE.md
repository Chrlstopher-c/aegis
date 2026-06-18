# STATE — Aegis
*Dernière mise à jour : 2026-06-18*

> Résumé vivant cross-session. Garder < 300 lignes.

## Statut global

**Phase : exécution — Lots 0 à 5 livrés. MVP fonctionnel installé en service.**
Daemon Rust opérationnel (fanotify temps réel + YARA + comportemental + FIM +
policy graduée + réponse), UI dashboard React branchée sur bridge WebSocket,
service systemd actif. 13 tests workspace verts, clippy clean. Détail par lot plus bas.

---

## ⏩ REPRISE — état actuel & prochaines étapes
*(session 2026-06-18 suite : AppImage+tray, panel quarantaine, banc red-team, fix écran blanc, Lot A réponse graduée interactive)*

**⚠️ ACTION REQUISE EN PREMIER (sinon l'UI échoue) :** le daemon systemd tourne un
binaire périmé qui ne connaît pas les commandes du Lot A (`ListQuarantine`, exclusions,
pending → erreur `unknown variant`). Le release à jour est **déjà compilé**
(`target/release/aegis-daemon`). **Redéployer :**
`sudo ./packaging/install.sh && sudo systemctl restart aegis` (jamais build en root).

**Ce qui tourne :**
- Service systemd `aegis` actif (fanotify réel, boot). Binaire **à redéployer** (cf. ci-dessus).
- **App empaquetée AppImage** (`~/.local/bin/Aegis.AppImage`), bouclier **SysTray**
  (vert protégé / rouge menace), clic→dashboard, close-to-tray. Autostart `--hidden` au login.
  Rebuild : `cd ui && bun run bundle` (NO_STRIP requis — strip linuxdeploy trop vieux pour `.relr.dyn`).
  Intégration OS sans root : `packaging/install-ui.sh`.
- **Écran blanc RÉSOLU** : webkit2gtk+Wayland → `WEBKIT_DISABLE_DMABUF_RENDERER=1`
  (+ `WEBKIT_DISABLE_COMPOSITING_MODE=1`) injecté dans les `.desktop` (le lanceur ne
  porte pas l'env du shell). Validé : Chris a pu ouvrir le dashboard.

**Livré cette session :**
- **Panel quarantaine** (UI) : liste / restaure / supprime (confirm 2 temps, refresh auto). Validé E2E.
- **Banc red-team** `tests/redteam/pentest.sh` (root) : 4 vecteurs réels + 3 non couverts (eBPF). À lancer par Chris.
- **Lot A — réponse graduée interactive** (backend, commité a21525d, tests 7/7) :
  Medium en Detection → **Defer** (laisser passer + notifier + file d'attente, plus de
  quarantaine auto silencieuse) ; PrivilegeEscalation+Impact forcés Prevention (bloqués) ;
  High/Critical inchangés (auto-quarantine conservée). `ExclusionStore` (allowlist
  path/process persistée) + `PendingStore` (file persistée). Un process exclu
  court-circuite toute détection en tête de pipeline. Commandes : AddExclusion/
  RemoveExclusion (fonctionnels), ListExclusions, ListPending, DismissPending.

**Prochaines étapes (par priorité) :**
1. **Redéployer le daemon** (action ci-dessus) — débloque le panel quarantaine + Lot A.
2. **Lot B — UI du modèle interactif** (PAS commencé, périmètre validé avec Chris) :
   panneau « décisions en attente » (chaque medium listé → boutons quarantaine / kill /
   **autoriser**) + panneau exceptions (liste / suppression). « Autoriser » = AddExclusion
   par `exe_path`. À valider E2E avec une vraie menace medium qui remonte.
3. **Lot C** : notifications natives (toast système sur détection).
4. **Chantier eBPF (Lot 3 tranche 3)** — BLOQUÉ outillage (ni rustup/nightly/bpf-linker ;
   Rust = Arch stable 1.96). Réinstaller toolchain avant. Fera passer les 3 vecteurs
   « non couverts » du banc au vert. Mérite sa propre session.
5. Toggle Detection/Prevention dans l'UI (le daemon doit pousser son mode courant à la
   connexion, sinon le toggle ment après reconnexion). Auto-protection daemon (T1562.001).

---

### Détail par lot (historique)

**Lot 0 (Fondation & scaffold) — DONE :**
- Pré-vol kernel : `CONFIG_BPF_LSM=y`, `FANOTIFY`+`ACCESS_PERMISSIONS`=y, BTF présent,
  **`bpf` actif dans les LSM** → enforcement BPF-LSM disponible nativement, pas de
  modif GRUB ni reboot nécessaire (kill in-kernel possible, pas de fallback SIGKILL).
- Toolchain : `rustup` installé (installeur officiel, non destructif, shims dans
  `~/.cargo/bin`), `nightly` + `rust-src` + `bpf-linker v0.10.3` posés. Default global
  remis sur `stable`, nightly réservé à Aegis. `rust-toolchain.toml` pinne stable au
  workspace. bun 1.3.13, clang 22 OK.
- Workspace Cargo : `crates/{aegis-core,aegis-detection,aegis-response,aegis-daemon}`
  (`aegis-probes` exclu du workspace : compile sur cible bpf, viendra au Lot 1).
- `aegis-core` : contrat IPC complet et figé (events/process/verdict/command) conforme
  à `docs/ipc-contract.md` — `EventEnvelope`, `ProcessCtx`, 5 payloads, `Verdict`,
  `Command`, enums `Severity`/`ThreatCategory` (8 tactiques MITRE)/`Action`. `SCHEMA_VERSION=1`.
- `aegis-detection` : trait `DetectionEngine` (stub). `aegis-response` : `apply()` stub.
  `aegis-daemon` : binaire tokio + tracing (log de démarrage, pipeline non câblé).
- `scripts/start|stop|restart.sh` : PID dans `logs/aegis.pid`, reset logs (pas d'append).
- UI : Tauri v2 + React + TS + **Tailwind v4** (dark), build via Bun/Vite. Page
  placeholder dark épurée (accent emerald). **Validé E2E** : `cargo build` vert,
  daemon démarre, `bun run build` vert, rendu screenshoté (`logs/screenshots/lot0-ui.png`),
  zéro erreur console/process.

**Lot 1 (Capteurs + daemon cœur) — partie fanotify DONE et validée E2E :**
- `aegis-probes` : sonde **fanotify** `FAN_OPEN_EXEC_PERM` (`FAN_MARK_FILESYSTEM` sur
  `/`, `/tmp`, `/dev/shm`), thread dédié bloquant. Acquittement `FAN_ALLOW` de tout
  le batch **avant** enrichissement (invariant : zéro calcul lourd dans le chemin
  bloquant kernel). Enrichissement `ProcessCtx` via `/proc/<pid>` (best-effort).
  Lib `nix 0.29`. Intégré au workspace.
- `aegis-daemon` : pipeline tokio — `mpsc` capteurs→ingestion, `broadcast` vers
  clients. `pipeline.rs` log le flux (livrable). `ipc_socket.rs` : socket Unix
  (`/run/aegis/aegis.sock` si root, repli `$XDG_RUNTIME_DIR`), diffuse les
  `EventEnvelope` en **JSON ligne par ligne** aux clients abonnés.
- **Validé E2E en root** (`tests/redteam/lot1-exec-flux.sh`) : exec depuis `/tmp`
  capté en temps réel dans le flux. `cargo build` + `cargo clippy --workspace` clean.

**Lot 2 (Moteur signatures + quarantaine) — DONE et validé E2E temps réel :**
- `aegis-detection` : moteur **yara-x 0.11** (`YaraEngine::from_dir` compile `rules/`
  récursif, `scan_file`/`scan_bytes`). Métadonnées de règle (severity/category/mitre/
  description) → `Verdict`. Règles `rules/test.yar` (EICAR + reverse-shell oneliner).
- `aegis-response` : **quarantaine** (`Quarantine`) — déplacement vers store
  (`/var/lib/aegis/quarantine` root, repli `$XDG_DATA_HOME`), blob en `0o600` (perte
  du bit exec), métadonnées JSON (`<id>.bin`+`<id>.json`), restauration mode+contenu.
- `aegis-daemon` : **filtrage par zone** (`zones.rs`) — ne traite/scanne que les exec
  en zone inscriptible (`/tmp`,`/dev/shm`,`/home`,`/root`,`/var/tmp`,`/run/user`),
  ignore le bruit système (`/usr`,`/lib`,`/bin`…). **Thread de scan YARA dédié**
  (`scan.rs`, hors chemin bloquant kernel) : sur match ≥ High → quarantaine auto
  (signature = certitude, même en mode detection).
- **Validé** : unit/intégration (EICAR, fichier sain, quarantaine round-trip, zones) +
  **E2E root** (`tests/redteam/lot2-eicar-quarantine.sh`) : EICAR /tmp détecté +
  quarantiné en ~1 ms. `cargo build` + `clippy --workspace` clean.

**Lot 3 (Comportemental & anti-ransomware) — tranche 1/3 DONE et validée E2E :**
- `aegis-response/kill.rs` : `SIGKILL` (nix, features signal+process), idempotent (ESRCH = succès).
- `aegis-probes/canary.rs` : déploie des leurres (`0000_`/`zzzz_aegis_canary.*`, touchés
  tôt quel que soit le sens de parcours) dans les dossiers données (`SUDO_USER` réel,
  pas `/root`), configurable `AEGIS_CANARY_DIRS`.
- Sonde fanotify étendue : marque `FAN_MODIFY` (inode) sur chaque canari, route les
  événements par `event.mask()` (exec bloquant `FAN_OPEN_EXEC_PERM` vs canari notif).
- `aegis-detection/behavioral.rs` : `CanaryWatch` — écriture sur canari → verdict
  `Critical` / `Impact` / T1486 + `Action::Kill`.
- Pipeline : comportemental **prioritaire** (évalué avant filtrage/scan), kill immédiat.
- **Validé** : tests unitaires (canari kill, non-canari ignoré) + **E2E root**
  (`tests/redteam/lot3-ransomware-kill.sh`) : faux ransomware sur 2000 fichiers →
  neutralisé en 86 µs, 17/2000 chiffrées (0,85 %). `cargo build`+`clippy` clean.

**Reste du Lot 3 (tranches 2-3) :** détection de **rafale + entropie** (généralise
au-delà du canari : N écritures/renames/T s par pid), corrélation arbre de pid, et
sondes **eBPF** (mmap W+X fileless, capset/setuid escalade, socket_connect C2) via
crate eBPF aya nightly.

**Lot 3 tranche 2/3 (heuristiques exec) — DONE :**
- `ExecHeuristics` (behavioral.rs) : reverse shell via cmdline (Critical/C2/T1059.004/Kill),
  exec depuis zone inscriptible (High/Execution/T1059/Notify). Sans eBPF. Branché pipeline.
- Tests unitaires verts.

**Lot 4 (UI temps réel) — DONE et validé E2E (mode démo) :**
- `aegis-core/stream.rs` : `StreamMessage` (enum `event`|`verdict`, tag JSON).
- `aegis-daemon/ws_bridge.rs` : bridge **WebSocket localhost** (`127.0.0.1:8787`,
  `AEGIS_WS_ADDR`), réexpose le flux JSON. Le bus broadcast porte désormais
  `StreamMessage` (events + verdicts), poussé par pipeline + scan + comportemental.
- **Mode dégradé** : si fanotify échoue (pas de root), le daemon ne meurt plus —
  warn + UI/bridge servis. Daemon bloque sur `ctrl_c` (vrai cycle de vie).
- **Mode `--demo`** (`demo.rs`) : flux synthétique pour valider l'UI sans privilèges.
- UI : `useAegisStream` (hook WS, reconnexion auto, buffers bornés), dashboard React
  dark (`ProtectionHeader`/`VerdictList`/`EventFeed`), sévérités sémantiques.
- **Validé** : `bun run build` (tsc strict) + `cargo build`/`clippy` clean ; daemon
  `--demo` + UI, screenshot `logs/screenshots/lot4-dashboard.png` (flux live +
  détections codées par sévérité + badges MITRE), zéro erreur console. **Le rendu
  visuel reste l'appel de Chris.**

**Lot 5 (Réponse graduée & finition) — cœur DONE :**
- `policy.rs` : `PolicyEngine` — réponse graduée par sévérité × mode (Detection/
  Prevention), réglable global ou par catégorie (RwLock, modifiable à chaud).
  Défaut : Detection global, `Impact`=Prevention. Table conforme policy-model.md. 5 tests.
- `enforce.rs` : `Enforcer` — point unique d'application (Log/Notify/Quarantine/
  Isolate/Kill), partagé pipeline + thread scan. `aegis-response/isolate_process`
  (SIGSTOP, gel léger ; cgroup-freezer complet à venir).
- **Contrôle UI→daemon** : bridge WS bidirectionnel (`command.rs`), `Command`
  entrante → `CommandResult`. SetMode/Kill/Quarantine/Restore câblés. **Validé** :
  SetMode{Global,Prevention} via WS → `{"ok":true}`, mode appliqué (log confirmé).
- **FIM credential** : marques fanotify `FAN_ACCESS` sur fichiers sensibles
  (`/etc/shadow`, clés SSH ; `AEGIS_SENSITIVE_FILES`). `CredentialWatch` → verdict
  High/CredentialAccess/T1003, allowlist process système (sshd/sudo/su…).
- **Service systemd** : `packaging/aegis.service` (capabilities minimales
  CAP_SYS_ADMIN/DAC_READ_SEARCH/KILL/BPF, durcissement ProtectSystem/MDWX/etc.) +
  `packaging/install.sh`. `scripts/start.sh` avertit si lancé sans root.

**Dette restante :**
- **Lot 3 tranche 3/3** : sondes **eBPF** (mmap W+X fileless, capset/setuid, socket_connect
  C2) via crate eBPF aya nightly — gros chantier kernel dédié. + rafale/entropie + corrélation.
- Auto-protection daemon (T1562.001 : détecter tentative de kill du daemon) — non fait.
- Feed de règles YARA externe + cache LRU des hash. Sonde eBPF exec enrichie (cgroup/caps).
- `ScanOnDemand`/`ScanMemory`/exclusions : commandes non encore câblées (stub).
- Tests root à lancer : `tests/redteam/lot5-credential-fim.sh` (FIM validé E2E : cat→T1003 ✓).
- Note : `/var/lib/aegis/quarantine` contient un EICAR de test (inoffensif).
- **Dette canaris** : `deploy_canaries` crée les leurres avec l'ownership du daemon
  (root en prod systemd) dans le home utilisateur → fichiers root visibles et non
  modifiables par l'utilisateur. À corriger : `chown` vers l'utilisateur réel +
  attribut caché, et nettoyage à l'uninstall. `scripts/clean-canaries.sh` pour le
  ménage manuel en attendant. Tests corrigés pour ne plus polluer le home réel.

**Conception produit complète** (pas seulement MVP), corpus dans `docs/` (index
`docs/README.md`) :
- Specs techniques : `ipc-contract.md`, `detection-catalog.md`, `policy-model.md`.
- Produit : `product-vision.md` (mission, scope in/out, horizon 3 ans),
  `feature-matrix.md` (inventaire exhaustif × version), `roadmap-versions.md`
  (v0.1 alpha → v1.0 stable → v1.x profondeur → v2.0 chasseur → v3.0 fleet),
  `modules.md` (11 crates cibles).
- Opérations : `threat-intel.md`, `ui-spec.md`, `qa-and-perf.md`,
  `distribution-and-release.md`, `security-and-governance.md`. + `SECURITY.md`.
- Avantage concurrentiel : `competitive-edge.md` — 8 features qui battent les
  concurrents (anti-evasion cross-view, rootkits eBPF, io_uring, drift, deception)
  face au champ de bataille 2026 (VoidLink, RingReaper). Reflété en catégorie Q de
  la feature-matrix.

Toutes les décisions techniques sont déléguées à l'agent — Chris fournit vision et
orchestration, ne tranche pas la technique (délégation actée et durable).

## Décisions figées (2026-06-17)

- **Cible** : poste de travail Linux (desktop, local). Pas serveur/VPS. Perf
  maîtrisée mais on peut se permettre des traitements non triviaux.
- **Nature du produit** : EDR hybride desktop, pas un clone de scanner Windows.
  Signatures (YARA) + comportemental kernel (eBPF + fanotify).
- **Langage** : Rust (daemon + sondes + détection + réponse), TypeScript/React
  (UI uniquement).
- **Interface** : daemon persistant (systemd, privilégié) + UI client de contrôle.
  UI empaquetée en Tauri (pas Electron — surface d'attaque). Le même front est
  servable en webapp via le WebSocket local, gratuitement.
- **API** : locale obligatoire (socket Unix + WebSocket). Externe = non par défaut,
  aucun port réseau ouvert ; architecture qui la permet plus tard, hors MVP.
- **Licence** : MIT. ClamAV (GPLv2) écarté du MVP pour préserver MIT — YARA (BSD)
  suffit. ClamAV éventuel en process séparé post-MVP.
- **IA locale** : écartée pour l'instant (trop lourde, peu pertinente à ce stade).

## Prochaine session — exécution

Plan d'implémentation complet validé : `~/.claude/plans/le-but-de-l-app-abundant-truffle.md`.
Objectif : mise en place concrète. Stack figée — eBPF `aya`, signatures `yara-x`,
fanotify pour blocage fichiers/exec, BPF-LSM (fallback SIGKILL userspace), tokio,
Tauri v2. **Pré-vol obligatoire** : diagnostic kernel (CONFIG_BPF_LSM, lsm=bpf,
BTF, fanotify) + toolchain (nightly, bpf-linker, bun). Si `bpf` absent des LSM
actifs → Chris doit modifier GRUB + reboot. Cible session : Lots 0→1 complets +
Lot 2 (yara-x on-demand) + amorce UI flux live.

Invariants imposés : temps réel exhaustif · budget CPU strict (filtrage in-kernel,
zéro polling) · zéro GPU/VRAM (pas de ML, détection règles+corrélation).

## Garde-fous perf (desktop)

- fanotify ciblé exécution + zones chaudes, pas tout le filesystem.
- eBPF en mode léger (exec + escalade), pas de tracing exhaustif type Tracee.

## Inspirations retenues

- Tetragon — enforcement in-kernel (kill avant exécution du syscall, anti-TOCTOU).
- Falco — moteur de règles comportementales mappées MITRE.
- YARA — signatures fichier + mémoire (fileless).
- Wazuh — FIM déclenchant un scan YARA.
- Linux Malware Detect — modèle multi-moteurs en cascade + quarantaine.

## Différenciateurs visés

1. Fusion signatures + comportemental dans un produit unique et utilisable.
2. UX temps réel soignée sur du runtime-security (inexistant en open source).
3. Souveraineté native, 100 % local, zéro télémétrie.

## Contexte

- Nom : **Aegis** (validé).
- Repo local : `/mnt/projects/aegis`. Repo GitHub public : https://github.com/trinityUwU/aegis (branche `master`).
