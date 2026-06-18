# STATE — Aegis
*Dernière mise à jour : 2026-06-18*

> Résumé vivant cross-session. Garder < 300 lignes.

## Statut global

**Phase : exécution — Lot 0 terminé et validé.** Le scaffold applicatif existe et
compile. Pré-vol environnement passé sans bloquant majeur.

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

**Prochaine étape : Lot 1** — capteurs kernel (eBPF exec via aya + fanotify
`FAN_OPEN_EXEC_PERM`) + daemon cœur (boucle ingestion tokio, socket Unix
`/run/aegis/aegis.sock`). Nécessite root pour tester (chargement eBPF, fanotify PERM).

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
