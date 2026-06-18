# TODO — Aegis
*Dernière mise à jour : 2026-06-17*

## Conception (session 2026-06-17 — terminée)
- [x] Vision, cibles, stack, architecture, specs fondamentales (IPC, détection, policy)
- [x] Conception produit complète : product-vision, feature-matrix exhaustive, roadmap-versions (v0.1→v3.0), modules (11 crates)
- [x] Opérations : threat-intel, ui-spec, qa-and-perf, distribution-and-release, security-and-governance + SECURITY.md
- [x] Avantage concurrentiel : competitive-edge (anti-evasion, rootkits eBPF/io_uring, decloak, drift, deception)
- [x] Plan d'exécution alpha v0.1 validé (`~/.claude/plans/le-but-de-l-app-abundant-truffle.md`)
- [ ] Étendre le plan d'exécution aux versions ≥ v0.5 (au moment venu)

## Roadmap MVP

Ordre de bataille : fondation → capteurs → détection → comportement → UI →
réponse. Chaque phase a un livrable validé avant d'enchaîner.

### Phase 0 — Fondation
- [x] Conception : vision, cibles, stack, architecture
- [x] Documentation racine (README, ARCHITECTURE, STATE, TODO, ARBORESCENCE)
- [x] Licence MIT
- [x] Dépôt local + git
- [x] Repo GitHub public — https://github.com/trinityUwU/aegis
- [x] Pré-vol environnement (kernel BPF-LSM/fanotify/BTF OK · nightly+bpf-linker installés)
- [x] Scaffold workspace Cargo (`crates/` : core+detection+response+daemon) + `aegis-core` contrat IPC complet
- [x] Scaffold UI Tauri v2 + React/TS/Tailwind v4 dark (page placeholder, build vert, rendu validé)
- [x] Scripts `start.sh` / `stop.sh` / `restart.sh` avec gestion PID + reset logs

### Phase 1 — Capteurs kernel + daemon cœur
- [x] fanotify on-access bloquant sur exécution (`FAN_OPEN_EXEC_PERM`, FS `/`, `/tmp`, `/dev/shm`)
- [ ] Sonde eBPF exec-monitoring (`execve` / `bprm_check`) avec contexte (caps, cgroup) — aya, optionnel/enrichissement
- [x] Daemon orchestrateur : ingestion événements (tokio mpsc/broadcast), socket Unix local (JSON)
- [x] Livrable : flux temps réel des exec en logs — **validé E2E** (exec /tmp capté)

### Phase 2 — Moteur de détection signature
- [x] Intégration YARA natif (**yara-x 0.11**, pas yara-rust : pur Rust)
- [x] Scan on-access (déclenché par fanotify, zone chaude) + scan_file/scan_bytes ; planifié à venir
- [x] Scan mémoire : `scan_bytes` prêt (câblage `/proc/<pid>/mem` au Lot 3)
- [x] Quarantaine : isolation + métadonnées JSON + restauration (round-trip testé)
- [x] Livrable : EICAR + règle YARA détecté et mis en quarantaine en temps réel — **validé E2E**
- [ ] Cache LRU des hash (éviter re-scans) — prévu plan

### Phase 3 — Détection comportementale
- [ ] Règles eBPF : escalade privilèges, reverse shell, persistance (cron/systemd/LD_PRELOAD) — tranche 3
- [x] Anti-ransomware : fichiers canari (`FAN_MODIFY`) → kill (`SIGKILL`) — **validé E2E (86 µs, 0,85 % chiffré)**
- [ ] Anti-ransomware : détection rafale + entropie (au-delà du canari) — tranche 2
- [x] Mapping MITRE ATT&CK sur chaque détection (T1486 ransomware, T1204 EICAR)
- [x] Livrable : ransomware simulé tué avant propagation — **validé**
- [ ] Corrélation : arbre de pid + fenêtre temporelle — tranche 2

### Phase 4 — UI temps réel
- [ ] Bridge WebSocket daemon ↔ UI
- [ ] Dashboard React dark épuré : flux live, état protection, détections, quarantaine
- [ ] Contrôles UI→daemon : quarantaine/restauration, exclusions, kill, toggle détection ⇄ prévention
- [ ] Empaquetage Tauri (tray, notifications natives)
- [ ] Livrable : render validé par Chris

### Phase 5 — Réponse & finition
- [ ] Réponse graduée (alerte → isolation → kill)
- [ ] FIM léger sur fichiers critiques (déclenche YARA)
- [ ] Mise à jour des règles YARA (feed open source + règles maison)
- [ ] Livrable : MVP utilisable au quotidien

## Backlog (hors MVP)
- IA locale comportementale (classification séquences syscalls)
- ClamAV optionnel en process séparé (moteur signature additionnel)
- Détection rootkit avancée
- Rollback ransomware (restauration fichiers chiffrés)
- API externe optionnelle + console multi-postes (cas flotte/entreprise)
- Version serveur/VPS
