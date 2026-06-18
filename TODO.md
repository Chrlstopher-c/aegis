# TODO — Aegis
*Dernière mise à jour : 2026-06-18*

## 🎯 Prochaine session (priorité)
- [ ] Débloquer fenêtre Tauri sous Wayland (`Gdk Error 71`) — tester `WEBKIT_DISABLE_DMABUF_RENDERER=1` (+ `GDK_BACKEND=x11`) ; sinon acter fallback navigateur
- [ ] **Chantier eBPF** (Lot 3 tranche 3) : crate `aegis-probes-ebpf` (aya, nightly) — mmap W+X (fileless), capset/setuid (escalade), socket_connect (C2). Le plus gros morceau restant.
- [ ] Dette canaris : `deploy_canaries` doit `chown` vers l'utilisateur réel (sinon canaris root dans le home en prod systemd)
- [ ] Pousser le binaire release à jour dans le service : `sudo ./packaging/install.sh && sudo systemctl restart aegis`

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
- [x] Bridge WebSocket daemon ↔ UI (`ws_bridge.rs`, 127.0.0.1:8787, StreamMessage JSON)
- [x] Dashboard React dark épuré : flux live, état protection, détections (sévérité/MITRE)
- [ ] Contrôles UI→daemon : quarantaine/restauration, exclusions, kill, toggle détection ⇄ prévention (Lot 5)
- [ ] Empaquetage Tauri (tray, notifications natives) (Lot 5)
- [x] Livrable : dashboard live validé E2E (mode démo) — **rendu visuel à valider par Chris**
- [x] Bonus : mode dégradé (daemon survit sans capteurs) + mode `--demo`

### Phase 5 — Réponse & finition
- [x] Réponse graduée (policy engine : sévérité × mode, global/catégorie) — 5 tests
- [x] Isolation (SIGSTOP, gel léger ; cgroup-freezer complet à venir)
- [x] Contrôle UI→daemon (Command via WS bidirectionnel) — SetMode validé
- [x] FIM credential access (fanotify FAN_ACCESS sur fichiers sensibles → T1003)
- [x] Service systemd + capabilities minimales (packaging/aegis.service + install.sh)
- [ ] Mise à jour des règles YARA (feed open source + règles maison)
- [ ] Auto-protection daemon (T1562.001)
- [ ] Commandes ScanOnDemand/ScanMemory/exclusions (stub)
- [~] Livrable : MVP utilisable au quotidien — cœur fonctionnel, sondes eBPF à venir

## Backlog (hors MVP)
- IA locale comportementale (classification séquences syscalls)
- ClamAV optionnel en process séparé (moteur signature additionnel)
- Détection rootkit avancée
- Rollback ransomware (restauration fichiers chiffrés)
- API externe optionnelle + console multi-postes (cas flotte/entreprise)
- Version serveur/VPS
