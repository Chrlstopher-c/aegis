# Arborescence — Aegis

Une ligne par fichier. **Code applicatif** = scaffold Lot 0 livré (workspace + UI).
**Structure prévue** documente la cible au-delà du Lot 0.

## Code applicatif (Lot 0)

```
aegis/
├── Cargo.toml                       # workspace (core+detection+response+daemon ; probes exclu)
├── rust-toolchain.toml              # pinne stable au workspace (probes → nightly explicite)
├── crates/
│   ├── aegis-core/                  # contrat IPC, aucun métier
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs               # exports + SCHEMA_VERSION
│   │       ├── process.rs           # ProcessCtx + AppAttribution/AppKind
│   │       ├── events.rs            # EventEnvelope, EventSource, 5 payloads
│   │       ├── verdict.rs           # Verdict, Engine, Severity, ThreatCategory, Action
│   │       ├── stream.rs            # StreamMessage (event|verdict) du flux UI
│   │       └── command.rs           # Command, CommandResult, Mode/Exclusion enums
│   ├── aegis-probes/                # capteurs bas niveau (fanotify)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs               # exports (spawn_fanotify, canaris)
│   │       ├── fanotify.rs          # sonde exec (PERM) + canaris (MODIFY), routage par mask
│   │       ├── canary.rs            # déploiement leurres anti-ransomware (+ chown user réel)
│   │       ├── attribution.rs       # attribution process → app racine (cgroup + ancêtres)
│   │       └── proc.rs              # enrichissement ProcessCtx via /proc (+ app)
│   ├── aegis-detection/             # moteurs de verdict
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs               # trait DetectionEngine + exports
│   │   │   ├── yara.rs              # YaraEngine (yara-x) : compile rules/, scan→Verdict
│   │   │   └── behavioral.rs        # CanaryWatch : écriture canari → verdict ransomware
│   │   └── tests/                   # eicar.rs, canary.rs
│   ├── aegis-response/              # application des actions
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs               # exports Quarantine, kill_process
│   │   │   ├── quarantine.rs        # store quarantaine + restauration
│   │   │   └── kill.rs              # neutralisation SIGKILL
│   │   └── tests/quarantine.rs      # round-trip quarantine/restore
│   └── aegis-daemon/                # orchestrateur (binaire tokio + tracing)
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs              # câblage pipeline + YARA + policy + enforcer + bridges
│           ├── pipeline.rs          # ingestion, comportemental/FIM prioritaires, filtrage, scan
│           ├── policy.rs            # PolicyEngine : réponse graduée sévérité × mode
│           ├── enforce.rs           # Enforcer : application unique des décisions
│           ├── command.rs           # traitement des commandes UI → daemon
│           ├── ipc_socket.rs        # socket Unix, diffusion JSON du flux (StreamMessage)
│           ├── ws_bridge.rs         # bridge WebSocket localhost ↔ UI (flux + commandes)
│           ├── scan.rs              # thread scan YARA → enforcer
│           ├── demo.rs              # flux synthétique (--demo) pour validation UI hors root
│           └── zones.rs             # classification zone chaude/froide (anti-bruit)
├── packaging/
│   ├── aegis.service                # unit systemd (capabilities minimales, durcissement)
│   └── install.sh                   # installation service + binaire + règles (root)
├── scripts/
│   └── clean-canaries.sh            # nettoyage des canaris résiduels dans le home
├── ui/src/                          # dashboard React (Lot 4)
│   ├── App.tsx                      # layout dashboard (header + détections + flux)
│   ├── types.ts                     # miroir TS du contrat IPC (StreamMessage, Command, Action)
│   ├── useAegisStream.ts            # hook WebSocket (flux + sendCommand corrélé, reconnexion)
│   └── components/                  # ProtectionHeader, VerdictList, VerdictCard,
│                                    #   EventFeed, eventAggregate, verdictActions, severity
├── rules/
│   └── test.yar                     # règles EICAR + reverse-shell (convention meta)
├── tests/redteam/
│   ├── lot1-exec-flux.sh            # validation flux exec temps réel (root)
│   ├── lot2-eicar-quarantine.sh     # validation détection + quarantaine (root)
│   ├── lot3-ransomware-kill.sh      # validation ransomware tué avant propagation (root)
│   └── lot5-credential-fim.sh       # validation FIM credential access (root)
├── ui/                              # Tauri v2 + React/TS/Tailwind v4 dark
│   ├── vite.config.ts               # plugins react + tailwindcss
│   └── src/
│       ├── main.tsx                 # entrée React, import index.css
│       ├── App.tsx                  # page placeholder dark (Lot 0)
│       └── index.css                # @import tailwindcss, color-scheme dark
├── scripts/
│   ├── start.sh                     # PID logs/aegis.pid, reset logs/daemon.log
│   ├── stop.sh                      # kill via PID file
│   └── restart.sh                   # stop + start
```

## Documentation & racine

```
aegis/
├── LICENSE              # licence MIT
├── README.md            # présentation, stack, principes
├── SECURITY.md          # politique de divulgation des vulnérabilités
├── ARCHITECTURE.md      # domaines, frontières de modules, sécurité
├── STATE.md             # état vivant cross-session
├── TODO.md              # roadmap MVP + backlog
├── ARBORESCENCE.md      # ce fichier
├── .echoforge.yml       # métadonnées projet EchoForge
├── .gitignore           # exclusions git
├── .env.example         # variables d'environnement (vide de secrets)
├── docs/
│   ├── README.md               # index de la documentation
│   ├── product-vision.md       # mission, positionnement, scope, horizon 3 ans
│   ├── feature-matrix.md       # inventaire exhaustif des capacités × version
│   ├── roadmap-versions.md     # v0.1 → v3.0, thèmes, critères de sortie
│   ├── competitive-edge.md     # features qui battent les concurrents (anti-evasion, decloak, drift, deception)
│   ├── modules.md              # architecture complète des crates (au-delà du MVP)
│   ├── ipc-contract.md         # contrat IPC : événements, verdicts, commandes (aegis-core)
│   ├── detection-catalog.md    # ce qu'on traque par tactique MITRE + signal + moteur
│   ├── policy-model.md         # modes detection/prevention, réponse graduée, faux positifs
│   ├── threat-intel.md         # feeds, mises à jour signées, IOC, réputation de hash
│   ├── ui-spec.md              # design system, écrans, motion, temps réel
│   ├── qa-and-perf.md          # budget perf, bench offensif, corpus, CI, E2E
│   ├── distribution-and-release.md # packaging multi-distro, canaux, signature
│   └── security-and-governance.md  # threat model produit, anti-tamper, gouvernance OSS
├── rules/               # règles YARA + comportementales (vide)
├── scripts/             # start/stop/restart (à créer)
└── logs/                # logs runtime (reset à chaque restart)
```

## Structure prévue (cible)

```
aegis/
├── crates/                      # workspace Cargo (code Rust)
│   ├── aegis-core/              # types partagés, contrat IPC, logging          [v0.1]
│   ├── aegis-probes/            # sondes eBPF + fanotify                         [v0.1]
│   ├── aegis-detection/         # YARA (fichier/mémoire), comportemental, corrélation [v0.1]
│   ├── aegis-response/          # quarantaine, restauration, kill, isolation, rollback [v0.5]
│   ├── aegis-daemon/            # orchestrateur, policy engine, socket + WebSocket [v0.1]
│   ├── aegis-net/               # réseau host : connexions par process, C2, egress [v0.5]
│   ├── aegis-intel/             # feeds, updates signées, store IOC, réputation hash [v1.0]
│   ├── aegis-forensics/         # event store, timeline, threat hunting, export   [v1.0]
│   ├── aegis-cli/               # interface ligne de commande (aegisctl)          [v1.0]
│   ├── aegis-integrity/         # FIM, intégrité binaires système, rootkit        [v1.x]
│   └── aegis-sandbox/           # détonation isolée (bubblewrap/namespaces)        [v1.x]
├── ui/                          # front React/TS/Tailwind + Tauri (client de contrôle)
├── rules/                       # yara/ + behavior/ + ioc/ + SOURCES.md
├── packaging/                   # AUR/.deb/.rpm/Flatpak/AppImage, unit systemd, post-install [v1.0]
├── tests/redteam/               # bench offensif simulé (EICAR, ransomware jouet, reverse shell…)
├── scripts/                     # start.sh / stop.sh / restart.sh (gestion PID, reset logs)
└── logs/                        # logs runtime
```
