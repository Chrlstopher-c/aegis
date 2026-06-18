# Aegis

Antivirus desktop Linux temps réel, 100 % local et souverain. Hybride : moteur de
détection par signatures (YARA) **et** détection comportementale dans le kernel
(eBPF + fanotify). Aucune télémétrie cloud, aucun port réseau ouvert par défaut.

> Statut : **MVP fonctionnel** (Lots 0→5). Daemon temps réel + UI dashboard +
> service systemd. Reste à venir : sondes eBPF (fileless/escalade), finitions.
> Voir [`STATE.md`](./STATE.md) pour l'état détaillé et les prochaines étapes.

## Pourquoi

Le paysage antivirus Linux est binaire : d'un côté des scanners de signatures
(ClamAV) sans détection comportementale ; de l'autre des outils eBPF puissants
(Falco, Tetragon) pensés pour Kubernetes, pilotés en YAML/CLI, inutilisables par
un humain sur son poste. Aegis fusionne les deux dans un produit unique, avec une
interface temps réel soignée, et 100 % local.

## Cible

Poste de travail Linux (desktop). Pas serveur, pas VPS — une version flotte
pourra être dérivée plus tard.

## Stack prévue

| Couche | Choix |
|---|---|
| Sondes kernel | Rust — fanotify (actif) ; eBPF (`aya`) à venir |
| Moteur signatures | YARA (`yara-x`, pur Rust), scan fichier + mémoire |
| Daemon | Rust — orchestrateur, policy engine, socket Unix + WebSocket |
| UI | React + TypeScript + Tailwind (dark), empaquetée via Tauri v2 |
| IPC temps réel | Socket Unix local + WebSocket (`127.0.0.1:8787`) |

## Lancer

```sh
# Backend : compiler puis installer comme service systemd (capabilities minimales)
cargo build --release
sudo ./packaging/install.sh
sudo systemctl enable --now aegis        # logs : journalctl -u aegis -f

# UI (fenêtre Tauri) — se connecte au bridge WebSocket du daemon
cd ui && WEBKIT_DISABLE_DMABUF_RENDERER=1 bun run tauri dev
# ou en navigateur : bun run dev → http://localhost:1420
```

Sans systemd, en dev : `sudo ./scripts/start.sh` (root requis pour fanotify).
Mode démo UI sans privilèges : `./target/debug/aegis-daemon --demo`.

## Principes non négociables

- **Local-first** : aucune dépendance cloud, aucune télémétrie.
- **Pas d'API externe par défaut** : le daemon n'ouvre aucun port réseau. Une API
  externe optionnelle (console multi-postes) reste architecturalement possible
  mais désactivée et hors MVP.
- **Licence propre** : MIT. YARA (BSD) est compatible ; ClamAV (GPLv2) est écarté
  du MVP et n'interviendra qu'en process séparé pour préserver MIT.
- **Perf desktop** : on ne hooke pas tout le filesystem. fanotify cible
  l'exécution et les zones chaudes ; eBPF reste en mode léger.

## Documentation

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — domaines, frontières de modules
- [`STATE.md`](./STATE.md) — état courant cross-session
- [`TODO.md`](./TODO.md) — roadmap MVP et backlog
- [`ARBORESCENCE.md`](./ARBORESCENCE.md) — arborescence fichier par fichier

## Licence

MIT — voir [`LICENSE`](./LICENSE).
