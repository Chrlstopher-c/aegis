<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/readme/banner-dark.svg">
    <img src="docs/readme/banner-light.svg" alt="Aegis, real-time antivirus for Linux desktops" width="100%">
  </picture>
</p>

# Aegis

Real-time antivirus for a Linux desktop. Two engines in one daemon: YARA signatures, and behaviour detection fed by the kernel through fanotify. It runs on your machine, talks to nothing on the internet, and opens no network port.

> Status: working MVP. Real-time daemon, quarantine, anti-ransomware canaries, dashboard, systemd service. eBPF probes are the next big piece. Last active June 2026.

<p align="center">
  <img src="docs/readme/shots/dashboard.png" alt="Aegis dashboard showing four detections from an EICAR test file" width="100%">
</p>
<p align="center"><sub>An EICAR test file dropped in <code>/tmp</code> and <code>/dev/shm</code>, then executed. The YARA rule and the "executed from a writable location" heuristic both fire, and the file is quarantined.</sub></p>

## Why I built it

On Linux you choose between ClamAV, which knows signatures and nothing about behaviour, and Kubernetes-grade eBPF tools like Falco or Tetragon that nobody wants to drive from a laptop with YAML. I wanted one program that does both, with a dashboard a human can read, and that never phones home.

## What it does

- Watches every program execution on `/`, `/tmp` and `/dev/shm` through fanotify, and can block it before it runs.
- Scans files and memory with YARA-X rules, the pure Rust build of YARA.
- Catches ransomware with canary files. The first write to a canary kills the writer with SIGKILL. Measured on a 2 000-file test set: the process died 86 µs after touching the canary, with 17 files encrypted.
- Flags reverse shells and binaries launched from writable directories, each mapped to a MITRE ATT&CK id.
- Quarantines automatically above a severity threshold, keeps the metadata, restores on demand.
- Shows everything live in a dashboard grouped by application, with a tray icon that turns red.

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/readme/how-it-works-dark.svg">
    <img src="docs/readme/how-it-works-light.svg" alt="Aegis architecture: kernel probes, detection, response and a local dashboard" width="100%">
  </picture>
</p>

The daemon runs as a systemd service with only the capabilities fanotify needs. Kernel events go through the probes, the detection engines return a verdict, and the policy decides what happens: log it, defer it to you, or quarantine on the spot. A WebSocket bridge on `127.0.0.1:8787` feeds the dashboard, which runs unprivileged in your session and only sends commands back (quarantine this, restore that, exclude this path). The UI never touches the filesystem itself.

## Quick start

You need Rust stable, Bun and a distribution with systemd.

```sh
cargo build --release
sudo ./packaging/install.sh            # binary + unit with minimal capabilities
sudo systemctl enable --now aegis
journalctl -u aegis -f                 # watch the daemon think

cd ui && WEBKIT_DISABLE_DMABUF_RENDERER=1 bun run tauri dev   # the dashboard window
```

Want to see it catch something? Put the [EICAR test string](https://www.eicar.org/download-anti-malware-testfile/) in a file, make it executable, run it. It is harmless, and every antivirus on earth recognises it.

Without systemd: `sudo ./scripts/start.sh`. Without root, just to look at the UI: `./target/debug/aegis-daemon --demo`.

## Help

| Symptom | Cause | Fix |
|---|---|---|
| White window instead of the dashboard | WebKitGTK on Wayland with some Nvidia drivers | `WEBKIT_DISABLE_DMABUF_RENDERER=1`. Put it in the `.desktop` file too, the launcher does not inherit your shell. |
| `unknown variant` errors in the UI | the service still runs an older binary than the one you built | `sudo ./packaging/install.sh && sudo systemctl restart aegis` |
| "degraded mode" at startup | not root, so no fanotify | run through systemd or `sudo` |
| `bun run bundle` fails on `.relr.dyn` | linuxdeploy ships a strip too old for that section | the script already sets `NO_STRIP=true`, keep it |
| daemon dies when you harden the unit | yara-x embeds wasmtime, which needs W+X memory | `MemoryDenyWriteExecute` stays off on purpose |

Never build as root. Build as your user, then install with sudo.

Found a detection that looks wrong, or a miss? Open an issue with the `journalctl -u aegis` lines around it and the file involved.

## Where it stands

Works today: fanotify exec hooks, YARA-X scan and quarantine (EICAR caught in about 1 ms), canaries, exec heuristics, sensitive-file access monitoring, graded policy with exclusions, dashboard and tray.

Not there yet: eBPF probes (fileless execution, privilege escalation, outbound C2 connections), entropy-based ransomware detection beyond canaries, a panel for pending decisions, native notifications, self-protection of the daemon. The UI is in French for now.

Tests: `cargo test` at the workspace root. The scripts in `tests/redteam/` replay the EICAR and ransomware scenarios end to end against a live daemon.

## Stack

| Layer | Choice |
|---|---|
| Daemon | Rust, tokio, nix (fanotify), systemd |
| Signatures | yara-x 0.11 |
| Response | quarantine store, SIGKILL / SIGSTOP |
| IPC | Unix socket + WebSocket, localhost only |
| Dashboard | Tauri v2, React 19, TypeScript, Tailwind 4 |

## Project docs

`ARCHITECTURE.md` (domains and module boundaries), `STATE.md` (current state and decisions), `TODO.md` (roadmap), `SECURITY.md`, `ARBORESCENCE.md` (one line per file).

## Licence

MIT. See `LICENSE`.
