#!/usr/bin/env bash
# Redémarre le daemon Aegis (stop puis start, logs reset par start).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT/scripts/stop.sh"
"$ROOT/scripts/start.sh"
