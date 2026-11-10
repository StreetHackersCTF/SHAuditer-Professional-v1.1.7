#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "[!] Python venv support is required. On Kali/Debian install: sudo apt install python3-venv"
  exit 1
fi

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "[+] Creating isolated SHAuditer Python environment..."
  python3 -m venv "$ROOT/.venv"
fi

"$ROOT/.venv/bin/python" -m pip install --upgrade pip >/dev/null
"$ROOT/.venv/bin/python" -m pip install -e .

chmod +x "$ROOT/SHAuditer" "$ROOT/SHAuditer-gui"
mkdir -p "$ROOT/reports"

printf '\nSHAuditer v1.1.7 installed in %s/.venv\n' "$ROOT"
printf 'CLI:       %s/SHAuditer doctor\n' "$ROOT"
printf 'Graphical: %s/SHAuditer gui\n' "$ROOT"
printf 'Reports:   %s/reports/<AUDIT-ID>/\n' "$ROOT"
printf '\nThe dashboard binds to 127.0.0.1 only by default.\n'
printf 'External security tools are intentionally not installed automatically.\n'
