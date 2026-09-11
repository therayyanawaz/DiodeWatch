#!/usr/bin/env bash
# =============================================================================
# DiodeWatch — offline environment setup
#
#   bash setup/setup.sh              # online: pip installs from PyPI
#   bash setup/setup.sh --offline    # air-gapped: install from setup/wheels/
#   bash setup/setup.sh --check      # verify the env only (no changes)
#
# What it does, in order:
#   1. find a usable system Python (3.11+ preferred, 3.10 tolerated)
#   2. create/refresh the local .venv (no sudo, no system packages touched)
#   3. install requirements.txt — offline from setup/wheels/ when asked, or
#      when no network is reachable (auto-fallback)
#   4. verify the toolchain imports and print a summary
#
# No step needs root. Nothing outside the repo directory is modified.
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO/.venv"
WHEELS="$REPO/setup/wheels"
REQ="$REPO/requirements.txt"

# --- Windows Git-Bash quirk: venv python is Scripts/python.exe, not bin/ -----
IS_WINDOWS=0
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
esac
PY_BIN="$VENV/bin/python"
[ "$IS_WINDOWS" = "1" ] && PY_BIN="$VENV/Scripts/python.exe"

# uv-managed venvs ship without pip; fall back to `uv pip install` when present.
# (--python belongs to the `install` subcommand on uv >= 0.12, so the prefix
# below already includes `install`; call sites must NOT repeat it.)
PIP=($PY_BIN -m pip install)
if ! "$PY_BIN" -m pip --version >/dev/null 2>&1; then
  if command -v uv >/dev/null 2>&1; then
    PIP=(uv pip install --python "$PY_BIN")
  elif "$PY_BIN" -m ensurepip --version >/dev/null 2>&1; then
    "$PY_BIN" -m ensurepip --upgrade >/dev/null 2>&1 || true
    "$PY_BIN" -m pip --version >/dev/null 2>&1 || PIP=()
  else
    PIP=()
  fi
fi

OFFLINE=0
CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=1 ;;
    --check)   CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (use --offline | --check)"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }

# --- 1. find python ----------------------------------------------------------
# The wheelhouse is built for CPython 3.11 (README §Offline bundle), so when
# --offline is requested the interpreter MUST be 3.11 (any launcher name —
# on Windows versioned exes are often not on PATH, so also probe `python`).
find_python() {
  local cands=("python3.11" "py -3.11" "python3" "python" "py" \
               "python3.12" "py -3.12" "python3.13" "py -3.13" "py -3.10")
  local req='import sys; assert sys.version_info[:2] >= (3, 10)'
  [ "$OFFLINE" = "1" ] && req='import sys; assert sys.version_info[:2] == (3, 11)'
  local cand
  for cand in "${cands[@]}"; do
    $cand -c "$req" 2>/dev/null && { echo "$cand"; return 0; }
  done
  return 1
}

# --- 2/3. create venv + install ----------------------------------------------
if [ "$CHECK_ONLY" = "1" ]; then
  [ -x "$PY_BIN" ] || die "no venv found at $VENV — run: bash setup/setup.sh"
else
  say "Looking for a system Python (3.10+, 3.11 preferred)"
  PY="$(find_python)" || die "no suitable Python found on PATH — install Python 3.11 first (see README §Offline bundle)"
  ok "using $($PY -c 'import sys; print(sys.executable, sys.version.split()[0])')"

  # a venv built with a different minor than the chosen interpreter cannot use
  # the wheelhouse — recreate it rather than fail deep inside pip
  if [ -x "$PY_BIN" ]; then
    VENV_MINOR="$($PY_BIN -c 'import sys; print(sys.version_info[1])' 2>/dev/null || echo '?')"
    PY_MINOR="$($PY -c 'import sys; print(sys.version_info[1])')"
    if [ "$VENV_MINOR" != "$PY_MINOR" ]; then
      warn ".venv is Python 3.$VENV_MINOR but selected interpreter is 3.$PY_MINOR — recreating"
      rm -rf "$VENV"
    fi
  fi

  if [ ! -x "$PY_BIN" ]; then
    say "Creating virtual environment at .venv (user-owned, no sudo)"
    "$PY" -m venv "$VENV" || die "python -m venv failed (on Debian/Ubuntu: sudo apt install python3-venv, then re-run)"
  else
    ok ".venv already exists — reusing"
  fi
fi

[ ${#PIP[@]} -gt 0 ] || die ".venv has no pip and uv is not installed —\n      either: $PY_BIN -m ensurepip --upgrade\n      or:    install uv (https://docs.astral.sh/uv/) and re-run"

# network probe: only trusted when --offline was NOT passed
NET_OK=0
if [ "$OFFLINE" = "0" ]; then
  if "$PY_BIN" - <<'EOF' 2>/dev/null
import socket, sys
try:
    socket.create_connection(("pypi.org", 443), timeout=4).close()
    sys.exit(0)
except OSError:
    sys.exit(1)
EOF
  then NET_OK=1; fi
fi

if [ "$CHECK_ONLY" = "1" ]; then
  say "Checking installed packages"
  "${PIP[@]}" -q --no-index -r "$REQ" --dry-run 2>/dev/null \
    && ok "all requirements satisfied" \
    || { warn "some requirements missing"; NET_OK=1; }
else
  if [ "$OFFLINE" = "1" ] || [ "$NET_OK" = "0" ]; then
    [ "$OFFLINE" = "0" ] && warn "no network reachable — falling back to offline wheelhouse"
    [ -d "$WHEELS" ] && [ -n "$(ls -A "$WHEELS" 2>/dev/null)" ] \
      || die "offline install requested but $WHEELS is empty — fill it on a networked machine (see README §Offline bundle)"
    say "Installing requirements OFFLINE from setup/wheels/"
    "${PIP[@]}" --no-index --find-links "$WHEELS" -r "$REQ" \
      || die "offline install failed — wheels missing for this platform? (see README §Offline bundle)"
  else
    say "Installing requirements from PyPI"
    "${PIP[@]}" -r "$REQ" \
      || die "online install failed — if this machine is air-gapped, use: bash setup/setup.sh --offline"
  fi
fi

# --- 4. verify ----------------------------------------------------------------
say "Verifying the toolchain imports"
"$PY_BIN" - <<'EOF' || die "import verification failed"
import importlib.util
import sys
missing = [m for m in ("pandas", "numpy", "polars", "sklearn", "lightgbm",
                       "scapy", "streamlit", "fastapi", "pyarrow")
           if importlib.util.find_spec(m) is None]
print("  core imports: " + ("OK" if not missing else f"MISSING {missing}"))
sys.exit(1 if missing else 0)
EOF

say "Setup complete"
echo "    python : $PY_BIN"
echo "    next   : bash run_demo.sh        (full demo)"
echo "             bash run_rehearsal.sh   (headless pre-flight)"
[ "$IS_WINDOWS" = "1" ] && echo "    note   : run these from Git Bash (bundled with Git for Windows)"
