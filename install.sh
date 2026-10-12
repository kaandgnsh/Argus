#!/bin/sh
# ARGUS installer — creates an isolated virtual environment.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

die() {
    printf '[ARGUS] ERROR: %s\n' "$1" >&2
    exit 1
}

PYTHON=$(command -v python3 || true)
[ -n "$PYTHON" ] || die "python3 was not found. Install Python 3.10 or newer."

"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "Python 3.10 or newer is required."

VENV_DIR="$SCRIPT_DIR/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"

if [ ! -x "$VENV_PYTHON" ]; then
    printf '[ARGUS] Creating virtual environment at %s\n' "$VENV_DIR"
    "$PYTHON" -m venv "$VENV_DIR" \
        || die "Could not create the virtual environment. Install your distribution's venv package (often python3-venv) and retry."
fi

printf '[ARGUS] Installing required dependencies into .venv\n'
"$VENV_PYTHON" -m pip install --upgrade pip
"$VENV_PYTHON" -m pip install -r "$SCRIPT_DIR/requirements.txt"

printf '\n[ARGUS] Optional dependencies can enable extra metadata and integrations.\n'
printf 'Review requirements-optional.txt before proceeding. Install them? [y/N]: '
answer=''
read -r answer || true

case "$answer" in
    y|Y|yes|YES|Yes)
        "$VENV_PYTHON" -m pip install -r "$SCRIPT_DIR/requirements-optional.txt"
        ;;
    *)
        printf '[ARGUS] Optional dependencies skipped.\n'
        ;;
esac

printf '\n[ARGUS] Installation complete.\n'
printf 'Activate the environment with:\n'
printf '  . "%s/bin/activate"\n' "$VENV_DIR"
printf 'Then run:\n'
printf '  python argus.py --version\n'
