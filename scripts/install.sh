#!/usr/bin/env bash
# KING REAPER X installer for Kali Linux / Debian / Ubuntu.
#
# The framework is standard-library only, so this script never installs Python
# packages: it verifies the interpreter, creates a private config directory and
# drops a launcher on PATH. Any optional extras are opt-in.
set -euo pipefail

APP_NAME="king-reaper-x"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
WRAPPER="$BIN_DIR/reaper-x"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '%s[!]%s %s\n' "$YEL" "$RST" "$1"; }
die()  { printf '%s[x]%s %s\n' "$RED" "$RST" "$1" >&2; exit 1; }

printf '%s\n' "KING REAPER X - installer"
printf '%s\n' "target: $HERE"

# ---------------------------------------------------------------- interpreter
PY=""
for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9; do
    if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
done
[ -n "$PY" ] || die "python3 not found. Install it with: sudo apt install -y python3"

PYVER="$($PY -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PYMAJ="$($PY -c 'import sys; print(sys.version_info[0])')"
PYMIN="$($PY -c 'import sys; print(sys.version_info[1])')"
if [ "$PYMAJ" -lt 3 ] || { [ "$PYMAJ" -eq 3 ] && [ "$PYMIN" -lt 8 ]; }; then
    die "Python $PYVER found, but 3.8 or newer is required."
fi
ok "python $PYVER at $(command -v "$PY")"

# ------------------------------------------------------------------- stdlib
# Verify the standard-library modules the framework imports are present.
# Some minimal distros ship python3 without ssl or sqlite3.
MISSING="$($PY - <<'PYCODE'
import importlib
missing = []
for mod in ("socket", "ssl", "sqlite3", "json", "argparse",
            "http.server", "urllib.request", "concurrent.futures", "ipaddress"):
    try:
        importlib.import_module(mod)
    except Exception:
        missing.append(mod)
print(",".join(sorted(set(missing))))
PYCODE
)"
if [ -n "$MISSING" ]; then
    warn "missing standard-library modules: $MISSING"
    warn "on Debian/Ubuntu: sudo apt install -y python3-full"
    warn "on Kali the package is normally already installed"
fi

# ------------------------------------------------------- optional tooling
if command -v openssl >/dev/null 2>&1; then
    ok "openssl present (TLS tests enabled)"
else
    warn "openssl not found - TLS smoke tests will be skipped (sudo apt install -y openssl)"
fi

# ---------------------------------------------------------------- directories
CFG="${REAPER_CONFIG_DIR:-$HOME/.$APP_NAME}"
mkdir -p "$CFG" && chmod 700 "$CFG"
ok "config directory: $CFG (0700)"

# ------------------------------------------------------------------ launcher
mkdir -p "$BIN_DIR"
cat > "$WRAPPER" <<WRAP
#!/usr/bin/env bash
exec "$(command -v "$PY")" "$HERE/main.py" "\$@"
WRAP
chmod 755 "$WRAPPER"
ok "launcher: $WRAPPER"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) warn "$BIN_DIR is not on PATH. Add this to ~/.bashrc:"
       printf '    export PATH="%s:$PATH"\n' "$BIN_DIR" ;;
esac

# --------------------------------------------------------------------- check
cd "$HERE"
if "$PY" main.py --version >/dev/null 2>&1; then
    ok "framework responds to --version"
else
    die "the framework failed to start. Run '$PY main.py --version' to see why."
fi

printf '\n'
printf '%sInstallation complete.%s\n' "$GRN" "$RST"
printf '\n'
printf '  %sreaper-x --help%s              list every command\n' "$DIM" "$RST"
printf '  %sreaper-x doctor%s              verify the environment\n' "$DIM" "$RST"
printf '  %sreaper-x%s                     interactive menu\n' "$DIM" "$RST"
printf '  %sreaper-x dashboard%s           command centre on 127.0.0.1:8899\n' "$DIM" "$RST"
printf '\n'
printf 'First run asks you to accept the authorized-use terms once.\n'
printf 'Run the test suite with: ./scripts/run_tests.sh\n'
