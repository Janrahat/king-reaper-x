#!/usr/bin/env bash
# KING REAPER X installer for Termux (Android).
#
# Termux specifics this script respects:
#   * no root, ever — everything lands under $PREFIX and $HOME
#   * python is a package, not a system binary
#   * the framework needs no pip packages, so nothing is compiled
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '%s[!]%s %s\n' "$YEL" "$RST" "$1"; }
die()  { printf '%s[x]%s %s\n' "$RED" "$RST" "$1" >&2; exit 1; }

printf '%s\n' "KING REAPER X — Termux installer"

# --------------------------------------------------------------- environment
if [ -z "${PREFIX:-}" ] || [ ! -d "${PREFIX:-/nonexistent}" ]; then
    die "This does not look like Termux (\$PREFIX is unset).
    On Kali/Debian/Ubuntu use ./scripts/install.sh instead."
fi
ok "Termux prefix: $PREFIX"

if [ "$(id -u)" = "0" ]; then
    warn "running as root inside Termux is not supported by upstream; continuing anyway"
fi

# ------------------------------------------------------------------- python
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    warn "python is not installed; installing it now"
    pkg update -y || warn "pkg update failed — continuing"
    pkg install -y python || die "pkg install python failed. Run 'pkg update && pkg install python' manually."
fi
PY="$(command -v python3 || command -v python)"
[ -n "$PY" ] || die "no python interpreter found after install"
PYVER="$($PY -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
ok "python $PYVER at $PY"

PYMIN="$($PY -c 'import sys; print(sys.version_info[1])')"
if [ "$PYMIN" -lt 8 ]; then
    die "Python $PYVER is too old; run 'pkg upgrade python' (3.8+ required)."
fi

# ------------------------------------------------------------- stdlib checks
# Termux's python ships ssl and sqlite3, but a broken install is common after
# an interrupted upgrade. Detect it here instead of at first scan.
BROKEN="$($PY - <<'PYCODE'
import importlib
bad = []
for mod in ("ssl", "sqlite3", "socket", "http.server"):
    try:
        importlib.import_module(mod)
    except Exception:
        bad.append(mod)
print(",".join(bad))
PYCODE
)"
if [ -n "$BROKEN" ]; then
    warn "these standard-library modules fail to import: $BROKEN"
    warn "try: pkg reinstall python"
    # cryptography/ssl problems are the usual cause on Termux; the framework
    # degrades gracefully (TLS module reports a clean error) rather than lying.
fi

# --------------------------------------------------------------- openssl (opt)
if command -v openssl >/dev/null 2>&1; then
    ok "openssl present (TLS smoke tests enabled)"
else
    warn "openssl not found — TLS smoke tests will be skipped."
    warn "install with: pkg install -y openssl   (optional, not required to run)"
fi

# ---------------------------------------------------------- optional helpers
# NOTE: no pip package is required. These are only for the *optional* extras
# some users want; the core framework never imports them.
for pkgname in dnsutils whois; do
    if command -v "${pkgname}" >/dev/null 2>&1; then
        ok "optional helper present: $pkgname"
    fi
done

# ---------------------------------------------------------------- directories
CFG="${REAPER_CONFIG_DIR:-$HOME/.king-reaper-x}"
mkdir -p "$CFG" && chmod 700 "$CFG"
ok "config directory: $CFG (0700)"

# ------------------------------------------------------------------ launcher
BIN_DIR="$PREFIX/bin"
WRAPPER="$BIN_DIR/reaper-x"
cat > "$WRAPPER" <<WRAP
#!/data/data/com.termux/files/usr/bin/bash
exec "$PY" "$HERE/main.py" "\$@"
WRAP
chmod 755 "$WRAPPER"
ok "launcher: $WRAPPER  (just type: reaper-x)"

# --------------------------------------------------------------------- check
cd "$HERE"
if "$PY" main.py --version >/dev/null 2>&1; then
    ok "framework responds to --version"
else
    die "the framework failed to start. Run '$PY main.py --version' to see why."
fi

printf '\n%sInstallation complete.%s\n\n' "$GRN" "$RST"
printf '  reaper-x --help          list every command\n'
printf '  reaper-x doctor          verify this Termux environment\n'
printf '  reaper-x                 interactive menu\n'
printf '  reaper-x dashboard       command centre (127.0.0.1:8899)\n'
printf '\n'
printf 'Note: Termux cannot bind privileged ports and has no root by default.\n'
printf 'Port scans of remote hosts need authorization — pass --authorized.\n'
