#!/bin/bash
# install.sh — Install anzen system-wide
set -euo pipefail

INSTALL_BIN="/usr/local/bin/anzen"
INSTALL_DIR="/usr/local/lib/anzen"
COMPLETION_DIR_BASH="/etc/bash_completion.d"
COMPLETION_DIR_ZSH="/usr/local/share/zsh/site-functions"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: install.sh must be run as root (or with sudo)" >&2
    exit 1
fi

echo "Installing anzen to $INSTALL_DIR ..."

# Copy library + checks
mkdir -p "$INSTALL_DIR"
cp -r "$SCRIPT_DIR/lib" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/anzen.sh" "$INSTALL_DIR/"
[ -f "$SCRIPT_DIR/anzen.conf.example" ] && cp "$SCRIPT_DIR/anzen.conf.example" "$INSTALL_DIR/"

# Create reports dir
mkdir -p "$INSTALL_DIR/reports"

# Create wrapper in PATH
cat > "$INSTALL_BIN" <<WRAPPER
#!/bin/bash
exec bash "$INSTALL_DIR/anzen.sh" "\$@"
WRAPPER
chmod +x "$INSTALL_BIN"
echo "  Installed binary: $INSTALL_BIN"

# Bash completion
if [ -d "$COMPLETION_DIR_BASH" ]; then
    cp "$SCRIPT_DIR/completions/anzen.bash" "$COMPLETION_DIR_BASH/anzen"
    echo "  Installed bash completion: $COMPLETION_DIR_BASH/anzen"
fi

# Zsh completion
if [ -d "$COMPLETION_DIR_ZSH" ]; then
    cp "$SCRIPT_DIR/completions/anzen.zsh" "$COMPLETION_DIR_ZSH/_anzen"
    echo "  Installed zsh completion: $COMPLETION_DIR_ZSH/_anzen"
fi

echo ""
echo "Done. Run: anzen --help"
