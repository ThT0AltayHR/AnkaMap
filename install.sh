#!/usr/bin/env bash
# Installs Anka's CLI launchers (`anka`, `anka-help`) onto your PATH so
# you can run them from any directory without `cd` or `python3` prefixes.
#
# Usage:
#   cd anka && bash install.sh
#
# What it does:
#   1. chmod +x the launcher scripts in bin/
#   2. Symlinks bin/anka and bin/anka-help into a directory already on
#      your PATH (prefers ~/.local/bin, falls back to /usr/local/bin
#      with sudo if writable, otherwise prints manual instructions).

set -e
ANKA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$ANKA_DIR/bin/anka" "$ANKA_DIR/bin/anka-help"

TARGET_DIR=""
if [ -d "$HOME/.local/bin" ] || mkdir -p "$HOME/.local/bin" 2>/dev/null; then
    TARGET_DIR="$HOME/.local/bin"
elif [ -w "/usr/local/bin" ]; then
    TARGET_DIR="/usr/local/bin"
fi

if [ -z "$TARGET_DIR" ]; then
    echo "Could not find a writable directory on PATH."
    echo "Add this to your shell profile instead:"
    echo "  export PATH=\"$ANKA_DIR/bin:\$PATH\""
    exit 0
fi

ln -sf "$ANKA_DIR/bin/anka" "$TARGET_DIR/anka"
ln -sf "$ANKA_DIR/bin/anka-help" "$TARGET_DIR/anka-help"

echo "Installed: anka, anka-help -> $TARGET_DIR"
case ":$PATH:" in
    *":$TARGET_DIR:"*)
        echo "PATH already includes $TARGET_DIR -- you can run 'anka' and 'anka-help' now."
        ;;
    *)
        echo "Add this to your shell profile (~/.bashrc or ~/.zshrc) then restart your shell:"
        echo "  export PATH=\"$TARGET_DIR:\$PATH\""
        ;;
esac
