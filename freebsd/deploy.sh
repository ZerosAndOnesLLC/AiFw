#!/bin/sh
# AiFw Deploy — pull latest, build, deploy binaries + UI, restart services
# Usage: ssh root@<appliance> 'sh /root/AiFw/freebsd/deploy.sh'
#   or locally: sh freebsd/deploy.sh

set -e

REPO_DIR="/root/AiFw"
BINS="aifw aifw-api aifw-daemon aifw-setup aifw-tui"
BIN_DIR="/usr/local/sbin"
UI_DIR="/usr/local/share/aifw/ui"

echo "============================================"
echo "  AiFw Deploy"
echo "============================================"
echo ""

# --- Ensure we're in the repo ---
if [ ! -f "$REPO_DIR/Cargo.toml" ]; then
    echo "ERROR: Repo not found at $REPO_DIR"
    echo "Run: git clone https://github.com/ZerosAndOnesLLC/AiFw.git $REPO_DIR"
    exit 1
fi

cd "$REPO_DIR"

# --- Ensure cargo is available ---
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo not found. Install rust first:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    exit 1
fi

# --- Ensure dependencies ---
for pkg in kea sudo unbound; do
    if ! pkg info -q "$pkg" 2>/dev/null; then
        echo "Installing $pkg..."
        pkg install -y "$pkg"
    fi
done

# Ensure unbound directory has correct ownership
if [ -d /var/unbound ]; then
    chown -R unbound:unbound /var/unbound
fi

# --- Pull latest ---
echo "[1/5] Pulling latest..."
git pull
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
echo "  Version: $VERSION"
echo ""

# --- Build Rust ---
echo "[2/5] Building Rust (release)..."
cargo build --release 2>&1 | tail -3
echo ""

# --- Build UI ---
echo "[3/5] Building UI..."
cd aifw-ui
npm ci --silent 2>&1 | tail -1
npm run build 2>&1 | tail -3
cd "$REPO_DIR"
echo ""

# --- Stop services ---
echo "[4/5] Deploying..."
service aifw_api stop 2>/dev/null || true
service aifw_daemon stop 2>/dev/null || true
sleep 1

# Copy binaries
for bin in $BINS; do
    cp "target/release/$bin" "$BIN_DIR/$bin"
    chmod 755 "$BIN_DIR/$bin"
done
echo "  Binaries installed to $BIN_DIR"

# Copy UI
cp -a aifw-ui/out/* "$UI_DIR/"
echo "  UI deployed to $UI_DIR"

# Ensure permissions
chown -R aifw:aifw /var/db/aifw 2>/dev/null || true
chown -R aifw:aifw /var/log/aifw 2>/dev/null || true

# Ensure sudoers for pfctl
if [ ! -f /usr/local/etc/sudoers.d/aifw ]; then
    mkdir -p /usr/local/etc/sudoers.d
    echo 'aifw ALL=(ALL) NOPASSWD: /sbin/pfctl' > /usr/local/etc/sudoers.d/aifw
    chmod 440 /usr/local/etc/sudoers.d/aifw
    echo "  Sudoers configured"
fi

echo ""

# --- Restart services ---
echo "[5/5] Restarting services..."
service aifw_daemon start 2>/dev/null || echo "  WARNING: aifw_daemon not configured"
service aifw_api start 2>/dev/null || echo "  WARNING: aifw_api not configured"
sleep 2

# --- Verify ---
echo ""
echo "============================================"
echo "  Deploy complete — v$VERSION"
echo "============================================"
echo ""
service aifw_daemon status 2>&1 || true
service aifw_api status 2>&1 || true
echo ""
