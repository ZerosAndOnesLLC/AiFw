#!/bin/sh
# AiFw Local Build — run this on a FreeBSD machine to build the ISO + IMG
# Usage: ./build-local.sh [version]
#   version defaults to the value in Cargo.toml

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() {
    echo "ERROR: $1" >&2
    exit 1
}

# --- Must be FreeBSD ---
if [ "$(uname -s)" != "FreeBSD" ]; then
    die "This script must be run on FreeBSD"
fi

# --- Must be root ---
if [ "$(id -u)" -ne 0 ]; then
    die "Must be run as root (try: sudo sh $0)"
fi

# --- Install dependencies ---
echo "=== [1/6] Installing dependencies ==="
pkg install -y curl git gmake node24 npm-node24

# Install Rust via rustup if not present
if ! command -v cargo >/dev/null 2>&1; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"
fi

# --- Clone or update repo ---
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "=== Cloning repository ==="
    git clone https://github.com/ZerosAndOnesLLC/AiFw.git "$PROJECT_ROOT"
fi

cd "$PROJECT_ROOT"

# --- Extract version ---
VERSION="${1:-$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')}"
echo ""
echo "  Building AiFw v${VERSION}"
echo ""

# --- Build Web UI static export ---
echo "=== [2/6] Building Web UI static export ==="
cd "$PROJECT_ROOT/aifw-ui"
npm ci
npm run build
cd "$PROJECT_ROOT"

# --- Build Rust binaries ---
echo "=== [3/6] Building Rust binaries (release) ==="
cargo build --release

# --- Stage build inputs ---
echo "=== [4/6] Staging build inputs ==="
mkdir -p "$SCRIPT_DIR/release"
for bin in aifw aifw-daemon aifw-api aifw-tui aifw-setup; do
    cp "$PROJECT_ROOT/target/release/${bin}" "$SCRIPT_DIR/release/${bin}"
done

rm -rf "$SCRIPT_DIR/ui-export"
cp -a "$PROJECT_ROOT/aifw-ui/out" "$SCRIPT_DIR/ui-export"

# --- Build ISO + IMG ---
echo "=== [5/6] Building ISO + IMG ==="
sh "$SCRIPT_DIR/build-iso.sh" "$VERSION" amd64

# --- Done ---
echo ""
echo "=== [6/6] Complete ==="
echo ""
ls -lh /usr/obj/aifw-iso/output/
echo ""
echo "Files are in /usr/obj/aifw-iso/output/"
