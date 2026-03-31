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
# Ensure cargo is in PATH (rustup installs to $HOME/.cargo/bin)
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
cargo build --release

# Build TrafficCop (reverse proxy)
TRAFFICCOP_DIR="$PROJECT_ROOT/../trafficcop"
if [ ! -d "$TRAFFICCOP_DIR" ]; then
    echo "Cloning TrafficCop..."
    git clone https://github.com/ZerosAndOnesLLC/TrafficCop.git "$TRAFFICCOP_DIR"
fi
echo "Building TrafficCop..."
cd "$TRAFFICCOP_DIR"
git pull 2>/dev/null || true
cargo build --release
cd "$PROJECT_ROOT"

# Build rDHCP (DHCP server)
RDHCP_DIR="$PROJECT_ROOT/../rDHCP"
if [ ! -d "$RDHCP_DIR" ]; then
    echo "Cloning rDHCP..."
    git clone https://github.com/ZerosAndOnesLLC/rDHCP.git "$RDHCP_DIR"
fi
echo "Building rDHCP..."
cd "$RDHCP_DIR"
git pull 2>/dev/null || true
cargo build --release
cd "$PROJECT_ROOT"

# Build rDNS (DNS server)
RDNS_DIR="$PROJECT_ROOT/../rDNS"
if [ ! -d "$RDNS_DIR" ]; then
    echo "Cloning rDNS..."
    git clone https://github.com/ZerosAndOnesLLC/rDNS.git "$RDNS_DIR"
fi
echo "Building rDNS..."
cd "$RDNS_DIR"
git pull 2>/dev/null || true
cargo build --release
cd "$PROJECT_ROOT"

# --- Stage build inputs ---
echo "=== [4/6] Staging build inputs ==="
mkdir -p "$SCRIPT_DIR/release"
for bin in aifw aifw-daemon aifw-api aifw-tui aifw-setup; do
    cp "$PROJECT_ROOT/target/release/${bin}" "$SCRIPT_DIR/release/${bin}"
done
# Stage TrafficCop binary if built
if [ -f "$TRAFFICCOP_DIR/target/release/trafficcop" ]; then
    cp "$TRAFFICCOP_DIR/target/release/trafficcop" "$SCRIPT_DIR/release/trafficcop"
fi
# Stage rDHCP binary if built
if [ -f "$RDHCP_DIR/target/release/rdhcpd" ]; then
    cp "$RDHCP_DIR/target/release/rdhcpd" "$SCRIPT_DIR/release/rdhcpd"
fi
# Stage rDNS binaries if built
if [ -f "$RDNS_DIR/target/release/rdns" ]; then
    cp "$RDNS_DIR/target/release/rdns" "$SCRIPT_DIR/release/rdns"
fi
if [ -f "$RDNS_DIR/target/release/rdns-control" ]; then
    cp "$RDNS_DIR/target/release/rdns-control" "$SCRIPT_DIR/release/rdns-control"
fi

rm -rf "$SCRIPT_DIR/ui-export"
cp -a "$PROJECT_ROOT/aifw-ui/out" "$SCRIPT_DIR/ui-export"

# --- Build update tarball ---
echo "=== [5/8] Building update tarball ==="
TARBALL_DIR="/tmp/aifw-update-${VERSION}-amd64"
rm -rf "$TARBALL_DIR"
mkdir -p "$TARBALL_DIR/bin" "$TARBALL_DIR/ui"
for bin in aifw aifw-daemon aifw-api aifw-tui aifw-setup; do
    cp "$PROJECT_ROOT/target/release/${bin}" "$TARBALL_DIR/bin/"
done
# Include TrafficCop in update tarball
if [ -f "$TRAFFICCOP_DIR/target/release/trafficcop" ]; then
    cp "$TRAFFICCOP_DIR/target/release/trafficcop" "$TARBALL_DIR/bin/"
fi
# Include rDHCP in update tarball
if [ -f "$RDHCP_DIR/target/release/rdhcpd" ]; then
    cp "$RDHCP_DIR/target/release/rdhcpd" "$TARBALL_DIR/bin/"
fi
# Include rDNS in update tarball
if [ -f "$RDNS_DIR/target/release/rdns" ]; then
    cp "$RDNS_DIR/target/release/rdns" "$TARBALL_DIR/bin/"
fi
if [ -f "$RDNS_DIR/target/release/rdns-control" ]; then
    cp "$RDNS_DIR/target/release/rdns-control" "$TARBALL_DIR/bin/"
fi
cp -a "$PROJECT_ROOT/aifw-ui/out/"* "$TARBALL_DIR/ui/"
echo "$VERSION" > "$TARBALL_DIR/version"
OUTPUTDIR="/usr/obj/aifw-iso/output"
mkdir -p "$OUTPUTDIR"
tar -C /tmp -cJf "${OUTPUTDIR}/aifw-update-${VERSION}-amd64.tar.xz" "aifw-update-${VERSION}-amd64"
cd "$OUTPUTDIR"
sha256 "aifw-update-${VERSION}-amd64.tar.xz" > "aifw-update-${VERSION}-amd64.tar.xz.sha256"
rm -rf "$TARBALL_DIR"
echo "  Update tarball: ${OUTPUTDIR}/aifw-update-${VERSION}-amd64.tar.xz"
ls -lh "${OUTPUTDIR}/aifw-update-${VERSION}-amd64.tar.xz"
cd "$PROJECT_ROOT"

# --- Build ISO + IMG ---
echo "=== [6/8] Building ISO + IMG ==="
sh "$SCRIPT_DIR/build-iso.sh" "$VERSION" amd64

# --- Cleanup intermediate files ---
echo "=== [7/8] Cleaning up intermediate files ==="
rm -rf "$SCRIPT_DIR/release"
rm -rf "$SCRIPT_DIR/ui-export"
# Remove staging dirs but keep output with the final artifacts
for d in stage dist iso efi-stage; do
    if [ -d "/usr/obj/aifw-iso/$d" ]; then
        chflags -R noschg "/usr/obj/aifw-iso/$d" 2>/dev/null || true
        rm -rf "/usr/obj/aifw-iso/$d"
    fi
done
echo "  Removed staged binaries, UI export, and build intermediates"

# --- Done ---
echo ""
echo "=== [8/8] Complete ==="
echo ""
ls -lh /usr/obj/aifw-iso/output/
echo ""
echo "Files are in /usr/obj/aifw-iso/output/"
