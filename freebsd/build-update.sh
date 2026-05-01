#!/bin/sh
# AiFw tarball-only build — produces JUST the update tarball (no ISO/IMG).
#
# Usage:
#   sh freebsd/build-update.sh [version]
#
# Output:
#   ${AIFW_STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz
#   ${AIFW_STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz.sha256
#
# AIFW_STAGE_OUT defaults to /usr/obj/aifw-release-stage (same as build-local.sh)
# but can be overridden via the env var for non-FreeBSD test iteration that
# targets a different path (e.g. AIFW_STAGE_OUT=/tmp/aifw-out sh build-update.sh).
#
# This script must be run as root on FreeBSD.  It performs the same sanity
# checks as build-local.sh (rust toolchain, jq, manifest.json, rDNS staleness)
# and produces a tarball that is byte-identical in content and layout to the
# one build-local.sh produces — just without the ISO/IMG steps.
#
# NOTE: build-update.sh and build-local.sh share a common code path for
# the tarball-pack step.  If you modify tarball staging logic here, mirror
# the change in build-local.sh (steps [5/9]) so the two outputs stay in
# sync.  A future refactor could extract freebsd/lib-build.sh to avoid the
# duplication; for now keeping them parallel is simpler.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() {
    echo "ERROR: $1" >&2
    exit 1
}

# --- Must be FreeBSD ---
if [ "$(uname -s)" != "FreeBSD" ]; then
    die "This script must be run on FreeBSD (it invokes pkg, sha256, etc.)"
fi

# --- Must be root ---
if [ "$(id -u)" -ne 0 ]; then
    die "Must be run as root (try: sudo sh $0)"
fi

# --- Output directory ---
# Allow operator to override so test iteration can land the tarball
# in a convenient location (e.g. AIFW_STAGE_OUT=/tmp/out sh build-update.sh).
STAGE_OUT="${AIFW_STAGE_OUT:-/usr/obj/aifw-release-stage}"

# --- Install dependencies ---
echo "=== [1/6] Installing dependencies ==="
pkg install -y curl git gmake node24 npm-node24 brotli jq

# Source cargo env before checking — sudo clears PATH so even an installed
# toolchain won't be visible without this.  Same reasoning as build-local.sh.
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"
fi

echo "--- Using cargo: $(command -v cargo) ---"
cargo --version

# --- Clone or update repo ---
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "=== Cloning repository ==="
    git clone https://github.com/ZerosAndOnesLLC/AiFw.git "$PROJECT_ROOT"
fi

cd "$PROJECT_ROOT"

# --- Extract version ---
VERSION="${1:-$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')}"
echo ""
echo "  Building AiFw update tarball v${VERSION}"
echo ""

# --- Build Web UI static export ---
echo "=== [2/6] Building Web UI static export ==="
cd "$PROJECT_ROOT/aifw-ui"
npm config delete python 2>/dev/null || true
npm ci
npm run build

if [ -d out ]; then
    echo "  Pre-compressing UI text assets (br + gz)..."
    has_brotli=0
    command -v brotli >/dev/null 2>&1 && has_brotli=1
    find out -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' \
        -o -name '*.svg' -o -name '*.json' -o -name '*.txt' \
        -o -name '*.map' -o -name '*.xml' \) | while read -r f; do
        if [ "$has_brotli" -eq 1 ] && [ ! -f "${f}.br" ]; then
            brotli -q 11 -k "$f" 2>/dev/null || true
        fi
        if [ ! -f "${f}.gz" ]; then
            gzip -k -9 "$f" 2>/dev/null || true
        fi
    done
    js_orig=$(find out -name '*.js' -not -name '*.gz' -not -name '*.br' -exec stat -f%z {} + 2>/dev/null | awk '{s+=$1} END {print s}')
    js_br=$(find out -name '*.js.br' -exec stat -f%z {} + 2>/dev/null | awk '{s+=$1} END {print s}')
    if [ -n "$js_orig" ] && [ -n "$js_br" ] && [ "$js_orig" -gt 0 ]; then
        printf "  JS size: %d KB raw  ->  %d KB brotli (%d%% smaller)\n" \
            "$((js_orig / 1024))" "$((js_br / 1024))" \
            "$(( (js_orig - js_br) * 100 / js_orig ))"
    fi
fi
cd "$PROJECT_ROOT"

# --- Build Rust binaries ---
echo "=== [3/6] Building Rust binaries (release) ==="
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
echo "--- AiFw commit: $(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown) ---"
cargo build --release

# Clone-or-update a companion repo; fail loudly on pull errors.
# (Same function as in build-local.sh — keep them in sync.)
build_companion() {
    local name="$1" dir="$2" url="$3"
    if [ ! -d "$dir" ]; then
        echo "Cloning $name from $url ..."
        git clone "$url" "$dir" || {
            echo "ERROR: clone of $name failed" >&2
            exit 1
        }
    fi
    echo "--- Updating $name ---"
    ( cd "$dir" && \
        git fetch --tags origin && \
        git reset --hard origin/main ) || {
        echo "ERROR: git update of $name ($dir) failed — refusing to build stale code" >&2
        exit 1
    }
    local sha
    sha=$(git -C "$dir" rev-parse --short HEAD)
    echo "--- $name commit: $sha ---"
    ( cd "$dir" && cargo build --release ) || {
        echo "ERROR: cargo build of $name failed" >&2
        exit 1
    }
}

echo "=== [4/6] Building companion services ==="
TRAFFICCOP_DIR="$PROJECT_ROOT/../trafficcop"
RDHCP_DIR="$PROJECT_ROOT/../rDHCP"
RDNS_DIR="$PROJECT_ROOT/../rDNS"
RTIME_DIR="$PROJECT_ROOT/../rTIME"

build_companion TrafficCop "$TRAFFICCOP_DIR" https://github.com/ZerosAndOnesLLC/TrafficCop.git
build_companion rDHCP      "$RDHCP_DIR"      https://github.com/ZerosAndOnesLLC/rDHCP.git
build_companion rDNS       "$RDNS_DIR"       https://github.com/ZerosAndOnesLLC/rDNS.git
build_companion rTIME      "$RTIME_DIR"      https://github.com/ZerosAndOnesLLC/rTIME.git
cd "$PROJECT_ROOT"

# Pull the binary list from manifest.json (same source-of-truth as build-local.sh).
LOCAL_BINS=$(jq -r '.binaries.local[]' "$PROJECT_ROOT/freebsd/manifest.json" | tr '\n' ' ')
[ -n "$LOCAL_BINS" ] || die "Could not parse binaries.local from manifest.json (jq failed)"
for bin in $LOCAL_BINS; do
    if [ ! -f "$PROJECT_ROOT/target/release/${bin}" ]; then
        echo "ERROR: ${bin} listed in manifest but not built — refusing to ship a partial release" >&2
        exit 1
    fi
done

# --- Stage tarball contents ---
echo "=== [5/6] Staging tarball contents ==="
TARBALL_DIR="/tmp/aifw-update-${VERSION}-amd64"
rm -rf "$TARBALL_DIR"
mkdir -p "$TARBALL_DIR/bin" "$TARBALL_DIR/ui"

for bin in $LOCAL_BINS; do
    cp "$PROJECT_ROOT/target/release/${bin}" "$TARBALL_DIR/bin/"
done
if [ -f "$TRAFFICCOP_DIR/target/release/trafficcop" ]; then
    cp "$TRAFFICCOP_DIR/target/release/trafficcop" "$TARBALL_DIR/bin/"
fi
if [ -f "$RDHCP_DIR/target/release/rdhcpd" ]; then
    cp "$RDHCP_DIR/target/release/rdhcpd" "$TARBALL_DIR/bin/"
fi
if [ -f "$RDNS_DIR/target/release/rdns" ]; then
    cp "$RDNS_DIR/target/release/rdns" "$TARBALL_DIR/bin/"
fi
if [ -f "$RDNS_DIR/target/release/rdns-control" ]; then
    cp "$RDNS_DIR/target/release/rdns-control" "$TARBALL_DIR/bin/"
fi
if [ -f "$RTIME_DIR/target/release/rtime" ]; then
    cp "$RTIME_DIR/target/release/rtime" "$TARBALL_DIR/bin/"
fi
cp -a "$PROJECT_ROOT/aifw-ui/out/"* "$TARBALL_DIR/ui/"

mkdir -p "$TARBALL_DIR/rc.d"
if [ -d "$PROJECT_ROOT/freebsd/overlay/usr/local/etc/rc.d" ]; then
    cp -a "$PROJECT_ROOT/freebsd/overlay/usr/local/etc/rc.d/"* "$TARBALL_DIR/rc.d/" 2>/dev/null || true
fi

mkdir -p "$TARBALL_DIR/sbin"
if [ -d "$PROJECT_ROOT/freebsd/overlay/usr/local/sbin" ]; then
    cp -a "$PROJECT_ROOT/freebsd/overlay/usr/local/sbin/"* "$TARBALL_DIR/sbin/" 2>/dev/null || true
fi

mkdir -p "$TARBALL_DIR/libexec"
if [ -d "$PROJECT_ROOT/freebsd/overlay/usr/local/libexec" ]; then
    cp -a "$PROJECT_ROOT/freebsd/overlay/usr/local/libexec/"* "$TARBALL_DIR/libexec/" 2>/dev/null || true
fi

echo "$VERSION" > "$TARBALL_DIR/version"

# Write a BUILD_MANIFEST so stale companion repos are visible at build time.
{
    echo "AiFw             $(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    [ -d "$TRAFFICCOP_DIR/.git" ] && echo "TrafficCop       $(git -C "$TRAFFICCOP_DIR" rev-parse --short HEAD)"
    [ -d "$RDHCP_DIR/.git" ]      && echo "rDHCP            $(git -C "$RDHCP_DIR"      rev-parse --short HEAD)"
    [ -d "$RDNS_DIR/.git" ]       && echo "rDNS             $(git -C "$RDNS_DIR"       rev-parse --short HEAD)"
    [ -d "$RTIME_DIR/.git" ]      && echo "rTIME            $(git -C "$RTIME_DIR"      rev-parse --short HEAD)"
    if [ -f "$TARBALL_DIR/bin/rdns" ]; then
        rver=$(grep -ao 'rDNS [0-9][0-9.]*' "$TARBALL_DIR/bin/rdns" | head -1 || true)
        echo "rdns binary      ${rver:-unknown}"
    fi
} | tee "$TARBALL_DIR/BUILD_MANIFEST"

# Refuse to release a stale rDNS (pre-v1.10 is missing stats-json / streaming control).
if [ -f "$TARBALL_DIR/bin/rdns" ]; then
    if ! grep -q 'stats-json' "$TARBALL_DIR/bin/rdns"; then
        echo "ERROR: rDNS binary does not contain 'stats-json' — this is a stale build (pre-v1.10)." >&2
        echo "       Check that $RDNS_DIR is on origin/main before re-running." >&2
        exit 1
    fi
fi

# --- Pack tarball + sha256 ---
echo "=== [6/6] Packing tarball ==="
mkdir -p "$STAGE_OUT"
XZ_OPT='-9 -T0' tar -C /tmp -cJf "${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz" "aifw-update-${VERSION}-amd64"
( cd "$STAGE_OUT" && sha256 "aifw-update-${VERSION}-amd64.tar.xz" > "aifw-update-${VERSION}-amd64.tar.xz.sha256" )
rm -rf "$TARBALL_DIR"

echo ""
echo "=== Complete ==="
echo ""
echo "  Update tarball: ${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz"
ls -lh "${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz"
echo "  Checksum:       ${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz.sha256"
echo ""
echo "  Install on a test VM via the UI (/updates -> Install from package)"
echo "  or via the CLI: aifw update install --from ${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz"
