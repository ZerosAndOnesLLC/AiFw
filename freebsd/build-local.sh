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
pkg install -y curl git gmake node24 npm-node24 brotli

# `sudo` clears PATH, so even if rust is already installed under root's home
# we won't see `cargo` on PATH unless we source cargo's env first. Skipping
# this check caused v5.47 builds on a working toolchain to attempt a full
# rustup re-sync against static.rust-lang.org and fail on networks where
# IPv6/IPv4 resolution for that host is broken.
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi

# Only bootstrap rustup when cargo really isn't installed.
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
echo "  Building AiFw v${VERSION}"
echo ""

# --- Build Web UI static export ---
echo "=== [2/6] Building Web UI static export ==="
cd "$PROJECT_ROOT/aifw-ui"
npm config delete python 2>/dev/null || true
npm ci
npm run build

# Pre-compress every text asset alongside the originals. tower_http's
# ServeDir picks up .br / .gz siblings automatically when the request
# advertises the matching Accept-Encoding. Skipping images / fonts —
# they're already compressed.
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
    # Quick stats so the build log shows the win.
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
# Ensure cargo is in PATH (rustup installs to $HOME/.cargo/bin)
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
echo "--- AiFw commit: $(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown) ---"
cargo build --release

# Helper: clone-or-update a companion repo and FAIL LOUDLY on pull errors.
# Previous version used `git pull 2>/dev/null || true` which silently
# swallowed stale-checkout / merge-conflict errors, causing releases to
# ship with ancient bundled rDNS / rDHCP / rTIME binaries.
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

# Build companion services (reverse proxy, DHCP, DNS, NTP).
TRAFFICCOP_DIR="$PROJECT_ROOT/../trafficcop"
RDHCP_DIR="$PROJECT_ROOT/../rDHCP"
RDNS_DIR="$PROJECT_ROOT/../rDNS"
RTIME_DIR="$PROJECT_ROOT/../rTIME"

build_companion TrafficCop "$TRAFFICCOP_DIR" https://github.com/ZerosAndOnesLLC/TrafficCop.git
build_companion rDHCP      "$RDHCP_DIR"      https://github.com/ZerosAndOnesLLC/rDHCP.git
build_companion rDNS       "$RDNS_DIR"       https://github.com/ZerosAndOnesLLC/rDNS.git
build_companion rTIME      "$RTIME_DIR"      https://github.com/ZerosAndOnesLLC/rTIME.git
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
# Stage rTIME binary if built
if [ -f "$RTIME_DIR/target/release/rtime" ]; then
    cp "$RTIME_DIR/target/release/rtime" "$SCRIPT_DIR/release/rtime"
fi
if [ -f "$RDNS_DIR/target/release/rdns-control" ]; then
    cp "$RDNS_DIR/target/release/rdns-control" "$SCRIPT_DIR/release/rdns-control"
fi

rm -rf "$SCRIPT_DIR/ui-export"
cp -a "$PROJECT_ROOT/aifw-ui/out" "$SCRIPT_DIR/ui-export"

# --- Build update tarball FIRST ---
#
# The update tarball is the critical artifact — every appliance gets new
# code through the in-app updater, which only needs this file. Building it
# before the ISO means a busted ISO step (e.g. pkg.FreeBSD.org DNS issues
# on the build host) doesn't block a release. We stage to a separate
# directory that build-iso.sh will not wipe, then copy into the release
# OUTPUTDIR at the end.
echo "=== [5/9] Building update tarball ==="
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
# Include rTIME in update tarball
if [ -f "$RTIME_DIR/target/release/rtime" ]; then
    cp "$RTIME_DIR/target/release/rtime" "$TARBALL_DIR/bin/"
fi
cp -a "$PROJECT_ROOT/aifw-ui/out/"* "$TARBALL_DIR/ui/"

# rc.d service scripts — the updater (aifw-core/src/updater.rs) looks for
# these under <tarball>/rc.d/ and installs each one listed in manifest.json's
# `rc_scripts`. Skipping this ships stale service files (e.g. control-socket
# chown/chmod fixes never reach the appliance).
mkdir -p "$TARBALL_DIR/rc.d"
if [ -d "$PROJECT_ROOT/freebsd/overlay/usr/local/etc/rc.d" ]; then
    cp -a "$PROJECT_ROOT/freebsd/overlay/usr/local/etc/rc.d/"* "$TARBALL_DIR/rc.d/" 2>/dev/null || true
fi

# sbin scripts — aifw-console, aifw-installer, etc.
mkdir -p "$TARBALL_DIR/sbin"
if [ -d "$PROJECT_ROOT/freebsd/overlay/usr/local/sbin" ]; then
    cp -a "$PROJECT_ROOT/freebsd/overlay/usr/local/sbin/"* "$TARBALL_DIR/sbin/" 2>/dev/null || true
fi

echo "$VERSION" > "$TARBALL_DIR/version"

# Write a manifest of what made it into the tarball — commit SHAs for every
# component plus a quick sanity check on rDNS features. Makes stale companion
# repos (which have burned us before — rdns 1.5.1 shipping in a v5.45.0
# tarball) visible at build time.
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

# Refuse to release an obviously-stale rDNS. Any rdns earlier than 1.10 is
# missing per-zone counters and the streaming control commands that the
# dashboard depends on.
if [ -f "$TARBALL_DIR/bin/rdns" ]; then
    if ! grep -q 'stats-json' "$TARBALL_DIR/bin/rdns"; then
        echo "ERROR: rDNS binary does not contain 'stats-json' — this is a stale build (pre-v1.10)." >&2
        echo "       Check that $RDNS_DIR is on origin/main before re-running." >&2
        exit 1
    fi
fi
# Stage the tarball outside /usr/obj/aifw-iso/ — build-iso.sh wipes that
# tree, so anything we put under it before the ISO step would vanish.
STAGE_OUT="/usr/obj/aifw-release-stage"
mkdir -p "$STAGE_OUT"
XZ_OPT='-9 -T0' tar -C /tmp -cJf "${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz" "aifw-update-${VERSION}-amd64"
( cd "$STAGE_OUT" && sha256 "aifw-update-${VERSION}-amd64.tar.xz" > "aifw-update-${VERSION}-amd64.tar.xz.sha256" )
rm -rf "$TARBALL_DIR"
echo "  Update tarball staged: ${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz"
ls -lh "${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz"
cd "$PROJECT_ROOT"

# --- Build ISO + IMG (best-effort) ---
#
# build-iso.sh runs `pkg bootstrap` against pkg.FreeBSD.org. When the
# build host has flaky IPv6/IPv4 DNS for that name, this step fails. We
# don't want one bad ISO build to block a release — every appliance gets
# new code through the update tarball, not the ISO. So: failures here
# are noted but non-fatal.
echo "=== [6/9] Building ISO + IMG (best-effort) ==="
ISO_BUILD_OK=1
sh "$SCRIPT_DIR/build-iso.sh" "$VERSION" amd64 || ISO_BUILD_OK=0
if [ "$ISO_BUILD_OK" -eq 0 ]; then
    echo "WARNING: ISO/IMG build failed. The update tarball is still good for"
    echo "         the in-app updater; release.sh will skip the ISO/IMG upload."
fi

# Move the staged tarball into the release output dir (created by
# build-iso.sh; we recreate if the ISO step failed).
OUTPUTDIR="/usr/obj/aifw-iso/output"
mkdir -p "$OUTPUTDIR"
mv "${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz" "$OUTPUTDIR/"
mv "${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz.sha256" "$OUTPUTDIR/"
rmdir "$STAGE_OUT" 2>/dev/null || true

# --- Compress ISO + IMG ---
echo "=== [7/9] Compressing ISO + IMG ==="
for f in "${OUTPUTDIR}"/aifw-*.iso "${OUTPUTDIR}"/aifw-*.img; do
    if [ -f "$f" ] && [ ! -f "${f}.xz" ]; then
        echo "  Compressing $(basename $f)..."
        xz -T0 -9 "$f"
        sha256 "${f}.xz" > "${f}.xz.sha256"
    fi
done

# --- Cleanup intermediate files ---
echo "=== [8/8] Cleaning up ==="
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
echo "=== Complete ==="
echo ""
ls -lh /usr/obj/aifw-iso/output/
echo ""
echo "Files are in /usr/obj/aifw-iso/output/"
