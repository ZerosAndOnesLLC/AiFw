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

# --- Guard: the compiled binary version MUST match the release version ---
# $VERSION drives the tarball name + version file, but the binaries' version
# is baked in from Cargo.toml at compile time. A divergence (stale cargo
# artifact not recompiled after a bump, or a $VERSION arg that doesn't match
# the checked-out Cargo.toml) ships binaries that install as the wrong
# version — the silent no-op upgrade that stranded appliances on 5.96.8.
BIN_VER="$("$PROJECT_ROOT/target/release/aifw" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
[ "$BIN_VER" = "$VERSION" ] || die "version mismatch: building v${VERSION} but target/release/aifw reports v${BIN_VER:-unknown}. Bump Cargo.toml and rebuild (try 'cargo clean -p aifw') before releasing."
echo "--- Verified compiled aifw binary is v${VERSION} ---"

# Clone-or-build a companion repo at its manifest pin, restoring the
# operator's checkout afterwards. (Same function as in build-local.sh —
# keep them in sync.)
#
# This used to `git reset --hard origin/main`, which (a) silently discarded
# any uncommitted work in the operator's companion repos, (b) left them
# moved off their branch, and (c) bypassed the #538 manifest pins — the
# update tarball shipped whatever origin/main happened to be, not the
# reviewed revision.
build_companion() {
    local name="$1" dir="$2" url="$3"
    local pin
    pin=$(jq -r --arg n "$name" \
        '.external_repos[] | select(.name == $n) | .commit // empty' \
        "$PROJECT_ROOT/freebsd/manifest.json")
    [ -n "$pin" ] || die "no pinned commit for $name in manifest.json (#538)"
    if [ ! -d "$dir" ]; then
        echo "Cloning $name from $url ..."
        git clone "$url" "$dir" || {
            echo "ERROR: clone of $name failed" >&2
            exit 1
        }
    fi
    local prev
    prev=$(git -C "$dir" symbolic-ref --quiet --short HEAD || git -C "$dir" rev-parse HEAD)
    echo "--- Checking out $name @ $pin (will restore '$prev' after build) ---"
    ( cd "$dir" && \
        git fetch --tags origin && \
        git checkout --quiet --detach "$pin" ) || {
        echo "ERROR: pinned commit $pin not found in $name ($dir), or the" >&2
        echo "       working tree has uncommitted changes — commit/stash first" >&2
        exit 1
    }
    local actual
    actual=$(git -C "$dir" rev-parse HEAD)
    [ "$actual" = "$pin" ] || die "$name checked out $actual, expected pinned $pin"
    echo "--- $name commit: $actual ---"
    local rc=0
    ( cd "$dir" && cargo build --release ) || rc=1
    git -C "$dir" checkout --quiet "$prev" || \
        echo "WARN: could not restore $name to '$prev' — left detached at $pin" >&2
    # Root-run builds litter the operator's repo with root-owned .git
    # objects and target/ artifacts, breaking their later git/cargo use
    # (seen live: 'insufficient permission for adding an object'). Hand
    # the repo back to the invoking user.
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        chown -R "$SUDO_USER" "$dir" 2>/dev/null || true
    fi
    if [ "$rc" -ne 0 ]; then
        echo "ERROR: cargo build of $name failed" >&2
        exit 1
    fi
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

# Everything the appliance executes must carry the x bit regardless of
# checkout modes — sudo reports a 644 helper as "command not found" (#469).
chmod 755 "$TARBALL_DIR"/rc.d/* "$TARBALL_DIR"/sbin/* "$TARBALL_DIR"/libexec/* 2>/dev/null || true

echo "$VERSION" > "$TARBALL_DIR/version"

# Write a BUILD_MANIFEST so stale companion repos are visible at build time.
{
    echo "AiFw             $(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    # Companion SHAs from the manifest pins — build_companion verified each
    # checkout matched its pin, then restored the operator's branch.
    for n in TrafficCop rDHCP rDNS rTIME; do
        p=$(jq -r --arg n "$n" '.external_repos[] | select(.name == $n) | .commit // empty' \
            "$PROJECT_ROOT/freebsd/manifest.json")
        [ -n "$p" ] && printf '%-16s %.12s (manifest pin)\n' "$n" "$p"
    done
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

# Unless the operator overrode the output path for test iteration, land the
# artifacts in the release output dir that release.sh actually reads. Without
# this the tarball stayed in the staging dir and release.sh could publish a
# STALE tarball left in OUTPUTDIR under a fresh version tag.
if [ -z "${AIFW_STAGE_OUT:-}" ]; then
    OUTPUTDIR="/usr/obj/aifw-iso/output"
    mkdir -p "$OUTPUTDIR"
    mv "${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz" "$OUTPUTDIR/"
    mv "${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz.sha256" "$OUTPUTDIR/"
    rmdir "$STAGE_OUT" 2>/dev/null || true
    STAGE_OUT="$OUTPUTDIR"
    # release.sh runs unprivileged and signs next to these files — hand
    # them to the invoking user when this build ran under sudo.
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        chown -R "$SUDO_USER" "$OUTPUTDIR" 2>/dev/null || true
    fi
fi

echo ""
echo "=== Complete ==="
echo ""
echo "  Update tarball: ${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz"
ls -lh "${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz"
echo "  Checksum:       ${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz.sha256"
echo ""
echo "  Install on a test VM via the UI (/updates -> Install from package)"
echo "  or via the CLI: aifw update install --from ${STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz"
