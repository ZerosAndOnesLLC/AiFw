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

echo "=== [4/6] Installing companion services from crates.io ==="
# Companions come from crates.io at the versions pinned in manifest.json
# (#651, replacing the #538 git SHA pins — the published crates track the
# companion repo releases, so there are no sibling checkouts to clone or
# branch-juggle). Same loop as build-local.sh — keep them in sync.
# cargo install is a no-op when the pinned version is already in
# COMPANIONS_ROOT and fails loudly on a missing or unpublished pin.
COMPANIONS_ROOT="$PROJECT_ROOT/target/companions"
COMPANIONS_BIN="$COMPANIONS_ROOT/bin"
for name in $(jq -r '.external_repos[].name' "$PROJECT_ROOT/freebsd/manifest.json"); do
    crate=$(jq -r --arg n "$name" \
        '.external_repos[] | select(.name == $n) | .crate // empty' \
        "$PROJECT_ROOT/freebsd/manifest.json")
    ver=$(jq -r --arg n "$name" \
        '.external_repos[] | select(.name == $n) | .version // empty' \
        "$PROJECT_ROOT/freebsd/manifest.json")
    [ -n "$crate" ] || die "no crate name for $name in manifest.json (#651)"
    [ -n "$ver" ] || die "no pinned version for $name in manifest.json (#651)"
    echo "--- Installing $name ($crate $ver from crates.io) ---"
    cargo install --locked --version "$ver" --root "$COMPANIONS_ROOT" "$crate" \
        || die "cargo install of $crate $ver failed"
    for bin in $(jq -r --arg n "$name" \
        '.external_repos[] | select(.name == $n) | .binaries[]' \
        "$PROJECT_ROOT/freebsd/manifest.json"); do
        [ -f "$COMPANIONS_BIN/$bin" ] || die "$crate $ver did not produce binary $bin"
    done
done
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
# Companion binaries — installed from crates.io above, so a missing one
# is a bug; refuse to ship a partial artifact set.
EXT_BINS=$(jq -r '.external_repos[].binaries[]' "$PROJECT_ROOT/freebsd/manifest.json" | tr '\n' ' ')
for bin in $EXT_BINS; do
    [ -f "$COMPANIONS_BIN/$bin" ] || die "companion binary $bin missing from $COMPANIONS_BIN"
    cp "$COMPANIONS_BIN/$bin" "$TARBALL_DIR/bin/"
done
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

# Stamp the FreeBSD release these binaries link against (#612). The
# updater refuses to install the tarball on an older OS — binaries built
# on 15.1 need libc symbols a 15.0 box doesn't have and would crash-loop
# every service. The build host's userland IS the compatibility floor.
freebsd-version -u | sed 's/-.*//' > "$TARBALL_DIR/required-os"

# Write a BUILD_MANIFEST so a stale or mispinned companion is visible at
# build time.
{
    echo "AiFw             $(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    # Companion versions come from the manifest crates.io pins — the
    # install step verified each pinned version produced its binaries.
    jq -r '.external_repos[] | "\(.name) \(.version) \(.crate)"' \
        "$PROJECT_ROOT/freebsd/manifest.json" | \
    while read -r n v c; do
        printf '%-16s %s (crates.io %s)\n' "$n" "$v" "$c"
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
        echo "       Check the rdns-server version pin in freebsd/manifest.json." >&2
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
