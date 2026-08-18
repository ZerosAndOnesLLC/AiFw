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
pkg install -y curl git gmake node24 npm-node24 brotli jq

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

# --- Guard: the compiled binary version MUST match the release version ---
# The version label, tarball name and version file all come from $VERSION,
# but the binaries' version is baked in from Cargo.toml at compile time. If
# those diverge — a stale cargo artifact that wasn't recompiled after a
# version bump, or a $VERSION arg that doesn't match the checked-out
# Cargo.toml — we'd ship a tarball whose binaries install as the WRONG
# version. That shipped a "5.96.10" tarball containing 5.96.8 binaries,
# making every appliance's in-app update a silent no-op. Fail loudly instead.
BIN_VER="$("$PROJECT_ROOT/target/release/aifw" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
[ "$BIN_VER" = "$VERSION" ] || die "version mismatch: building v${VERSION} but target/release/aifw reports v${BIN_VER:-unknown}. Bump Cargo.toml and rebuild (try 'cargo clean -p aifw') before releasing."
echo "--- Verified compiled aifw binary is v${VERSION} ---"

# Install companion services (reverse proxy, DHCP, DNS, NTP) from
# crates.io at the versions pinned in manifest.json (#651, replacing the
# #538 git SHA pins — the published crates track the companion repo
# releases, so there are no sibling checkouts to clone or branch-juggle).
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

# --- Stage build inputs ---
echo "=== [4/6] Staging build inputs ==="
mkdir -p "$SCRIPT_DIR/release"

# Pull the binary list from manifest.json so adding a new crate to the
# workspace (e.g. aifw-ids in 5.76) requires only a manifest edit, not a
# build-script edit. Hardcoding the list here was the bug that shipped a
# 5.76.1 release missing aifw-ids.
LOCAL_BINS=$(jq -r '.binaries.local[]' "$PROJECT_ROOT/freebsd/manifest.json" | tr '\n' ' ')
[ -n "$LOCAL_BINS" ] || die "Could not parse binaries.local from manifest.json (jq failed)"
for bin in $LOCAL_BINS; do
    if [ ! -f "$PROJECT_ROOT/target/release/${bin}" ]; then
        echo "ERROR: ${bin} listed in manifest but not built — refusing to ship a partial release" >&2
        exit 1
    fi
    cp "$PROJECT_ROOT/target/release/${bin}" "$SCRIPT_DIR/release/${bin}"
done
# Stage companion binaries — installed from crates.io above, so a missing
# one is a bug; refuse to ship a partial artifact set.
EXT_BINS=$(jq -r '.external_repos[].binaries[]' "$PROJECT_ROOT/freebsd/manifest.json" | tr '\n' ' ')
for bin in $EXT_BINS; do
    [ -f "$COMPANIONS_BIN/$bin" ] || die "companion binary $bin missing from $COMPANIONS_BIN"
    cp "$COMPANIONS_BIN/$bin" "$SCRIPT_DIR/release/$bin"
done

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
# Same source-of-truth as the staging step above.
for bin in $LOCAL_BINS; do
    cp "$PROJECT_ROOT/target/release/${bin}" "$TARBALL_DIR/bin/"
done
# Companion binaries from the crates.io install — same missing-binary
# refusal as the staging step above.
for bin in $EXT_BINS; do
    [ -f "$COMPANIONS_BIN/$bin" ] || die "companion binary $bin missing from $COMPANIONS_BIN"
    cp "$COMPANIONS_BIN/$bin" "$TARBALL_DIR/bin/"
done
cp -a "$PROJECT_ROOT/aifw-ui/out/"* "$TARBALL_DIR/ui/"

# rc.d service scripts — the updater (aifw-core/src/updater/) iterates
# every file found under <tarball>/rc.d/ and installs it; it does not consult
# manifest.json's rc_scripts list. Skipping this ships stale service files.
mkdir -p "$TARBALL_DIR/rc.d"
if [ -d "$PROJECT_ROOT/freebsd/overlay/usr/local/etc/rc.d" ]; then
    cp -a "$PROJECT_ROOT/freebsd/overlay/usr/local/etc/rc.d/"* "$TARBALL_DIR/rc.d/" 2>/dev/null || true
fi

# sbin scripts — aifw-console, aifw-installer, etc.
mkdir -p "$TARBALL_DIR/sbin"
if [ -d "$PROJECT_ROOT/freebsd/overlay/usr/local/sbin" ]; then
    cp -a "$PROJECT_ROOT/freebsd/overlay/usr/local/sbin/"* "$TARBALL_DIR/sbin/" 2>/dev/null || true
fi

# libexec scripts — aifw-restart.sh (detached bouncer), aifw-watchdog.sh
# (self-heal loop), aifw-motd-cleanup.sh, aifw-login-migrate.sh. The
# updater (aifw-core/src/updater/) iterates <tarball>/libexec/ on
# install. Skipping this means the new bouncer never reaches the
# appliance and restart_services() falls back to the in-process loop.
mkdir -p "$TARBALL_DIR/libexec"
if [ -d "$PROJECT_ROOT/freebsd/overlay/usr/local/libexec" ]; then
    cp -a "$PROJECT_ROOT/freebsd/overlay/usr/local/libexec/"* "$TARBALL_DIR/libexec/" 2>/dev/null || true
fi

# Everything the appliance executes must carry the x bit regardless of
# checkout modes — sudo reports a 644 helper as "command not found" (#469).
chmod 755 "$TARBALL_DIR"/rc.d/* "$TARBALL_DIR"/sbin/* "$TARBALL_DIR"/libexec/* 2>/dev/null || true

echo "$VERSION" > "$TARBALL_DIR/version"
# OS floor stamp (#612): the updater refuses this tarball on a FreeBSD
# older than the build host — its binaries wouldn't link.
freebsd-version -u | sed 's/-.*//' > "$TARBALL_DIR/required-os"

# Write a manifest of what made it into the tarball — the crates.io
# version of every component plus a quick sanity check on rDNS features.
# Makes a stale or mispinned companion (which has burned us before —
# rdns 1.5.1 shipping in a v5.45.0 tarball) visible at build time.
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

# Refuse to release an obviously-stale rDNS. Any rdns earlier than 1.10 is
# missing per-zone counters and the streaming control commands that the
# dashboard depends on.
if [ -f "$TARBALL_DIR/bin/rdns" ]; then
    if ! grep -q 'stats-json' "$TARBALL_DIR/bin/rdns"; then
        echo "ERROR: rDNS binary does not contain 'stats-json' — this is a stale build (pre-v1.10)." >&2
        echo "       Check the rdns-server version pin in freebsd/manifest.json." >&2
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

# Hand the artifacts to the user who invoked the build: this script runs as
# root, but release.sh runs unprivileged (it needs the operator's gh auth
# and minisign key) and must be able to write .minisig files next to the
# checksums. Without this, every release run died on "Permission denied".
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    chown -R "$SUDO_USER" "$OUTPUTDIR"
    echo "  Output ownership -> $SUDO_USER (for unprivileged release.sh)"
fi

# --- Done ---
echo ""
echo "=== Complete ==="
echo ""
ls -lh /usr/obj/aifw-iso/output/
echo ""
echo "Files are in /usr/obj/aifw-iso/output/"
