#!/bin/sh
# AiFw Local Build — run this on a FreeBSD machine to build the ISO + IMG
# Usage: ./build-local.sh [version]
#   version defaults to the value in Cargo.toml

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Must be FreeBSD, as root ---
if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "ERROR: This script must be run on FreeBSD" >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must be run as root (try: sudo sh $0)" >&2
    exit 1
fi

# All shared build steps come from lib-build.sh (#203) — the same code CI
# and build-update.sh run, so the three release paths cannot drift.
. "$SCRIPT_DIR/lib-build.sh"

# --- Install dependencies ---
echo "=== [1/8] Installing dependencies ==="
pkg install -y curl git gmake node24 npm-node24 brotli jq
aifw_ensure_cargo

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
echo "=== [2/8] Building Web UI static export ==="
cd "$PROJECT_ROOT/aifw-ui"
npm config delete python 2>/dev/null || true
npm ci
npm run build
aifw_precompress_ui "$PROJECT_ROOT/aifw-ui/out"
cd "$PROJECT_ROOT"

# --- Build Rust binaries ---
echo "=== [3/8] Building Rust binaries (release) ==="
echo "--- AiFw commit: $(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown) ---"
cargo build --release
aifw_verify_binary_version "$VERSION"

# --- Companion services from crates.io (#651) ---
echo "=== [4/8] Installing companion services from crates.io ==="
COMPANIONS_ROOT="$PROJECT_ROOT/target/companions"
COMPANIONS_BIN="$COMPANIONS_ROOT/bin"
aifw_install_companions "$COMPANIONS_ROOT"

# --- Stage build inputs for build-iso.sh ---
echo "=== [5/8] Staging build inputs ==="
aifw_stage_binaries "$SCRIPT_DIR/release" "$COMPANIONS_BIN"
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
echo "=== [6/8] Building update tarball ==="
STAGE_OUT="/usr/obj/aifw-release-stage"
aifw_build_update_tarball "$VERSION" "$COMPANIONS_BIN" "$PROJECT_ROOT/aifw-ui/out" "$STAGE_OUT"
cd "$PROJECT_ROOT"

# --- Build ISO + IMG (best-effort) ---
#
# build-iso.sh runs `pkg bootstrap` against pkg.FreeBSD.org. When the
# build host has flaky IPv6/IPv4 DNS for that name, this step fails. We
# don't want one bad ISO build to block a release — every appliance gets
# new code through the update tarball, not the ISO. So: failures here
# are noted but non-fatal.
echo "=== [7/8] Building ISO + IMG (best-effort) ==="
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
echo "=== [8/8] Compressing ISO + IMG ==="
for f in "${OUTPUTDIR}"/aifw-*.iso "${OUTPUTDIR}"/aifw-*.img; do
    if [ -f "$f" ] && [ ! -f "${f}.xz" ]; then
        echo "  Compressing $(basename $f)..."
        xz -T0 -9 "$f"
        sha256 "${f}.xz" > "${f}.xz.sha256"
    fi
done

# --- Cleanup intermediate files ---
echo "=== Cleaning up ==="
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
