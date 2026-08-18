#!/bin/sh
# AiFw tarball-only build — produces JUST the update tarball (no ISO/IMG).
#
# Usage:
#   sh freebsd/build-update.sh [version]
#
# Output:
#   ${AIFW_STAGE_OUT}/aifw-update-${VERSION}-amd64.tar.xz (+ .sha256)
#
# AIFW_STAGE_OUT defaults to /usr/obj/aifw-release-stage and is then moved
# into /usr/obj/aifw-iso/output (what release.sh reads); set it explicitly for
# test iteration that should land somewhere else.
#
# All build steps live in freebsd/lib-build.sh and are shared with
# build-local.sh and the CI ISO workflow (#203) — the tarball this produces
# is byte-for-byte the same layout as theirs.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
. "$SCRIPT_DIR/lib-build.sh"

[ "$(uname -s)" = "FreeBSD" ] || aifw_die "This script must be run on FreeBSD (it invokes pkg, sha256, etc.)"
[ "$(id -u)" -eq 0 ] || aifw_die "Must be run as root (try: sudo sh $0)"

STAGE_OUT="${AIFW_STAGE_OUT:-/usr/obj/aifw-release-stage}"

echo "=== [1/5] Installing dependencies ==="
pkg install -y curl git gmake node24 npm-node24 brotli jq
aifw_ensure_cargo

if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "=== Cloning repository ==="
    git clone https://github.com/ZerosAndOnesLLC/AiFw.git "$PROJECT_ROOT"
fi
cd "$PROJECT_ROOT"

VERSION="${1:-$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')}"
echo ""
echo "  Building AiFw v${VERSION} (update tarball only)"
echo ""

echo "=== [2/5] Building Web UI static export ==="
cd "$PROJECT_ROOT/aifw-ui"
npm config delete python 2>/dev/null || true
npm ci
npm run build
aifw_precompress_ui "$PROJECT_ROOT/aifw-ui/out"
cd "$PROJECT_ROOT"

echo "=== [3/5] Building Rust binaries (release) ==="
echo "--- AiFw commit: $(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown) ---"
cargo build --release
aifw_verify_binary_version "$VERSION"

echo "=== [4/5] Installing companion services from crates.io ==="
COMPANIONS_ROOT="$PROJECT_ROOT/target/companions"
aifw_install_companions "$COMPANIONS_ROOT"

echo "=== [5/5] Building update tarball ==="
aifw_build_update_tarball "$VERSION" "$COMPANIONS_ROOT/bin" "$PROJECT_ROOT/aifw-ui/out" "$STAGE_OUT"

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
