#!/bin/sh
# AiFw Release — upload ISO/IMG to a GitHub Release
# Usage: ./release.sh [version]
#   version defaults to the value in Cargo.toml
#   Requires: gh (GitHub CLI) authenticated
#
# Run from the project root or freebsd/ directory on the build machine.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() { echo "ERROR: $1" >&2; exit 1; }

# --- Check dependencies ---
command -v gh >/dev/null 2>&1 || die "GitHub CLI (gh) not found. Install: pkg install gh"

# --- Extract version ---
VERSION="${1:-$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')}"
TAG="v${VERSION}"

OUTPUTDIR="/usr/obj/aifw-iso/output"
ISO="${OUTPUTDIR}/aifw-${VERSION}-amd64.iso"
IMG="${OUTPUTDIR}/aifw-${VERSION}-amd64.img"
ISO_XZ="${ISO}.xz"
IMG_XZ="${IMG}.xz"
ISO_SHA="${ISO}.sha256"
IMG_SHA="${IMG}.sha256"
ISO_XZ_SHA="${ISO_XZ}.sha256"
IMG_XZ_SHA="${IMG_XZ}.sha256"

echo "============================================"
echo "  AiFw Release"
echo "  Version: ${VERSION}"
echo "  Tag:     ${TAG}"
echo "============================================"
echo ""

# --- Verify build artifacts exist (prefer .xz, fall back to uncompressed) ---
if [ -f "$ISO_XZ" ]; then
    ISO_UPLOAD="$ISO_XZ"
    ISO_SHA_UPLOAD="$ISO_XZ_SHA"
elif [ -f "$ISO" ]; then
    ISO_UPLOAD="$ISO"
    ISO_SHA_UPLOAD="$ISO_SHA"
else
    die "Missing: $ISO (or ${ISO}.xz) — run build-local.sh first"
fi

if [ -f "$IMG_XZ" ]; then
    IMG_UPLOAD="$IMG_XZ"
    IMG_SHA_UPLOAD="$IMG_XZ_SHA"
elif [ -f "$IMG" ]; then
    IMG_UPLOAD="$IMG"
    IMG_SHA_UPLOAD="$IMG_SHA"
else
    die "Missing: $IMG (or ${IMG}.xz) — run build-local.sh first"
fi

# Verify checksum files exist
for f in "$ISO_SHA_UPLOAD" "$IMG_SHA_UPLOAD"; do
    [ -f "$f" ] || die "Missing checksum: $f"
done

# If uncompressed IMG exists and is over 1.5GB, compress for GitHub (2GB limit)
if [ "$IMG_UPLOAD" = "$IMG" ]; then
    IMG_SIZE_BYTES=$(stat -f%z "$IMG" 2>/dev/null || stat -c%s "$IMG" 2>/dev/null || echo 0)
    IMG_SIZE_MB=$((IMG_SIZE_BYTES / 1048576))
    if [ "$IMG_SIZE_MB" -gt 1500 ]; then
        XZ_IMG="/tmp/aifw-${VERSION}-amd64.img.xz"
        if [ ! -f "$XZ_IMG" ] || [ "$IMG" -nt "$XZ_IMG" ]; then
            echo "Compressing IMG (${IMG_SIZE_MB}MB) with xz..."
            xz -k -9 -T0 --stdout "$IMG" > "$XZ_IMG"
        fi
        IMG_UPLOAD="$XZ_IMG"
        IMG_SHA_UPLOAD="${XZ_IMG}.sha256"
        sha256 "$XZ_IMG" > "$IMG_SHA_UPLOAD"
    fi
fi

# --- Locate update tarball ---
UPDATE_TARBALL="${OUTPUTDIR}/aifw-update-${VERSION}-amd64.tar.xz"
UPDATE_SHA="${UPDATE_TARBALL}.sha256"
if [ ! -f "$UPDATE_TARBALL" ]; then
    echo "WARNING: Update tarball not found: $UPDATE_TARBALL"
    echo "  (AiFw self-update won't be available for this release)"
    UPDATE_TARBALL=""
    UPDATE_SHA=""
fi

echo "Artifacts:"
ls -lh "$ISO_UPLOAD" "$IMG_UPLOAD"
[ -n "$UPDATE_TARBALL" ] && ls -lh "$UPDATE_TARBALL"
echo ""

# --- Create git tag if it doesn't exist ---
cd "$PROJECT_ROOT"
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "Tag ${TAG} already exists"
else
    echo "Creating tag ${TAG}..."
    git tag -a "$TAG" -m "AiFw ${VERSION}"
    git push origin "$TAG"
fi

# --- Create or update GitHub release ---
echo ""
echo "Creating GitHub release ${TAG}..."

IMG_BASENAME="$(basename "$IMG_UPLOAD")"
ISO_BASENAME="$(basename "$ISO_UPLOAD")"
DECOMPRESS_NOTE=""
if echo "$IMG_BASENAME" | grep -q '\.xz$'; then
    DECOMPRESS_NOTE="
> **Note:** The USB image is compressed with xz. Decompress before writing:
> \`\`\`bash
> xz -d ${IMG_BASENAME}
> dd if=aifw-${VERSION}-amd64.img of=/dev/sdX bs=1M status=progress
> \`\`\`"
fi

BODY="## AiFw v${VERSION}

AI-Powered Firewall for FreeBSD 15.0

### Downloads

| File | Size | Description |
|------|------|-------------|
| \`${ISO_BASENAME}\` | $(du -h "$ISO_UPLOAD" | awk '{print $1}') | Bootable ISO (CD/DVD, VM) |
| \`${IMG_BASENAME}\` | $(du -h "$IMG_UPLOAD" | awk '{print $1}') | USB flash drive image |
${DECOMPRESS_NOTE}
### Quick Start

1. Boot from the ISO or write the IMG to a USB drive
2. The setup wizard starts automatically on first boot
3. Follow the prompts to configure networking, admin account, and firewall policy
4. Use menu option **14** to install to disk (ZFS or UFS)
5. Access the web UI at \`https://<firewall-ip>:8080\`

### Verify Downloads

\`\`\`
$(cat "$ISO_SHA_UPLOAD")
$(cat "$IMG_SHA_UPLOAD")
\`\`\`"

# Build asset list
ASSETS="$ISO_UPLOAD $IMG_UPLOAD $ISO_SHA_UPLOAD $IMG_SHA_UPLOAD"
if [ -n "$UPDATE_TARBALL" ]; then
    ASSETS="$ASSETS $UPDATE_TARBALL $UPDATE_SHA"
fi

# Create release (or update if exists)
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "Release ${TAG} exists, uploading assets..."
    gh release upload "$TAG" $ASSETS --clobber
    # Ensure it's not stuck as a draft
    gh release edit "$TAG" --draft=false --title "AiFw v${VERSION}" --notes "$BODY" 2>/dev/null || true
else
    gh release create "$TAG" \
        $ASSETS \
        --title "AiFw v${VERSION}" \
        --notes "$BODY"
fi

# --- Cleanup temp files ---
if [ -n "$XZ_IMG" ]; then
    rm -f "$XZ_IMG" "$IMG_SHA_UPLOAD"
    echo "Cleaned up temp files in /tmp"
fi

# --- Cleanup old releases (keep most recent N) ---
MAX_RELEASES=20
echo ""
echo "Checking for old releases to clean up (keeping ${MAX_RELEASES})..."
RELEASE_COUNT=$(gh release list --limit 1000 --json tagName -q 'length')
if [ "$RELEASE_COUNT" -gt "$MAX_RELEASES" ]; then
    DELETE_COUNT=$((RELEASE_COUNT - MAX_RELEASES))
    echo "Found ${RELEASE_COUNT} releases, deleting oldest ${DELETE_COUNT}..."
    gh release list --limit 1000 --json tagName -q '.[].tagName' | tail -n "$DELETE_COUNT" | while read -r OLD_TAG; do
        echo "  Deleting release ${OLD_TAG}..."
        gh release delete "$OLD_TAG" --yes --cleanup-tag 2>/dev/null || true
    done
    echo "Cleanup complete. ${MAX_RELEASES} releases retained."
else
    echo "Only ${RELEASE_COUNT} releases, no cleanup needed."
fi

# --- Cleanup old build artifacts ---
echo "Cleaning build output directory..."
find "$OUTPUTDIR" -name "aifw-*" -not -name "*${VERSION}*" -type f -delete 2>/dev/null
CLEANED=$(find "$OUTPUTDIR" -name "aifw-*" -not -name "*${VERSION}*" -type f 2>/dev/null | wc -l | tr -d ' ')
echo "Build artifacts cleaned (kept v${VERSION} only)"

echo ""
echo "============================================"
echo "  Release complete!"
echo "============================================"
echo ""
gh release view "$TAG" --json url -q '.url'
