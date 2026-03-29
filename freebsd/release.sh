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
ISO_SHA="${ISO}.sha256"
IMG_SHA="${IMG}.sha256"

echo "============================================"
echo "  AiFw Release"
echo "  Version: ${VERSION}"
echo "  Tag:     ${TAG}"
echo "============================================"
echo ""

# --- Verify build artifacts exist ---
for f in "$ISO" "$IMG" "$ISO_SHA" "$IMG_SHA"; do
    [ -f "$f" ] || die "Missing: $f — run build-local.sh first"
done

# --- Compress large files for GitHub (2GB limit) ---
ISO_UPLOAD="$ISO"
IMG_UPLOAD="$IMG"
ISO_SHA_UPLOAD="$ISO_SHA"
IMG_SHA_UPLOAD="$IMG_SHA"

# Compress IMG with xz if over 1.5GB (GitHub limit is 2GB)
IMG_SIZE_MB=$(du -m "$IMG" | awk '{print $1}')
if [ "$IMG_SIZE_MB" -gt 1500 ]; then
    XZ_IMG="${IMG}.xz"
    if [ ! -f "$XZ_IMG" ] || [ "$IMG" -nt "$XZ_IMG" ]; then
        echo "Compressing IMG (${IMG_SIZE_MB}MB) with xz..."
        xz -k -9 -T0 "$IMG"
    fi
    IMG_UPLOAD="$XZ_IMG"
    # Generate checksum for compressed file
    IMG_SHA_UPLOAD="${XZ_IMG}.sha256"
    sha256 "$XZ_IMG" > "$IMG_SHA_UPLOAD"
fi

echo "Artifacts:"
ls -lh "$ISO_UPLOAD" "$IMG_UPLOAD"
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

# Create release (or update if exists)
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "Release ${TAG} exists, uploading assets..."
    gh release upload "$TAG" "$ISO_UPLOAD" "$IMG_UPLOAD" "$ISO_SHA_UPLOAD" "$IMG_SHA_UPLOAD" --clobber
else
    gh release create "$TAG" \
        "$ISO_UPLOAD" "$IMG_UPLOAD" "$ISO_SHA_UPLOAD" "$IMG_SHA_UPLOAD" \
        --title "AiFw v${VERSION}" \
        --notes "$BODY"
fi

echo ""
echo "============================================"
echo "  Release complete!"
echo "============================================"
echo ""
gh release view "$TAG" --json url -q '.url'
