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

echo "Artifacts:"
ls -lh "$ISO" "$IMG"
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

BODY="## AiFw v${VERSION}

AI-Powered Firewall for FreeBSD 15.0

### Downloads

| File | Size | Description |
|------|------|-------------|
| \`aifw-${VERSION}-amd64.iso\` | $(du -h "$ISO" | awk '{print $1}') | Bootable ISO (CD/DVD, VM) |
| \`aifw-${VERSION}-amd64.img\` | $(du -h "$IMG" | awk '{print $1}') | USB flash drive image |

### Quick Start

1. Boot from the ISO or write the IMG to a USB drive (\`dd if=aifw-*.img of=/dev/sdX bs=1M\`)
2. The setup wizard starts automatically on first boot
3. Follow the prompts to configure networking, admin account, and firewall policy
4. Use menu option **14** to install to disk (ZFS or UFS)
5. Access the web UI at \`https://<firewall-ip>:8080\`

### Verify Downloads

\`\`\`bash
sha256sum -c aifw-${VERSION}-amd64.iso.sha256
sha256sum -c aifw-${VERSION}-amd64.img.sha256
\`\`\`

### Checksums

\`\`\`
$(cat "$ISO_SHA")
$(cat "$IMG_SHA")
\`\`\`"

# Create release (or update if exists)
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "Release ${TAG} exists, uploading assets..."
    gh release upload "$TAG" "$ISO" "$IMG" "$ISO_SHA" "$IMG_SHA" --clobber
else
    gh release create "$TAG" \
        "$ISO" "$IMG" "$ISO_SHA" "$IMG_SHA" \
        --title "AiFw v${VERSION}" \
        --notes "$BODY"
fi

echo ""
echo "============================================"
echo "  Release complete!"
echo "============================================"
echo ""
gh release view "$TAG" --json url -q '.url'
