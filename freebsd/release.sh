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
#
# ISO/IMG are nice-to-have; the update tarball is what every existing
# appliance pulls via the in-app updater. If the build VM's network was
# wedged (pkg.FreeBSD.org IPv6/IPv4 resolution issues we keep hitting)
# the ISO step gets skipped but the tarball is still produced. Don't
# block a release just because we can't ship a fresh ISO.
ISO_UPLOAD=""
ISO_SHA_UPLOAD=""
IMG_UPLOAD=""
IMG_SHA_UPLOAD=""
if [ -f "$ISO_XZ" ]; then
    ISO_UPLOAD="$ISO_XZ"
    ISO_SHA_UPLOAD="$ISO_XZ_SHA"
elif [ -f "$ISO" ]; then
    ISO_UPLOAD="$ISO"
    ISO_SHA_UPLOAD="$ISO_SHA"
fi

if [ -f "$IMG_XZ" ]; then
    IMG_UPLOAD="$IMG_XZ"
    IMG_SHA_UPLOAD="$IMG_XZ_SHA"
elif [ -f "$IMG" ]; then
    IMG_UPLOAD="$IMG"
    IMG_SHA_UPLOAD="$IMG_SHA"
fi

# Validate checksum files for whichever artifacts we found.
for f in "$ISO_SHA_UPLOAD" "$IMG_SHA_UPLOAD"; do
    if [ -n "$f" ] && [ ! -f "$f" ]; then
        die "Missing checksum: $f"
    fi
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

# --- Guard: the tarball we're about to publish MUST actually contain ${VERSION} ---
# release.sh reads a fixed path. A stale or mislabeled tarball sitting there
# would be published under a v${VERSION} tag while its payload installs an
# older build — the in-app updater then reports "updated" but the appliance
# never moves (it stayed on 5.96.8 across several "upgrades"). Verify the
# tarball's version file AND its compiled aifw binary before uploading.
if [ -n "$UPDATE_TARBALL" ]; then
    INNER="aifw-update-${VERSION}-amd64"
    TVER="$(tar -xJOf "$UPDATE_TARBALL" "${INNER}/version" 2>/dev/null | tr -d '[:space:]')"
    [ "$TVER" = "$VERSION" ] || die "update tarball version file is '${TVER:-missing}', expected ${VERSION} — stale/mismatched artifact at ${UPDATE_TARBALL}. Rebuild before releasing."
    TMPV="$(mktemp -d)"
    if tar -xJf "$UPDATE_TARBALL" -C "$TMPV" "${INNER}/bin/aifw" 2>/dev/null; then
        BVER="$("$TMPV/${INNER}/bin/aifw" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
        if [ -n "$BVER" ] && [ "$BVER" != "$VERSION" ]; then
            rm -rf "$TMPV"
            die "update tarball binary is v${BVER}, expected v${VERSION} — refusing to publish a mislabeled update."
        fi
    fi
    rm -rf "$TMPV"
    echo "Verified update tarball payload is v${VERSION}"
fi

if [ -z "$ISO_UPLOAD" ] && [ -z "$IMG_UPLOAD" ] && [ -z "$UPDATE_TARBALL" ]; then
    die "No artifacts to release. Run build-local.sh first."
fi

# --- Guard: signing writes .minisig files next to the checksums, so the
# output dir must be writable by this (unprivileged) user. Builds run as
# root and used to leave root-owned artifacts, killing every release run
# with "Permission denied" mid-signing. The build scripts now chown their
# output, but self-heal here too for artifacts from older builds — sudo -n
# only, so this never hangs on a password prompt.
UNWRITABLE=0
[ -w "$OUTPUTDIR" ] || UNWRITABLE=1
for f in "$OUTPUTDIR"/*; do
    [ -e "$f" ] || continue
    [ -w "$f" ] || { UNWRITABLE=1; break; }
done
if [ "$UNWRITABLE" = 1 ]; then
    echo "Output dir has files this user can't write (root-owned build artifacts); fixing ownership..."
    sudo -n chown -R "$(id -un)" "$OUTPUTDIR" 2>/dev/null \
        || die "Cannot write to ${OUTPUTDIR} — run: sudo chown -R $(id -un) ${OUTPUTDIR}"
fi

# --- Sign checksums (publisher authenticity) ---
# The in-app updater fails closed: a release without a valid .minisig for
# its update tarball checksum cannot be installed by any appliance. Signing
# happens here — the single local publish gate — so build-local.sh /
# build-update.sh test iterations don't need the key.
# Key management: freebsd/RELEASE-SIGNING.md.
SIGNKEY="${AIFW_MINISIGN_SECKEY:-$HOME/.minisign/aifw-update.key}"
PUBKEY="$PROJECT_ROOT/freebsd/overlay/usr/local/etc/aifw/update-signing.pub"
command -v minisign >/dev/null 2>&1 || die "minisign is required to sign release checksums: pkg install -y minisign"
[ -f "$PUBKEY" ] || die "Missing committed public key: $PUBKEY"
SIG_ASSETS=""
for sha in "$ISO_SHA_UPLOAD" "$IMG_SHA_UPLOAD" "$UPDATE_SHA"; do
    [ -n "$sha" ] || continue
    sig="${sha}.minisig"
    if [ ! -f "$sig" ] || [ "$sha" -nt "$sig" ]; then
        [ -f "$SIGNKEY" ] || die "No signing key at $SIGNKEY (override with AIFW_MINISIGN_SECKEY). Unsigned releases cannot be installed — see freebsd/RELEASE-SIGNING.md."
        minisign -S -s "$SIGNKEY" -m "$sha" -x "$sig" || die "Signing failed for $sha"
    fi
    # Verify against the COMMITTED public key — the one compiled into the
    # appliance updater. Catches signing with a stale/rotated secret key
    # before the release is published.
    minisign -Vm "$sha" -x "$sig" -p "$PUBKEY" >/dev/null || die "Signature for $sha does not verify against $PUBKEY — signed with the wrong key?"
    SIG_ASSETS="$SIG_ASSETS $sig"
done
echo "Signed and verified $(echo "$SIG_ASSETS" | wc -w | tr -d ' ') checksum file(s)"

echo "Artifacts:"
[ -n "$ISO_UPLOAD" ]      && ls -lh "$ISO_UPLOAD"
[ -n "$IMG_UPLOAD" ]      && ls -lh "$IMG_UPLOAD"
[ -n "$UPDATE_TARBALL" ]  && ls -lh "$UPDATE_TARBALL"
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

# Build downloads table from whatever artifacts we actually have. ISO/IMG
# may be absent on a tarball-only release (build-iso.sh failed and was
# skipped). Update tarball may be absent on a fresh-install-only release.
DOWNLOADS_ROWS=""
SHASUMS=""
DECOMPRESS_NOTE=""
if [ -n "$ISO_UPLOAD" ]; then
    ISO_BASENAME="$(basename "$ISO_UPLOAD")"
    DOWNLOADS_ROWS="${DOWNLOADS_ROWS}| \`${ISO_BASENAME}\` | $(du -h "$ISO_UPLOAD" | awk '{print $1}') | Bootable ISO (CD/DVD, VM) |
"
    SHASUMS="${SHASUMS}$(cat "$ISO_SHA_UPLOAD")
"
fi
if [ -n "$IMG_UPLOAD" ]; then
    IMG_BASENAME="$(basename "$IMG_UPLOAD")"
    DOWNLOADS_ROWS="${DOWNLOADS_ROWS}| \`${IMG_BASENAME}\` | $(du -h "$IMG_UPLOAD" | awk '{print $1}') | USB flash drive image |
"
    SHASUMS="${SHASUMS}$(cat "$IMG_SHA_UPLOAD")
"
    if echo "$IMG_BASENAME" | grep -q '\.xz$'; then
        DECOMPRESS_NOTE="
> **Note:** The USB image is compressed with xz. Decompress before writing:
> \`\`\`bash
> xz -d ${IMG_BASENAME}
> dd if=aifw-${VERSION}-amd64.img of=/dev/sdX bs=1M status=progress
> \`\`\`"
    fi
fi
if [ -n "$UPDATE_TARBALL" ]; then
    TARBALL_BASENAME="$(basename "$UPDATE_TARBALL")"
    DOWNLOADS_ROWS="${DOWNLOADS_ROWS}| \`${TARBALL_BASENAME}\` | $(du -h "$UPDATE_TARBALL" | awk '{print $1}') | In-app update tarball |
"
    SHASUMS="${SHASUMS}$(cat "$UPDATE_SHA")
"
fi
[ -z "$ISO_UPLOAD$IMG_UPLOAD" ] && TARBALL_ONLY_NOTE="
> **Note:** This release ships only the in-app update tarball — no ISO/IMG
> were produced (build VM network issue). Existing appliances can still
> update via the in-app updater. For fresh installs, use the previous
> release's ISO/IMG and update from there." || TARBALL_ONLY_NOTE=""

BODY="## AiFw v${VERSION}

AI-Powered Firewall for FreeBSD 15.1
${TARBALL_ONLY_NOTE}

### Downloads

| File | Size | Description |
|------|------|-------------|
${DOWNLOADS_ROWS}
${DECOMPRESS_NOTE}
### Quick Start

1. Boot from the ISO or write the IMG to a USB drive
2. The setup wizard starts automatically on first boot
3. Follow the prompts to configure networking, admin account, and firewall policy
4. Use menu option **14** to install to disk (ZFS or UFS)
5. Access the web UI at \`https://<firewall-ip>:8080\`

### Verify Downloads

Each \`.sha256\` file is signed with the AiFw release key (\`update-signing.pub\`):

\`\`\`bash
minisign -Vm <file>.sha256 -x <file>.sha256.minisig -p update-signing.pub
sha256sum -c <file>.sha256
\`\`\`

\`\`\`
${SHASUMS}\`\`\`"

# Build asset list — only include artifacts we actually have. `gh release
# upload` errors on empty file paths, which would happen on a tarball-only
# release if we just concatenated all four ISO/IMG vars unguarded.
ASSETS=""
[ -n "$ISO_UPLOAD" ]      && ASSETS="$ASSETS $ISO_UPLOAD $ISO_SHA_UPLOAD"
[ -n "$IMG_UPLOAD" ]      && ASSETS="$ASSETS $IMG_UPLOAD $IMG_SHA_UPLOAD"
[ -n "$UPDATE_TARBALL" ]  && ASSETS="$ASSETS $UPDATE_TARBALL $UPDATE_SHA"
ASSETS="$ASSETS $SIG_ASSETS $PUBKEY"

# Publish as a PRE-RELEASE by default so it can be tested before the
# community auto-pulls it: the in-app updater's stable channel uses GitHub
# /releases/latest, which skips pre-releases, so a pre-release is only seen
# by boxes that opted into the pre-release channel (aifw update --pre / UI
# toggle). Set AIFW_RELEASE_FINAL=1 to cut a stable release that every field
# appliance will pull. Promote a tested pre-release later with:
#     gh release edit <tag> --prerelease=false --latest
if [ -n "${AIFW_RELEASE_FINAL:-}" ]; then
    CREATE_PRE=""                 # omit --prerelease -> stable, becomes latest
    EDIT_PRE="--prerelease=false"
    echo "Publishing STABLE release (AIFW_RELEASE_FINAL set) — field appliances will pull this."
else
    CREATE_PRE="--prerelease"
    EDIT_PRE="--prerelease=true"
    echo "Publishing PRE-RELEASE (default) — only --pre / pre-release-channel boxes will pull it."
    echo "  Set AIFW_RELEASE_FINAL=1 for a stable release, or promote later with:"
    echo "    gh release edit ${TAG} --prerelease=false --latest"
fi

# Create release (or update if exists)
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "Release ${TAG} exists, uploading assets..."
    # Pre-release gate FIRST, upload after: field appliances poll
    # /releases/latest, so fresh assets must never sit on a stable release
    # even for the duration of the upload. Strict (no || true) — if the
    # flag can't be applied, abort before any asset lands. The stable flip
    # for AIFW_RELEASE_FINAL stays AFTER the upload for the same reason,
    # in the publish edit below.
    if [ -z "${AIFW_RELEASE_FINAL:-}" ]; then
        gh release edit "$TAG" --prerelease=true
    fi
    gh release upload "$TAG" $ASSETS --clobber
    # Publish last: un-draft, retitle, and (for FINAL) flip to stable only
    # once the asset set is complete.
    gh release edit "$TAG" --draft=false $EDIT_PRE --title "AiFw v${VERSION}" --notes "$BODY" 2>/dev/null || true
else
    gh release create "$TAG" \
        $ASSETS \
        $CREATE_PRE \
        --title "AiFw v${VERSION}" \
        --notes "$BODY"
fi

# --- Cleanup temp files ---
if [ -n "$XZ_IMG" ]; then
    rm -f "$XZ_IMG" "$IMG_SHA_UPLOAD" "${IMG_SHA_UPLOAD}.minisig"
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
