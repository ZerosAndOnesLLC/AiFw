#!/bin/sh
# AiFw ISO Build Script
# Runs inside a FreeBSD environment to produce a bootable live CD ISO + USB image
# Usage: ./build-iso.sh <version> [arch]
#   version: e.g. 0.17.0
#   arch:    amd64 (default)

set -e

VERSION="${1:?Usage: $0 <version> [arch]}"
ARCH="${2:-amd64}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

FREEBSD_VERSION="15.0"
FREEBSD_RELEASE="15.0-RELEASE"
FREEBSD_MIRROR="https://download.freebsd.org/releases/${ARCH}/${FREEBSD_RELEASE}"

WORKDIR="/usr/obj/aifw-iso"
STAGEDIR="${WORKDIR}/stage"
ISODIR="${WORKDIR}/iso"
DISTDIR="${WORKDIR}/dist"
OUTPUTDIR="${WORKDIR}/output"

# cd9660 labels must be d-characters only (A-Z, 0-9, _)
LABEL="AIFW_$(echo "$VERSION" | tr '.' '_')"

echo "============================================"
echo "  AiFw ISO Builder"
echo "  Version: ${VERSION}"
echo "  Arch:    ${ARCH}"
echo "  FreeBSD: ${FREEBSD_RELEASE}"
echo "============================================"
echo ""

# --- Sanity checks ---
if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "ERROR: This script must run on FreeBSD"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must be run as root"
    exit 1
fi

# --- Clean previous build ---
echo "[1/9] Cleaning previous build..."
if [ -d "$WORKDIR" ]; then
    chflags -R noschg "$WORKDIR"
    rm -rf "$WORKDIR"
fi
mkdir -p "$STAGEDIR" "$ISODIR" "$DISTDIR" "$OUTPUTDIR"

# --- Fetch FreeBSD base + kernel ---
echo "[2/9] Fetching FreeBSD ${FREEBSD_RELEASE} base and kernel..."
for dist in base.txz kernel.txz; do
    if [ ! -f "${DISTDIR}/${dist}" ]; then
        fetch -o "${DISTDIR}/${dist}" "${FREEBSD_MIRROR}/${dist}"
    fi
done

# --- Extract base + kernel into staging ---
echo "[3/9] Extracting base system..."
tar -xf "${DISTDIR}/base.txz" -C "$STAGEDIR"
tar -xf "${DISTDIR}/kernel.txz" -C "$STAGEDIR"

# --- Strip unnecessary components ---
echo "[4/9] Stripping unnecessary components..."

# Documentation, examples, tests
rm -rf "$STAGEDIR/usr/share/doc"
rm -rf "$STAGEDIR/usr/share/examples"
rm -rf "$STAGEDIR/usr/share/games"
rm -rf "$STAGEDIR/usr/share/man"
rm -rf "$STAGEDIR/usr/share/info"
rm -rf "$STAGEDIR/usr/share/calendar"
rm -rf "$STAGEDIR/usr/share/dict"
rm -rf "$STAGEDIR/usr/share/groff_font"
rm -rf "$STAGEDIR/usr/share/me"
rm -rf "$STAGEDIR/usr/share/openssl"
rm -rf "$STAGEDIR/usr/share/i18n"
rm -rf "$STAGEDIR/usr/share/nls"
rm -rf "$STAGEDIR/usr/share/syscons/fonts"
rm -rf "$STAGEDIR/usr/share/syscons/keymaps"
rm -rf "$STAGEDIR/usr/share/syscons/scrnmaps"
rm -rf "$STAGEDIR/usr/share/vt/keymaps"
rm -rf "$STAGEDIR/usr/share/bsdconfig"
rm -rf "$STAGEDIR/usr/share/sendmail"
rm -rf "$STAGEDIR/usr/share/dtrace"
rm -rf "$STAGEDIR/usr/tests"
rm -rf "$STAGEDIR/usr/lib/debug"
rm -rf "$STAGEDIR/usr/lib/clang"
rm -rf "$STAGEDIR/rescue"

# Profiling libraries
rm -rf "$STAGEDIR/usr/lib"/*.a 2>/dev/null || true

# Unnecessary binaries — compilers, debuggers, profilers
rm -f "$STAGEDIR/usr/bin/clang"* "$STAGEDIR/usr/bin/llvm"* "$STAGEDIR/usr/bin/lldb"*
rm -f "$STAGEDIR/usr/bin/cc" "$STAGEDIR/usr/bin/c++" "$STAGEDIR/usr/bin/cpp"
rm -f "$STAGEDIR/usr/bin/gdb"* "$STAGEDIR/usr/bin/objdump"
rm -f "$STAGEDIR/usr/bin/addr2line" "$STAGEDIR/usr/bin/readelf"
rm -f "$STAGEDIR/usr/bin/lld" "$STAGEDIR/usr/bin/ld.lld"
rm -rf "$STAGEDIR/usr/include"

# Strip debug symbols from all binaries and libraries
find "$STAGEDIR/usr/bin" "$STAGEDIR/usr/sbin" "$STAGEDIR/usr/local/sbin" \
     "$STAGEDIR/bin" "$STAGEDIR/sbin" \
     -type f -perm +0111 -exec strip -s {} \; 2>/dev/null || true
find "$STAGEDIR/usr/lib" "$STAGEDIR/usr/local/lib" "$STAGEDIR/lib" \
     -name '*.so*' -type f -exec strip --strip-unneeded {} \; 2>/dev/null || true

# Strip debug info from kernel modules (keep all modules for hardware compatibility)
if [ -d "$STAGEDIR/boot/kernel" ]; then
    find "$STAGEDIR/boot/kernel" -name '*.ko' -exec strip --strip-debug {} \; 2>/dev/null || true
fi

echo "  Stripped size: $(du -sh "$STAGEDIR" | awk '{print $1}')"

# --- Install packages into staging via chroot ---
echo "[5/9] Installing packages..."
mkdir -p "$STAGEDIR/dev"
mount -t devfs devfs "$STAGEDIR/dev"
trap 'umount "$STAGEDIR/dev" 2>/dev/null || true' EXIT

# Copy resolv.conf for DNS in chroot
cp /etc/resolv.conf "$STAGEDIR/etc/resolv.conf"

# Bootstrap pkg and install required packages
chroot "$STAGEDIR" /bin/sh -c '
    env ASSUME_ALWAYS_YES=yes pkg bootstrap -f
    pkg install -y wireguard-tools sudo unbound
'

umount "$STAGEDIR/dev"
trap - EXIT

# Clean pkg cache and install artifacts to save space
rm -rf "$STAGEDIR/var/db/pkg/repos"
rm -rf "$STAGEDIR/var/cache/pkg"
rm -rf "$STAGEDIR/tmp/"*
# Strip package binaries too
find "$STAGEDIR/usr/local/bin" "$STAGEDIR/usr/local/sbin" "$STAGEDIR/usr/local/lib" \
     -type f \( -perm +0111 -o -name '*.so*' \) -exec strip -s {} \; 2>/dev/null || true

# --- Overlay AiFw binaries and config ---
echo "[6/9] Installing AiFw..."

# Binaries (should be pre-built and placed in freebsd/release/)
BINDIR="${SCRIPT_DIR}/release"
for bin in aifw aifw-daemon aifw-api aifw-tui aifw-setup trafficcop rdhcpd rdns rdns-control rtime; do
    if [ -f "${BINDIR}/${bin}" ]; then
        install -s -m 755 "${BINDIR}/${bin}" "$STAGEDIR/usr/local/sbin/${bin}"
    else
        echo "WARNING: ${bin} not found in ${BINDIR}, skipping"
    fi
done

# Static UI build
UI_DIR="${SCRIPT_DIR}/ui-export"
if [ -d "$UI_DIR" ]; then
    mkdir -p "$STAGEDIR/usr/local/share/aifw/ui"
    cp -a "$UI_DIR/"* "$STAGEDIR/usr/local/share/aifw/ui/"
fi

# Overlay files (rc.d scripts, console menu, installer)
OVERLAY_DIR="${SCRIPT_DIR}/overlay"
if [ -d "$OVERLAY_DIR" ]; then
    cp -a "$OVERLAY_DIR/"* "$STAGEDIR/"
    # Ensure scripts are executable
    chmod 755 "$STAGEDIR/usr/local/etc/rc.d/"* 2>/dev/null || true
    chmod 755 "$STAGEDIR/usr/local/sbin/aifw-console" 2>/dev/null || true
    chmod 755 "$STAGEDIR/usr/local/sbin/aifw-install" 2>/dev/null || true
fi

# Create required directories
mkdir -p "$STAGEDIR/usr/local/etc/aifw"
mkdir -p "$STAGEDIR/usr/local/etc/aifw/anchors"
mkdir -p "$STAGEDIR/usr/local/share/aifw"
mkdir -p "$STAGEDIR/var/db/aifw"
mkdir -p "$STAGEDIR/var/log/aifw"
mkdir -p "$STAGEDIR/var/log/trafficcop"
mkdir -p "$STAGEDIR/var/db/rdhcpd/leases"
mkdir -p "$STAGEDIR/var/log/rdhcpd"
mkdir -p "$STAGEDIR/usr/local/etc/rdhcpd"
mkdir -p "$STAGEDIR/usr/local/etc/rdns/zones"
mkdir -p "$STAGEDIR/usr/local/etc/rdns/rpz"
mkdir -p "$STAGEDIR/var/run/rdns"
mkdir -p "$STAGEDIR/var/log/rdns"
mkdir -p "$STAGEDIR/usr/local/etc/rtime"
mkdir -p "$STAGEDIR/var/run/rtime"
mkdir -p "$STAGEDIR/var/log/rtime"

# --- Configure live environment ---
echo "[7/9] Configuring live environment..."

# rc.conf for live boot
cat > "$STAGEDIR/etc/rc.conf" <<'RCCONF'
hostname="aifw"
ifconfig_DEFAULT="DHCP"
pf_enable="YES"
pflog_enable="YES"
gateway_enable="YES"
sshd_enable="YES"
sendmail_enable="NONE"
sendmail_submit_enable="NO"
sendmail_outbound_enable="NO"
sendmail_msp_queue_enable="NO"
aifw_firstboot_enable="YES"
trafficcop_enable="NO"
rdhcpd_enable="NO"
rdns_enable="NO"
rtime_enable="NO"
RCCONF

# fstab for live CD (read-only root + tmpfs)
cat > "$STAGEDIR/etc/fstab" <<'FSTAB'
/dev/cd0    /       cd9660  ro          0  0
tmpfs       /tmp    tmpfs   rw,mode=01777  0  0
tmpfs       /var    tmpfs   rw          0  0
FSTAB

# loader.conf
cat > "$STAGEDIR/boot/loader.conf" <<'LOADER'
autoboot_delay="3"
beastie_disable="YES"
loader_logo="none"
kern.geom.label.disk_ident.enable="0"
kern.geom.label.gptid.enable="0"
vfs.root.mountfrom="cd9660:cd0"
LOADER

# Root shell stays /bin/sh so SSH works normally.
# Console menu runs via autologin on ttyv0 only (physical console).

# /etc/ttys — auto-login on ttyv0 runs the console menu
sed -i '' 's|^ttyv0.*|ttyv0 "/usr/libexec/getty autologin" xterm on secure|' "$STAGEDIR/etc/ttys"

# Add aifw-console to /etc/shells so it can be used as a login shell
echo "/usr/local/sbin/aifw-console" >> "$STAGEDIR/etc/shells"

# Configure sshd for password auth (append to end to override any defaults)
cat >> "$STAGEDIR/etc/ssh/sshd_config" <<'SSHD'

# AiFw: enable root login and password auth
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
SSHD

# Create /etc/login.conf entry for autologin (no password prompt)
if ! grep -q 'autologin' "$STAGEDIR/etc/gettytab" 2>/dev/null; then
    cat >> "$STAGEDIR/etc/gettytab" <<'GETTY'

# Auto-login for AiFw console
autologin|al|Auto login:\
    :ht:np:sp#115200:al=root:lo=/usr/local/sbin/aifw-console:
GETTY
fi

# Entropy for live boot
dd if=/dev/random of="$STAGEDIR/boot/entropy" bs=4096 count=1 2>/dev/null
dd if=/dev/random of="$STAGEDIR/entropy" bs=4096 count=1 2>/dev/null

# Version file
echo "$VERSION" > "$STAGEDIR/usr/local/share/aifw/version"

# MOTD
cat > "$STAGEDIR/etc/motd.template" <<MOTD

  AiFw ${VERSION} — AI-Powered Firewall for FreeBSD

  Commands:
    aifw-console        Launch the management menu
    aifw-install        Install AiFw to disk
    aifw-setup          Run the setup wizard
    aifw                CLI tool (aifw --help)
    aifw-tui            Terminal UI

  Web UI:  https://<this-ip>:8080/

MOTD

# --- Build ISO ---
echo "[8/9] Building ISO image..."

# Create EFI boot image
EFIIMG="${WORKDIR}/efiboot.img"
EFI_STAGEDIR="${WORKDIR}/efi-stage"
mkdir -p "$EFI_STAGEDIR/EFI/BOOT"
cp "$STAGEDIR/boot/loader.efi" "$EFI_STAGEDIR/EFI/BOOT/BOOTX64.efi"
makefs -t msdos -s 5m -o fat_type=12 "$EFIIMG" "$EFI_STAGEDIR"

# Copy EFI image into staging for ISO
mkdir -p "$STAGEDIR/boot/efi"
cp "$EFIIMG" "$STAGEDIR/boot/efi/efiboot.img"

# Build ISO with makefs
# El Torito: BIOS boot from cdboot, EFI boot from efiboot.img
# bootimage paths must be absolute
makefs -t cd9660 \
    -o rockridge \
    -o label="${LABEL}" \
    -o bootimage="i386;${STAGEDIR}/boot/cdboot" \
    -o no-emul-boot \
    -o bootimage="efi;${STAGEDIR}/boot/efi/efiboot.img" \
    -o no-emul-boot \
    -o platformid=efi \
    "${OUTPUTDIR}/aifw-${VERSION}-${ARCH}.iso" \
    "$STAGEDIR"

echo "  ISO: ${OUTPUTDIR}/aifw-${VERSION}-${ARCH}.iso"
ls -lh "${OUTPUTDIR}/aifw-${VERSION}-${ARCH}.iso"

# --- Build USB image ---
echo "[9/9] Building USB image..."

IMG="${OUTPUTDIR}/aifw-${VERSION}-${ARCH}.img"
# Stage size + 50% headroom for EFI partition (260MB), UFS journal, inodes, and metadata
IMG_SIZE=$(du -sm "$STAGEDIR" | awk '{print int($1 * 1.5) + 300}')

# Clean up any stale md devices from previous failed runs
for stale_md in $(mdconfig -l 2>/dev/null); do
    umount -f "/dev/${stale_md}p3" 2>/dev/null || true
    umount -f "/dev/${stale_md}p1" 2>/dev/null || true
    mdconfig -d -u "$stale_md" 2>/dev/null || true
done

# Create raw image
truncate -s "${IMG_SIZE}m" "$IMG"

# Create GPT
MD=$(mdconfig -a -t vnode -f "$IMG")
gpart create -s gpt "$MD"
gpart add -t efi -s 260m -l efi "$MD"
gpart add -t freebsd-boot -s 512k -l boot "$MD"
gpart add -t freebsd-ufs -l aifw "$MD"

# Format EFI
newfs_msdos -F 32 -c 1 "/dev/${MD}p1"
mount -t msdos "/dev/${MD}p1" /mnt
mkdir -p /mnt/EFI/BOOT
cp "$STAGEDIR/boot/loader.efi" /mnt/EFI/BOOT/BOOTX64.efi
umount /mnt

# Write bootcode
gpart bootcode -b "$STAGEDIR/boot/pmbr" -p "$STAGEDIR/boot/gptboot" -i 2 "$MD"

# Format UFS root
newfs -U -j "/dev/${MD}p3"
mount "/dev/${MD}p3" /mnt

# Clone staged system into USB image
# Update fstab for USB boot
cp -a "$STAGEDIR/"* /mnt/
cat > /mnt/etc/fstab <<USBFSTAB
/dev/ufs/aifw  /       ufs     rw  1  1
tmpfs          /tmp    tmpfs   rw,mode=01777  0  0
USBFSTAB

# Update loader.conf for USB boot
sed -i '' '/vfs.root.mountfrom/d' /mnt/boot/loader.conf
echo 'vfs.root.mountfrom="ufs:/dev/ufs/aifw"' >> /mnt/boot/loader.conf

# Restore writable root shell for installed system
chroot /mnt /usr/sbin/pw usermod root -s /usr/local/sbin/aifw-console 2>/dev/null || true

umount /mnt
mdconfig -d -u "$MD"

echo "  IMG: ${IMG}"
ls -lh "$IMG"

# --- Checksums ---
echo ""
echo "Generating checksums..."
cd "$OUTPUTDIR"
sha256 "aifw-${VERSION}-${ARCH}.iso" > "aifw-${VERSION}-${ARCH}.iso.sha256"
sha256 "aifw-${VERSION}-${ARCH}.img" > "aifw-${VERSION}-${ARCH}.img.sha256"

echo ""
echo "============================================"
echo "  Build complete!"
echo "============================================"
echo ""
ls -lh "$OUTPUTDIR/"
echo ""
cat "$OUTPUTDIR/"*.sha256
