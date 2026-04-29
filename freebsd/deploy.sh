#!/bin/sh
# AiFw Deploy — pull latest, build, deploy binaries + UI, restart services
# Usage: ssh root@<appliance> 'sh /root/AiFw/freebsd/deploy.sh'
#   or locally: sh freebsd/deploy.sh

set -e

REPO_DIR="/root/AiFw"
BINS="aifw aifw-api aifw-daemon aifw-ids aifw-setup aifw-tui"
TRAFFICCOP_DIR="/root/trafficcop"
RDHCP_DIR="/root/rDHCP"
RDNS_DIR="/root/rDNS"
RTIME_DIR="/root/rTIME"
BIN_DIR="/usr/local/sbin"
UI_DIR="/usr/local/share/aifw/ui"

echo "============================================"
echo "  AiFw Deploy"
echo "============================================"
echo ""

# --- Ensure we're in the repo ---
if [ ! -f "$REPO_DIR/Cargo.toml" ]; then
    echo "ERROR: Repo not found at $REPO_DIR"
    echo "Run: git clone https://github.com/ZerosAndOnesLLC/AiFw.git $REPO_DIR"
    exit 1
fi

cd "$REPO_DIR"

# --- Ensure cargo is available ---
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo not found. Install rust first:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    exit 1
fi

# --- Ensure dependencies ---
for pkg in sudo unbound curl; do
    if ! pkg info -q "$pkg" 2>/dev/null; then
        echo "Installing $pkg..."
        pkg install -y "$pkg"
    fi
done

# Ensure unbound directory has correct ownership
if [ -d /var/unbound ]; then
    chown -R unbound:unbound /var/unbound
fi

# --- Pull latest ---
echo "[1/5] Pulling latest..."
git checkout -- Cargo.lock 2>/dev/null || true
git pull
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
echo "  Version: $VERSION"
echo ""

# --- Build Rust ---
echo "[2/5] Building Rust (release)..."
cargo build --release 2>&1 | tail -3

# Build TrafficCop if source available
if [ -d "$TRAFFICCOP_DIR" ]; then
    echo "  Building TrafficCop..."
    cd "$TRAFFICCOP_DIR"
    git pull 2>/dev/null || true
    cargo build --release 2>&1 | tail -3
    cd "$REPO_DIR"
elif [ ! -f "$BIN_DIR/trafficcop" ]; then
    echo "  Cloning TrafficCop..."
    git clone https://github.com/ZerosAndOnesLLC/TrafficCop.git "$TRAFFICCOP_DIR"
    cd "$TRAFFICCOP_DIR"
    cargo build --release 2>&1 | tail -3
    cd "$REPO_DIR"
fi

# Build rDHCP if source available
if [ -d "$RDHCP_DIR" ]; then
    echo "  Building rDHCP..."
    cd "$RDHCP_DIR"
    git pull 2>/dev/null || true
    cargo build --release 2>&1 | tail -3
    cd "$REPO_DIR"
elif [ ! -f "$BIN_DIR/rdhcpd" ]; then
    echo "  Cloning rDHCP..."
    git clone https://github.com/ZerosAndOnesLLC/rDHCP.git "$RDHCP_DIR"
    cd "$RDHCP_DIR"
    cargo build --release 2>&1 | tail -3
    cd "$REPO_DIR"
fi

# Build rDNS if source available
if [ -d "$RDNS_DIR" ]; then
    echo "  Building rDNS..."
    cd "$RDNS_DIR"
    git pull 2>/dev/null || true
    cargo build --release 2>&1 | tail -3
    cd "$REPO_DIR"
elif [ ! -f "$BIN_DIR/rdns" ]; then
    echo "  Cloning rDNS..."
    git clone https://github.com/ZerosAndOnesLLC/rDNS.git "$RDNS_DIR"
    cd "$RDNS_DIR"
    cargo build --release 2>&1 | tail -3
    cd "$REPO_DIR"
fi

# Build rTIME if source available
if [ -d "$RTIME_DIR" ]; then
    echo "  Building rTIME..."
    cd "$RTIME_DIR"
    git pull 2>/dev/null || true
    cargo build --release 2>&1 | tail -3
    cd "$REPO_DIR"
elif [ ! -f "$BIN_DIR/rtime" ]; then
    echo "  Cloning rTIME..."
    git clone https://github.com/ZerosAndOnesLLC/rTIME.git "$RTIME_DIR"
    cd "$RTIME_DIR"
    cargo build --release 2>&1 | tail -3
    cd "$REPO_DIR"
fi
echo ""

# --- Build UI ---
echo "[3/5] Building UI..."
cd aifw-ui
npm config delete python 2>/dev/null || true
npm ci --silent 2>&1 | tail -1
npm run build 2>&1 | tail -3
cd "$REPO_DIR"
echo ""

# --- Stop services ---
echo "[4/5] Deploying..."
service trafficcop stop 2>/dev/null || true
pkill -9 -f "daemon.*trafficcop" 2>/dev/null || true
pkill -9 -f trafficcop 2>/dev/null || true
service rdhcpd stop 2>/dev/null || true
pkill -9 -f "daemon.*rdhcpd" 2>/dev/null || true
pkill -9 -f rdhcpd 2>/dev/null || true
service rdns stop 2>/dev/null || true
pkill -9 -f "daemon.*rdns" 2>/dev/null || true
pkill -9 -f rdns 2>/dev/null || true
service rtime stop 2>/dev/null || true
pkill -9 -f "daemon.*rtime" 2>/dev/null || true
pkill -9 -f rtime 2>/dev/null || true
service aifw_api stop 2>/dev/null || true
service aifw_ids stop 2>/dev/null || true
service aifw_daemon stop 2>/dev/null || true
pkill -9 -f "aifw-api.*8081" 2>/dev/null || true
pkill -9 -f "daemon.*aifw-ids" 2>/dev/null || true
pkill -9 -f "aifw-ids" 2>/dev/null || true
sleep 2

# Copy binaries
for bin in $BINS; do
    cp "target/release/$bin" "$BIN_DIR/$bin"
    chmod 755 "$BIN_DIR/$bin"
done
# Copy TrafficCop binary
if [ -f "$TRAFFICCOP_DIR/target/release/trafficcop" ]; then
    cp "$TRAFFICCOP_DIR/target/release/trafficcop" "$BIN_DIR/trafficcop"
    chmod 755 "$BIN_DIR/trafficcop"
fi
# Copy rDHCP binary
if [ -f "$RDHCP_DIR/target/release/rdhcpd" ]; then
    cp "$RDHCP_DIR/target/release/rdhcpd" "$BIN_DIR/rdhcpd"
    chmod 755 "$BIN_DIR/rdhcpd"
fi
# Copy rDNS binaries
if [ -f "$RDNS_DIR/target/release/rdns" ]; then
    cp "$RDNS_DIR/target/release/rdns" "$BIN_DIR/rdns"
    chmod 755 "$BIN_DIR/rdns"
fi
if [ -f "$RDNS_DIR/target/release/rdns-control" ]; then
    cp "$RDNS_DIR/target/release/rdns-control" "$BIN_DIR/rdns-control"
    chmod 755 "$BIN_DIR/rdns-control"
fi
# Copy rTIME binary
if [ -f "$RTIME_DIR/target/release/rtime" ]; then
    cp "$RTIME_DIR/target/release/rtime" "$BIN_DIR/rtime"
    chmod 755 "$BIN_DIR/rtime"
fi
echo "  Binaries installed to $BIN_DIR"

# Copy UI
cp -a aifw-ui/out/* "$UI_DIR/"
echo "  UI deployed to $UI_DIR"

# Update version file
echo "$VERSION" > /usr/local/share/aifw/version
echo "  Version file updated to $VERSION"

# Ensure permissions
chown -R aifw:aifw /var/db/aifw 2>/dev/null || true
chown -R aifw:aifw /var/log/aifw 2>/dev/null || true
mkdir -p /var/log/trafficcop
chown -R aifw:aifw /var/log/trafficcop 2>/dev/null || true
mkdir -p /usr/local/etc/trafficcop
chown -R aifw:aifw /usr/local/etc/trafficcop 2>/dev/null || true
mkdir -p /var/db/rdhcpd/leases /var/log/rdhcpd /usr/local/etc/rdhcpd
chown -R aifw:aifw /var/db/rdhcpd /var/log/rdhcpd /usr/local/etc/rdhcpd 2>/dev/null || true
mkdir -p /usr/local/etc/rdns/zones /usr/local/etc/rdns/rpz /var/run/rdns /var/log/rdns
# Create rdns user if not exists
pw user show rdns >/dev/null 2>&1 || pw useradd rdns -d /nonexistent -s /usr/sbin/nologin -c "rDNS DNS Server" 2>/dev/null || true
mkdir -p /usr/local/etc/rtime /var/run/rtime /var/log/rtime
chown -R aifw:aifw /usr/local/etc/rtime /var/log/rtime 2>/dev/null || true

# Install TrafficCop default config if not present
if [ ! -f /usr/local/etc/trafficcop/config.yaml ]; then
    cp "$REPO_DIR/freebsd/overlay/usr/local/etc/trafficcop/config.yaml" /usr/local/etc/trafficcop/config.yaml
    chown aifw:aifw /usr/local/etc/trafficcop/config.yaml
fi

# Install TrafficCop rc.d script
cp "$REPO_DIR/freebsd/overlay/usr/local/etc/rc.d/trafficcop" /usr/local/etc/rc.d/trafficcop
chmod 755 /usr/local/etc/rc.d/trafficcop

# Install rDHCP rc.d script
cp "$REPO_DIR/freebsd/overlay/usr/local/etc/rc.d/rdhcpd" /usr/local/etc/rc.d/rdhcpd
chmod 755 /usr/local/etc/rc.d/rdhcpd

# Install rDNS rc.d script
cp "$REPO_DIR/freebsd/overlay/usr/local/etc/rc.d/rdns" /usr/local/etc/rc.d/rdns
chmod 755 /usr/local/etc/rc.d/rdns

# Install rTIME rc.d script
cp "$REPO_DIR/freebsd/overlay/usr/local/etc/rc.d/rtime" /usr/local/etc/rc.d/rtime
chmod 755 /usr/local/etc/rc.d/rtime

# Install aifw_daemon rc.d script
cp "$REPO_DIR/freebsd/overlay/usr/local/etc/rc.d/aifw_daemon" /usr/local/etc/rc.d/aifw_daemon
chmod 755 /usr/local/etc/rc.d/aifw_daemon

# Install aifw_api rc.d script
cp "$REPO_DIR/freebsd/overlay/usr/local/etc/rc.d/aifw_api" /usr/local/etc/rc.d/aifw_api
chmod 755 /usr/local/etc/rc.d/aifw_api

# Install aifw_ids rc.d script
cp "$REPO_DIR/freebsd/overlay/usr/local/etc/rc.d/aifw_ids" /usr/local/etc/rc.d/aifw_ids
chmod 755 /usr/local/etc/rc.d/aifw_ids

# Install aifw_watchdog rc.d script
cp "$REPO_DIR/freebsd/overlay/usr/local/etc/rc.d/aifw_watchdog" /usr/local/etc/rc.d/aifw_watchdog
chmod 755 /usr/local/etc/rc.d/aifw_watchdog

# HA rc.d helpers (only meaningful on cluster-enabled nodes)
for rcd in aifw_carp_demote aifw_demote_on_shutdown; do
    src="$REPO_DIR/freebsd/overlay/usr/local/etc/rc.d/$rcd"
    [ -f "$src" ] && install -m 755 "$src" "/usr/local/etc/rc.d/$rcd"
done

# Install libexec scripts (restart driver, watchdog loop, motd cleanup,
# login migrate, shutdown hook). Mode 755 so the daemon supervisor can exec them.
mkdir -p /usr/local/libexec
for script in aifw-restart.sh aifw-watchdog.sh aifw-motd-cleanup.sh aifw-login-migrate.sh aifw-shutdown-hook.sh; do
    src="$REPO_DIR/freebsd/overlay/usr/local/libexec/$script"
    if [ -f "$src" ]; then
        install -m 755 "$src" "/usr/local/libexec/$script"
    fi
done

# Ensure sudoers for aifw user
mkdir -p /usr/local/etc/sudoers.d
echo 'aifw ALL=(ALL) NOPASSWD: /sbin/pfctl, /sbin/ifconfig, /sbin/dhclient, /sbin/route, /usr/sbin/service, /usr/sbin/sysrc, /usr/sbin/pkg, /usr/sbin/freebsd-update, /sbin/shutdown, /bin/hostname, /bin/cat, /bin/pkill, /usr/bin/pkill, /usr/bin/tee, /usr/sbin/chown, /bin/mkdir, /usr/sbin/tcpdump, /usr/bin/install, /bin/rm /usr/local/etc/rdns/rpz/*
aifw ALL=(root) NOPASSWD: /usr/sbin/daemon -f *' > /usr/local/etc/sudoers.d/aifw
chmod 440 /usr/local/etc/sudoers.d/aifw

echo ""

# Strip stale AiFw version from MOTD template (idempotent; respects user customizations via /var/db/aifw/motd.user-edited marker).
if [ -x /usr/local/libexec/aifw-motd-cleanup.sh ]; then
    /usr/local/libexec/aifw-motd-cleanup.sh || true
fi

# --- Restart services ---
echo "[5/5] Restarting services..."
# Make sure rc.conf has the rcvar for every AiFw service. Older test VMs
# were brought up before aifw_ids existed, so the rcvar was never set —
# `service aifw_ids start` was a silent no-op and IDS endpoints returned
# 503. Idempotent: sysrc rewrites the line whether or not it exists.
sysrc aifw_daemon_enable=YES >/dev/null
sysrc aifw_ids_enable=YES >/dev/null
sysrc aifw_api_enable=YES >/dev/null
sysrc aifw_watchdog_enable=YES >/dev/null
service aifw_daemon start </dev/null >/dev/null 2>&1 || echo "  WARNING: aifw_daemon not configured"
# aifw_ids must come up before aifw_api (aifw_api REQUIREs aifw_ids)
service aifw_ids start </dev/null >/dev/null 2>&1 || echo "  WARNING: aifw_ids not configured"
service aifw_api start </dev/null >/dev/null 2>&1 || echo "  WARNING: aifw_api not configured"
service aifw_watchdog start </dev/null >/dev/null 2>&1 || echo "  WARNING: aifw_watchdog not configured"
# Start TrafficCop if enabled
if [ "$(sysrc -n trafficcop_enable 2>/dev/null)" = "YES" ]; then
    service trafficcop start </dev/null >/dev/null 2>&1 || true
fi
# Start rDHCP if enabled
if [ "$(sysrc -n rdhcpd_enable 2>/dev/null)" = "YES" ]; then
    service rdhcpd start </dev/null >/dev/null 2>&1 || true
fi
# Start rDNS if enabled
if [ "$(sysrc -n rdns_enable 2>/dev/null)" = "YES" ]; then
    service rdns start </dev/null >/dev/null 2>&1 || true
fi
# Start rTIME if enabled
if [ "$(sysrc -n rtime_enable 2>/dev/null)" = "YES" ]; then
    service rtime start </dev/null >/dev/null 2>&1 || true
fi
sleep 1

# --- Verify ---
echo ""
DAEMON_STATUS=$(service aifw_daemon status 2>&1 || true)
API_STATUS=$(service aifw_api status 2>&1 || true)
echo "  $DAEMON_STATUS"
echo "  $API_STATUS"
echo ""
echo "============================================"
echo "  Deploy complete — v$VERSION"
echo "============================================"
