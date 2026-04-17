#!/bin/sh
# aifw-rescue.sh — snapshot current AiFw binaries, or restore them on failure.
#
# Run BEFORE an upgrade:          sh aifw-rescue.sh snapshot
# Run if internet breaks after:   sh aifw-rescue.sh restore
# Check what's stashed:           sh aifw-rescue.sh status

set -u
CMD="${1:-status}"

SBIN=/usr/local/sbin
UI=/usr/local/share/aifw/ui
PREV_DIR=/usr/local/aifw-prev
RC=/etc/rc.conf
RC_BAK="$PREV_DIR/rc.conf"
DB=/var/db/aifw/aifw.db
DB_BAK="$PREV_DIR/aifw.db"

BINS="aifw aifw-api aifw-daemon aifw-tui aifw-setup"

say() { echo "[aifw-rescue] $*"; }

snapshot() {
  mkdir -p "$PREV_DIR"

  for b in $BINS; do
    if [ -x "$SBIN/$b" ]; then
      cp -p "$SBIN/$b" "$PREV_DIR/$b"
      say "saved binary: $b"
    fi
  done

  if [ -d "$UI" ]; then
    rm -rf "$PREV_DIR/ui"
    cp -a "$UI" "$PREV_DIR/ui"
    say "saved UI"
  fi

  cp -p "$RC" "$RC_BAK"
  say "saved rc.conf -> $RC_BAK"

  # DB snapshot uses sqlite3 .backup so it's safe while the daemon is running.
  if [ -r "$DB" ]; then
    sqlite3 "$DB" ".backup $DB_BAK" 2>&1
    if [ -r "$DB_BAK" ]; then
      say "saved DB -> $DB_BAK ($(wc -c < $DB_BAK | tr -d ' ') bytes)"
    else
      say "WARNING: DB snapshot failed (continuing)"
    fi
  fi

  /usr/local/sbin/aifw --version > "$PREV_DIR/version.txt" 2>&1 || true
  date > "$PREV_DIR/snapshot_at.txt"
  say "Snapshot complete: $PREV_DIR"
  say "Version at snapshot time: $(cat $PREV_DIR/version.txt 2>/dev/null || echo unknown)"
}

restore() {
  if [ ! -d "$PREV_DIR" ]; then
    say "ERROR: no snapshot at $PREV_DIR. Cannot restore."
    exit 1
  fi

  say "Stopping aifw + resolver services..."
  service aifw_api stop       2>/dev/null || true
  service aifw_daemon stop    2>/dev/null || true
  service rdns stop           2>/dev/null || true
  service local_unbound stop  2>/dev/null || true

  say "Restoring binaries..."
  for b in $BINS; do
    if [ -x "$PREV_DIR/$b" ]; then
      cp -p "$PREV_DIR/$b" "$SBIN/$b"
      say "  restored: $b"
    fi
  done

  if [ -d "$PREV_DIR/ui" ]; then
    rm -rf "$UI"
    cp -a "$PREV_DIR/ui" "$UI"
    say "  restored: UI"
  fi

  if [ -r "$RC_BAK" ]; then
    cp -p "$RC_BAK" "$RC"
    say "  restored: rc.conf"
  fi

  # DB restore is OPT-IN via a second arg because it wipes post-snapshot config
  # changes. Usually you want the new binaries to read the new DB.
  if [ "${2:-}" = "--with-db" ] && [ -r "$DB_BAK" ]; then
    cp -p "$DB_BAK" "$DB"
    say "  restored: DB (because --with-db)"
  fi

  say "Starting services per restored rc.conf..."
  if [ "$(sysrc -n rdns_enable 2>/dev/null)" = YES ]; then
    service rdns start
  fi
  if [ "$(sysrc -n local_unbound_enable 2>/dev/null)" = YES ]; then
    service local_unbound start
  fi
  service aifw_daemon start
  service aifw_api start

  sleep 2
  say "Restore complete. Status:"
  /usr/local/sbin/aifw --version 2>&1 || true
  sockstat -4l -p 53 2>&1 | head -6
}

status() {
  if [ -d "$PREV_DIR" ]; then
    echo "Snapshot dir:      $PREV_DIR"
    echo "Snapshot taken:    $(cat $PREV_DIR/snapshot_at.txt 2>/dev/null || echo unknown)"
    echo "Snapshot version:  $(cat $PREV_DIR/version.txt 2>/dev/null || echo unknown)"
    echo
    echo "Current version:   $(/usr/local/sbin/aifw --version 2>/dev/null || echo unknown)"
    echo
    echo "Snapshot contents:"
    ls -la "$PREV_DIR"
  else
    echo "No snapshot at $PREV_DIR. Run: sh $0 snapshot"
  fi
}

case "$CMD" in
  snapshot) snapshot ;;
  restore)  restore "$@" ;;
  status)   status ;;
  *) echo "Usage: $0 {snapshot|restore|status}"; exit 1 ;;
esac
