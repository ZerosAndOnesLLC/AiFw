#!/bin/sh
# aifw-login-migrate.sh — idempotent one-shot migration that enforces
# password-protected console login on existing AiFw installs.
#
# Two changes:
#   1. /etc/ttys ttyv0 uses standard "Pc" getty (not autologin).
#   2. Root's login shell is /usr/local/sbin/aifw-console.
#
# Skips if the system is already configured. Safe to re-run.

set -eu

TTYS="/etc/ttys"
SHELLS="/etc/shells"
AIFW_CONSOLE="/usr/local/sbin/aifw-console"

# --- 1. Rewrite ttyv0 if still using autologin ---
if [ -f "$TTYS" ] && grep -qE '^ttyv0[[:space:]].*autologin' "$TTYS"; then
    # FreeBSD sed in place requires -i ''.
    sed -i '' 's|^ttyv0.*|ttyv0 "/usr/libexec/getty Pc" xterm on secure|' "$TTYS"
fi

# --- 2. Ensure aifw-console is a valid shell ---
if [ -f "$SHELLS" ] && ! grep -q "^${AIFW_CONSOLE}$" "$SHELLS"; then
    echo "$AIFW_CONSOLE" >> "$SHELLS"
fi

# --- 3. Set root's login shell to aifw-console (if not already) ---
current_shell=$(getent passwd root 2>/dev/null | awk -F: '{print $7}')
if [ -z "$current_shell" ]; then
    current_shell=$(awk -F: '$1=="root" {print $10}' /etc/master.passwd 2>/dev/null || true)
fi
if [ "$current_shell" != "$AIFW_CONSOLE" ] && [ -x "$AIFW_CONSOLE" ]; then
    /usr/sbin/pw usermod root -s "$AIFW_CONSOLE" || true
fi

exit 0
