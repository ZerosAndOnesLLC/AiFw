#!/bin/sh
# aifw-motd-cleanup.sh — idempotent MOTD version stripper.
#
# Removes any "AiFw <version> — AI-Powered ..." line from /etc/motd.template.
# Skips if the admin has customized MOTD via the UI (marker file present).

set -eu

MARKER="/var/db/aifw/motd.user-edited"
TEMPLATE="/etc/motd.template"

if [ -f "$MARKER" ]; then
    # Admin has customized MOTD — leave it alone.
    exit 0
fi

if [ ! -f "$TEMPLATE" ]; then
    exit 0
fi

# POSIX sed in place: FreeBSD requires `-i ''`, GNU sed accepts `-i`.
# Detect and branch.
if sed --version >/dev/null 2>&1; then
    SED_INPLACE="sed -i"
else
    SED_INPLACE="sed -i ''"
fi

# Strip version line; matches: optional leading whitespace + "AiFw <number>... " + "AI-Powered"
# Use eval so the SED_INPLACE value (which may contain a space-separated '' arg) expands correctly.
eval "$SED_INPLACE -E '/^[[:space:]]*AiFw [0-9][0-9.]+[[:space:]]*[—-][[:space:]]*AI-Powered/d' \"\$TEMPLATE\""
exit 0
