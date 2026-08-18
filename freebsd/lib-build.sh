#!/bin/sh
# AiFw shared build steps (#203).
#
# Sourced — not executed — by freebsd/build-local.sh, freebsd/build-update.sh
# and the FreeBSD VM step of .github/workflows/build-iso.yml, so the three
# release paths run the *same* code for: UI pre-compression, the compiled-
# version guard, companion installs from crates.io, staging, and packing the
# update tarball. Change a step here and every path picks it up; there is
# nothing left to mirror by hand.
#
# Requirements of the sourcing script: POSIX sh, `set -e`, `PROJECT_ROOT`
# set to the repo checkout, `jq` and `cargo` on PATH (`aifw_ensure_cargo`
# sources rustup's env), running on FreeBSD for the tarball steps
# (`freebsd-version`, `sha256`).

aifw_die() {
    echo "ERROR: $1" >&2
    exit 1
}

# Source rustup's env (sudo/CI shells lose PATH) and bootstrap rustup only
# when cargo is really missing — a re-sync against static.rust-lang.org on a
# working toolchain has broken builds on hosts with flaky DNS.
aifw_ensure_cargo() {
    if [ -f "$HOME/.cargo/env" ]; then
        . "$HOME/.cargo/env"
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        echo "Installing Rust via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        . "$HOME/.cargo/env"
    fi
    echo "--- Using cargo: $(command -v cargo) ($(cargo --version)) ---"
}

# Pre-compress every text asset in a static UI export alongside the
# originals. tower_http's ServeDir picks up .br / .gz siblings when the
# request advertises the matching Accept-Encoding. Images/fonts are skipped
# (already compressed).
#   $1 = UI export directory (e.g. aifw-ui/out)
aifw_precompress_ui() {
    _dir="$1"
    [ -d "$_dir" ] || return 0
    echo "  Pre-compressing UI text assets in $_dir (br + gz)..."
    _has_brotli=0
    command -v brotli >/dev/null 2>&1 && _has_brotli=1
    find "$_dir" -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' \
        -o -name '*.svg' -o -name '*.json' -o -name '*.txt' \
        -o -name '*.map' -o -name '*.xml' \) | while read -r f; do
        if [ "$_has_brotli" -eq 1 ] && [ ! -f "${f}.br" ]; then
            brotli -q 11 -k "$f" 2>/dev/null || true
        fi
        if [ ! -f "${f}.gz" ]; then
            gzip -k -9 "$f" 2>/dev/null || true
        fi
    done
    # stat -f%z is BSD; on Linux fall back to wc -c so CI's ubuntu job can
    # print the same summary.
    if stat -f%z / >/dev/null 2>&1; then
        _sz='stat -f%z'
    else
        _sz='stat -c%s'
    fi
    _js_orig=$(find "$_dir" -name '*.js' -not -name '*.gz' -not -name '*.br' -exec $_sz {} + 2>/dev/null | awk '{s+=$1} END {print s}')
    _js_br=$(find "$_dir" -name '*.js.br' -exec $_sz {} + 2>/dev/null | awk '{s+=$1} END {print s}')
    if [ -n "$_js_orig" ] && [ -n "$_js_br" ] && [ "$_js_orig" -gt 0 ]; then
        printf "  JS size: %d KB raw  ->  %d KB brotli (%d%% smaller)\n" \
            "$((_js_orig / 1024))" "$((_js_br / 1024))" \
            "$(( (_js_orig - _js_br) * 100 / _js_orig ))"
    fi
}

# The version label, tarball name and version file all come from $VERSION,
# but the binaries' version is baked in from Cargo.toml at compile time. A
# divergence (stale cargo artifact after a bump, or a VERSION arg that
# doesn't match the checkout) ships binaries that install as the WRONG
# version — the silent no-op upgrade that stranded appliances on 5.96.8.
#   $1 = expected version
aifw_verify_binary_version() {
    _bin_ver="$("$PROJECT_ROOT/target/release/aifw" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    [ "$_bin_ver" = "$1" ] || aifw_die "version mismatch: building v$1 but target/release/aifw reports v${_bin_ver:-unknown}. Bump Cargo.toml and rebuild (try 'cargo clean -p aifw') before releasing."
    echo "--- Verified compiled aifw binary is v$1 ---"
}

# Install companion services (reverse proxy, DHCP, DNS, NTP) from crates.io
# at the versions pinned in freebsd/manifest.json (#651). A missing pin or an
# unpublished version fails the build — never fall back to branch HEAD.
# cargo install is a no-op when the pin is already present in the root.
#   $1 = install root (binaries land in $1/bin)
aifw_install_companions() {
    _root="$1"
    _manifest="$PROJECT_ROOT/freebsd/manifest.json"
    for _name in $(jq -r '.external_repos[].name' "$_manifest"); do
        _crate=$(jq -r --arg n "$_name" '.external_repos[] | select(.name == $n) | .crate // empty' "$_manifest")
        _ver=$(jq -r --arg n "$_name" '.external_repos[] | select(.name == $n) | .version // empty' "$_manifest")
        [ -n "$_crate" ] || aifw_die "no crate name for $_name in manifest.json (#651)"
        [ -n "$_ver" ] || aifw_die "no pinned version for $_name in manifest.json (#651)"
        echo "--- Installing $_name ($_crate $_ver from crates.io) ---"
        cargo install --locked --version "$_ver" --root "$_root" "$_crate" \
            || aifw_die "cargo install of $_crate $_ver failed"
        for _bin in $(jq -r --arg n "$_name" '.external_repos[] | select(.name == $n) | .binaries[]' "$_manifest"); do
            [ -f "$_root/bin/$_bin" ] || aifw_die "$_crate $_ver did not produce binary $_bin"
        done
    done
}

# Copy every binary the manifest lists (local + companion) into a staging
# directory. Refuses to ship a partial set — hardcoding the list here was the
# bug that shipped a 5.76.1 release missing aifw-ids.
#   $1 = destination dir, $2 = companion bin dir
aifw_stage_binaries() {
    _dest="$1"; _cbin="$2"
    _manifest="$PROJECT_ROOT/freebsd/manifest.json"
    mkdir -p "$_dest"
    _local=$(jq -r '.binaries.local[]' "$_manifest" | tr '\n' ' ')
    [ -n "$_local" ] || aifw_die "Could not parse binaries.local from manifest.json (jq failed)"
    for _bin in $_local; do
        [ -f "$PROJECT_ROOT/target/release/$_bin" ] || aifw_die "$_bin listed in manifest but not built — refusing to ship a partial release"
        cp "$PROJECT_ROOT/target/release/$_bin" "$_dest/$_bin"
    done
    for _bin in $(jq -r '.external_repos[].binaries[]' "$_manifest"); do
        [ -f "$_cbin/$_bin" ] || aifw_die "companion binary $_bin missing from $_cbin"
        cp "$_cbin/$_bin" "$_dest/$_bin"
    done
}

# Machine-readable record of the exact source that produced an artifact
# set: AiFw commit + every pinned companion crate version. Ships as a
# release asset and inside the update tarball.
#   $1 = version, $2 = output file
aifw_write_components_json() {
    _commit="$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
    jq -n \
        --arg version "$1" \
        --arg aifw_commit "$_commit" \
        --slurpfile manifest "$PROJECT_ROOT/freebsd/manifest.json" \
        '{version: $version, aifw_commit: $aifw_commit,
          components: [$manifest[0].external_repos[] | {name, repo, crate, version}]}' \
        > "$2"
}

# Build the update tarball — the critical artifact: every appliance gets
# new code through the in-app updater, which only needs this file.
#   $1 = version, $2 = companion bin dir, $3 = UI export dir, $4 = output dir
# Produces $4/aifw-update-$1-amd64.tar.xz (+ .sha256).
aifw_build_update_tarball() {
    _ver="$1"; _cbin="$2"; _ui="$3"; _out="$4"
    _tdir="/tmp/aifw-update-${_ver}-amd64"
    rm -rf "$_tdir"
    mkdir -p "$_tdir/bin" "$_tdir/ui" "$_tdir/rc.d" "$_tdir/sbin" "$_tdir/libexec"
    aifw_stage_binaries "$_tdir/bin" "$_cbin"
    cp -a "$_ui/"* "$_tdir/ui/"
    # rc.d service scripts — the updater iterates every file under
    # <tarball>/rc.d/ (it does not consult manifest rc_scripts); sbin
    # (aifw-console, aifw-installer, …); libexec (restart driver, watchdog,
    # narrow-grant sudo helpers — #469: without these the appliance never
    # gets helper updates).
    _ov="$PROJECT_ROOT/freebsd/overlay/usr/local"
    [ -d "$_ov/etc/rc.d" ] && cp -a "$_ov/etc/rc.d/"* "$_tdir/rc.d/"
    [ -d "$_ov/sbin" ] && cp -a "$_ov/sbin/"* "$_tdir/sbin/"
    [ -d "$_ov/libexec" ] && cp -a "$_ov/libexec/"* "$_tdir/libexec/"
    # Everything the appliance executes must carry the x bit regardless of
    # checkout modes — sudo reports a 644 helper as "command not found".
    chmod 755 "$_tdir"/rc.d/* "$_tdir"/sbin/* "$_tdir"/libexec/* 2>/dev/null || true
    echo "$_ver" > "$_tdir/version"
    # OS floor stamp (#612): the updater refuses this tarball on a FreeBSD
    # older than the build host — its binaries wouldn't link.
    freebsd-version -u | sed 's/-.*//' > "$_tdir/required-os"
    aifw_write_components_json "$_ver" "$_tdir/components.json"
    # Human-readable manifest so a stale or mispinned companion is visible
    # at build time (rdns 1.5.1 once shipped in a v5.45.0 tarball).
    {
        echo "AiFw             $(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
        jq -r '.external_repos[] | "\(.name) \(.version) \(.crate)"' "$PROJECT_ROOT/freebsd/manifest.json" | \
        while read -r n v c; do
            printf '%-16s %s (crates.io %s)\n' "$n" "$v" "$c"
        done
        if [ -f "$_tdir/bin/rdns" ]; then
            _rver=$(grep -ao 'rDNS [0-9][0-9.]*' "$_tdir/bin/rdns" | head -1 || true)
            echo "rdns binary      ${_rver:-unknown}"
        fi
    } | tee "$_tdir/BUILD_MANIFEST"
    # Refuse a stale rDNS: pre-1.10 lacks per-zone counters and the
    # streaming control commands the dashboard depends on.
    if [ -f "$_tdir/bin/rdns" ] && ! grep -q 'stats-json' "$_tdir/bin/rdns"; then
        aifw_die "rDNS binary does not contain 'stats-json' — stale build (pre-v1.10). Check the rdns-server pin in freebsd/manifest.json."
    fi
    mkdir -p "$_out"
    XZ_OPT='-9 -T0' tar -C /tmp -cJf "$_out/aifw-update-${_ver}-amd64.tar.xz" "aifw-update-${_ver}-amd64"
    ( cd "$_out" && sha256 "aifw-update-${_ver}-amd64.tar.xz" > "aifw-update-${_ver}-amd64.tar.xz.sha256" )
    rm -rf "$_tdir"
    echo "  Update tarball: $_out/aifw-update-${_ver}-amd64.tar.xz"
}
