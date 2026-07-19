#!/bin/sh
# Generate a deterministic, machine-readable SPDX inventory for release inputs.
set -eu
out=${1:?output path required}
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cargo metadata --format-version 1 --no-deps --manifest-path "$root/Cargo.toml" \
  | jq '{spdxVersion:"SPDX-2.3",dataLicense:"CC0-1.0",SPDXID:"SPDXRef-DOCUMENT",name:"aifw",documentNamespace:("https://aifw.invalid/sbom/" + (.workspace_members|join("-"))),packages:[.packages[]|{SPDXID:("SPDXRef-" + (.name|gsub("[^A-Za-z0-9.-]";"-"))),name,versionInfo: .version,downloadLocation:"NOASSERTION",licenseConcluded:"NOASSERTION",licenseDeclared:"NOASSERTION"}]}' > "$tmp"
mv "$tmp" "$out"
