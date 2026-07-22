# Release Signing

Every release checksum (`*.sha256`) is signed with
[minisign](https://jedisct1.github.io/minisign/). The in-app updater **fails
closed**: it downloads `aifw-update-*.tar.xz.sha256.minisig`, verifies it
against the public key **compiled into the running `aifw-api` binary**, and
refuses to install when the signature is missing or invalid. Because the key
travels inside the binary, a compromised GitHub release (swapped tarball +
swapped checksum) is not sufficient to push code onto appliances — the
attacker would also need the secret key.

CI-built releases are additionally attested with GitHub build provenance
(`gh attestation verify <asset> --repo ZerosAndOnesLLC/AiFw`) and ship a
CycloneDX SBOM (`aifw-release.cdx.json`) generated from `Cargo.lock` and
`aifw-ui/package-lock.json`.

## Key locations

| What | Where |
|------|-------|
| Public key (trust root) | `freebsd/overlay/usr/local/etc/aifw/update-signing.pub` — committed; compiled into the updater via `include_str!`, baked into ISOs, published as a release asset |
| Secret key (local releases) | `~/.minisign/aifw-update.key` on the release machine (override: `AIFW_MINISIGN_SECKEY`) — **never commit** |
| Secret key (CI releases) | GitHub secret `MINISIGN_SECRET_KEY` (file contents); optional `MINISIGN_PASSWORD` if the key is password-protected |

`freebsd/release.sh` signs at publish time and refuses to publish unsigned
artifacts; CI signs in `build-iso.yml` and re-verifies against the committed
public key before the release job uploads anything. Both paths catch a
secret key that doesn't match the committed public key.

## Generating a key

```sh
minisign -G -p ~/.minisign/aifw-update.pub -s ~/.minisign/aifw-update.key
```

Use `-W` for a passwordless key (required if CI must sign and no
`MINISIGN_PASSWORD` secret is set). Keep an offline backup of the secret
key; losing it means rotating (below) with no overlap.

## Rotating the key

Appliances trust exactly the key embedded in the build they are running, so
rotation is a two-release handover:

1. Generate the new keypair. Do **not** replace the old secret key yet.
2. Commit the new public key to
   `freebsd/overlay/usr/local/etc/aifw/update-signing.pub`.
3. Cut the transition release **signed with the OLD key**. Fleet appliances
   verify it with their embedded old key, install it, and are now running a
   build that trusts the new key.
4. All releases after the transition release are signed with the NEW key.
   Update `~/.minisign/aifw-update.key` and the `MINISIGN_SECRET_KEY`
   secret; retire the old key.

An appliance that skips the transition release (offline during the window)
verifies with the old key and will reject newer releases. Recovery: install
the transition release explicitly (`aifw update install --from <tarball>`
or the UI's manual upload), then update normally.

## Compromised key / compromised release

1. Immediately delete the `MINISIGN_SECRET_KEY` GitHub secret and destroy
   the on-disk secret key.
2. Mark every release signed by the compromised key as a **pre-release** on
   GitHub (stable-channel appliances only pull `/releases/latest`, which
   skips pre-releases) and delete any release known to carry a tampered
   artifact.
3. Rotate per the procedure above. The transition release must be built
   from audited source and signed with the compromised key — that is
   unavoidable (it is the only key the fleet trusts), so pin its content by
   publishing its SHA-256 and attestation through an out-of-band channel
   (project site, security advisory) before promoting it to stable.
4. Publish a security advisory listing the compromised key ID, the affected
   release window, and the new key.
