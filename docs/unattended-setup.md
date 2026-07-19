# Unattended first-boot setup

AiFw writable images can consume optional read-only seed media during first
boot. This provides a platform-neutral automation interface for image testing
and repeatable appliance provisioning while preserving the interactive wizard
when no seed is attached.

Create an ISO 9660 filesystem labelled `AIFW_SEED` containing `setup.json` at
its root. The document uses the same `SetupConfig` JSON accepted by:

```sh
aifw-setup --config /path/to/setup.json
```

Attach the filesystem before the first boot. AiFw mounts it read-only, applies
the configuration, unmounts it, and disables the first-boot service after a
successful setup. If the seed is missing, the console wizard starts normally.
If unattended setup fails, first boot returns a failure and remains enabled so
the error can be corrected rather than silently starting a partial appliance.

Seed media must contain password hashes and public SSH keys, never plaintext
passwords, API tokens, or private keys. Treat the media as configuration input,
not as a secrets store, and remove it after provisioning.
