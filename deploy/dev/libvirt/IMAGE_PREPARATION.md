# Dev Base Image Preparation

Run `scripts/prepare-dev-base-image.py` as non-root `mizuame` on
`ichikawap1`, from a trusted checkout. It takes no arguments and must run
from a new private staging directory, not directly from the checkout.
Prerequisites are Python 3, curl, gpgv, qemu-img, GNU timeout, and the existing
trusted `/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg`. No key is imported.

```sh
stage="$(mktemp -d /tmp/hetero-dev-base-image.XXXXXXXXXX)"
install -m 0600 scripts/prepare-dev-base-image.py "$stage/prepare-dev-base-image.py"
install -m 0600 deploy/dev/libvirt/profile.json "$stage/profile.json"
env LC_ALL=C /usr/bin/timeout 900 /usr/bin/python3 -B "$stage/prepare-dev-base-image.py"
```

The initial directory must contain only those two files. The script downloads
the exact pinned profile image URL and its `SHA256SUMS` and `SHA256SUMS.gpg`
over HTTPS. It verifies the signed checksum against the existing root-owned
keyring and the profile pin before downloading the image, then hashes the image
and inspects QCOW2 metadata read-only. Backing files, encrypted images, and
dirty/corrupt or external-data QCOW2 headers are rejected.

Downloads are limited to 2 GiB for the image and 2 MiB per metadata file, with
60-second metadata and 600-second image transfer limits. Disk checks preserve
at least 128 GiB (or the larger profile reserve). Successful output includes
`verification.json` (mode `0600`) and the image (mode `0400`) inside the owned
`0700` directory. Failure may leave partial files; do not reuse a populated
directory. Allocate a new directory for a subsequent authorized attempt.

## Observed Receipt

The verified run on `ichikawap1` produced:

- Receipt: `/tmp/hetero-dev-base-image.YJa0fiJbuD/verification.json`.
- Image: `ubuntu-24.04-server-cloudimg-amd64.img`, 624829952 bytes.
- SHA256: `d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30`.
- Signing fingerprint: `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`.
- Signature and profile pin verified; one QCOW2 image, no backing file,
  virtual size 3758096384 bytes.

This `/tmp` receipt is ephemeral historical evidence, not durable provenance
or a deployment-readiness claim. Preparation does not use sudo, create or boot
guests, modify libvirt, or activate native services. The apply/import operation
must independently reverify the actual image bytes and trust inputs before use;
it must not rely on this receipt or the temporary path alone.
