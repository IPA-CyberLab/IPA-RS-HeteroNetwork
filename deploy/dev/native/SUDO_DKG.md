# Exclusive DEV Sudo DKG

`scripts/dev-sudo-dkg.py` runs the existing FROST CLI on each of the three
identity-pinned development guests. It does not generate a dealer key, install
a sudo plugin, start a signer, alter an agent or enable enforcement. The fixed
roster in `sudo-roster.json` belongs only to the isolated DEV cluster. Three
voters require two signatures; production membership is not reduced to match it.
All three guests share a physical host and its administrator, so this is not
evidence of independently secured production voters or physical HA.

## Inputs And Delivery

The guest-local bundle is `/opt/heteronetwork-dev-sudo-dkg`, root-owned mode 0700.
It contains the reviewed helper, the public `roster.json`, and `ipars` from the
verified dev.5 native slot. `ipars` must be executable, root-owned and not writable
by other users. Its pinned SHA-256 is
`11a02f292963a864adae9f5fb883b624ecd106f2b5d5f2e0d146afee532fb3c4`.
The agent binary running in `/opt/heteronetwork/bin` is not replaced.

Only deliver through the existing provisioner's SSH keys and pinned host keys.
Check actual guest hostname, machine ID and DMI UUID before writing a bundle.
The helper repeats those checks, verifies the bootstrap cluster and the live
agent's node ID/VPN IP, and hashes the CLI before any ceremony phase.

## Ordered Ceremony

On each guest, as its authorized administrator:

```sh
sudo python3 /opt/heteronetwork-dev-sudo-dkg/dev-sudo-dkg.py preflight
sudo python3 /opt/heteronetwork-dev-sudo-dkg/dev-sudo-dkg.py part1
```

Part one exclusively creates `/var/lib/heteronetwork-dev-sudo-dkg` (0700).
The CLI writes each output privately, refusing existing output files. Copy only
`round1-I.json` from member I to the same state directory on every other member,
using exclusive file creation and mode 0600. Compare the received bytes with the
sender's public packet before continuing. Never copy `round1.secret.json`.

```sh
sudo python3 /opt/heteronetwork-dev-sudo-dkg/dev-sudo-dkg.py part2
```

Deliver `outgoing-round2/to-J.json` from member I **only to J**, as
`round2-from-I.json`, privately and exclusively. These packets are confidential:
transfer through authenticated encrypted channels, never print them or store
them in operator logs, and never broadcast or commit them. Local round-two
secret state stays on its guest. The CLI verifies the frozen roster and complete
round-one transcript and rejects foreign, missing or duplicate packet senders.

```sh
sudo python3 /opt/heteronetwork-dev-sudo-dkg/dev-sudo-dkg.py part3
sudo python3 /opt/heteronetwork-dev-sudo-dkg/dev-sudo-dkg.py inspect
```

Compare the public `manifest_file_sha256` from all three independently executed
part-three results. Retain `key-share.json` privately on its own guest. Never
collect those shares centrally or reconstruct a master key. A successful `inspect`
checks expected public fields and private file metadata, not that a signer has
started or a real owner has authenticated. Native signer configuration checks
and actual majority issuance remain subsequent required gates.

Repeated phase commands refuse to overwrite ceremony output. On interruption,
preserve and inspect all state; do not delete the directory or regenerate keys
to force progress. A new ceremony requires an explicitly reviewed new identity
and epoch, not an automatic retry. Keep intermediate secret files private until
all participants have accepted the manifest and the retention step is approved.
