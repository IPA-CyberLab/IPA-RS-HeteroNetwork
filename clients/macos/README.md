# HeteroNetwork for macOS

The macOS client is a native SwiftUI menu-bar app. A small root-owned helper
creates a userspace WireGuard `utun`, installs only the projected overlay
routes, and publishes split DNS for `heteronetwork.internal`. It does not use
Apple's Network Extension framework, so the downloadable build does not need a
Developer ID Network Extension entitlement.

The Mac joins as a control-only client. It never advertises routes, registers
with Signal, accepts relay traffic, or appears in the normal node inventory.

## Requirements

- macOS 13 or later
- An administrator account for installing and starting the network helper
- Xcode and XcodeGen 2.45.4 when building locally
- Go 1.20.14 or later for the pinned `wireguard-go` implementation

## Install the latest release

```sh
curl -fsSL https://raw.githubusercontent.com/IPA-CyberLab/IPA-RS-HeteroNetwork/master/install-client.sh | sh
```

The installer verifies the release checksum, installs the matching Apple
Silicon or Intel app under `~/Applications`, and uses `sudo` to copy the helper
to:

```text
/Library/PrivilegedHelperTools/jp.go.ipa.cyberlab.heteronetwork.root-helper
```

The helper remains root-owned and is never setuid. Selecting **Connect** shows
the normal macOS administrator prompt before the helper creates the tunnel.
Once running, status, gateway updates, and disconnect requests use an
owner-only Unix socket and do not prompt again.

## Generate and build

```bash
cd clients/macos
./scripts/bootstrap.sh
open HeteroNetwork.xcodeproj
```

The app build runs `scripts/build-root-helper.sh` and embeds the resulting
architecture-specific helper in the app resources. The Go module pins the same
reviewed `wireguard-go` revision used by the prior WireGuardKit build. The app
uses the normal per-application Keychain and does not require an App Group or
Network Extension entitlement.

## Enroll

1. Select **Generate registration request** in the macOS app.
2. SSH to any enrolled HeteroNetwork node and run
   `sudo ipars client register '<heteronetwork://register?...>'`.
3. Paste the returned `heteronetwork://import?...` profile into the macOS app
   and select **Import profile**.
4. Select **Connect** and approve the administrator prompt.
5. Open `http://console.heteronetwork.internal/ui/` from the app.

The Ed25519 identity and WireGuard private keys are generated on the Mac and
stored as device-only Keychain items. The SSH registration request contains
only their public keys and a proof-of-possession signature. The WireGuard
private key is passed to the root helper through a randomly named, mode `0600`
file and an owner-only Unix socket; it is never placed in a process argument or
log.

The control plane supplies up to four ready gateway candidates. While
connected, the app refreshes its signed peer map every five seconds and updates
the running helper if the preferred gateway changes. Two failed VPN-local HTTP
and DNS probes trigger cached-gateway failover before server-side health expiry.
The client rejects default routes, STUN/local/relay candidates, non-global
gateway addresses, public management URLs, and invalid WireGuard keys before
starting the tunnel.
