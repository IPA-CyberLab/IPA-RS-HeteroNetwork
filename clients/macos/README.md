# HeteroNetwork for macOS

The macOS client is a native SwiftUI menu-bar app backed by a
`NEPacketTunnelProvider` and the official WireGuardKit package. It joins an
existing HeteroNetwork overlay as a control-only client. It never advertises
routes, registers with Signal, accepts relay traffic, or appears in the normal
node inventory.

## Requirements

- macOS 13 or later
- Xcode with a Developer ID or Apple Development team that has the Network
  Extension capability
- XcodeGen 2.45.4
- Go 1.20.14 for WireGuardKit's `wireguard-go` bridge

## Generate and build

```bash
cd clients/macos
./scripts/bootstrap.sh
open HeteroNetwork.xcodeproj
```

`bootstrap.sh` fetches the official WireGuardKit source at the pinned commit
into the ignored `.build` directory, corrects its inconsistent Swift tools
manifest declaration, and applies the reviewed split-DNS patch in `patches/`
before generating the project. It refuses a checkout at any other revision.

Set the same Apple development team on `HeteroNetwork`,
`HeteroNetworkPacketTunnel`, and `HeteroNetworkCore`. The bundle IDs, App Group,
and shared Keychain group in `project.yml` and `Config/*.entitlements` must be
registered for that team before an archive can be signed.

The CI job performs an unsigned app/extension build and the core unit tests.
Running the packet tunnel on a Mac still requires a signed Network Extension.

## Enroll

1. Select **Generate registration request** in the macOS app.
2. SSH to any enrolled HeteroNetwork node and run
   `sudo ipars client register '<heteronetwork://register?...>'`.
3. Paste the returned `heteronetwork://import?...` profile into the macOS app
   and select **Import profile**.
4. Approve the VPN configuration prompt and select **Connect**.
5. Open `http://console.heteronetwork.internal:9781/ui/` from the app.

The Ed25519 identity and WireGuard private keys are generated on the Mac and
stored as a pending, device-only Keychain item. The SSH registration request
contains only their public keys and a proof-of-possession signature. A valid
import profile promotes those pending keys into the shared client session and
then deletes the pending item. Neither URI contains private key material.

The client installs only the active gateway and projected overlay CIDRs. The
control plane supplies up to four ready gateway candidates, while the packet
tunnel refreshes its signed peer map every five seconds and updates the running
WireGuard adapter when the preferred gateway changes. Two failed VPN-local
health probes also trigger a cached-gateway switch before server-side health
expiry. Each refresh signs the active gateway ID so the control plane can move
the client's return routes on every Linux node at the same time. The internal
console name uses split DNS against the active gateway; unrelated DNS remains
on the host's normal resolver. The first connection uses the imported peer map
without contacting the VPN-only management API. The client refuses default
routes, STUN/local/relay candidates, non-global gateway addresses, public
management URLs, and invalid WireGuard keys before starting the tunnel.
