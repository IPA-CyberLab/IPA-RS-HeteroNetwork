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

1. In the control-plane Web UI, create a macOS client enrollment.
2. Open the returned `heteronetwork://enroll?...` link on the Mac.
3. Confirm enrollment in HeteroNetwork and approve the VPN configuration prompt.
4. Select **Connect** from the menu-bar app.
5. Open `http://console.heteronetwork.internal:9781/ui/` from the app.

The one-use enrollment token remains in memory only. The Ed25519 identity,
WireGuard private key, assigned VPN address, and current gateway map are stored
in the shared, device-only Keychain item used by the app and packet-tunnel
extension.

The client installs only the active gateway and projected overlay CIDRs. The
control plane supplies up to four ready gateway candidates, while the packet
tunnel refreshes its signed peer map every five seconds and updates the running
WireGuard adapter when the preferred gateway changes. Two failed VPN-local
health probes also trigger a cached-gateway switch before server-side health
expiry. Each refresh signs the active gateway ID so the control plane can move
the client's return routes on every Linux node at the same time. The internal
console name uses split DNS against the active gateway; unrelated DNS remains
on the host's normal resolver. The client refuses default routes, local/relay
endpoint candidates, and invalid WireGuard keys before starting the tunnel.
