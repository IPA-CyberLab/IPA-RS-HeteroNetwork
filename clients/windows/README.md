# HeteroNetwork for Windows

The Windows client is a native WPF task-tray application. It uses SSH-sponsored
public-key registration, Ed25519 request signatures, a gateway-only WireGuard
profile, five-second peer-map refresh, cached gateway failover, and overlay
health checks.

Private identity and WireGuard keys are stored in a current-user Windows DPAPI
blob before the public registration request is displayed. Neither private key
is included in the registration request or returned import profile. The app
builds and bundles the official WireGuard embeddable tunnel service and the
signed WireGuardNT driver library at pinned versions. The active WireGuard
configuration is machine-DPAPI protected before it is handed to that embedded
service. An NRPT suffix rule sends the entire `heteronetwork.internal` zone to
the active gateway.

## Requirements

- Windows 10 version 2004 (build 19041) or later, or Windows 11
- .NET 9 Desktop Runtime (the repository build machine needs the .NET 9 SDK)
- Git and internet access for the first repository build
- Administrator approval when connecting, disconnecting, or changing gateways

WireGuard does not need to be installed separately.

## Build and run

From PowerShell:

```powershell
cd clients\windows
.\build.ps1
.\artifacts\win-x64\HeteroNetwork.exe
```

For a quick development build:

```powershell
.\bootstrap-wireguard.ps1
dotnet run --project .\src\HeteroNetworkApp\HeteroNetwork.App.csproj
```

The bootstrap pins `wireguard-windows` to commit
`4e6726c23ae9c5cb58e0c9910f3b7515621d133d`, verifies the official
WireGuardNT 1.1 archive by SHA-256, verifies the `WireGuard LLC` Authenticode
signature, and copies only the x64 runtime into the application. Generated
source, toolchains, and binaries remain under the ignored `.build` directory.

### Smart App Control and code signing

Windows 11 Smart App Control blocks new unsigned desktop binaries. On an
enforcing development PC, build with an RSA code-signing certificate issued by
a provider in the Microsoft Trusted Root Program:

```powershell
.\build.ps1 `
  -SigningCertificateThumbprint <certificate-sha1-thumbprint> `
  -SigningCertificateStore CurrentUser
```

The script signs the first-party test binaries before running them, then signs
`HeteroNetwork.exe`, `HeteroNetwork.dll`, and `HeteroNetwork.Core.dll` in the
published output. Dependencies from Microsoft and Bouncy Castle already carry
their publishers' Authenticode signatures. A locally generated self-signed
certificate is not sufficient for Smart App Control.

The app registers the `heteronetwork://` URL scheme for the current user on
first launch. You can also paste an import profile directly into its window.

## Register

1. Select **Generate registration request**. The public
   `heteronetwork://register?...` URI is copied to the clipboard.
2. SSH to any machine already joined to HeteroNetwork and run:

   ```text
   sudo ipars client register '<heteronetwork://register?...>'
   ```

3. Paste the returned `heteronetwork://import?...` URI into the app, or open it
   through the registered URL scheme.
4. Select **Import and configure**, then **Connect**.
5. Approve the Windows administrator prompt and open the private overlay
   console from **Open Web UI**.

Import is offline. The client validates that the profile matches its pending
keys and rejects expired profiles, default routes, malformed CIDRs,
local/STUN/relay candidates, non-global gateway endpoints, public management
URLs, and invalid WireGuard keys before touching Windows networking. Connect
uses the cached gateway first and refreshes management state only after the VPN
tunnel starts. Disconnecting removes both the WireGuard tunnel service and the
managed split-DNS rule.
