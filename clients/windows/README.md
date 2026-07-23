# HeteroNetwork for Windows

The Windows client is a native WPF task-tray application. It uses the same
control-only enrollment, Ed25519 request signatures, gateway-only WireGuard
profile, five-second peer-map refresh, cached gateway failover, and overlay
health checks as the macOS client.

Private identity and WireGuard keys are stored in a current-user Windows DPAPI
blob. The one-use enrollment token is never persisted. The app builds and
bundles the official WireGuard embeddable tunnel service and the signed
WireGuardNT driver library at pinned versions. The active WireGuard
configuration is machine-DPAPI protected before it is handed to that embedded
service. An NRPT rule sends only
`console.heteronetwork.internal` DNS queries to the active gateway.

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
dotnet run --project .\src\HeteroNetwork.App\HeteroNetwork.App.csproj
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
first launch. You can also paste the enrollment link directly into its window.

## Enroll

1. In the control-plane Web UI, create a desktop client enrollment.
2. Open the returned `heteronetwork://enroll?...` link or paste it into the app.
3. Select **Enroll this PC**, then **Connect**.
4. Approve the Windows administrator prompt.
5. Open the overlay console from **Open Web UI**.

The client rejects default routes, malformed CIDRs, local/relay candidates, and
invalid WireGuard keys before touching Windows networking. Disconnecting
removes both the WireGuard tunnel service and the managed split-DNS rule.
