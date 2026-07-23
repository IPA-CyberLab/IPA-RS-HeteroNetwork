[CmdletBinding()]
param(
    [switch]$ForceBuild
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$wireGuardWindowsRepository = "https://git.zx2c4.com/wireguard-windows"
$wireGuardWindowsRevision = "4e6726c23ae9c5cb58e0c9910f3b7515621d133d"
$wireGuardNtVersion = "1.1"
$wireGuardNtUrl =
    "https://download.wireguard.com/wireguard-nt/wireguard-nt-$wireGuardNtVersion.zip"
$wireGuardNtArchiveSha256 =
    "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace"
$wireGuardDllSha256 =
    "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3"

$buildRoot = Join-Path $PSScriptRoot ".build"
$sourceRoot = Join-Path $buildRoot "wireguard-windows"
$downloadsRoot = Join-Path $buildRoot "downloads"
$extractRoot = Join-Path $buildRoot "wireguard-nt-$wireGuardNtVersion"
$nativeRoot = Join-Path $buildRoot "native\win-x64"
$archivePath = Join-Path $downloadsRoot "wireguard-nt-$wireGuardNtVersion.zip"
$legacyArchivePath = Join-Path $buildRoot "wireguard-nt-$wireGuardNtVersion.zip"
$revisionMarker = Join-Path $buildRoot "tunnel-revision.txt"
$sourceTunnel = Join-Path $sourceRoot "embeddable-dll-service\amd64\tunnel.dll"
$sourceWireGuard = Join-Path $extractRoot "wireguard-nt\bin\amd64\wireguard.dll"

function Invoke-Git {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    & git @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Assert-Sha256 {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Expected
    )

    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "SHA-256 mismatch for $Path. Expected $Expected, received $actual."
    }
}

New-Item -ItemType Directory -Force -Path $buildRoot, $downloadsRoot, $nativeRoot |
    Out-Null

if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot ".git"))) {
    Invoke-Git @(
        "clone",
        "--no-checkout",
        $wireGuardWindowsRepository,
        $sourceRoot
    )
}

$configuredRemote = (& git -C $sourceRoot remote get-url origin).Trim()
if ($LASTEXITCODE -ne 0 -or $configuredRemote -ne $wireGuardWindowsRepository) {
    throw "Unexpected wireguard-windows origin: $configuredRemote"
}

& git -C $sourceRoot cat-file -e "$wireGuardWindowsRevision`^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) {
    Invoke-Git @(
        "-C",
        $sourceRoot,
        "fetch",
        "--depth",
        "1",
        "origin",
        $wireGuardWindowsRevision
    )
}
Invoke-Git @(
    "-C",
    $sourceRoot,
    "checkout",
    "--detach",
    $wireGuardWindowsRevision
)

$actualRevision = (& git -C $sourceRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualRevision -ne $wireGuardWindowsRevision) {
    throw "wireguard-windows is not at the pinned revision."
}

$trackedChanges = & git -C $sourceRoot status --short --untracked-files=no
if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect the wireguard-windows source tree."
}
if ($trackedChanges) {
    throw "The pinned wireguard-windows source tree has tracked modifications."
}

$builtRevision = if (Test-Path -LiteralPath $revisionMarker) {
    (Get-Content -LiteralPath $revisionMarker -Raw).Trim()
} else {
    ""
}
if (
    $ForceBuild -or
    $builtRevision -ne $wireGuardWindowsRevision -or
    -not (Test-Path -LiteralPath $sourceTunnel -PathType Leaf)
) {
    & (Join-Path $sourceRoot "embeddable-dll-service\build.bat")
    if ($LASTEXITCODE -ne 0) {
        throw "The official WireGuard tunnel library build failed."
    }
    Set-Content `
        -LiteralPath $revisionMarker `
        -Value $wireGuardWindowsRevision `
        -NoNewline
}

if (-not (Test-Path -LiteralPath $sourceTunnel -PathType Leaf)) {
    throw "The official build did not produce the amd64 tunnel.dll."
}

if (Test-Path -LiteralPath $archivePath -PathType Leaf) {
    try {
        Assert-Sha256 -Path $archivePath -Expected $wireGuardNtArchiveSha256
    } catch {
        Remove-Item -LiteralPath $archivePath -Force
    }
}
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf) -and (Test-Path -LiteralPath $legacyArchivePath -PathType Leaf)) {
    Assert-Sha256 -Path $legacyArchivePath -Expected $wireGuardNtArchiveSha256
    Copy-Item -LiteralPath $legacyArchivePath -Destination $archivePath
}
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    $downloaded = $false
    for ($attempt = 1; $attempt -le 3 -and -not $downloaded; $attempt++) {
        try {
            Invoke-WebRequest `
                -UseBasicParsing `
                -Uri $wireGuardNtUrl `
                -OutFile $archivePath
            $downloaded = $true
        } catch {
            if ($attempt -eq 3) {
                throw
            }
            Start-Sleep -Seconds $attempt
        }
    }
}
Assert-Sha256 -Path $archivePath -Expected $wireGuardNtArchiveSha256

if (-not (Test-Path -LiteralPath $sourceWireGuard -PathType Leaf)) {
    if (Test-Path -LiteralPath $extractRoot) {
        $resolvedExtractRoot = (Resolve-Path -LiteralPath $extractRoot).Path
        $resolvedBuildRoot = (Resolve-Path -LiteralPath $buildRoot).Path
        if (-not $resolvedExtractRoot.StartsWith(
                "$resolvedBuildRoot\",
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to replace an extraction directory outside the build root."
        }
        Remove-Item -LiteralPath $resolvedExtractRoot -Recurse -Force
    }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot
}

Assert-Sha256 -Path $sourceWireGuard -Expected $wireGuardDllSha256
$wireGuardSignature = Get-AuthenticodeSignature -LiteralPath $sourceWireGuard
if ($wireGuardSignature.Status -ne "Valid" -or
    $wireGuardSignature.SignerCertificate.Subject -notmatch "(^|, )O=WireGuard LLC(,|$)") {
    throw "wireguard.dll does not have a valid WireGuard LLC Authenticode signature."
}

Copy-Item -LiteralPath $sourceTunnel -Destination (Join-Path $nativeRoot "tunnel.dll") -Force
Copy-Item `
    -LiteralPath $sourceWireGuard `
    -Destination (Join-Path $nativeRoot "wireguard.dll") `
    -Force
Copy-Item `
    -LiteralPath (Join-Path $sourceRoot "COPYING") `
    -Destination (Join-Path $nativeRoot "WIREGUARD-WINDOWS-COPYING.txt") `
    -Force
Copy-Item `
    -LiteralPath (Join-Path $extractRoot "wireguard-nt\LICENSE.txt") `
    -Destination (Join-Path $nativeRoot "WIREGUARD-NT-LICENSE.txt") `
    -Force

Write-Host "WireGuard runtime prepared: $nativeRoot"
Write-Host "  wireguard-windows: $wireGuardWindowsRevision"
Write-Host "  WireGuardNT:       $wireGuardNtVersion"
