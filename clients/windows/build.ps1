[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$NoPublish,
    [string]$SigningCertificateThumbprint,
    [ValidateSet("CurrentUser", "LocalMachine")]
    [string]$SigningCertificateStore = "CurrentUser",
    [ValidatePattern("^https://")]
    [string]$TimestampUrl = "https://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$clientRoot = $PSScriptRoot
$solution = Join-Path $clientRoot "HeteroNetwork.Windows.slnx"
$wireGuardBootstrap = Join-Path $clientRoot "bootstrap-wireguard.ps1"

function Invoke-DotNet {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Get-SignTool {
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    $signTool = Get-ChildItem `
        -Path $kitsRoot `
        -Filter "signtool.exe" `
        -File `
        -Recurse `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $signTool) {
        throw "The x64 Windows SDK SignTool was not found under $kitsRoot."
    }
    return $signTool.FullName
}

function Assert-CodeSigningCertificate {
    param(
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$Store
    )

    $normalized = $Thumbprint.Replace(" ", "").ToUpperInvariant()
    if ($normalized -notmatch "^[0-9A-F]{40}$") {
        throw "The signing certificate thumbprint must be a 40-character SHA-1 thumbprint."
    }
    $certificatePath = "Cert:\$Store\My\$normalized"
    $certificate = Get-Item -LiteralPath $certificatePath -ErrorAction SilentlyContinue
    if (-not $certificate) {
        throw "The signing certificate was not found at $certificatePath."
    }
    if (-not $certificate.HasPrivateKey) {
        throw "The signing certificate does not have an accessible private key."
    }
    if ($certificate.NotAfter -le (Get-Date)) {
        throw "The signing certificate has expired."
    }
    if ($certificate.PublicKey.Oid.Value -ne "1.2.840.113549.1.1.1") {
        throw "Smart App Control requires an RSA code-signing certificate."
    }
    if ($certificate.EnhancedKeyUsageList.ObjectId -notcontains "1.3.6.1.5.5.7.3.3") {
        throw "The certificate is not valid for code signing."
    }
    return $normalized
}

function Invoke-CodeSign {
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$Store
    )

    $signTool = Get-SignTool
    foreach ($path in $Paths | Sort-Object -Unique) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "The signing target does not exist: $path"
        }
        $arguments = @(
            "sign",
            "/sha1", $Thumbprint,
            "/s", "My",
            "/fd", "SHA256",
            "/tr", $TimestampUrl,
            "/td", "SHA256"
        )
        if ($Store -eq "LocalMachine") {
            $arguments += "/sm"
        }
        $arguments += $path
        & $signTool @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "SignTool failed for $path with exit code $LASTEXITCODE."
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne "Valid") {
            throw "The Authenticode signature for $path is not valid: $($signature.StatusMessage)"
        }
    }
}

$normalizedThumbprint = $null
if ($SigningCertificateThumbprint) {
    $normalizedThumbprint = Assert-CodeSigningCertificate `
        -Thumbprint $SigningCertificateThumbprint `
        -Store $SigningCertificateStore
}

& $wireGuardBootstrap
if ($LASTEXITCODE -ne 0) {
    throw "The embedded WireGuard runtime bootstrap failed."
}

Invoke-DotNet @("restore", $solution)
Invoke-DotNet @("build", $solution, "--configuration", $Configuration, "--no-restore")

if ($normalizedThumbprint) {
    $testSigningTargets = Get-ChildItem `
        -Path $clientRoot `
        -File `
        -Recurse `
        -Include "HeteroNetwork*.dll", "HeteroNetwork*.exe" |
        Where-Object {
            $_.FullName -match "\\bin\\$Configuration\\" -and
            $_.FullName -notmatch "\\ref(int)?\\" -and
            ($_.Name -like "HeteroNetwork*" -or $_.Name -eq "tunnel.dll")
        } |
        Select-Object -ExpandProperty FullName
    Invoke-CodeSign `
        -Paths $testSigningTargets `
        -Thumbprint $normalizedThumbprint `
        -Store $SigningCertificateStore
}

Invoke-DotNet @(
    "test",
    $solution,
    "--configuration",
    $Configuration,
    "--no-build",
    "--no-restore"
)

if (-not $NoPublish) {
    $output = Join-Path $clientRoot "artifacts\win-x64"
    $appProject = Join-Path $clientRoot "src\HeteroNetwork.App\HeteroNetwork.App.csproj"
    Invoke-DotNet @(
        "restore",
        $appProject,
        "--runtime",
        "win-x64"
    )
    Invoke-DotNet @(
        "publish",
        $appProject,
        "--configuration",
        $Configuration,
        "--runtime",
        "win-x64",
        "--self-contained",
        "false",
        "--no-restore",
        "--output",
        $output
    )
    if ($normalizedThumbprint) {
        Invoke-CodeSign `
            -Paths @(
                (Join-Path $output "HeteroNetwork.exe"),
                (Join-Path $output "HeteroNetwork.dll"),
                (Join-Path $output "HeteroNetwork.Core.dll"),
                (Join-Path $output "tunnel.dll")
            ) `
            -Thumbprint $normalizedThumbprint `
            -Store $SigningCertificateStore
    }
    $publishedExecutable = Join-Path $output "HeteroNetwork.exe"
    $selfTest = Start-Process `
        -FilePath $publishedExecutable `
        -ArgumentList "--wireguard-self-test" `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    if ($selfTest.ExitCode -ne 0) {
        throw "The embedded WireGuard runtime self-test failed with exit code $($selfTest.ExitCode)."
    }
    Write-Host "Embedded WireGuard runtime self-test passed."
    Write-Host "Published: $(Join-Path $output 'HeteroNetwork.exe')"
}
