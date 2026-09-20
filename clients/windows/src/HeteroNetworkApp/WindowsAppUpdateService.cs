using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using HeteroNetwork.Core;

namespace HeteroNetwork.App;

internal sealed record PreparedWindowsAppUpdate(
    DesktopReleaseUpdate Release,
    string StagedDirectory,
    string TargetDirectory);

internal sealed class WindowsAppUpdateException : Exception
{
    public WindowsAppUpdateException(string message)
        : base(message)
    {
    }

    public WindowsAppUpdateException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal sealed class WindowsAppUpdateService : IDisposable
{
    private const int MaximumCatalogSize = 5 * 1024 * 1024;
    private const long MaximumArchiveSize = 512L * 1024 * 1024;
    private const long MaximumExpandedSize = 1024L * 1024 * 1024;
    private const int MaximumArchiveEntries = 20_000;
    private static readonly Uri CatalogUrl = new(
        "https://api.github.com/repos/IPA-CyberLab/IPA-RS-HeteroNetwork/releases?per_page=100");
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly HashSet<string> ReservedWindowsNames = new(
        [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ],
        StringComparer.OrdinalIgnoreCase);
    private readonly HttpClient httpClient;

    public WindowsAppUpdateService(HttpMessageHandler? handler = null)
    {
        httpClient = handler is null ? new HttpClient() : new HttpClient(handler, true);
        httpClient.Timeout = TimeSpan.FromMinutes(10);
        httpClient.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        httpClient.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("HeteroNetwork-Windows-updater");
    }

    public async Task<DesktopReleaseUpdate?> AvailableUpdateAsync(
        string currentTag,
        CancellationToken cancellationToken = default)
    {
        var data = await DownloadDataAsync(
            CatalogUrl,
            MaximumCatalogSize,
            cancellationToken).ConfigureAwait(false);
        return DesktopReleaseCatalog.AvailableUpdate(data, currentTag);
    }

    public async Task<PreparedWindowsAppUpdate> PrepareAsync(
        DesktopReleaseUpdate release,
        CancellationToken cancellationToken = default)
    {
        var target = ValidateTargetDirectory();
        var parent = Directory.GetParent(target)?.FullName
            ?? throw new WindowsAppUpdateException(
                "The HeteroNetwork installation directory has no writable parent.");
        var work = Path.Combine(
            Path.GetTempPath(),
            $"heteronetwork-update-{Guid.NewGuid():N}");
        var stage = Path.Combine(
            parent,
            $".{Path.GetFileName(target)}.update-{Guid.NewGuid():N}");
        Directory.CreateDirectory(work);
        try
        {
            var checksumData = await DownloadDataAsync(
                release.ChecksumUrl,
                4096,
                cancellationToken).ConfigureAwait(false);
            var expectedChecksum = ParseChecksum(checksumData, release.AssetName);
            var archive = Path.Combine(work, release.AssetName);
            var actualChecksum = await DownloadArchiveAsync(
                release.ArchiveUrl,
                archive,
                cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(actualChecksum),
                    Convert.FromHexString(expectedChecksum)))
            {
                throw new WindowsAppUpdateException(
                    "The downloaded release did not match its SHA-256 checksum.");
            }

            await ExtractVerifiedArchiveAsync(
                archive,
                stage,
                cancellationToken).ConfigureAwait(false);
            await ValidateStagedApplicationAsync(
                stage,
                release.Tag,
                cancellationToken).ConfigureAwait(false);
            return new PreparedWindowsAppUpdate(release, stage, target);
        }
        catch
        {
            TryDeleteDirectory(stage);
            throw;
        }
        finally
        {
            TryDeleteDirectory(work);
        }
    }

    public void Activate(PreparedWindowsAppUpdate prepared)
    {
        ValidatePreparedPaths(prepared);
        var support = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "HeteroNetwork",
            "Updates");
        Directory.CreateDirectory(support);
        var script = Path.Combine(support, $"updater-{Guid.NewGuid():N}.ps1");
        var log = Path.Combine(support, "updater.log");
        File.WriteAllText(script, UpdaterScript, new UTF8Encoding(false));

        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var powershell = Path.Combine(system, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell))
        {
            TryDeleteFile(script);
            throw new WindowsAppUpdateException(
                "Windows PowerShell is unavailable, so the update cannot be activated.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = powershell,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(script);
        startInfo.ArgumentList.Add(Process.GetCurrentProcess().Id.ToString(
            System.Globalization.CultureInfo.InvariantCulture));
        startInfo.ArgumentList.Add(prepared.TargetDirectory);
        startInfo.ArgumentList.Add(prepared.StagedDirectory);
        startInfo.ArgumentList.Add(prepared.Release.Tag);
        startInfo.ArgumentList.Add(log);
        startInfo.ArgumentList.Add(script);
        try
        {
            using var updater = Process.Start(startInfo)
                ?? throw new WindowsAppUpdateException(
                    "The background updater did not start.");
        }
        catch
        {
            TryDeleteFile(script);
            throw;
        }
    }

    public void Dispose() => httpClient.Dispose();

    private static string ValidateTargetDirectory()
    {
        var target = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(AppContext.BaseDirectory));
        var executable = Environment.ProcessPath
            ?? throw new WindowsAppUpdateException(
                "The running application path is unavailable.");
        var expectedExecutable = Path.Combine(target, "HeteroNetwork.exe");
        if (!string.Equals(
                Path.GetFullPath(executable),
                expectedExecutable,
                StringComparison.OrdinalIgnoreCase)
            || !Directory.Exists(target)
            || (File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0)
        {
            throw new WindowsAppUpdateException(
                "HeteroNetwork must be installed in a regular per-user directory to update automatically.");
        }

        return target;
    }

    private static void ValidatePreparedPaths(PreparedWindowsAppUpdate prepared)
    {
        var target = ValidateTargetDirectory();
        var stage = Path.GetFullPath(prepared.StagedDirectory);
        var parent = Directory.GetParent(target)?.FullName;
        if (!string.Equals(target, Path.GetFullPath(prepared.TargetDirectory), StringComparison.OrdinalIgnoreCase)
            || parent is null
            || !string.Equals(
                Directory.GetParent(stage)?.FullName,
                parent,
                StringComparison.OrdinalIgnoreCase)
            || !Directory.Exists(stage)
            || (File.GetAttributes(stage) & FileAttributes.ReparsePoint) != 0
            || !DesktopReleaseCatalog.IsSafeReleaseTag(prepared.Release.Tag))
        {
            throw new WindowsAppUpdateException("The staged application update is invalid.");
        }
    }

    private async Task<byte[]> DownloadDataAsync(
        Uri url,
        int maximumSize,
        CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(
            url,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        ValidateResponse(response, maximumSize);
        await using var source = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var destination = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var count = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            if (destination.Length + count > maximumSize)
            {
                throw new WindowsAppUpdateException(
                    "The release server response exceeded its allowed size.");
            }

            await destination.WriteAsync(
                buffer.AsMemory(0, count),
                cancellationToken).ConfigureAwait(false);
        }

        return destination.ToArray();
    }

    private async Task<string> DownloadArchiveAsync(
        Uri url,
        string destination,
        CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(
            url,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        ValidateResponse(response, MaximumArchiveSize);
        await using var source = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var output = new FileStream(
            destination,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        long total = 0;
        var buffer = new byte[128 * 1024];
        while (true)
        {
            var count = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            total += count;
            if (total > MaximumArchiveSize)
            {
                throw new WindowsAppUpdateException(
                    "The release archive exceeded its allowed size.");
            }

            hash.AppendData(buffer, 0, count);
            await output.WriteAsync(
                buffer.AsMemory(0, count),
                cancellationToken).ConfigureAwait(false);
        }

        if (total == 0)
        {
            throw new WindowsAppUpdateException("The release archive was empty.");
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static void ValidateResponse(HttpResponseMessage response, long maximumSize)
    {
        if (response.StatusCode != HttpStatusCode.OK
            || response.RequestMessage?.RequestUri is not { } finalUrl
            || !string.Equals(
                finalUrl.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase)
            || response.Content.Headers.ContentLength > maximumSize)
        {
            throw new WindowsAppUpdateException(
                "The release server returned an invalid response.");
        }
    }

    private static string ParseChecksum(byte[] data, string assetName)
    {
        string value;
        try
        {
            value = StrictUtf8.GetString(data);
        }
        catch (DecoderFallbackException error)
        {
            throw new WindowsAppUpdateException(
                "The release checksum file is invalid.",
                error);
        }

        var fields = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length != 2
            || !string.Equals(fields[1], assetName, StringComparison.Ordinal)
            || fields[0].Length != 64
            || fields[0].Any(character =>
                !char.IsAsciiHexDigit(character) || char.IsAsciiLetterUpper(character)))
        {
            throw new WindowsAppUpdateException("The release checksum file is invalid.");
        }

        return fields[0];
    }

    private static async Task ExtractVerifiedArchiveAsync(
        string archivePath,
        string destination,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(destination);
        var destinationRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(destination)) + Path.DirectorySeparatorChar;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long expandedSize = 0;
        using var archive = ZipFile.OpenRead(archivePath);
        if (archive.Entries.Count == 0 || archive.Entries.Count > MaximumArchiveEntries)
        {
            throw new WindowsAppUpdateException(
                "The release archive contains an invalid number of entries.");
        }

        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = entry.FullName.Replace('\\', '/');
            var segments = name.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var unixType = ((uint)entry.ExternalAttributes >> 16) & 0xF000;
            if (string.IsNullOrEmpty(name)
                || name.StartsWith('/')
                || name.Contains(':')
                || segments.Length == 0
                || segments.Any(segment => !IsSafeArchiveSegment(segment))
                || unixType == 0xA000)
            {
                throw new WindowsAppUpdateException(
                    "The release archive contains an unsafe path.");
            }

            var outputPath = Path.GetFullPath(Path.Combine(destination, Path.Combine(segments)));
            if (!outputPath.StartsWith(destinationRoot, StringComparison.OrdinalIgnoreCase)
                || !seen.Add(outputPath))
            {
                throw new WindowsAppUpdateException(
                    "The release archive contains a duplicate or escaping path.");
            }

            if (entry.Name.Length == 0)
            {
                Directory.CreateDirectory(outputPath);
                continue;
            }

            expandedSize = checked(expandedSize + entry.Length);
            if (entry.Length < 0 || expandedSize > MaximumExpandedSize)
            {
                throw new WindowsAppUpdateException(
                    "The expanded release exceeded its allowed size.");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            await using var input = entry.Open();
            await using var output = new FileStream(
                outputPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool IsSafeArchiveSegment(string segment)
    {
        if (segment is "." or ".."
            || segment.EndsWith('.')
            || segment.EndsWith(' ')
            || segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            return false;
        }

        var stem = segment.Split('.', 2)[0];
        return !ReservedWindowsNames.Contains(stem);
    }

    private static async Task ValidateStagedApplicationAsync(
        string directory,
        string expectedTag,
        CancellationToken cancellationToken)
    {
        var executable = Path.Combine(directory, "HeteroNetwork.exe");
        var requiredFiles = new[]
        {
            executable,
            Path.Combine(directory, "HeteroNetwork.dll"),
            Path.Combine(directory, "HeteroNetwork.Core.dll"),
            Path.Combine(directory, "tunnel.dll"),
            Path.Combine(directory, "wireguard.dll"),
        };
        if (requiredFiles.Any(path =>
                !File.Exists(path)
                || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0))
        {
            throw new WindowsAppUpdateException(
                "The release archive did not contain a complete HeteroNetwork application.");
        }

        var productVersion = FileVersionInfo.GetVersionInfo(executable).ProductVersion;
        if (!string.Equals(productVersion, expectedTag, StringComparison.Ordinal))
        {
            throw new WindowsAppUpdateException(
                "The downloaded application does not match the selected release.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = directory,
        };
        startInfo.ArgumentList.Add("--wireguard-self-test");
        using var process = Process.Start(startInfo)
            ?? throw new WindowsAppUpdateException(
                "The staged application self-test did not start.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            process.Kill(true);
            throw new WindowsAppUpdateException(
                "The staged application self-test timed out.");
        }

        if (process.ExitCode != 0)
        {
            throw new WindowsAppUpdateException(
                "The staged application failed its embedded WireGuard self-test.");
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private const string UpdaterScript = """
        param(
            [Parameter(Mandatory = $true)][int]$ParentProcessId,
            [Parameter(Mandatory = $true)][string]$Target,
            [Parameter(Mandatory = $true)][string]$Stage,
            [Parameter(Mandatory = $true)][string]$ExpectedTag,
            [Parameter(Mandatory = $true)][string]$LogPath,
            [Parameter(Mandatory = $true)][string]$ScriptPath
        )

        $ErrorActionPreference = "Stop"
        $backup = "$Target.old-$([Guid]::NewGuid().ToString('N'))"
        function Write-UpdateLog([string]$Message) {
            $timestamp = [DateTimeOffset]::UtcNow.ToString("O")
            [IO.File]::AppendAllText($LogPath, "$timestamp $Message`n", [Text.UTF8Encoding]::new($false))
        }

        try {
            $parent = Get-Process -Id $ParentProcessId -ErrorAction SilentlyContinue
            if ($parent) {
                if (-not $parent.WaitForExit(30000)) {
                    throw "The running application did not exit before the update deadline."
                }
            }

            $stageExecutable = Join-Path $Stage "HeteroNetwork.exe"
            if (-not (Test-Path -LiteralPath $stageExecutable -PathType Leaf)) {
                throw "The staged application is missing."
            }
            $stageVersion = (Get-Item -LiteralPath $stageExecutable).VersionInfo.ProductVersion
            if ($stageVersion -ne $ExpectedTag) {
                throw "The staged application release tag changed before activation."
            }

            if (Test-Path -LiteralPath $backup) {
                Remove-Item -LiteralPath $backup -Recurse -Force
            }
            Move-Item -LiteralPath $Target -Destination $backup
            try {
                Move-Item -LiteralPath $Stage -Destination $Target
            } catch {
                Move-Item -LiteralPath $backup -Destination $Target
                throw
            }

            $activatedExecutable = Join-Path $Target "HeteroNetwork.exe"
            try {
                Start-Process -FilePath $activatedExecutable -WorkingDirectory $Target
            } catch {
                Remove-Item -LiteralPath $Target -Recurse -Force -ErrorAction SilentlyContinue
                Move-Item -LiteralPath $backup -Destination $Target
                Start-Process -FilePath (Join-Path $Target "HeteroNetwork.exe") -WorkingDirectory $Target
                throw
            }
            Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue
            Write-UpdateLog "Activated HeteroNetwork $ExpectedTag."
            exit 0
        } catch {
            Write-UpdateLog "Update failed: $($_.Exception.Message)"
            if (-not (Test-Path -LiteralPath $Target) -and (Test-Path -LiteralPath $backup)) {
                Move-Item -LiteralPath $backup -Destination $Target -ErrorAction SilentlyContinue
            }
            $fallback = Join-Path $Target "HeteroNetwork.exe"
            if (Test-Path -LiteralPath $fallback -PathType Leaf) {
                Start-Process -FilePath $fallback -WorkingDirectory $Target -ErrorAction SilentlyContinue
            }
            exit 1
        } finally {
            Remove-Item -LiteralPath $ScriptPath -Force -ErrorAction SilentlyContinue
        }
        """;
}
