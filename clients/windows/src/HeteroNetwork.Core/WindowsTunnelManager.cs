using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace HeteroNetwork.Core;

public enum TunnelConnectionStatus
{
    NotConfigured,
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Reconnecting,
}

public sealed class WindowsTunnelManager
{
    public const string TunnelName = "HeteroNetwork";
    private const string ServiceName = "WireGuardTunnel$HeteroNetwork";
    private const string ServiceDisplayName = "HeteroNetwork WireGuard Tunnel";
    private const string ServiceDescription =
        "Gateway-only WireGuard tunnel managed by HeteroNetwork.";
    private const string NrptComment = "HeteroNetwork managed split DNS";
    private readonly ClientSessionStore sessionStore;

    public WindowsTunnelManager(ClientSessionStore? sessionStore = null)
    {
        this.sessionStore = sessionStore ?? new ClientSessionStore();
    }

    public bool IsWireGuardInstalled => EmbeddedWireGuardRuntime.IsAvailable;

    public TunnelConnectionStatus GetStatus()
    {
        if (!IsWireGuardInstalled)
        {
            return TunnelConnectionStatus.NotConfigured;
        }

        return WindowsServiceStatus.Query(ServiceName) switch
        {
            WindowsServiceState.StartPending => TunnelConnectionStatus.Connecting,
            WindowsServiceState.Running => TunnelConnectionStatus.Connected,
            WindowsServiceState.StopPending => TunnelConnectionStatus.Disconnecting,
            _ => TunnelConnectionStatus.Disconnected,
        };
    }

    public Task ConnectAsync(CancellationToken cancellationToken = default) =>
        RunElevatedAsync("--tunnel-connect", cancellationToken);

    public Task DisconnectAsync(CancellationToken cancellationToken = default) =>
        RunElevatedAsync("--tunnel-disconnect", cancellationToken);

    public async Task<int> RunHelperAsync(
        string operation,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (!IsAdministrator())
            {
                throw new InvalidOperationException(
                    "Administrator approval is required to manage the VPN tunnel.");
            }

            switch (operation)
            {
                case "--tunnel-connect":
                    await InstallTunnelAsync(cancellationToken).ConfigureAwait(false);
                    break;
                case "--tunnel-disconnect":
                    await RemoveTunnelAsync(cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    throw new ArgumentException("Unknown tunnel helper operation.", nameof(operation));
            }

            HelperLog.Write("Tunnel helper completed successfully.");
            return 0;
        }
        catch (Exception error)
        {
            HelperLog.Write(error.ToString());
            return 1;
        }
    }

    public async Task<bool> ProbeAsync(
        TunnelProfile profile,
        CancellationToken cancellationToken = default)
    {
        return await ProbeWebUiAsync(profile, cancellationToken).ConfigureAwait(false)
            && await ProbeDnsAsync(profile, cancellationToken).ConfigureAwait(false);
    }

    public static string ReadLastHelperError()
    {
        try
        {
            if (!File.Exists(HelperLog.Path))
            {
                return "The elevated tunnel helper failed.";
            }

            return File.ReadAllText(HelperLog.Path);
        }
        catch (IOException)
        {
            return "The elevated tunnel helper failed.";
        }
    }

    private async Task RunElevatedAsync(
        string operation,
        CancellationToken cancellationToken)
    {
        if (IsAdministrator())
        {
            var directResult = await RunHelperAsync(operation, cancellationToken)
                .ConfigureAwait(false);
            if (directResult != 0)
            {
                throw new InvalidOperationException(ReadLastHelperError());
            }

            return;
        }

        var executable = Environment.ProcessPath
            ?? throw new InvalidOperationException("The application path is unavailable.");
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        startInfo.ArgumentList.Add(operation);
        try
        {
            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("The elevated tunnel helper did not start.");
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(ReadLastHelperError());
            }
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            throw new InvalidOperationException(
                "Administrator approval was canceled.",
                error);
        }
    }

    private async Task InstallTunnelAsync(CancellationToken cancellationToken)
    {
        EmbeddedWireGuardRuntime.AssertAvailable();
        var session = sessionStore.Load()
            ?? throw new InvalidOperationException("No enrolled HeteroNetwork session was found.");
        var gatewayIndex = session.SelectedGatewayNodeId is { } selected
            ? IndexOfGateway(session, selected)
            : 0;
        var profile = TunnelProfile.FromSession(session, gatewayIndex < 0 ? 0 : gatewayIndex);
        var keys = new ClientKeyMaterial(
            session.IdentityPrivateKey,
            session.WireGuardPrivateKey);
        var configuration = WireGuardConfiguration(keys, profile);
        var configurationPath = await WriteMachineProtectedConfigurationAsync(
            configuration,
            cancellationToken).ConfigureAwait(false);

        try
        {
            await EmbeddedTunnelService.InstallAndStartAsync(
                ServiceName,
                ServiceDisplayName,
                ServiceDescription,
                ApplicationExecutablePath(),
                configurationPath,
                cancellationToken).ConfigureAwait(false);
            await ConfigureSplitDnsAsync(profile.GatewayVpnIp, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await EmbeddedTunnelService.RemoveAsync(ServiceName, cancellationToken)
                .ConfigureAwait(false);
            await RemoveSplitDnsAsync(cancellationToken).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task RemoveTunnelAsync(CancellationToken cancellationToken)
    {
        await EmbeddedTunnelService.RemoveAsync(ServiceName, cancellationToken)
            .ConfigureAwait(false);
        await RemoveSplitDnsAsync(cancellationToken).ConfigureAwait(false);
        var configurationPath = ConfigurationPath();
        if (File.Exists(configurationPath))
        {
            File.Delete(configurationPath);
        }
    }

    private static int IndexOfGateway(ClientSession session, string nodeId)
    {
        for (var index = 0; index < session.PeerMap.Peers.Count; index++)
        {
            if (session.PeerMap.Peers[index].NodeId == nodeId)
            {
                return index;
            }
        }

        return -1;
    }

    private static string WireGuardConfiguration(
        ClientKeyMaterial keys,
        TunnelProfile profile)
    {
        return string.Join(
            "\r\n",
            "[Interface]",
            $"PrivateKey = {keys.WireGuardPrivateKeyBase64}",
            $"Address = {profile.ClientAddress}",
            string.Empty,
            "[Peer]",
            $"PublicKey = {profile.GatewayWireGuardPublicKey}",
            $"Endpoint = {profile.GatewayEndpoint}",
            $"AllowedIPs = {string.Join(", ", profile.AllowedIps)}",
            "PersistentKeepalive = 25",
            string.Empty);
    }

    private static async Task<string> WriteMachineProtectedConfigurationAsync(
        string configuration,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var directory = Path.GetDirectoryName(ConfigurationPath())
            ?? throw new InvalidOperationException("The tunnel configuration path is invalid.");
        Directory.CreateDirectory(directory);
        await HardenConfigurationDirectoryAsync(directory, cancellationToken)
            .ConfigureAwait(false);

        var plaintext = Encoding.UTF8.GetBytes(configuration);
        byte[]? protectedConfiguration = null;
        var temporaryPath = $"{ConfigurationPath()}.{Guid.NewGuid():N}.tmp";
        try
        {
            protectedConfiguration = WindowsDataProtection.ProtectLocalMachine(plaintext);
            await File.WriteAllBytesAsync(
                temporaryPath,
                protectedConfiguration,
                cancellationToken).ConfigureAwait(false);
            File.Move(temporaryPath, ConfigurationPath(), true);
        }
        finally
        {
            Array.Clear(plaintext);
            if (protectedConfiguration is not null)
            {
                Array.Clear(protectedConfiguration);
            }

            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }

        return ConfigurationPath();
    }

    private static async Task HardenConfigurationDirectoryAsync(
        string directory,
        CancellationToken cancellationToken)
    {
        await RunProcessAsync(
            Path.Combine(Environment.SystemDirectory, "icacls.exe"),
            [
                directory,
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
            TimeSpan.FromSeconds(10),
            cancellationToken,
            allowFailure: false).ConfigureAwait(false);
    }

    private static Task ConfigureSplitDnsAsync(
        string gatewayVpnIp,
        CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(gatewayVpnIp, out _))
        {
            throw new InvalidOperationException("The gateway DNS address is invalid.");
        }

        var command =
            "$ErrorActionPreference = 'Stop'\r\n"
            + $"Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NrptComment}' }} "
            + "| Remove-DnsClientNrptRule -Force\r\n"
            + $"Add-DnsClientNrptRule -Namespace '{HeteroNetworkConstants.OverlayDnsName}' "
            + $"-NameServers '{gatewayVpnIp}' -Comment '{NrptComment}'";
        return RunPowerShellAsync(command, cancellationToken);
    }

    private static Task RemoveSplitDnsAsync(CancellationToken cancellationToken)
    {
        var command =
            "$ErrorActionPreference = 'Stop'\r\n"
            + $"Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NrptComment}' }} "
            + "| Remove-DnsClientNrptRule -Force";
        return RunPowerShellAsync(command, cancellationToken);
    }

    private static Task RunPowerShellAsync(
        string command,
        CancellationToken cancellationToken)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
        return RunProcessAsync(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe"),
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            TimeSpan.FromSeconds(20),
            cancellationToken,
            allowFailure: false);
    }

    private static async Task RunProcessAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        bool allowFailure)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Failed to start {Path.GetFileName(fileName)}.");
        var standardOutput = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var standardError = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            process.Kill(true);
            throw new TimeoutException($"{Path.GetFileName(fileName)} timed out.");
        }

        var output = (await standardOutput.ConfigureAwait(false)).Trim();
        var error = (await standardError.ConfigureAwait(false)).Trim();
        if (!allowFailure && process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"{Path.GetFileName(fileName)} failed ({process.ExitCode}): "
                + $"{(error.Length == 0 ? output : error)}");
        }
    }

    private static string ApplicationExecutablePath()
    {
        var appHost = Path.Combine(AppContext.BaseDirectory, "HeteroNetwork.exe");
        if (File.Exists(appHost))
        {
            return appHost;
        }

        var executable = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(executable)
            && !string.Equals(
                Path.GetFileName(executable),
                "dotnet.exe",
                StringComparison.OrdinalIgnoreCase))
        {
            return executable;
        }

        throw new InvalidOperationException(
            "The application host executable is unavailable. Publish the Windows client first.");
    }

    private static string ConfigurationPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "HeteroNetwork",
        $"{TunnelName}.conf.dpapi");

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity)
            .IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static async Task<bool> ProbeWebUiAsync(
        TunnelProfile profile,
        CancellationToken cancellationToken)
    {
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(3),
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(3),
        };
        var host = profile.GatewayVpnIp.Contains(':')
            ? $"[{profile.GatewayVpnIp}]"
            : profile.GatewayVpnIp;
        var uri = new Uri(
            $"http://{host}:{HeteroNetworkConstants.OverlayWebUiPort}/v1/web-ui/healthz");
        try
        {
            using var response = await client.GetAsync(
                uri,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK
                || response.Content.Headers.ContentLength > 1024)
            {
                return false;
            }

            var health = await response.Content.ReadFromJsonAsync<JsonElement>(
                HeteroNetworkJson.Options,
                cancellationToken).ConfigureAwait(false);
            return health.ValueKind == JsonValueKind.Object
                && health.TryGetProperty("status", out var status)
                && status.GetString() == "ok";
        }
        catch (Exception error) when (error is HttpRequestException
                                      or TaskCanceledException
                                      or JsonException)
        {
            return false;
        }
    }

    private static async Task<bool> ProbeDnsAsync(
        TunnelProfile profile,
        CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(profile.GatewayVpnIp, out var gateway))
        {
            return false;
        }

        using var udp = new UdpClient(gateway.AddressFamily);
        var queryIdBytes = RandomNumberGenerator.GetBytes(2);
        var queryId = (ushort)((queryIdBytes[0] << 8) | queryIdBytes[1]);
        var query = DnsHealthQuery(queryId);
        try
        {
            await udp.SendAsync(
                query,
                new IPEndPoint(gateway, 53),
                cancellationToken).ConfigureAwait(false);
            using var timeout =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            var response = await udp.ReceiveAsync(timeout.Token).ConfigureAwait(false);
            return IsHealthyDnsResponse(response.Buffer, queryId);
        }
        catch (Exception error) when (error is SocketException
                                      or OperationCanceledException)
        {
            return false;
        }
    }

    private static byte[] DnsHealthQuery(ushort queryId)
    {
        using var stream = new MemoryStream();
        static void WriteUInt16(Stream target, ushort value)
        {
            target.WriteByte((byte)(value >> 8));
            target.WriteByte((byte)(value & 0xff));
        }

        WriteUInt16(stream, queryId);
        WriteUInt16(stream, 0x0100);
        WriteUInt16(stream, 1);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);
        foreach (var label in HeteroNetworkConstants.OverlayDnsName.Split('.'))
        {
            var encoded = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((byte)encoded.Length);
            stream.Write(encoded);
        }

        stream.WriteByte(0);
        WriteUInt16(stream, 1);
        WriteUInt16(stream, 1);
        return stream.ToArray();
    }

    private static bool IsHealthyDnsResponse(byte[] data, ushort queryId)
    {
        if (data.Length < 12)
        {
            return false;
        }

        static ushort ReadUInt16(byte[] value, int offset) =>
            (ushort)((value[offset] << 8) | value[offset + 1]);
        var flags = ReadUInt16(data, 2);
        return ReadUInt16(data, 0) == queryId
            && (flags & 0x8000) != 0
            && (flags & 0x000f) == 0
            && ReadUInt16(data, 4) == 1
            && ReadUInt16(data, 6) > 0;
    }

    private static class HelperLog
    {
        public static string Path => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "HeteroNetwork",
            "tunnel-helper.log");

        public static void Write(string value)
        {
            var directory = System.IO.Path.GetDirectoryName(Path);
            if (directory is not null)
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(Path, value);
        }
    }
}

internal enum WindowsServiceState : uint
{
    Missing = 0,
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    Unknown = uint.MaxValue,
}

internal static class WindowsServiceStatus
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ErrorServiceDoesNotExist = 1060;

    public static WindowsServiceState Query(string serviceName)
    {
        var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            return WindowsServiceState.Unknown;
        }

        try
        {
            var service = OpenService(manager, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return Marshal.GetLastWin32Error() == ErrorServiceDoesNotExist
                    ? WindowsServiceState.Missing
                    : WindowsServiceState.Unknown;
            }

            try
            {
                if (!QueryServiceStatus(service, out var status))
                {
                    return WindowsServiceState.Unknown;
                }

                return Enum.IsDefined(typeof(WindowsServiceState), status.CurrentState)
                    ? (WindowsServiceState)status.CurrentState
                    : WindowsServiceState.Unknown;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(
        IntPtr serviceManager,
        string serviceName,
        uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(
        IntPtr service,
        out ServiceStatus serviceStatus);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }
}
