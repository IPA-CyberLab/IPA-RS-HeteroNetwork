using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HeteroNetwork.Core;

internal static class EmbeddedTunnelService
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerCreateService = 0x0002;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint Delete = 0x00010000;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceDemandStart = 0x00000003;
    private const uint ServiceErrorNormal = 0x00000001;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceConfigDescription = 1;
    private const uint ServiceConfigSidInfo = 5;
    private const uint ServiceSidTypeUnrestricted = 1;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorServiceAlreadyRunning = 1056;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorServiceMarkedForDelete = 1072;

    public static async Task InstallAndStartAsync(
        string serviceName,
        string displayName,
        string description,
        string executablePath,
        string configurationPath,
        CancellationToken cancellationToken)
    {
        await RemoveAsync(serviceName, cancellationToken).ConfigureAwait(false);

        var manager = OpenSCManager(
            null,
            null,
            ScManagerConnect | ScManagerCreateService);
        if (manager == IntPtr.Zero)
        {
            throw LastWin32Exception("Unable to open the Windows service manager.");
        }

        var dependencies = Marshal.StringToHGlobalUni("Nsi\0TcpIp\0\0");
        IntPtr service = IntPtr.Zero;
        try
        {
            var commandLine =
                $"{QuoteCommandLineArgument(executablePath)} /service "
                + QuoteCommandLineArgument(configurationPath);
            service = CreateService(
                manager,
                serviceName,
                displayName,
                ServiceQueryStatus
                    | ServiceStart
                    | ServiceStop
                    | ServiceChangeConfig
                    | Delete,
                ServiceWin32OwnProcess,
                ServiceDemandStart,
                ServiceErrorNormal,
                commandLine,
                null,
                IntPtr.Zero,
                dependencies,
                null,
                null);
            if (service == IntPtr.Zero)
            {
                throw LastWin32Exception("Unable to create the WireGuard tunnel service.");
            }

            var sidInfo = new ServiceSidInfo
            {
                ServiceSidType = ServiceSidTypeUnrestricted,
            };
            if (!ChangeServiceConfig2Sid(
                    service,
                    ServiceConfigSidInfo,
                    ref sidInfo))
            {
                throw LastWin32Exception(
                    "Unable to assign the WireGuard tunnel service SID.");
            }

            var serviceDescription = new ServiceDescription
            {
                Description = description,
            };
            if (!ChangeServiceConfig2Description(
                    service,
                    ServiceConfigDescription,
                    ref serviceDescription))
            {
                throw LastWin32Exception(
                    "Unable to set the WireGuard tunnel service description.");
            }

            if (!StartService(service, 0, null)
                && Marshal.GetLastWin32Error() != ErrorServiceAlreadyRunning)
            {
                throw LastWin32Exception("Unable to start the WireGuard tunnel service.");
            }

            await WaitForStateAsync(
                service,
                WindowsServiceState.Running,
                TimeSpan.FromSeconds(30),
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (service != IntPtr.Zero)
            {
                _ = DeleteService(service);
            }

            throw;
        }
        finally
        {
            if (service != IntPtr.Zero)
            {
                CloseServiceHandle(service);
            }

            Marshal.FreeHGlobal(dependencies);
            CloseServiceHandle(manager);
        }
    }

    public static async Task RemoveAsync(
        string serviceName,
        CancellationToken cancellationToken)
    {
        var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            throw LastWin32Exception("Unable to open the Windows service manager.");
        }

        try
        {
            var service = OpenService(
                manager,
                serviceName,
                ServiceQueryStatus | ServiceStop | Delete);
            if (service == IntPtr.Zero)
            {
                if (Marshal.GetLastWin32Error() == ErrorServiceDoesNotExist)
                {
                    return;
                }

                throw LastWin32Exception("Unable to open the WireGuard tunnel service.");
            }

            try
            {
                if (!ControlService(service, ServiceControlStop, out _)
                    && Marshal.GetLastWin32Error() != ErrorServiceNotActive)
                {
                    throw LastWin32Exception(
                        "Unable to stop the WireGuard tunnel service.");
                }

                await WaitForStateAsync(
                    service,
                    WindowsServiceState.Stopped,
                    TimeSpan.FromSeconds(20),
                    cancellationToken).ConfigureAwait(false);
                if (!DeleteService(service)
                    && Marshal.GetLastWin32Error() != ErrorServiceMarkedForDelete)
                {
                    throw LastWin32Exception(
                        "Unable to delete the WireGuard tunnel service.");
                }
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

        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);
        while (WindowsServiceStatus.Query(serviceName) != WindowsServiceState.Missing)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException(
                    "The WireGuard tunnel service is still pending deletion.");
            }

            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }
    }

    internal static string QuoteCommandLineArgument(string value)
    {
        if (value.Contains('"', StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Windows paths cannot contain quotation marks.",
                nameof(value));
        }

        return $"\"{value}\"";
    }

    private static async Task WaitForStateAsync(
        IntPtr service,
        WindowsServiceState expected,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!QueryServiceStatus(service, out var status))
            {
                throw LastWin32Exception(
                    "Unable to query the WireGuard tunnel service.");
            }

            var state = (WindowsServiceState)status.CurrentState;
            if (state == expected)
            {
                return;
            }

            if (expected == WindowsServiceState.Running
                && state == WindowsServiceState.Stopped)
            {
                throw new Win32Exception(
                    unchecked((int)status.Win32ExitCode),
                    "The WireGuard tunnel service stopped during startup.");
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException(
                    $"The WireGuard tunnel service did not reach {expected}.");
            }

            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }
    }

    private static Win32Exception LastWin32Exception(string message) =>
        new(Marshal.GetLastWin32Error(), message);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateService(
        IntPtr serviceManager,
        string serviceName,
        string displayName,
        uint desiredAccess,
        uint serviceType,
        uint startType,
        uint errorControl,
        string binaryPathName,
        string? loadOrderGroup,
        IntPtr tagId,
        IntPtr dependencies,
        string? serviceStartName,
        string? password);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(
        IntPtr serviceManager,
        string serviceName,
        uint desiredAccess);

    [DllImport(
        "advapi32.dll",
        EntryPoint = "ChangeServiceConfig2W",
        SetLastError = true,
        CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2Sid(
        IntPtr service,
        uint infoLevel,
        ref ServiceSidInfo info);

    [DllImport(
        "advapi32.dll",
        EntryPoint = "ChangeServiceConfig2W",
        SetLastError = true,
        CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2Description(
        IntPtr service,
        uint infoLevel,
        ref ServiceDescription description);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(
        IntPtr service,
        uint argumentCount,
        string[]? arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(
        IntPtr service,
        uint control,
        out ServiceStatus serviceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(
        IntPtr service,
        out ServiceStatus serviceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(IntPtr service);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceSidInfo
    {
        public uint ServiceSidType;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceDescription
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Description;
    }

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
