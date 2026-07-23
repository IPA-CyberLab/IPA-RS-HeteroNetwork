using System.Runtime.InteropServices;

namespace HeteroNetwork.Core;

public static class EmbeddedWireGuardRuntime
{
    private const string TunnelLibraryName = "tunnel.dll";
    private const string WireGuardLibraryName = "wireguard.dll";

    public static string TunnelLibraryPath =>
        Path.Combine(AppContext.BaseDirectory, TunnelLibraryName);

    public static string WireGuardLibraryPath =>
        Path.Combine(AppContext.BaseDirectory, WireGuardLibraryName);

    public static bool IsAvailable =>
        RuntimeInformation.ProcessArchitecture == Architecture.X64
        && File.Exists(TunnelLibraryPath)
        && File.Exists(WireGuardLibraryPath);

    public static void SelfTest()
    {
        AssertAvailable();
        _ = NativeLibrary.Load(WireGuardLibraryPath);
        var tunnelHandle = NativeLibrary.Load(TunnelLibraryPath);
        _ = NativeLibrary.GetExport(tunnelHandle, "WireGuardTunnelService");
    }

    public static int RunTunnelService(string configurationPath)
    {
        AssertAvailable();
        if (!Path.IsPathFullyQualified(configurationPath)
            || !configurationPath.EndsWith(
                ".conf.dpapi",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "The WireGuard service requires an absolute .conf.dpapi path.",
                nameof(configurationPath));
        }

        _ = NativeLibrary.Load(WireGuardLibraryPath);
        var tunnelHandle = NativeLibrary.Load(TunnelLibraryPath);
        var entryPoint = NativeLibrary.GetExport(
            tunnelHandle,
            "WireGuardTunnelService");
        var run = Marshal.GetDelegateForFunctionPointer<TunnelServiceEntryPoint>(
            entryPoint);
        return run(configurationPath) ? 0 : 1;
    }

    public static void AssertAvailable()
    {
        if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException(
                "This release contains the x64 WireGuard runtime.");
        }

        if (!File.Exists(TunnelLibraryPath) || !File.Exists(WireGuardLibraryPath))
        {
            throw new FileNotFoundException(
                "The embedded WireGuard runtime is missing. Rebuild the Windows client.");
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool TunnelServiceEntryPoint(
        [MarshalAs(UnmanagedType.LPWStr)] string configurationPath);
}
