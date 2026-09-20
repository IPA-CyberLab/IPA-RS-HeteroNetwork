using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace HeteroNetwork.Core;

internal static class WindowsProxySettings
{
    private const int InternetOptionRefresh = 37;
    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionProxySettingsChanged = 95;
    private const int InternetOptionPerConnection = 75;
    private const int InternetPerConnectionFlags = 1;
    private const int InternetPerConnectionFlagsUi = 10;
    private const uint ProxyTypeDirect = 0x00000001;
    private const uint ProxyTypeProxy = 0x00000002;
    private const uint ProxyTypeAutoProxyUrl = 0x00000004;
    private const uint ProxyTypeAutoDetect = 0x00000008;
    private const string StateKeyPath = @"Software\HeteroNetwork";
    private const string ManagedAutoDetectValue = "ManagedAutoDetectDisabled";

    public static void DisableUnusedAutoDetect()
    {
        using var state = Registry.CurrentUser.CreateSubKey(StateKeyPath, writable: true)
            ?? throw new InvalidOperationException("The HeteroNetwork user settings are unavailable.");
        var flags = QueryFlags();
        var managed = Convert.ToInt32(state.GetValue(ManagedAutoDetectValue, 0)) == 1;
        if (managed && (flags & ProxyTypeAutoDetect) == 0)
        {
            return;
        }

        if (managed)
        {
            state.DeleteValue(ManagedAutoDetectValue, throwOnMissingValue: false);
        }

        var hasConfiguredProxy = (flags & (ProxyTypeProxy | ProxyTypeAutoProxyUrl)) != 0;
        if ((flags & ProxyTypeAutoDetect) == 0 || hasConfiguredProxy)
        {
            return;
        }

        state.SetValue(ManagedAutoDetectValue, 1, RegistryValueKind.DWord);
        try
        {
            SetFlags((flags | ProxyTypeDirect) & ~ProxyTypeAutoDetect);
        }
        catch
        {
            state.DeleteValue(ManagedAutoDetectValue, throwOnMissingValue: false);
            throw;
        }
    }

    public static void RestoreManagedAutoDetect()
    {
        using var state = Registry.CurrentUser.CreateSubKey(StateKeyPath, writable: true)
            ?? throw new InvalidOperationException("The HeteroNetwork user settings are unavailable.");
        if (Convert.ToInt32(state.GetValue(ManagedAutoDetectValue, 0)) != 1)
        {
            return;
        }

        var flags = QueryFlags();
        if ((flags & ProxyTypeAutoDetect) == 0)
        {
            SetFlags(flags | ProxyTypeDirect | ProxyTypeAutoDetect);
        }

        state.DeleteValue(ManagedAutoDetectValue, throwOnMissingValue: false);
    }

    private static uint QueryFlags()
    {
        var error = 0;
        foreach (var option in new[] { InternetPerConnectionFlagsUi, InternetPerConnectionFlags })
        {
            try
            {
                return QueryFlags(option);
            }
            catch (Win32Exception exception)
            {
                error = exception.NativeErrorCode;
            }
        }

        throw new Win32Exception(error, "Could not read the Windows proxy settings.");
    }

    private static uint QueryFlags(int option)
    {
        var optionBuffer = Marshal.AllocCoTaskMem(Marshal.SizeOf<InternetPerConnectionOption>());
        try
        {
            Marshal.StructureToPtr(
                new InternetPerConnectionOption { Option = option },
                optionBuffer,
                fDeleteOld: false);
            var options = new InternetPerConnectionOptionList
            {
                Size = Marshal.SizeOf<InternetPerConnectionOptionList>(),
                OptionCount = 1,
                Options = optionBuffer,
            };
            var size = options.Size;
            if (!InternetQueryOption(
                    IntPtr.Zero,
                    InternetOptionPerConnection,
                    ref options,
                    ref size))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var result = Marshal.PtrToStructure<InternetPerConnectionOption>(optionBuffer);
            return unchecked((uint)result.Value.ToInt64());
        }
        finally
        {
            Marshal.FreeCoTaskMem(optionBuffer);
        }
    }

    private static void SetFlags(uint flags)
    {
        var optionBuffer = Marshal.AllocCoTaskMem(Marshal.SizeOf<InternetPerConnectionOption>());
        try
        {
            Marshal.StructureToPtr(
                new InternetPerConnectionOption
                {
                    Option = InternetPerConnectionFlags,
                    Value = unchecked((IntPtr)(long)flags),
                },
                optionBuffer,
                fDeleteOld: false);
            var options = new InternetPerConnectionOptionList
            {
                Size = Marshal.SizeOf<InternetPerConnectionOptionList>(),
                OptionCount = 1,
                Options = optionBuffer,
            };
            if (!InternetSetOption(
                    IntPtr.Zero,
                    InternetOptionPerConnection,
                    ref options,
                    options.Size))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not update the Windows proxy settings.");
            }
        }
        finally
        {
            Marshal.FreeCoTaskMem(optionBuffer);
        }

        NotifySettingsChanged(InternetOptionProxySettingsChanged);
        NotifySettingsChanged(InternetOptionSettingsChanged);
        NotifySettingsChanged(InternetOptionRefresh);
    }

    private static void NotifySettingsChanged(int option)
    {
        _ = InternetSetOption(IntPtr.Zero, option, IntPtr.Zero, 0);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct InternetPerConnectionOption
    {
        public int Option;
        public IntPtr Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct InternetPerConnectionOptionList
    {
        public int Size;
        public IntPtr Connection;
        public int OptionCount;
        public int OptionError;
        public IntPtr Options;
    }

    [DllImport("wininet.dll", EntryPoint = "InternetQueryOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetQueryOption(
        IntPtr internet,
        int option,
        ref InternetPerConnectionOptionList buffer,
        ref int bufferLength);

    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOption(
        IntPtr internet,
        int option,
        ref InternetPerConnectionOptionList buffer,
        int bufferLength);

    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOption(
        IntPtr internet,
        int option,
        IntPtr buffer,
        int bufferLength);
}
