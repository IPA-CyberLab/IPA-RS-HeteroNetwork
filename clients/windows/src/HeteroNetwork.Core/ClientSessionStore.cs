using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace HeteroNetwork.Core;

public sealed class ClientSessionStore
{
    private static readonly byte[] Entropy =
        Encoding.UTF8.GetBytes("HeteroNetwork.Windows.ClientSession.v1");
    private readonly string sessionPath;

    public ClientSessionStore(string? sessionPath = null)
    {
        this.sessionPath = sessionPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "HeteroNetwork",
            "client-session.dpapi");
    }

    public string SessionPath => sessionPath;

    public ClientSession? Load()
    {
        if (!File.Exists(sessionPath))
        {
            return null;
        }

        try
        {
            var encrypted = File.ReadAllBytes(sessionPath);
            var plaintext = WindowsDataProtection.UnprotectCurrentUser(encrypted, Entropy);
            try
            {
                var session = JsonSerializer.Deserialize<ClientSession>(
                        plaintext,
                        HeteroNetworkJson.Options)
                    ?? throw new InvalidDataException("The saved client session is invalid.");
                if (session.SchemaVersion != HeteroNetworkConstants.SessionSchemaVersion)
                {
                    throw new InvalidDataException(
                        $"The saved client session version {session.SchemaVersion} is unsupported.");
                }

                _ = new ClientKeyMaterial(
                    session.IdentityPrivateKey,
                    session.WireGuardPrivateKey);
                return session;
            }
            finally
            {
                Array.Clear(plaintext);
            }
        }
        catch (Exception error) when (error is IOException
                                      or UnauthorizedAccessException
                                      or JsonException
                                      or ExternalException)
        {
            throw new InvalidDataException("The saved client session is invalid.", error);
        }
    }

    public void Save(ClientSession session)
    {
        if (session.SchemaVersion != HeteroNetworkConstants.SessionSchemaVersion)
        {
            throw new InvalidDataException(
                $"The saved client session version {session.SchemaVersion} is unsupported.");
        }

        var directory = Path.GetDirectoryName(sessionPath)
            ?? throw new InvalidOperationException("The session path has no parent directory.");
        Directory.CreateDirectory(directory);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(
            session,
            HeteroNetworkJson.Options);
        byte[]? encrypted = null;
        var temporaryPath = $"{sessionPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            encrypted = WindowsDataProtection.ProtectCurrentUser(plaintext, Entropy);
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(encrypted);
                stream.Flush(true);
            }

            File.Move(temporaryPath, sessionPath, true);
        }
        finally
        {
            Array.Clear(plaintext);
            if (encrypted is not null)
            {
                Array.Clear(encrypted);
            }

            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public void Delete()
    {
        if (File.Exists(sessionPath))
        {
            File.Delete(sessionPath);
        }
    }
}

internal static class WindowsDataProtection
{
    private const uint CryptProtectUiForbidden = 0x1;
    private const uint CryptProtectLocalMachine = 0x4;

    public static byte[] ProtectCurrentUser(byte[] plaintext, byte[] entropy) =>
        Protect(plaintext, entropy, false);

    public static byte[] ProtectLocalMachine(byte[] plaintext) =>
        Protect(plaintext, null, true);

    public static byte[] UnprotectCurrentUser(byte[] encrypted, byte[] entropy) =>
        Unprotect(encrypted, entropy);

    private static byte[] Protect(byte[] plaintext, byte[]? entropy, bool localMachine)
    {
        using var input = DataBlob.FromBytes(plaintext);
        using var optionalEntropy = DataBlob.FromNullableBytes(entropy);
        var flags = CryptProtectUiForbidden
            | (localMachine ? CryptProtectLocalMachine : 0u);
        if (!CryptProtectData(
                ref input.Value,
                "HeteroNetwork",
                optionalEntropy.Pointer,
                IntPtr.Zero,
                IntPtr.Zero,
                flags,
                out var output))
        {
            throw new ExternalException(
                "Windows data protection failed.",
                Marshal.GetLastWin32Error());
        }

        try
        {
            var protectedBytes = new byte[output.Length];
            Marshal.Copy(output.Data, protectedBytes, 0, output.Length);
            return protectedBytes;
        }
        finally
        {
            LocalFree(output.Data);
        }
    }

    private static byte[] Unprotect(byte[] encrypted, byte[]? entropy)
    {
        using var input = DataBlob.FromBytes(encrypted);
        using var optionalEntropy = DataBlob.FromNullableBytes(entropy);
        if (!CryptUnprotectData(
                ref input.Value,
                IntPtr.Zero,
                optionalEntropy.Pointer,
                IntPtr.Zero,
                IntPtr.Zero,
                CryptProtectUiForbidden,
                out var output))
        {
            throw new ExternalException(
                "Windows data unprotection failed.",
                Marshal.GetLastWin32Error());
        }

        try
        {
            var plaintext = new byte[output.Length];
            Marshal.Copy(output.Data, plaintext, 0, output.Length);
            return plaintext;
        }
        finally
        {
            LocalFree(output.Data);
        }
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref Blob dataIn,
        string description,
        IntPtr optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        uint flags,
        out Blob dataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref Blob dataIn,
        IntPtr description,
        IntPtr optionalEntropy,
        IntPtr reserved,
        IntPtr promptStruct,
        uint flags,
        out Blob dataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [StructLayout(LayoutKind.Sequential)]
    private struct Blob
    {
        public int Length;
        public IntPtr Data;
    }

    private sealed class DataBlob : IDisposable
    {
        private DataBlob(byte[]? bytes)
        {
            if (bytes is null)
            {
                Value = new Blob();
                return;
            }

            Value = new Blob
            {
                Length = bytes.Length,
                Data = Marshal.AllocHGlobal(bytes.Length),
            };
            Marshal.Copy(bytes, 0, Value.Data, bytes.Length);
        }

        public Blob Value;
        public IntPtr Pointer
        {
            get
            {
                if (Value.Data == IntPtr.Zero)
                {
                    return IntPtr.Zero;
                }

                var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<Blob>());
                Marshal.StructureToPtr(Value, pointer, false);
                allocatedPointer = pointer;
                return pointer;
            }
        }

        private IntPtr allocatedPointer;

        public static DataBlob FromBytes(byte[] bytes) => new(bytes);
        public static DataBlob FromNullableBytes(byte[]? bytes) => new(bytes);

        public void Dispose()
        {
            if (allocatedPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(allocatedPointer);
            }

            if (Value.Data != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Value.Data);
            }
        }
    }
}
