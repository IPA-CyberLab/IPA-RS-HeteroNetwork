using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeteroNetwork.Core;

public sealed class PendingClientRegistrationStore
{
    private static readonly byte[] Entropy =
        Encoding.UTF8.GetBytes("HeteroNetwork.Windows.PendingClientRegistration.v1");
    private readonly string pendingPath;

    public PendingClientRegistrationStore(string? pendingPath = null)
    {
        this.pendingPath = pendingPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "HeteroNetwork",
            "pending-client-registration.dpapi");
    }

    public string PendingPath => pendingPath;

    public PendingClientRegistration? Load()
    {
        if (!File.Exists(pendingPath))
        {
            return null;
        }

        try
        {
            var encrypted = File.ReadAllBytes(pendingPath);
            var plaintext = WindowsDataProtection.UnprotectCurrentUser(encrypted, Entropy);
            try
            {
                var pending = JsonSerializer.Deserialize<PendingClientRegistration>(
                        plaintext,
                        HeteroNetworkJson.Options)
                    ?? throw new InvalidDataException(
                        "The pending client registration is invalid.");
                ClientRegistrationProtocol.ValidatePending(pending);
                return pending;
            }
            finally
            {
                Array.Clear(plaintext);
            }
        }
        catch (Exception error) when (error is IOException
                                      or UnauthorizedAccessException
                                      or JsonException
                                      or CryptographicException
                                      or ExternalException
                                      or ClientRegistrationException)
        {
            throw new InvalidDataException(
                "The pending client registration is invalid.",
                error);
        }
    }

    public void Save(PendingClientRegistration pending)
    {
        ClientRegistrationProtocol.ValidatePending(pending);
        var directory = Path.GetDirectoryName(pendingPath)
            ?? throw new InvalidOperationException(
                "The pending registration path has no parent directory.");
        Directory.CreateDirectory(directory);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(
            pending,
            HeteroNetworkJson.Options);
        byte[]? encrypted = null;
        var temporaryPath = $"{pendingPath}.{Guid.NewGuid():N}.tmp";
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

            File.Move(temporaryPath, pendingPath, true);
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
        if (File.Exists(pendingPath))
        {
            File.Delete(pendingPath);
        }
    }
}
