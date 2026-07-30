using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace HeteroNetwork.Core;

public sealed class ClientRegistrationException(string message) : Exception(message);

public static class ClientRegistrationProtocol
{
    private const int RegistrationMaximumBytes = 64 * 1024;
    private const int ImportProfileMaximumBytes = 128 * 1024;
    private const int NonceBytes = 24;
    private const int PublicKeyBytes = 32;
    private const int SignatureBytes = 64;
    private static readonly TimeSpan DefaultRegistrationValidity = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan MaximumRegistrationValidity = TimeSpan.FromHours(24);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(5);

    public static PendingClientRegistration GenerateRequest(
        ClientKeyMaterial? keys = null,
        DateTimeOffset? now = null,
        TimeSpan? validity = null,
        byte[]? nonce = null)
    {
        var keyMaterial = keys ?? ClientKeyMaterial.Generate();
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(
            (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds());
        var lifetime = validity ?? DefaultRegistrationValidity;
        if (lifetime < TimeSpan.FromSeconds(1)
            || lifetime > MaximumRegistrationValidity
            || lifetime.Ticks % TimeSpan.TicksPerSecond != 0)
        {
            throw new ClientRegistrationException(
                "Registration validity must be between one second and 24 hours.");
        }

        var nonceBytes = nonce?.ToArray() ?? RandomNumberGenerator.GetBytes(NonceBytes);
        if (nonceBytes.Length != NonceBytes)
        {
            throw new ClientRegistrationException(
                "The registration nonce must be exactly 24 bytes.");
        }

        var registration = new RegisterClientRequest(
            keyMaterial.ClientId,
            keyMaterial.IdentityPublicKey,
            keyMaterial.WireGuardPublicKey);
        var unsigned = new ClientRegistrationBundle
        {
            SchemaVersion = HeteroNetworkConstants.ClientRegistrationSchemaVersion,
            Registration = registration,
            EncodedIssuedAt = FormatTimestamp(issuedAt),
            EncodedExpiresAt = FormatTimestamp(issuedAt.Add(lifetime)),
            Nonce = Base64Url(nonceBytes),
            Signature = string.Empty,
        };
        var signature = keyMaterial.SignRegistrationPayload(SignaturePayload(unsigned));
        var bundle = unsigned with { Signature = signature };
        var pending = new PendingClientRegistration
        {
            IdentityPrivateKey = keyMaterial.IdentityPrivateKey.ToArray(),
            WireGuardPrivateKey = keyMaterial.WireGuardPrivateKey.ToArray(),
            Bundle = bundle,
        };
        ValidatePending(pending);
        return pending;
    }

    public static string RegistrationUri(ClientRegistrationBundle bundle)
    {
        ValidateBundle(bundle, null, false);
        var encoded = Base64Url(JsonSerializer.SerializeToUtf8Bytes(
            bundle,
            HeteroNetworkJson.Options));
        return $"heteronetwork://register?request={encoded}";
    }

    public static ClientRegistrationBundle ParseRegistrationUri(
        string input,
        DateTimeOffset? now = null)
    {
        var data = DecodeProtocolUri(
            input,
            "register",
            "request",
            RegistrationMaximumBytes,
            "registration request");
        try
        {
            var bundle = JsonSerializer.Deserialize<ClientRegistrationBundle>(
                    data,
                    HeteroNetworkJson.Options)
                ?? throw new JsonException("The registration request was empty.");
            ValidateBundle(bundle, now ?? DateTimeOffset.UtcNow, true);
            return bundle;
        }
        catch (Exception error) when (error is JsonException
                                      or FormatException
                                      or CryptographicException)
        {
            throw new ClientRegistrationException(
                "The registration request is malformed.");
        }
        finally
        {
            Array.Clear(data);
        }
    }

    public static string ImportUri(ClientImportProfile profile)
    {
        var encoded = Base64Url(JsonSerializer.SerializeToUtf8Bytes(
            profile,
            HeteroNetworkJson.Options));
        return $"heteronetwork://import?profile={encoded}";
    }

    public static bool IsImportUri(string input)
    {
        var trimmed = input.Trim();
        return Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
            && uri.Scheme.Equals("heteronetwork", StringComparison.OrdinalIgnoreCase)
            && uri.Host.Equals("import", StringComparison.OrdinalIgnoreCase);
    }

    public static ClientSession ImportProfile(
        string input,
        PendingClientRegistration pending,
        DateTimeOffset? now = null)
    {
        ValidatePending(pending);
        var data = DecodeProtocolUri(
            input,
            "import",
            "profile",
            ImportProfileMaximumBytes,
            "import profile");
        try
        {
            using var document = JsonDocument.Parse(data);
            if (ContainsPrivateKeyProperty(document.RootElement))
            {
                throw new ClientRegistrationException(
                    "The import profile must not contain private key material.");
            }

            var profile = document.RootElement.Deserialize<ClientImportProfile>(
                    HeteroNetworkJson.Options)
                ?? throw new JsonException("The import profile was empty.");
            var importedAt = now ?? DateTimeOffset.UtcNow;
            var managementUrls = ValidateImportProfile(profile, pending, importedAt);
            var keys = pending.KeyMaterial;
            var session = ClientSession.Create(
                keys,
                managementUrls,
                profile.Registration.Client,
                profile.Registration.PeerMap,
                profile.IssuedAt);
            for (var index = 0; index < session.PeerMap.Peers.Count; index++)
            {
                _ = TunnelProfile.FromSession(session, index);
            }

            return session;
        }
        catch (ClientRegistrationException)
        {
            throw;
        }
        catch (Exception error) when (error is JsonException
                                      or FormatException
                                      or CryptographicException
                                      or TunnelProfileException)
        {
            throw new ClientRegistrationException(
                $"The import profile is invalid: {error.Message}");
        }
        finally
        {
            Array.Clear(data);
        }
    }

    public static void ValidatePending(PendingClientRegistration pending)
    {
        if (pending.SchemaVersion != HeteroNetworkConstants.PendingRegistrationSchemaVersion)
        {
            throw new ClientRegistrationException(
                $"Pending registration version {pending.SchemaVersion} is unsupported.");
        }

        var keys = pending.KeyMaterial;
        var registration = pending.Bundle.Registration;
        if (registration.ClientId != keys.ClientId
            || registration.IdentityPublicKey != keys.IdentityPublicKey
            || registration.WireGuardPublicKey != keys.WireGuardPublicKey)
        {
            throw new ClientRegistrationException(
                "The pending registration keys do not match its public request.");
        }

        ValidateBundle(pending.Bundle, null, false);
    }

    public static byte[] SignaturePayload(ClientRegistrationBundle bundle)
    {
        var issuedAt = ParseTimestamp(bundle.EncodedIssuedAt, "issued_at");
        var expiresAt = ParseTimestamp(bundle.EncodedExpiresAt, "expires_at");
        return Encoding.UTF8.GetBytes(
            "heteronetwork-client-registration-v1\n"
            + $"{bundle.Registration.ClientId}\n"
            + $"{bundle.Registration.IdentityPublicKey}\n"
            + $"{bundle.Registration.WireGuardPublicKey}\n"
            + $"{issuedAt.ToUnixTimeSeconds()}\n"
            + $"{expiresAt.ToUnixTimeSeconds()}\n"
            + $"{bundle.Nonce}\n");
    }

    private static IReadOnlyList<Uri> ValidateImportProfile(
        ClientImportProfile profile,
        PendingClientRegistration pending,
        DateTimeOffset now)
    {
        if (profile.SchemaVersion != HeteroNetworkConstants.ClientRegistrationSchemaVersion)
        {
            throw new ClientRegistrationException(
                $"Import profile version {profile.SchemaVersion} is unsupported.");
        }

        if (string.IsNullOrWhiteSpace(profile.SponsorNodeId)
            || profile.SponsorNodeId.Length is < 6 or > 128
            || !profile.SponsorNodeId.StartsWith("node-", StringComparison.Ordinal)
            || profile.SponsorNodeId.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
        {
            throw new ClientRegistrationException(
                "The import profile sponsor node is invalid.");
        }

        var issuedAt = ParseTimestamp(profile.EncodedIssuedAt, "issued_at");
        var expiresAt = ParseTimestamp(profile.EncodedExpiresAt, "expires_at");
        if (issuedAt > now.Add(ClockSkew)
            || expiresAt <= now
            || expiresAt <= issuedAt)
        {
            throw new ClientRegistrationException(
                "The import profile is expired or not yet valid.");
        }

        var response = profile.Registration
            ?? throw new ClientRegistrationException(
                "The import profile registration is missing.");
        var client = response.Client
            ?? throw new ClientRegistrationException(
                "The import profile client is missing.");
        var peerMap = response.PeerMap
            ?? throw new ClientRegistrationException(
                "The import profile peer map is missing.");
        var requested = pending.Bundle.Registration;
        if (client.NodeId != requested.ClientId
            || client.IdentityPublicKey != requested.IdentityPublicKey
            || client.WireGuardPublicKey != requested.WireGuardPublicKey)
        {
            throw new ClientRegistrationException(
                "The import profile does not match the pending client keys.");
        }

        if (!client.Role.Equals("client", StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(client.ClusterId)
            || peerMap.ClusterId != client.ClusterId)
        {
            throw new ClientRegistrationException(
                "The import profile has an invalid client or cluster identity.");
        }

        if (!response.ClusterPolicy.HasValue
            || response.ClusterPolicy.Value.ValueKind != JsonValueKind.Object)
        {
            throw new ClientRegistrationException(
                "The import profile does not contain a cluster policy.");
        }

        if (peerMap.Peers is null || peerMap.Peers.Count is < 1 or > 4)
        {
            throw new ClientRegistrationException(
                "The import profile must contain between one and four gateways.");
        }

        var peerIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var gateway in peerMap.Peers)
        {
            if (gateway is null
                || string.IsNullOrWhiteSpace(gateway.NodeId)
                || !peerIds.Add(gateway.NodeId)
                || gateway.NodeId == client.NodeId
                || gateway.ClusterId != client.ClusterId
                || gateway.EndpointCandidates is null
                || gateway.EndpointCandidates.Count == 0
                || !TryDecodeCanonicalBase64(gateway.WireGuardPublicKey, PublicKeyBytes, out _))
            {
                throw new ClientRegistrationException(
                    "The import profile contains an invalid gateway.");
            }

            foreach (var candidate in gateway.EndpointCandidates)
            {
                if (candidate.NodeId != gateway.NodeId
                    || !IsGlobalWireGuardCandidate(candidate))
                {
                    throw new ClientRegistrationException(
                        "Every gateway endpoint must be a globally routable "
                        + "public_udp or ipv6 WireGuard endpoint.");
                }
            }
        }

        if (profile.ManagementUrls is null
            || profile.ManagementUrls.Count is < 1 or > 16)
        {
            throw new ClientRegistrationException(
                "The import profile does not contain a private management URL.");
        }

        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var managementUrls = new List<Uri>();
        foreach (var encoded in profile.ManagementUrls)
        {
            if (!TryPrivateManagementUri(encoded, out var uri))
            {
                throw new ClientRegistrationException(
                    "Every management URL must use HTTP on the private VPN overlay.");
            }

            var canonical = uri.AbsoluteUri.TrimEnd('/');
            if (seenUrls.Add(canonical))
            {
                managementUrls.Add(uri);
            }
        }

        if (managementUrls.Count == 0)
        {
            throw new ClientRegistrationException(
                "The import profile does not contain a private management URL.");
        }

        return managementUrls;
    }

    private static void ValidateBundle(
        ClientRegistrationBundle bundle,
        DateTimeOffset? now,
        bool requireCurrent)
    {
        if (bundle.SchemaVersion != HeteroNetworkConstants.ClientRegistrationSchemaVersion)
        {
            throw new ClientRegistrationException(
                $"Registration request version {bundle.SchemaVersion} is unsupported.");
        }

        var registration = bundle.Registration
            ?? throw new ClientRegistrationException(
                "The registration request is missing its public keys.");
        if (!TryDecodeCanonicalBase64(
                registration.IdentityPublicKey,
                PublicKeyBytes,
                out var identityPublicKey)
            || !TryDecodeCanonicalBase64(
                registration.WireGuardPublicKey,
                PublicKeyBytes,
                out _))
        {
            throw new ClientRegistrationException(
                "The registration request contains an invalid public key.");
        }

        var derivedClientId = ClientId(identityPublicKey);
        if (registration.ClientId != derivedClientId)
        {
            throw new ClientRegistrationException(
                "The registration request client ID does not match its identity key.");
        }

        var issuedAt = ParseTimestamp(bundle.EncodedIssuedAt, "issued_at");
        var expiresAt = ParseTimestamp(bundle.EncodedExpiresAt, "expires_at");
        var lifetime = expiresAt - issuedAt;
        if (lifetime < TimeSpan.FromSeconds(1) || lifetime > MaximumRegistrationValidity)
        {
            throw new ClientRegistrationException(
                "The registration request validity is invalid.");
        }

        if (requireCurrent
            && (issuedAt > now!.Value.Add(ClockSkew) || expiresAt <= now.Value))
        {
            throw new ClientRegistrationException(
                "The registration request is expired or not yet valid.");
        }

        if (!TryDecodeCanonicalBase64Url(bundle.Nonce, NonceBytes, out _))
        {
            throw new ClientRegistrationException(
                "The registration request nonce is invalid.");
        }

        if (!TryDecodeCanonicalBase64(bundle.Signature, SignatureBytes, out var signature))
        {
            throw new ClientRegistrationException(
                "The registration request signature is invalid.");
        }

        var payload = SignaturePayload(bundle);
        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(identityPublicKey));
            verifier.BlockUpdate(payload, 0, payload.Length);
            if (!verifier.VerifySignature(signature))
            {
                throw new ClientRegistrationException(
                    "The registration request signature is invalid.");
            }
        }
        finally
        {
            Array.Clear(payload);
        }
    }

    internal static bool IsGlobalWireGuardCandidate(EndpointCandidate candidate)
    {
        if (candidate.Kind is not (
                EndpointCandidateKind.PublicUdp or EndpointCandidateKind.Ipv6)
            || !IPEndPoint.TryParse(candidate.Address, out var endpoint)
            || endpoint.Port == 0
            || !IsGloballyRoutable(endpoint.Address))
        {
            return false;
        }

        return candidate.Kind switch
        {
            EndpointCandidateKind.PublicUdp => true,
            EndpointCandidateKind.Ipv6 =>
                endpoint.Address.AddressFamily == AddressFamily.InterNetworkV6,
            _ => false,
        };
    }

    internal static bool IsGloballyRoutable(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return bytes[0] is > 0 and < 224
                && bytes[0] != 10
                && bytes[0] != 127
                && !(bytes[0] == 100 && bytes[1] is >= 64 and <= 127)
                && !(bytes[0] == 169 && bytes[1] == 254)
                && !(bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                && !(bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0)
                && !(bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)
                && !(bytes[0] == 192 && bytes[1] == 168)
                && !(bytes[0] == 198 && bytes[1] is 18 or 19)
                && !(bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
                && !(bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113);
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.IPv6Loopback)
            || address.IsIPv6Multicast
            || address.IsIPv6LinkLocal
            || address.IsIPv6SiteLocal)
        {
            return false;
        }

        var globalUnicast = (bytes[0] & 0xe0) == 0x20;
        var documentation = bytes[0] == 0x20
            && bytes[1] == 0x01
            && bytes[2] == 0x0d
            && bytes[3] == 0xb8;
        return globalUnicast && !documentation;
    }

    internal static bool TryPrivateManagementUri(string encoded, out Uri uri)
    {
        if (!Uri.TryCreate(encoded, UriKind.Absolute, out uri!)
            || !IsPrivateManagementUri(uri))
        {
            return false;
        }

        return true;
    }

    internal static bool IsPrivateManagementUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri
            || uri.Scheme != Uri.UriSchemeHttp
            || string.IsNullOrWhiteSpace(uri.Host)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || uri.Port <= 0
            || uri.AbsolutePath != "/")
        {
            return false;
        }

        if (uri.Host.Equals(
                HeteroNetworkConstants.OverlayDnsName,
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!IPAddress.TryParse(uri.Host, out var address))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 10 && bytes[1] == 250;
        }

        return false;
    }

    private static byte[] DecodeProtocolUri(
        string input,
        string host,
        string queryName,
        int maximumBytes,
        string description)
    {
        var trimmed = input.Trim();
        if (Encoding.UTF8.GetByteCount(trimmed) > maximumBytes * 2
            || !Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
            || !uri.Scheme.Equals("heteronetwork", StringComparison.OrdinalIgnoreCase)
            || !uri.Host.Equals(host, StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !uri.IsDefaultPort
            || uri.AbsolutePath != "/"
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ClientRegistrationException($"The {description} URI is invalid.");
        }

        IReadOnlyList<KeyValuePair<string, string?>> query;
        try
        {
            query = ParseQuery(uri.Query).ToArray();
        }
        catch (UriFormatException)
        {
            throw new ClientRegistrationException($"The {description} URI is invalid.");
        }

        if (query.Count != 1
            || !query[0].Key.Equals(queryName, StringComparison.Ordinal)
            || query[0].Value is not { } encoded
            || !TryDecodeCanonicalBase64Url(encoded, null, out var data))
        {
            throw new ClientRegistrationException($"The {description} URI is invalid.");
        }

        if (data.Length > maximumBytes)
        {
            Array.Clear(data);
            throw new ClientRegistrationException($"The {description} is too large.");
        }

        return data;
    }

    private static IEnumerable<KeyValuePair<string, string?>> ParseQuery(string query)
    {
        foreach (var component in query.TrimStart('?').Split(
                     '&',
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var pair = component.Split('=', 2);
            yield return new KeyValuePair<string, string?>(
                Uri.UnescapeDataString(pair[0]),
                pair.Length == 2 ? Uri.UnescapeDataString(pair[1]) : null);
        }
    }

    private static bool ContainsPrivateKeyProperty(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                var normalized = property.Name
                    .Replace('-', '_')
                    .ToLowerInvariant();
                if (normalized.Contains("private_key", StringComparison.Ordinal)
                    || normalized is "identityprivatekey" or "wireguardprivatekey"
                    || ContainsPrivateKeyProperty(property.Value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            return element.EnumerateArray().Any(ContainsPrivateKeyProperty);
        }

        return false;
    }

    private static DateTimeOffset ParseTimestamp(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length < 20
            || value[4] != '-'
            || value[7] != '-'
            || value[10] != 'T'
            || value[13] != ':'
            || value[16] != ':')
        {
            throw new ClientRegistrationException($"{name} is not RFC 3339.");
        }

        var zoneIndex = value.EndsWith('Z')
            ? value.Length - 1
            : value.Length >= 25
              && value[^6] is '+' or '-'
              && value[^3] == ':'
                ? value.Length - 6
                : -1;
        if (zoneIndex < 19
            || (zoneIndex > 19
                && (value[19] != '.'
                    || zoneIndex == 20
                    || zoneIndex - 20 > 9
                    || !value.AsSpan(20, zoneIndex - 20).ToArray().All(char.IsAsciiDigit))))
        {
            throw new ClientRegistrationException($"{name} is not RFC 3339.");
        }

        try
        {
            return HeteroNetworkJson.ParseRfc3339(value);
        }
        catch (JsonException)
        {
            throw new ClientRegistrationException($"{name} is not RFC 3339.");
        }
    }

    private static bool TryDecodeCanonicalBase64(
        string value,
        int expectedBytes,
        out byte[] data)
    {
        try
        {
            data = Convert.FromBase64String(value);
            return data.Length == expectedBytes
                && Convert.ToBase64String(data) == value;
        }
        catch (FormatException)
        {
            data = [];
            return false;
        }
    }

    private static bool TryDecodeCanonicalBase64Url(
        string value,
        int? expectedBytes,
        out byte[] data)
    {
        if (string.IsNullOrEmpty(value)
            || value.Contains('=')
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_')))
        {
            data = [];
            return false;
        }

        var standard = value.Replace('-', '+').Replace('_', '/');
        standard = standard.PadRight(
            standard.Length + ((4 - (standard.Length % 4)) % 4),
            '=');
        try
        {
            data = Convert.FromBase64String(standard);
            return (!expectedBytes.HasValue || data.Length == expectedBytes.Value)
                && Base64Url(data) == value;
        }
        catch (FormatException)
        {
            data = [];
            return false;
        }
    }

    private static string ClientId(byte[] identityPublicKey)
    {
        var digest = SHA256.HashData(identityPublicKey);
        return $"node-{Convert.ToHexStringLower(digest.AsSpan(0, 16))}";
    }

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
