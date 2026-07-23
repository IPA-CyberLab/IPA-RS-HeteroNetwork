using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace HeteroNetwork.Core;

public sealed class ClientKeyMaterial
{
    public ClientKeyMaterial(byte[] identityPrivateKey, byte[] wireGuardPrivateKey)
    {
        if (identityPrivateKey.Length != Ed25519PrivateKeyParameters.KeySize)
        {
            throw new CryptographicException("The saved client identity key is invalid.");
        }

        if (wireGuardPrivateKey.Length != X25519PrivateKeyParameters.KeySize)
        {
            throw new CryptographicException("The saved WireGuard key is invalid.");
        }

        IdentityPrivateKey = identityPrivateKey.ToArray();
        WireGuardPrivateKey = wireGuardPrivateKey.ToArray();
    }

    public byte[] IdentityPrivateKey { get; }
    public byte[] WireGuardPrivateKey { get; }

    public string IdentityPublicKey =>
        Convert.ToBase64String(IdentityKey().GeneratePublicKey().GetEncoded());

    public string WireGuardPublicKey =>
        Convert.ToBase64String(WireGuardKey().GeneratePublicKey().GetEncoded());

    public string WireGuardPrivateKeyBase64 => Convert.ToBase64String(WireGuardPrivateKey);

    public string ClientId
    {
        get
        {
            var digest = SHA256.HashData(IdentityKey().GeneratePublicKey().GetEncoded());
            return $"node-{Convert.ToHexStringLower(digest.AsSpan(0, 16))}";
        }
    }

    public static ClientKeyMaterial Generate()
    {
        var random = new SecureRandom();
        var identity = new Ed25519PrivateKeyParameters(random);
        var wireGuard = new X25519PrivateKeyParameters(random);
        return new ClientKeyMaterial(identity.GetEncoded(), wireGuard.GetEncoded());
    }

    public ClientRequestSignature Sign(
        string clientId,
        ClientRequestKind kind,
        string? activeGatewayNodeId = null,
        DateTimeOffset? at = null,
        byte[]? nonce = null)
    {
        var nonceData = nonce?.ToArray() ?? RandomNumberGenerator.GetBytes(24);
        if (nonceData.Length != 24)
        {
            throw new CryptographicException("The request nonce must be exactly 24 bytes.");
        }

        var nonceValue = Base64Url(nonceData);
        var timestamp = (at ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        var operation = kind == ClientRequestKind.PeerMap ? "peer_map" : "remove";
        var payload = activeGatewayNodeId is null
            ? $"heteronetwork-client-request-v1\n{operation}\n{clientId}\n{timestamp}\n{nonceValue}\n"
            : $"heteronetwork-client-request-v2\n{operation}\n{clientId}\n{activeGatewayNodeId}\n{timestamp}\n{nonceValue}\n";
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var signer = new Ed25519Signer();
        signer.Init(true, IdentityKey());
        signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
        var signature = signer.GenerateSignature();
        return new ClientRequestSignature(
            DateTimeOffset.FromUnixTimeSeconds(timestamp),
            nonceValue,
            Convert.ToBase64String(signature));
    }

    private Ed25519PrivateKeyParameters IdentityKey() => new(IdentityPrivateKey);
    private X25519PrivateKeyParameters WireGuardKey() => new(WireGuardPrivateKey);

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
