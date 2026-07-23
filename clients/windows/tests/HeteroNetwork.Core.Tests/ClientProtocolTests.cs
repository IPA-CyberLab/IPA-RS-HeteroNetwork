using System.Text;
using System.Text.Json;
using HeteroNetwork.Core;

namespace HeteroNetwork.Core.Tests;

public sealed class ClientProtocolTests
{
    [Fact]
    public void SignatureMatchesRustAndMacOsGoldenVector()
    {
        var keys = new ClientKeyMaterial(
            Enumerable.Repeat((byte)7, 32).ToArray(),
            Enumerable.Repeat((byte)9, 32).ToArray());

        Assert.Equal("node-fe812c12f3ab4ce6ac5db69ac352f906", keys.ClientId);
        var signature = keys.Sign(
            keys.ClientId,
            ClientRequestKind.PeerMap,
            at: DateTimeOffset.FromUnixTimeSeconds(1_784_550_896),
            nonce: Enumerable.Repeat((byte)3, 24).ToArray());

        Assert.Equal("AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD", signature.Nonce);
        Assert.Equal(
            "34UsDq5YNr83tomJ2N2o3cgPcaPIihje5uO+OjPp3Ad9DIZJs9Tiu6Dek8OWMkNKPbf+5+ythYm1WTkQWVlGBg==",
            signature.Signature);
    }

    [Fact]
    public void EnrollmentPreservesSignedTimestampPrecision()
    {
        const string rawToken = """
            {
              "claims": {
                "cluster_id": "cluster-a",
                "bootstrap_endpoints": [
                  {"url": "https://gateway.example", "kind": "web_ui"},
                  {"url": "https://cp.example:8443", "kind": "control_plane"}
                ],
                "expires_at": "2026-07-24T12:34:56.846167233Z",
                "not_before": "2026-07-22T12:34:51.123456789Z",
                "role": "client",
                "tags": [],
                "issuer": "node-issuer",
                "key_id": "client-enrollment",
                "policy": {
                  "allow_join": true,
                  "allow_relay": false,
                  "allowed_routes": [],
                  "allowed_tags": [],
                  "max_token_uses": 1
                },
                "nonce": "client-enroll-precision-test"
              },
              "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
            """;
        var encoded = Base64Url(Encoding.UTF8.GetBytes(rawToken));
        var token = EnrollmentParser.Parse(
            $"heteronetwork://enroll?token={encoded}",
            DateTimeOffset.Parse("2026-07-23T00:00:00Z"));
        var request = new JoinClientRequest(
            token,
            new RegisterClientRequest("node-client", "identity", "wireguard"));

        var serialized = JsonSerializer.SerializeToUtf8Bytes(
            request,
            HeteroNetworkJson.Options);
        using var document = JsonDocument.Parse(serialized);
        var claims = document.RootElement.GetProperty("token").GetProperty("claims");
        Assert.Equal(
            "2026-07-24T12:34:56.846167233Z",
            claims.GetProperty("expires_at").GetString());
        Assert.Equal(
            "2026-07-22T12:34:51.123456789Z",
            claims.GetProperty("not_before").GetString());
    }

    [Fact]
    public void EnrollmentRejectsNonClientRole()
    {
        var token = TestData.Token(role: "edge");
        var serialized = JsonSerializer.SerializeToUtf8Bytes(
            token,
            HeteroNetworkJson.Options);

        var error = Assert.Throws<EnrollmentException>(
            () => EnrollmentParser.Parse(
                $"heteronetwork://enroll?token={Base64Url(serialized)}",
                TestData.Now));
        Assert.Contains("control-only client", error.Message);
    }

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
