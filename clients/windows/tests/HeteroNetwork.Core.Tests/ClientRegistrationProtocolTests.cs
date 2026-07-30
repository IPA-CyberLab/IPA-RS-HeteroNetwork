using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HeteroNetwork.Core;

namespace HeteroNetwork.Core.Tests;

public sealed class ClientRegistrationProtocolTests
{
    [Fact]
    public void RegistrationSignatureMatchesRustGoldenVector()
    {
        var keys = new ClientKeyMaterial(
            Enumerable.Repeat((byte)9, 32).ToArray(),
            Enumerable.Repeat((byte)7, 32).ToArray());
        var unsigned = new ClientRegistrationBundle
        {
            SchemaVersion = HeteroNetworkConstants.ClientRegistrationSchemaVersion,
            Registration = new RegisterClientRequest(
                keys.ClientId,
                keys.IdentityPublicKey,
                Convert.ToBase64String(Enumerable.Repeat((byte)8, 32).ToArray())),
            EncodedIssuedAt = "2026-07-30T12:00:00Z",
            EncodedExpiresAt = "2026-07-30T13:00:00Z",
            Nonce = Base64Url(Enumerable.Repeat((byte)5, 24).ToArray()),
            Signature = string.Empty,
        };
        var bundle = unsigned with
        {
            Signature = keys.SignRegistrationPayload(
                ClientRegistrationProtocol.SignaturePayload(unsigned)),
        };

        Assert.Equal(
            "node-dbc298251c51321b7266e78d1c151c2b",
            bundle.Registration.ClientId);
        Assert.Equal(
            "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=",
            bundle.Registration.WireGuardPublicKey);
        Assert.Equal(
            "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF",
            bundle.Nonce);
        Assert.Equal(
            "X084nfek9SQJlfKOEjrupHiAPaapn9fxsNpWYIBFwcD9YHn8f8qdS/XV1F2Te3HQPk1LYVrkmaeGXXTDGvJaBg==",
            bundle.Signature);

        var expectedPayload =
            "heteronetwork-client-registration-v1\n"
            + "node-dbc298251c51321b7266e78d1c151c2b\n"
            + $"{keys.IdentityPublicKey}\n"
            + "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=\n"
            + "1785412800\n"
            + "1785416400\n"
            + "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF\n";
        Assert.Equal(
            Encoding.UTF8.GetBytes(expectedPayload),
            ClientRegistrationProtocol.SignaturePayload(bundle));

        var registrationUri = ClientRegistrationProtocol.RegistrationUri(bundle);
        var requestJson = Encoding.UTF8.GetString(DecodeQueryValue(
            registrationUri,
            "request"));
        Assert.DoesNotContain("identity_private_key", requestJson);
        Assert.DoesNotContain("wireguard_private_key", requestJson);
        Assert.DoesNotContain(
            Convert.ToBase64String(keys.IdentityPrivateKey),
            requestJson);
        Assert.DoesNotContain(
            Convert.ToBase64String(keys.WireGuardPrivateKey),
            requestJson);

        var parsed = ClientRegistrationProtocol.ParseRegistrationUri(
            registrationUri,
            DateTimeOffset.Parse("2026-07-30T12:00:01Z"));
        Assert.Equal(bundle, parsed);
    }

    [Fact]
    public void RegistrationRejectsTampering()
    {
        var pending = TestData.PendingRegistration();
        var tampered = pending.Bundle with
        {
            Registration = pending.Bundle.Registration with
            {
                WireGuardPublicKey = Convert.ToBase64String(
                    Enumerable.Repeat((byte)42, 32).ToArray()),
            },
        };

        var error = Assert.Throws<ClientRegistrationException>(() =>
            ClientRegistrationProtocol.ParseRegistrationUri(
                EncodeRegistration(tampered),
                TestData.Now));
        Assert.Contains("signature", error.Message);
    }

    [Fact]
    public void RegistrationRejectsExpiredRequest()
    {
        var pending = TestData.PendingRegistration();

        var error = Assert.Throws<ClientRegistrationException>(() =>
            ClientRegistrationProtocol.ParseRegistrationUri(
                ClientRegistrationProtocol.RegistrationUri(pending.Bundle),
                TestData.Now.AddMinutes(11)));
        Assert.Contains("expired", error.Message);
    }

    [Fact]
    public void ImportBuildsSessionFromPendingKeysWithoutNetworkAccess()
    {
        var pending = TestData.PendingRegistration();
        var profile = TestData.ImportProfile(pending);

        var session = ClientRegistrationProtocol.ImportProfile(
            ClientRegistrationProtocol.ImportUri(profile),
            pending,
            TestData.Now.AddSeconds(1));

        Assert.Equal(pending.IdentityPrivateKey, session.IdentityPrivateKey);
        Assert.Equal(pending.WireGuardPrivateKey, session.WireGuardPrivateKey);
        Assert.Equal(pending.Bundle.Registration.ClientId, session.Client.NodeId);
        Assert.Equal(2, session.ControlPlaneUrls.Count);
        Assert.All(
            session.ControlPlaneUrls,
            uri => Assert.True(
                uri.Host == HeteroNetworkConstants.OverlayDnsName
                || uri.Host.StartsWith("10.250.", StringComparison.Ordinal)));
    }

    [Fact]
    public void ImportAllowsUnknownFields()
    {
        var pending = TestData.PendingRegistration();
        var root = JsonNode.Parse(JsonSerializer.Serialize(
            TestData.ImportProfile(pending),
            HeteroNetworkJson.Options))!.AsObject();
        root["future_top_level"] = new JsonObject
        {
            ["enabled"] = true,
        };
        root["registration"]!["cluster_policy"]!["future_policy_field"] = 17;

        var session = ClientRegistrationProtocol.ImportProfile(
            EncodeImport(root),
            pending,
            TestData.Now.AddSeconds(1));

        Assert.Equal(pending.Bundle.Registration.ClientId, session.Client.NodeId);
    }

    [Fact]
    public void ImportRejectsPendingKeyMismatch()
    {
        var pending = TestData.PendingRegistration();
        var profile = TestData.ImportProfile(pending);
        var mismatchedClient = profile.Registration.Client with
        {
            IdentityPublicKey = Convert.ToBase64String(
                Enumerable.Repeat((byte)99, 32).ToArray()),
        };
        var mismatched = profile with
        {
            Registration = profile.Registration with
            {
                Client = mismatchedClient,
            },
        };

        var error = Assert.Throws<ClientRegistrationException>(() =>
            ClientRegistrationProtocol.ImportProfile(
                ClientRegistrationProtocol.ImportUri(mismatched),
                pending,
                TestData.Now.AddSeconds(1)));
        Assert.Contains("pending client keys", error.Message);
    }

    [Fact]
    public void ImportRejectsExpiredProfile()
    {
        var pending = TestData.PendingRegistration();
        var profile = TestData.ImportProfile(
            pending,
            expiresAt: TestData.Now.AddSeconds(1));

        var error = Assert.Throws<ClientRegistrationException>(() =>
            ClientRegistrationProtocol.ImportProfile(
                ClientRegistrationProtocol.ImportUri(profile),
                pending,
                TestData.Now.AddSeconds(2)));
        Assert.Contains("expired", error.Message);
    }

    [Fact]
    public void ImportProfileContainsNoPrivateKeysAndRejectsInjectedOnes()
    {
        var pending = TestData.PendingRegistration();
        var profile = TestData.ImportProfile(pending);
        var encoded = JsonSerializer.Serialize(profile, HeteroNetworkJson.Options);
        Assert.DoesNotContain("identity_private_key", encoded);
        Assert.DoesNotContain("wireguard_private_key", encoded);
        Assert.DoesNotContain(
            Convert.ToBase64String(pending.IdentityPrivateKey),
            encoded);
        Assert.DoesNotContain(
            Convert.ToBase64String(pending.WireGuardPrivateKey),
            encoded);

        var root = JsonNode.Parse(encoded)!.AsObject();
        root["wireguard_private_key"] =
            Convert.ToBase64String(pending.WireGuardPrivateKey);
        var error = Assert.Throws<ClientRegistrationException>(() =>
            ClientRegistrationProtocol.ImportProfile(
                EncodeImport(root),
                pending,
                TestData.Now.AddSeconds(1)));
        Assert.Contains("must not contain private key", error.Message);
    }

    [Theory]
    [InlineData("WIREGUARD-PRIVATE-KEY")]
    [InlineData("identityPrivateKey")]
    [InlineData("future_private_key")]
    public void ImportRejectsPrivateKeyFieldNameVariants(string fieldName)
    {
        var pending = TestData.PendingRegistration();
        var root = JsonNode.Parse(JsonSerializer.Serialize(
            TestData.ImportProfile(pending),
            HeteroNetworkJson.Options))!.AsObject();
        root[fieldName] = Convert.ToBase64String(pending.WireGuardPrivateKey);

        var error = Assert.Throws<ClientRegistrationException>(() =>
            ClientRegistrationProtocol.ImportProfile(
                EncodeImport(root),
                pending,
                TestData.Now.AddSeconds(1)));
        Assert.Contains("must not contain private key", error.Message);
    }

    [Theory]
    [InlineData("heteronetwork://user@import?profile=e30")]
    [InlineData("heteronetwork://import:1234?profile=e30")]
    public void ImportRejectsAuthorityVariants(string uri)
    {
        var pending = TestData.PendingRegistration();

        Assert.Throws<ClientRegistrationException>(() =>
            ClientRegistrationProtocol.ImportProfile(uri, pending, TestData.Now));
    }

    [Theory]
    [InlineData("10.1.2.3:51820", EndpointCandidateKind.PublicUdp)]
    [InlineData("198.51.100.20:51820", EndpointCandidateKind.PublicUdp)]
    [InlineData("163.220.236.51:51820", EndpointCandidateKind.StunReflexive)]
    [InlineData("[fd00::1]:51820", EndpointCandidateKind.Ipv6)]
    public void ImportRejectsNonGlobalWireGuardCandidates(
        string address,
        EndpointCandidateKind kind)
    {
        var pending = TestData.PendingRegistration();
        var candidate = new EndpointCandidate(
            "node-gateway",
            kind,
            address,
            TestData.Now,
            100,
            1,
            "test");
        var profile = TestData.ImportProfile(pending, [candidate]);

        var error = Assert.Throws<ClientRegistrationException>(() =>
            ClientRegistrationProtocol.ImportProfile(
                ClientRegistrationProtocol.ImportUri(profile),
                pending,
                TestData.Now.AddSeconds(1)));
        Assert.Contains("globally routable", error.Message);
    }

    [Fact]
    public void ImportAcceptsGlobalIpv6PublicUdpCandidate()
    {
        var pending = TestData.PendingRegistration();
        var candidate = new EndpointCandidate(
            "node-gateway",
            EndpointCandidateKind.PublicUdp,
            "[2606:4700:4700::1111]:51820",
            TestData.Now,
            100,
            1,
            "test");
        var profile = TestData.ImportProfile(pending, [candidate]);

        var session = ClientRegistrationProtocol.ImportProfile(
            ClientRegistrationProtocol.ImportUri(profile),
            pending,
            TestData.Now.AddSeconds(1));

        Assert.Equal(
            "[2606:4700:4700::1111]:51820",
            TunnelProfile.FromSession(session).GatewayEndpoint);
    }

    [Theory]
    [InlineData("https://console.heteronetwork.internal:9781")]
    [InlineData("http://163.220.236.51:19088")]
    [InlineData("http://10.249.0.4:19088")]
    [InlineData("http://[fd00::1]:19088")]
    [InlineData("http://localhost:19088")]
    public void ImportRejectsManagementUrlsOutsidePrivateOverlay(string managementUrl)
    {
        var pending = TestData.PendingRegistration();
        var profile = TestData.ImportProfile(
            pending,
            managementUrls: [managementUrl]);

        var error = Assert.Throws<ClientRegistrationException>(() =>
            ClientRegistrationProtocol.ImportProfile(
                ClientRegistrationProtocol.ImportUri(profile),
                pending,
                TestData.Now.AddSeconds(1)));
        Assert.Contains("private VPN overlay", error.Message);
    }

    private static string EncodeRegistration(ClientRegistrationBundle bundle)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(
            bundle,
            HeteroNetworkJson.Options);
        return $"heteronetwork://register?request={Base64Url(json)}";
    }

    private static string EncodeImport(JsonNode profile)
    {
        var json = Encoding.UTF8.GetBytes(profile.ToJsonString(
            HeteroNetworkJson.Options));
        return $"heteronetwork://import?profile={Base64Url(json)}";
    }

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeQueryValue(string value, string name)
    {
        var uri = new Uri(value);
        var component = uri.Query.TrimStart('?').Split('=', 2);
        Assert.Equal(name, component[0]);
        var standard = component[1].Replace('-', '+').Replace('_', '/');
        standard = standard.PadRight(
            standard.Length + ((4 - standard.Length % 4) % 4),
            '=');
        return Convert.FromBase64String(standard);
    }
}
