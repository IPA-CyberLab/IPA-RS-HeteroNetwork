using System.Text.Json;
using HeteroNetwork.Core;

namespace HeteroNetwork.Core.Tests;

internal static class TestData
{
    public static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(1_784_550_896);

    public static SignedJoinToken Token(string role = "client") => new(
        new JoinTokenClaims
        {
            ClusterId = "cluster-a",
            BootstrapEndpoints =
            [
                new BootstrapEndpoint("https://cp-a.example:8443", BootstrapEndpointKind.ControlPlane),
                new BootstrapEndpoint("https://cp-b.example:8443", BootstrapEndpointKind.ControlPlane),
                new BootstrapEndpoint("https://gateway.example", BootstrapEndpointKind.WebUi),
            ],
            EncodedExpiresAt = Now.AddMinutes(10).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            EncodedNotBefore = Now.AddSeconds(-5).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            Role = role,
            Tags = [],
            Issuer = "node-issuer",
            KeyId = "client-enrollment",
            Policy = new TokenPolicy(true, false, [], [], 1),
            Nonce = "client-enrollment-test",
        },
        new string('A', 88));

    public static ClientSession Session(
        IReadOnlyList<string> routes,
        IReadOnlyList<EndpointCandidate>? suppliedCandidates = null)
    {
        const string gatewayId = "node-gateway";
        var candidates = suppliedCandidates ??
        [
            new EndpointCandidate(
                gatewayId,
                EndpointCandidateKind.PublicUdp,
                "163.220.236.51:51820",
                Now,
                100,
                1,
                "interface_scan"),
            new EndpointCandidate(
                gatewayId,
                EndpointCandidateKind.Ipv6,
                "[2606:4700:4700::1111]:51820",
                Now,
                10,
                100,
                "interface_scan"),
        ];
        var gateway = new NodeRecord(
            gatewayId,
            "cluster-a",
            "100.96.0.1",
            Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray()),
            Convert.ToBase64String(Enumerable.Repeat((byte)2, 32).ToArray()),
            "gateway",
            [],
            candidates,
            routes.Select((cidr, index) => new Route(
                $"route-{index}",
                cidr,
                gatewayId,
                gatewayId,
                10,
                [])).ToArray(),
            Now);
        var client = new NodeRecord(
            "node-client",
            "cluster-a",
            "100.96.0.4",
            Convert.ToBase64String(Enumerable.Repeat((byte)3, 32).ToArray()),
            Convert.ToBase64String(Enumerable.Repeat((byte)4, 32).ToArray()),
            "client",
            [],
            [],
            [],
            Now);
        return ClientSession.Create(
            new ClientKeyMaterial(
                Enumerable.Repeat((byte)5, 32).ToArray(),
                Enumerable.Repeat((byte)6, 32).ToArray()),
            [new Uri("http://10.250.0.4:19088")],
            client,
            new PeerMap("cluster-a", [gateway], [], Now),
            Now);
    }

    public static PendingClientRegistration PendingRegistration() =>
        ClientRegistrationProtocol.GenerateRequest(
            new ClientKeyMaterial(
                Enumerable.Repeat((byte)7, 32).ToArray(),
                Enumerable.Repeat((byte)9, 32).ToArray()),
            Now,
            TimeSpan.FromMinutes(10),
            Enumerable.Repeat((byte)3, 24).ToArray());

    public static ClientImportProfile ImportProfile(
        PendingClientRegistration? suppliedPending = null,
        IReadOnlyList<EndpointCandidate>? suppliedCandidates = null,
        IReadOnlyList<string>? managementUrls = null,
        string role = "client",
        DateTimeOffset? expiresAt = null)
    {
        var pending = suppliedPending ?? PendingRegistration();
        const string gatewayId = "node-gateway";
        var candidates = suppliedCandidates ??
        [
            new EndpointCandidate(
                gatewayId,
                EndpointCandidateKind.PublicUdp,
                "163.220.236.51:51820",
                Now,
                100,
                1,
                "interface_scan"),
        ];
        var client = new NodeRecord(
            pending.Bundle.Registration.ClientId,
            "cluster-a",
            "10.250.0.20",
            pending.Bundle.Registration.IdentityPublicKey,
            pending.Bundle.Registration.WireGuardPublicKey,
            role,
            [],
            [],
            [],
            Now);
        var gateway = new NodeRecord(
            gatewayId,
            "cluster-a",
            "10.250.0.4",
            Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray()),
            Convert.ToBase64String(Enumerable.Repeat((byte)2, 32).ToArray()),
            "edge",
            [],
            candidates,
            [],
            Now);
        var clusterPolicy = JsonDocument.Parse("{}").RootElement.Clone();
        return new ClientImportProfile
        {
            SchemaVersion = HeteroNetworkConstants.ClientRegistrationSchemaVersion,
            SponsorNodeId = "node-sponsor",
            Registration = new RegisterClientResponse(
                client,
                new PeerMap("cluster-a", [gateway], [], Now),
                clusterPolicy),
            ManagementUrls = managementUrls ??
            [
                "http://10.250.0.4:19088",
                "http://console.heteronetwork.internal",
            ],
            EncodedIssuedAt = Now.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            EncodedExpiresAt = (expiresAt ?? Now.AddMinutes(10))
                .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
        };
    }
}
