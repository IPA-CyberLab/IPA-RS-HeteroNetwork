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
                "198.51.100.10:51820",
                Now,
                100,
                1,
                "interface_scan"),
            new EndpointCandidate(
                gatewayId,
                EndpointCandidateKind.Ipv6,
                "[2001:db8::10]:51820",
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
            [new Uri("https://cp-a.example:8443")],
            client,
            new PeerMap("cluster-a", [gateway], [], Now),
            Now);
    }
}
