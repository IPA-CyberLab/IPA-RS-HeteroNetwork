using HeteroNetwork.Core;

namespace HeteroNetwork.Core.Tests;

public sealed class TunnelProfileTests
{
    [Fact]
    public void RoutesOnlyThroughPreferredPublicGateway()
    {
        var session = TestData.Session(["100.96.0.3/32", "10.42.0.0/16"]);

        var profile = TunnelProfile.FromSession(session);

        Assert.Equal("100.96.0.4/32", profile.ClientAddress);
        Assert.Equal("100.96.0.1", profile.GatewayVpnIp);
        Assert.Equal("[2001:db8::10]:51820", profile.GatewayEndpoint);
        Assert.Equal(
            ["100.96.0.1/32", "100.96.0.3/32", "10.42.0.0/16"],
            profile.AllowedIps);
    }

    [Fact]
    public void RejectsDefaultRoute()
    {
        var error = Assert.Throws<TunnelProfileException>(
            () => TunnelProfile.FromSession(TestData.Session(["0.0.0.0/0"])));
        Assert.Contains("invalid route", error.Message);
    }

    [Fact]
    public void RejectsLocalAndRelayOnlyEndpoints()
    {
        var session = TestData.Session(
            [],
            [
                new EndpointCandidate(
                    "node-gateway",
                    EndpointCandidateKind.LocalUdp,
                    "192.168.1.10:51820",
                    TestData.Now,
                    100,
                    1,
                    "interface_scan"),
                new EndpointCandidate(
                    "node-gateway",
                    EndpointCandidateKind.Relay,
                    "198.51.100.20:51820",
                    TestData.Now,
                    100,
                    1,
                    "relay"),
            ]);

        var error = Assert.Throws<TunnelProfileException>(
            () => TunnelProfile.FromSession(session));
        Assert.Contains("no usable public endpoint", error.Message);
    }

    [Fact]
    public void SessionRoundTripsThroughCurrentUserDpapi()
    {
        var testDirectory = Path.Combine(
            Path.GetTempPath(),
            $"heteronetwork-windows-tests-{Guid.NewGuid():N}");
        var path = Path.Combine(testDirectory, "session.dpapi");
        try
        {
            var store = new ClientSessionStore(path);
            var session = TestData.Session([]);
            store.Save(session);

            var loaded = Assert.IsType<ClientSession>(store.Load());
            Assert.Equal(session.Client.NodeId, loaded.Client.NodeId);
            Assert.Equal(session.IdentityPrivateKey, loaded.IdentityPrivateKey);
            Assert.NotEqual(
                Convert.ToBase64String(session.IdentityPrivateKey),
                Convert.ToBase64String(File.ReadAllBytes(path)));
        }
        finally
        {
            if (Directory.Exists(testDirectory))
            {
                Directory.Delete(testDirectory, true);
            }
        }
    }
}
