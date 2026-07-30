using System.Net;
using System.Net.Http.Json;
using HeteroNetwork.Core;

namespace HeteroNetwork.Core.Tests;

public sealed class ControlPlaneClientTests
{
    [Fact]
    public async Task RefreshReplacesRetiredControlPlanesWithLiveDirectory()
    {
        var storedSession = TestData.Session([]);
        storedSession.ControlPlaneUrls =
        [
            new Uri("http://10.250.0.10:19088"),
            new Uri("http://10.250.0.11:19088"),
        ];
        var livePeerMap = storedSession.PeerMap with
        {
            BootstrapEndpoints =
            [
                new BootstrapEndpoint(
                    "http://10.250.0.12:19088",
                    BootstrapEndpointKind.ControlPlane),
            ],
        };
        var requestedHosts = new List<string>();
        using var httpClient = new HttpClient(new StubHttpMessageHandler(request =>
        {
            requestedHosts.Add(request.RequestUri?.Host ?? string.Empty);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(
                    new RegisterClientResponse(storedSession.Client, livePeerMap),
                    options: HeteroNetworkJson.Options),
            };
        }));
        using var controlPlane = new ControlPlaneClient(httpClient);

        var refreshed = await controlPlane.RefreshAsync(storedSession);

        Assert.Equal(["10.250.0.10"], requestedHosts);
        Assert.Equal(
            new Uri("http://10.250.0.12:19088"),
            Assert.Single(refreshed.ControlPlaneUrls));
        Assert.DoesNotContain(
            refreshed.ControlPlaneUrls,
            uri => uri.Host == "10.250.0.10" || uri.Host == "10.250.0.11");
    }

    [Fact]
    public async Task RefreshNeverContactsPublicManagementEndpoint()
    {
        var storedSession = TestData.Session([]);
        storedSession.ControlPlaneUrls =
        [
            new Uri("https://163.220.236.51"),
            new Uri("http://8.8.8.8:19088"),
        ];
        var requestCount = 0;
        using var httpClient = new HttpClient(new StubHttpMessageHandler(_ =>
        {
            requestCount++;
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        using var controlPlane = new ControlPlaneClient(httpClient);

        var error = await Assert.ThrowsAsync<ControlPlaneException>(
            () => controlPlane.RefreshAsync(storedSession));

        Assert.Equal(0, requestCount);
        Assert.Contains("private VPN overlay", error.Message);
    }

    private sealed class StubHttpMessageHandler(
        Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(handler(request));
    }
}
