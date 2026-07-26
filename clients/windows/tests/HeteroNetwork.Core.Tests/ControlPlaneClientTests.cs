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
            new Uri("https://retired.example:8443"),
            new Uri("https://also-retired.example:8443"),
        ];
        var livePeerMap = storedSession.PeerMap with
        {
            BootstrapEndpoints =
            [
                new BootstrapEndpoint(
                    "https://active.example:8443",
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

        Assert.Equal(["retired.example"], requestedHosts);
        Assert.Equal(
            new Uri("https://active.example:8443"),
            Assert.Single(refreshed.ControlPlaneUrls));
        Assert.DoesNotContain(
            refreshed.ControlPlaneUrls,
            uri => uri.Host == "retired.example" || uri.Host == "also-retired.example");
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
