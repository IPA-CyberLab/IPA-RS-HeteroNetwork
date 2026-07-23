using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace HeteroNetwork.Core;

public sealed class ControlPlaneException(string message) : Exception(message);

public sealed class ControlPlaneClient : IDisposable
{
    private readonly HttpClient httpClient;
    private readonly bool ownsClient;

    public ControlPlaneClient(HttpClient? httpClient = null)
    {
        ownsClient = httpClient is null;
        this.httpClient = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10),
        };
    }

    public async Task<ClientSession> JoinAsync(
        SignedJoinToken token,
        ClientKeyMaterial keys,
        CancellationToken cancellationToken = default)
    {
        var managementUrls = EnrollmentParser.ManagementUrls(token);
        if (managementUrls.Count == 0)
        {
            throw new ControlPlaneException("No control plane endpoint is available.");
        }

        var registration = new RegisterClientRequest(
            keys.ClientId,
            keys.IdentityPublicKey,
            keys.WireGuardPublicKey);
        var joinRequest = new JoinClientRequest(token, registration);
        RegisterClientResponse response;
        try
        {
            response = await PerformFailoverAsync<JoinClientRequest, RegisterClientResponse>(
                managementUrls,
                "/v1/clients/join",
                HttpMethod.Post,
                _ => joinRequest,
                cancellationToken).ConfigureAwait(false);
        }
        catch (ControlPlaneException joinError)
        {
            try
            {
                response = await GetConfigurationAsync(
                    managementUrls,
                    registration.ClientId,
                    keys,
                    null,
                    cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                throw joinError;
            }
        }

        Validate(response, registration);
        return ClientSession.Create(
            keys,
            managementUrls,
            response.Client,
            response.PeerMap,
            DateTimeOffset.UtcNow);
    }

    public async Task<ClientSession> RefreshAsync(
        ClientSession storedSession,
        CancellationToken cancellationToken = default)
    {
        var keys = new ClientKeyMaterial(
            storedSession.IdentityPrivateKey,
            storedSession.WireGuardPrivateKey);
        var response = await GetConfigurationAsync(
            storedSession.ControlPlaneUrls,
            storedSession.Client.NodeId,
            keys,
            storedSession.SelectedGatewayNodeId,
            cancellationToken).ConfigureAwait(false);
        var registration = new RegisterClientRequest(
            storedSession.Client.NodeId,
            storedSession.Client.IdentityPublicKey,
            storedSession.Client.WireGuardPublicKey);
        Validate(response, registration);
        if (response.Client.ClusterId != storedSession.Client.ClusterId)
        {
            throw new ControlPlaneException("The control plane returned an invalid response.");
        }

        storedSession.PeerMap = response.PeerMap;
        storedSession.SelectedGatewayNodeId = response.PeerMap.Peers.FirstOrDefault()?.NodeId;
        storedSession.ControlPlaneUrls = MergeManagementUrls(
            EnrollmentParser.ManagementUrls(response.PeerMap.BootstrapEndpoints),
            storedSession.ControlPlaneUrls);
        storedSession.RefreshedAt = DateTimeOffset.UtcNow;
        return storedSession;
    }

    public async Task RemoveAsync(
        ClientSession storedSession,
        CancellationToken cancellationToken = default)
    {
        var keys = new ClientKeyMaterial(
            storedSession.IdentityPrivateKey,
            storedSession.WireGuardPrivateKey);
        var path = $"/v1/clients/{Uri.EscapeDataString(storedSession.Client.NodeId)}";
        var response = await PerformFailoverAsync<ClientControlRequest, RemoveClientResponse>(
            storedSession.ControlPlaneUrls,
            path,
            HttpMethod.Delete,
            _ => new ClientControlRequest(
                storedSession.Client.NodeId,
                null,
                keys.Sign(storedSession.Client.NodeId, ClientRequestKind.Remove)),
            cancellationToken).ConfigureAwait(false);
        if (response.Client.NodeId != storedSession.Client.NodeId)
        {
            throw new ControlPlaneException("The control plane returned an invalid response.");
        }
    }

    public void Dispose()
    {
        if (ownsClient)
        {
            httpClient.Dispose();
        }
    }

    private Task<RegisterClientResponse> GetConfigurationAsync(
        IReadOnlyList<Uri> bases,
        string clientId,
        ClientKeyMaterial keys,
        string? activeGatewayNodeId,
        CancellationToken cancellationToken)
    {
        return PerformFailoverAsync<ClientControlRequest, RegisterClientResponse>(
            bases,
            "/v1/clients/peers/query",
            HttpMethod.Post,
            _ => new ClientControlRequest(
                clientId,
                activeGatewayNodeId,
                keys.Sign(
                    clientId,
                    ClientRequestKind.PeerMap,
                    activeGatewayNodeId)),
            cancellationToken);
    }

    private async Task<TResponse> PerformFailoverAsync<TRequest, TResponse>(
        IReadOnlyList<Uri> bases,
        string path,
        HttpMethod method,
        Func<Uri, TRequest> requestBody,
        CancellationToken cancellationToken)
    {
        if (bases.Count == 0)
        {
            throw new ControlPlaneException("No control plane endpoint is available.");
        }

        var failures = new List<string>();
        ControlPlaneException? lastRejection = null;
        foreach (var baseUri in bases)
        {
            try
            {
                var endpoint = EndpointUri(baseUri, path);
                using var request = new HttpRequestMessage(method, endpoint)
                {
                    Content = JsonContent.Create(
                        requestBody(baseUri),
                        options: HeteroNetworkJson.Options),
                };
                request.Headers.Accept.ParseAdd("application/json");
                using var endpointTimeout =
                    CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                endpointTimeout.CancelAfter(TimeSpan.FromSeconds(10));
                using var response = await httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    endpointTimeout.Token).ConfigureAwait(false);
                var data = await ReadBoundedAsync(
                    response.Content,
                    1024 * 1024,
                    endpointTimeout.Token).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    var rejection = new ControlPlaneException(
                        $"Control plane rejected the request (HTTP {(int)response.StatusCode}): "
                        + ServerMessage(data));
                    lastRejection = rejection;
                    failures.Add($"{baseUri.Host}: HTTP {(int)response.StatusCode}");
                    continue;
                }

                try
                {
                    return JsonSerializer.Deserialize<TResponse>(
                            data,
                            HeteroNetworkJson.Options)
                        ?? throw new JsonException("The response was empty.");
                }
                catch (JsonException)
                {
                    failures.Add($"{baseUri.Host}: invalid JSON response");
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                failures.Add($"{baseUri.Host}: timed out");
            }
            catch (Exception error) when (error is HttpRequestException
                                          or IOException
                                          or ControlPlaneException)
            {
                failures.Add($"{baseUri.Host}: {error.Message}");
            }
        }

        if (lastRejection is not null)
        {
            throw lastRejection;
        }

        throw new ControlPlaneException(
            $"All control planes failed: {string.Join("; ", failures)}");
    }

    private static Uri EndpointUri(Uri baseUri, string path)
    {
        if (!baseUri.IsAbsoluteUri
            || (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps)
            || string.IsNullOrEmpty(baseUri.Host))
        {
            throw new ControlPlaneException("A control plane endpoint is invalid.");
        }

        var builder = new UriBuilder(baseUri)
        {
            Path = $"{baseUri.AbsolutePath.TrimEnd('/')}{path}",
            Query = string.Empty,
            Fragment = string.Empty,
        };
        return builder.Uri;
    }

    private static void Validate(
        RegisterClientResponse response,
        RegisterClientRequest registration)
    {
        if (response.Client.NodeId != registration.ClientId
            || response.Client.IdentityPublicKey != registration.IdentityPublicKey
            || response.Client.WireGuardPublicKey != registration.WireGuardPublicKey
            || response.Client.Role != "client"
            || response.PeerMap.ClusterId != response.Client.ClusterId)
        {
            throw new ControlPlaneException("The control plane returned an invalid response.");
        }
    }

    private static List<Uri> MergeManagementUrls(
        IEnumerable<Uri> discovered,
        IEnumerable<Uri> existing)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return discovered.Concat(existing)
            .Where(uri => seen.Add(uri.AbsoluteUri.TrimEnd('/')))
            .ToList();
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > maximumBytes)
        {
            throw new ControlPlaneException("The control plane response is too large.");
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return output.ToArray();
            }

            if (output.Length + read > maximumBytes)
            {
                throw new ControlPlaneException("The control plane response is too large.");
            }

            output.Write(buffer, 0, read);
        }
    }

    private static string ServerMessage(byte[] data)
    {
        if (data.Length == 0)
        {
            return "empty response";
        }

        try
        {
            using var document = JsonDocument.Parse(data);
            foreach (var key in new[] { "error", "message", "reason" })
            {
                if (document.RootElement.TryGetProperty(key, out var value)
                    && value.ValueKind == JsonValueKind.String)
                {
                    return (value.GetString() ?? string.Empty)[..Math.Min(
                        value.GetString()?.Length ?? 0,
                        512)];
                }
            }
        }
        catch (JsonException)
        {
            // Fall through to the bounded plain-text message.
        }

        return Encoding.UTF8.GetString(data.AsSpan(0, Math.Min(data.Length, 512)));
    }
}
