using System.Text;
using System.Text.Json;

namespace HeteroNetwork.Core;

public sealed class EnrollmentException(string message) : Exception(message);

public static class EnrollmentParser
{
    private const int MaximumTokenBytes = 64 * 1024;

    public static SignedJoinToken Parse(string input, DateTimeOffset? now = null)
    {
        var trimmed = input.Trim();
        if (trimmed.Length == 0)
        {
            throw new EnrollmentException("Enrollment link is required.");
        }

        byte[] tokenData;
        if (trimmed.StartsWith("heteronetwork://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
                || !uri.Scheme.Equals("heteronetwork", StringComparison.OrdinalIgnoreCase)
                || !uri.Host.Equals("enroll", StringComparison.OrdinalIgnoreCase))
            {
                throw new EnrollmentException("The enrollment link is invalid.");
            }

            var encoded = ParseQuery(uri.Query)
                .FirstOrDefault(item => item.Key.Equals("token", StringComparison.Ordinal))
                .Value;
            if (encoded is null || !TryDecodeBase64Url(encoded, out tokenData))
            {
                throw new EnrollmentException("The enrollment link is invalid.");
            }
        }
        else if (trimmed.StartsWith('{'))
        {
            tokenData = Encoding.UTF8.GetBytes(trimmed);
        }
        else
        {
            throw new EnrollmentException("The enrollment link is invalid.");
        }

        if (tokenData.Length > MaximumTokenBytes)
        {
            throw new EnrollmentException("The enrollment token is too large.");
        }

        SignedJoinToken token;
        try
        {
            token = JsonSerializer.Deserialize<SignedJoinToken>(
                    tokenData,
                    HeteroNetworkJson.Options)
                ?? throw new JsonException("The token was empty.");
            _ = token.Claims.ExpiresAt;
            _ = token.Claims.NotBefore;
        }
        catch (Exception error) when (error is JsonException or FormatException)
        {
            throw new EnrollmentException("The enrollment token is malformed.");
        }

        var current = now ?? DateTimeOffset.UtcNow;
        if (!token.Claims.Role.Equals("client", StringComparison.Ordinal))
        {
            throw new EnrollmentException("This token is not for a control-only client.");
        }

        if (token.Claims.NotBefore > current.AddSeconds(5))
        {
            throw new EnrollmentException("The enrollment token is not valid yet.");
        }

        if (token.Claims.ExpiresAt <= current)
        {
            throw new EnrollmentException("The enrollment token has expired.");
        }

        if (ManagementUrls(token).Count < 2)
        {
            throw new EnrollmentException(
                "The enrollment token does not contain redundant control planes.");
        }

        return token;
    }

    public static IReadOnlyList<Uri> ControlPlaneUrls(SignedJoinToken token) =>
        EndpointUrls(token.Claims.BootstrapEndpoints, [BootstrapEndpointKind.ControlPlane]);

    public static IReadOnlyList<Uri> ManagementUrls(SignedJoinToken token) =>
        EndpointUrls(
            token.Claims.BootstrapEndpoints,
            [BootstrapEndpointKind.WebUi, BootstrapEndpointKind.ControlPlane]);

    public static IReadOnlyList<Uri> ManagementUrls(IEnumerable<BootstrapEndpoint> endpoints) =>
        EndpointUrls(
            endpoints,
            [BootstrapEndpointKind.WebUi, BootstrapEndpointKind.ControlPlane]);

    private static IReadOnlyList<Uri> EndpointUrls(
        IEnumerable<BootstrapEndpoint> endpoints,
        IReadOnlyList<BootstrapEndpointKind> kinds)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var urls = new List<Uri>();
        foreach (var kind in kinds)
        {
            foreach (var endpoint in endpoints.Where(item => item.Kind == kind))
            {
                if (!Uri.TryCreate(endpoint.Url, UriKind.Absolute, out var uri)
                    || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                    || string.IsNullOrEmpty(uri.Host)
                    || !string.IsNullOrEmpty(uri.UserInfo)
                    || !string.IsNullOrEmpty(uri.Query)
                    || !string.IsNullOrEmpty(uri.Fragment))
                {
                    continue;
                }

                var canonical = uri.AbsoluteUri.TrimEnd('/');
                if (seen.Add(canonical))
                {
                    urls.Add(uri);
                }
            }
        }

        return urls;
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

    private static bool TryDecodeBase64Url(string value, out byte[] data)
    {
        var standard = value.Replace('-', '+').Replace('_', '/');
        standard = standard.PadRight(
            standard.Length + ((4 - (standard.Length % 4)) % 4),
            '=');
        try
        {
            data = Convert.FromBase64String(standard);
            return true;
        }
        catch (FormatException)
        {
            data = [];
            return false;
        }
    }
}
