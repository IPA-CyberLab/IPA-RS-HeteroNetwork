using System.Net;
using System.Net.Sockets;

namespace HeteroNetwork.Core;

public sealed class TunnelProfileException(string message) : Exception(message);

public sealed record TunnelProfile(
    string ClientAddress,
    string GatewayNodeId,
    string GatewayVpnIp,
    string GatewayWireGuardPublicKey,
    string GatewayEndpoint,
    IReadOnlyList<string> AllowedIps)
{
    public static TunnelProfile FromSession(ClientSession session, int gatewayIndex = 0)
    {
        if (!IPAddress.TryParse(session.Client.VpnIp, out var clientIp))
        {
            throw new TunnelProfileException("The assigned client VPN address is invalid.");
        }

        if (gatewayIndex < 0 || gatewayIndex >= session.PeerMap.Peers.Count)
        {
            throw new TunnelProfileException(
                $"The client peer map must contain at least one gateway; received "
                + $"{session.PeerMap.Peers.Count}.");
        }

        var gateway = session.PeerMap.Peers[gatewayIndex];
        if (!TryDecodeKey(gateway.WireGuardPublicKey))
        {
            throw new TunnelProfileException(
                "The selected gateway WireGuard key is invalid.");
        }

        var endpoint = PreferredEndpoint(gateway.EndpointCandidates)
            ?? throw new TunnelProfileException(
                "The selected gateway has no usable public endpoint.");
        if (!IsValidEndpoint(endpoint.Address))
        {
            throw new TunnelProfileException(
                "The selected gateway has no usable public endpoint.");
        }

        if (!IPAddress.TryParse(gateway.VpnIp, out var gatewayIp))
        {
            throw new TunnelProfileException(
                "The gateway advertised an invalid VPN address.");
        }

        var clientPrefix = clientIp.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        var gatewayPrefix = gatewayIp.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        var routes = new[] { $"{gateway.VpnIp}/{gatewayPrefix}" }
            .Concat(gateway.Routes.Select(route => route.Cidr));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var allowedIps = new List<string>();
        foreach (var route in routes)
        {
            if (!IsSafeCidr(route))
            {
                throw new TunnelProfileException(
                    $"The gateway advertised an invalid route: {route}.");
            }

            if (seen.Add(route))
            {
                allowedIps.Add(route);
            }
        }

        return new TunnelProfile(
            $"{session.Client.VpnIp}/{clientPrefix}",
            gateway.NodeId,
            gateway.VpnIp,
            gateway.WireGuardPublicKey,
            endpoint.Address,
            allowedIps);
    }

    public static EndpointCandidate? PreferredEndpoint(
        IEnumerable<EndpointCandidate> candidates)
    {
        return candidates
            .Where(candidate => candidate.Kind is EndpointCandidateKind.Ipv6
                or EndpointCandidateKind.PublicUdp
                or EndpointCandidateKind.StunReflexive)
            .OrderBy(candidate => candidate.Kind switch
            {
                EndpointCandidateKind.Ipv6 => 0,
                EndpointCandidateKind.PublicUdp => 1,
                EndpointCandidateKind.StunReflexive => 2,
                _ => 3,
            })
            .ThenBy(candidate => candidate.Cost)
            .ThenByDescending(candidate => candidate.Priority)
            .ThenBy(candidate => candidate.Address, StringComparer.Ordinal)
            .FirstOrDefault();
    }

    private static bool TryDecodeKey(string encoded)
    {
        try
        {
            return Convert.FromBase64String(encoded).Length == 32
                && encoded.Length == 44;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsSafeCidr(string value)
    {
        var parts = value.Split('/');
        if (parts.Length != 2
            || !IPAddress.TryParse(parts[0], out var address)
            || !byte.TryParse(parts[1], out var prefix))
        {
            return false;
        }

        var maximum = address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        return prefix > 0 && prefix <= maximum;
    }

    private static bool IsValidEndpoint(string value)
    {
        return IPEndPoint.TryParse(value, out var endpoint)
            && endpoint.Port > 0
            && !endpoint.Address.Equals(IPAddress.Any)
            && !endpoint.Address.Equals(IPAddress.IPv6Any);
    }
}
