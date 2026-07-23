using System.Text.Json.Serialization;

namespace HeteroNetwork.Core;

public static class HeteroNetworkConstants
{
    public const int SessionSchemaVersion = 1;
    public const string OverlayDnsName = "console.heteronetwork.internal";
    public const int OverlayWebUiPort = 9781;
    public static readonly Uri OverlayWebUiUri =
        new($"http://{OverlayDnsName}:{OverlayWebUiPort}/ui/");
}

[JsonConverter(typeof(JsonStringEnumConverter<BootstrapEndpointKind>))]
public enum BootstrapEndpointKind
{
    [JsonStringEnumMemberName("control_plane")]
    ControlPlane,
    [JsonStringEnumMemberName("signal")]
    Signal,
    [JsonStringEnumMemberName("stun")]
    Stun,
    [JsonStringEnumMemberName("relay")]
    Relay,
    [JsonStringEnumMemberName("web_ui")]
    WebUi,
}

public sealed record BootstrapEndpoint(
    [property: JsonPropertyName("url")] string Url,
    [property: JsonPropertyName("kind")] BootstrapEndpointKind Kind);

public sealed record TokenPolicy(
    [property: JsonPropertyName("allow_join")] bool AllowJoin,
    [property: JsonPropertyName("allow_relay")] bool AllowRelay,
    [property: JsonPropertyName("allowed_routes")] IReadOnlyList<string> AllowedRoutes,
    [property: JsonPropertyName("allowed_tags")] IReadOnlyList<string> AllowedTags,
    [property: JsonPropertyName("max_token_uses")] uint? MaxTokenUses);

public sealed record JoinTokenClaims
{
    [JsonPropertyName("cluster_id")]
    public required string ClusterId { get; init; }

    [JsonPropertyName("bootstrap_endpoints")]
    public required IReadOnlyList<BootstrapEndpoint> BootstrapEndpoints { get; init; }

    // Keep the exact signed RFC 3339 representation. Reformatting a timestamp,
    // including trimming sub-microsecond precision, invalidates the token.
    [JsonPropertyName("expires_at")]
    public required string EncodedExpiresAt { get; init; }

    [JsonPropertyName("not_before")]
    public required string EncodedNotBefore { get; init; }

    [JsonIgnore]
    public DateTimeOffset ExpiresAt => HeteroNetworkJson.ParseRfc3339(EncodedExpiresAt);

    [JsonIgnore]
    public DateTimeOffset NotBefore => HeteroNetworkJson.ParseRfc3339(EncodedNotBefore);

    [JsonPropertyName("role")]
    public required string Role { get; init; }

    [JsonPropertyName("tags")]
    public required IReadOnlyList<string> Tags { get; init; }

    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    [JsonPropertyName("key_id")]
    public required string KeyId { get; init; }

    [JsonPropertyName("policy")]
    public required TokenPolicy Policy { get; init; }

    [JsonPropertyName("nonce")]
    public required string Nonce { get; init; }
}

public sealed record SignedJoinToken(
    [property: JsonPropertyName("claims")] JoinTokenClaims Claims,
    [property: JsonPropertyName("signature")] string Signature);

[JsonConverter(typeof(JsonStringEnumConverter<EndpointCandidateKind>))]
public enum EndpointCandidateKind
{
    [JsonStringEnumMemberName("public_udp")]
    PublicUdp,
    [JsonStringEnumMemberName("ipv6")]
    Ipv6,
    [JsonStringEnumMemberName("stun_reflexive")]
    StunReflexive,
    [JsonStringEnumMemberName("local_udp")]
    LocalUdp,
    [JsonStringEnumMemberName("relay")]
    Relay,
}

public sealed record EndpointCandidate(
    [property: JsonPropertyName("node_id")] string NodeId,
    [property: JsonPropertyName("kind")] EndpointCandidateKind Kind,
    [property: JsonPropertyName("addr")] string Address,
    [property: JsonPropertyName("observed_at")] DateTimeOffset ObservedAt,
    [property: JsonPropertyName("priority")] ushort Priority,
    [property: JsonPropertyName("cost")] uint Cost,
    [property: JsonPropertyName("source")] string Source);

public sealed record Route(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("cidr")] string Cidr,
    [property: JsonPropertyName("advertised_by")] string AdvertisedBy,
    [property: JsonPropertyName("via")] string? Via,
    [property: JsonPropertyName("metric")] uint Metric,
    [property: JsonPropertyName("tags")] IReadOnlyList<string> Tags);

public sealed record NodeRecord(
    [property: JsonPropertyName("node_id")] string NodeId,
    [property: JsonPropertyName("cluster_id")] string ClusterId,
    [property: JsonPropertyName("vpn_ip")] string VpnIp,
    [property: JsonPropertyName("identity_public_key")] string IdentityPublicKey,
    [property: JsonPropertyName("wireguard_public_key")] string WireGuardPublicKey,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("tags")] IReadOnlyList<string> Tags,
    [property: JsonPropertyName("endpoint_candidates")] IReadOnlyList<EndpointCandidate> EndpointCandidates,
    [property: JsonPropertyName("routes")] IReadOnlyList<Route> Routes,
    [property: JsonPropertyName("registered_at")] DateTimeOffset RegisteredAt);

public sealed record PeerMap(
    [property: JsonPropertyName("cluster_id")] string ClusterId,
    [property: JsonPropertyName("peers")] IReadOnlyList<NodeRecord> Peers,
    [property: JsonPropertyName("bootstrap_endpoints")] IReadOnlyList<BootstrapEndpoint> BootstrapEndpoints,
    [property: JsonPropertyName("generated_at")] DateTimeOffset GeneratedAt);

public sealed record RegisterClientRequest(
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("identity_public_key")] string IdentityPublicKey,
    [property: JsonPropertyName("wireguard_public_key")] string WireGuardPublicKey);

public sealed record JoinClientRequest(
    [property: JsonPropertyName("token")] SignedJoinToken Token,
    [property: JsonPropertyName("registration")] RegisterClientRequest Registration);

public sealed record RegisterClientResponse(
    [property: JsonPropertyName("client")] NodeRecord Client,
    [property: JsonPropertyName("peer_map")] PeerMap PeerMap);

public enum ClientRequestKind
{
    PeerMap,
    Remove,
}

public sealed record ClientRequestSignature(
    [property: JsonPropertyName("signed_at")] DateTimeOffset SignedAt,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("signature")] string Signature);

public sealed record ClientControlRequest(
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("active_gateway_node_id")] string? ActiveGatewayNodeId,
    [property: JsonPropertyName("request_signature")] ClientRequestSignature RequestSignature);

public sealed record RemoveClientResponse(
    [property: JsonPropertyName("client")] NodeRecord Client,
    [property: JsonPropertyName("removed_at")] DateTimeOffset RemovedAt);

public sealed class ClientSession
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; } = HeteroNetworkConstants.SessionSchemaVersion;

    [JsonPropertyName("identity_private_key")]
    public required byte[] IdentityPrivateKey { get; init; }

    [JsonPropertyName("wireguard_private_key")]
    public required byte[] WireGuardPrivateKey { get; init; }

    [JsonPropertyName("control_plane_urls")]
    public required List<Uri> ControlPlaneUrls { get; set; }

    [JsonPropertyName("client")]
    public required NodeRecord Client { get; init; }

    [JsonPropertyName("peer_map")]
    public required PeerMap PeerMap { get; set; }

    [JsonPropertyName("selected_gateway_node_id")]
    public string? SelectedGatewayNodeId { get; set; }

    [JsonPropertyName("enrolled_at")]
    public DateTimeOffset EnrolledAt { get; init; }

    [JsonPropertyName("refreshed_at")]
    public DateTimeOffset RefreshedAt { get; set; }

    public static ClientSession Create(
        ClientKeyMaterial keys,
        IEnumerable<Uri> controlPlaneUrls,
        NodeRecord client,
        PeerMap peerMap,
        DateTimeOffset now)
    {
        return new ClientSession
        {
            IdentityPrivateKey = keys.IdentityPrivateKey.ToArray(),
            WireGuardPrivateKey = keys.WireGuardPrivateKey.ToArray(),
            ControlPlaneUrls = controlPlaneUrls.ToList(),
            Client = client,
            PeerMap = peerMap,
            SelectedGatewayNodeId = peerMap.Peers.FirstOrDefault()?.NodeId,
            EnrolledAt = now,
            RefreshedAt = now,
        };
    }
}
