import Foundation

public enum BootstrapEndpointKind: String, Codable, Sendable {
    case controlPlane = "control_plane"
    case signal
    case stun
    case relay
    case webUi = "web_ui"
}

public struct BootstrapEndpoint: Codable, Equatable, Sendable {
    public let url: String
    public let kind: BootstrapEndpointKind

    public init(url: String, kind: BootstrapEndpointKind) {
        self.url = url
        self.kind = kind
    }
}

public struct TokenPolicy: Codable, Equatable, Sendable {
    public let allowJoin: Bool
    public let allowRelay: Bool
    public let allowedRoutes: [String]
    public let allowedTags: [String]
    public let maxTokenUses: UInt32?

    public init(
        allowJoin: Bool,
        allowRelay: Bool,
        allowedRoutes: [String],
        allowedTags: [String],
        maxTokenUses: UInt32?
    ) {
        self.allowJoin = allowJoin
        self.allowRelay = allowRelay
        self.allowedRoutes = allowedRoutes
        self.allowedTags = allowedTags
        self.maxTokenUses = maxTokenUses
    }

    enum CodingKeys: String, CodingKey {
        case allowJoin = "allow_join"
        case allowRelay = "allow_relay"
        case allowedRoutes = "allowed_routes"
        case allowedTags = "allowed_tags"
        case maxTokenUses = "max_token_uses"
    }
}

public struct JoinTokenClaims: Codable, Equatable, Sendable {
    public let clusterID: String
    public let bootstrapEndpoints: [BootstrapEndpoint]
    public let expiresAt: Date
    public let notBefore: Date
    public let role: String
    public let tags: [String]
    public let issuer: String
    public let keyID: String
    public let policy: TokenPolicy
    public let nonce: String

    public init(
        clusterID: String,
        bootstrapEndpoints: [BootstrapEndpoint],
        expiresAt: Date,
        notBefore: Date,
        role: String,
        tags: [String],
        issuer: String,
        keyID: String,
        policy: TokenPolicy,
        nonce: String
    ) {
        self.clusterID = clusterID
        self.bootstrapEndpoints = bootstrapEndpoints
        self.expiresAt = expiresAt
        self.notBefore = notBefore
        self.role = role
        self.tags = tags
        self.issuer = issuer
        self.keyID = keyID
        self.policy = policy
        self.nonce = nonce
    }

    enum CodingKeys: String, CodingKey {
        case clusterID = "cluster_id"
        case bootstrapEndpoints = "bootstrap_endpoints"
        case expiresAt = "expires_at"
        case notBefore = "not_before"
        case role, tags, issuer, policy, nonce
        case keyID = "key_id"
    }
}

public struct SignedJoinToken: Codable, Equatable, Sendable {
    public let claims: JoinTokenClaims
    public let signature: String

    public init(claims: JoinTokenClaims, signature: String) {
        self.claims = claims
        self.signature = signature
    }
}

public enum EndpointCandidateKind: String, Codable, Sendable {
    case publicUDP = "public_udp"
    case ipv6
    case stunReflexive = "stun_reflexive"
    case localUDP = "local_udp"
    case relay
}

public struct EndpointCandidate: Codable, Equatable, Sendable {
    public let nodeID: String
    public let kind: EndpointCandidateKind
    public let address: String
    public let observedAt: Date
    public let priority: UInt16
    public let cost: UInt32
    public let source: String

    public init(
        nodeID: String,
        kind: EndpointCandidateKind,
        address: String,
        observedAt: Date,
        priority: UInt16,
        cost: UInt32,
        source: String
    ) {
        self.nodeID = nodeID
        self.kind = kind
        self.address = address
        self.observedAt = observedAt
        self.priority = priority
        self.cost = cost
        self.source = source
    }

    enum CodingKeys: String, CodingKey {
        case nodeID = "node_id"
        case kind
        case address = "addr"
        case observedAt = "observed_at"
        case priority, cost, source
    }
}

public struct Route: Codable, Equatable, Sendable {
    public let id: String
    public let cidr: String
    public let advertisedBy: String
    public let via: String?
    public let metric: UInt32
    public let tags: [String]

    public init(
        id: String,
        cidr: String,
        advertisedBy: String,
        via: String?,
        metric: UInt32,
        tags: [String]
    ) {
        self.id = id
        self.cidr = cidr
        self.advertisedBy = advertisedBy
        self.via = via
        self.metric = metric
        self.tags = tags
    }

    enum CodingKeys: String, CodingKey {
        case id, cidr, via, metric, tags
        case advertisedBy = "advertised_by"
    }
}

public struct NodeRecord: Codable, Equatable, Sendable {
    public let nodeID: String
    public let clusterID: String
    public let vpnIP: String
    public let identityPublicKey: String
    public let wireGuardPublicKey: String
    public let role: String
    public let tags: [String]
    public let endpointCandidates: [EndpointCandidate]
    public let routes: [Route]
    public let registeredAt: Date

    public init(
        nodeID: String,
        clusterID: String,
        vpnIP: String,
        identityPublicKey: String,
        wireGuardPublicKey: String,
        role: String,
        tags: [String],
        endpointCandidates: [EndpointCandidate],
        routes: [Route],
        registeredAt: Date
    ) {
        self.nodeID = nodeID
        self.clusterID = clusterID
        self.vpnIP = vpnIP
        self.identityPublicKey = identityPublicKey
        self.wireGuardPublicKey = wireGuardPublicKey
        self.role = role
        self.tags = tags
        self.endpointCandidates = endpointCandidates
        self.routes = routes
        self.registeredAt = registeredAt
    }

    enum CodingKeys: String, CodingKey {
        case nodeID = "node_id"
        case clusterID = "cluster_id"
        case vpnIP = "vpn_ip"
        case identityPublicKey = "identity_public_key"
        case wireGuardPublicKey = "wireguard_public_key"
        case role, tags, routes
        case endpointCandidates = "endpoint_candidates"
        case registeredAt = "registered_at"
    }
}

public struct PeerMap: Codable, Equatable, Sendable {
    public let clusterID: String
    public let peers: [NodeRecord]
    public let bootstrapEndpoints: [BootstrapEndpoint]
    public let generatedAt: Date

    public init(
        clusterID: String,
        peers: [NodeRecord],
        bootstrapEndpoints: [BootstrapEndpoint],
        generatedAt: Date
    ) {
        self.clusterID = clusterID
        self.peers = peers
        self.bootstrapEndpoints = bootstrapEndpoints
        self.generatedAt = generatedAt
    }

    enum CodingKeys: String, CodingKey {
        case clusterID = "cluster_id"
        case peers
        case bootstrapEndpoints = "bootstrap_endpoints"
        case generatedAt = "generated_at"
    }
}

public struct RegisterClientRequest: Codable, Equatable, Sendable {
    public let clientID: String
    public let identityPublicKey: String
    public let wireGuardPublicKey: String

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id"
        case identityPublicKey = "identity_public_key"
        case wireGuardPublicKey = "wireguard_public_key"
    }
}

public struct JoinClientRequest: Codable, Equatable, Sendable {
    public let token: SignedJoinToken
    public let registration: RegisterClientRequest
}

public struct RegisterClientResponse: Decodable, Sendable {
    public let client: NodeRecord
    public let peerMap: PeerMap

    enum CodingKeys: String, CodingKey {
        case client
        case peerMap = "peer_map"
    }
}

public enum ClientRequestKind: String, Sendable {
    case peerMap = "peer_map"
    case remove
}

public struct ClientRequestSignature: Codable, Equatable, Sendable {
    public let signedAt: Date
    public let nonce: String
    public let signature: String

    enum CodingKeys: String, CodingKey {
        case signedAt = "signed_at"
        case nonce, signature
    }
}

public struct ClientControlRequest: Codable, Equatable, Sendable {
    public let clientID: String
    public let activeGatewayNodeID: String?
    public let requestSignature: ClientRequestSignature

    public init(
        clientID: String,
        activeGatewayNodeID: String? = nil,
        requestSignature: ClientRequestSignature
    ) {
        self.clientID = clientID
        self.activeGatewayNodeID = activeGatewayNodeID
        self.requestSignature = requestSignature
    }

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id"
        case activeGatewayNodeID = "active_gateway_node_id"
        case requestSignature = "request_signature"
    }
}

public struct RemoveClientResponse: Decodable, Sendable {
    public let client: NodeRecord
    public let removedAt: Date

    enum CodingKeys: String, CodingKey {
        case client
        case removedAt = "removed_at"
    }
}

public struct ClientSession: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let identityPrivateKey: Data
    public let wireGuardPrivateKey: Data
    public var controlPlaneURLs: [URL]
    public let client: NodeRecord
    public var peerMap: PeerMap
    public var selectedGatewayNodeID: String?
    public let enrolledAt: Date
    public var refreshedAt: Date

    public init(
        identityPrivateKey: Data,
        wireGuardPrivateKey: Data,
        controlPlaneURLs: [URL],
        client: NodeRecord,
        peerMap: PeerMap,
        enrolledAt: Date
    ) {
        schemaVersion = HeteroNetworkConstants.sessionSchemaVersion
        self.identityPrivateKey = identityPrivateKey
        self.wireGuardPrivateKey = wireGuardPrivateKey
        self.controlPlaneURLs = controlPlaneURLs
        self.client = client
        self.peerMap = peerMap
        selectedGatewayNodeID = peerMap.peers.first?.nodeID
        self.enrolledAt = enrolledAt
        refreshedAt = enrolledAt
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case identityPrivateKey = "identity_private_key"
        case wireGuardPrivateKey = "wireguard_private_key"
        case controlPlaneURLs = "control_plane_urls"
        case client, peerMap, selectedGatewayNodeID, enrolledAt, refreshedAt
    }
}
