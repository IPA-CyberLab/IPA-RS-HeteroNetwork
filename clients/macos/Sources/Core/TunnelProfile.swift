import Darwin
import Foundation

public enum TunnelProfileError: LocalizedError, Equatable {
    case invalidClientAddress
    case invalidGatewayCount(Int)
    case missingGatewayEndpoint
    case invalidGatewayKey
    case invalidRoute(String)

    public var errorDescription: String? {
        switch self {
        case .invalidClientAddress: return "The assigned client VPN address is invalid."
        case .invalidGatewayCount(let count):
            return "The client peer map must contain at least one gateway; received \(count)."
        case .missingGatewayEndpoint: return "The selected gateway has no usable public endpoint."
        case .invalidGatewayKey: return "The selected gateway WireGuard key is invalid."
        case .invalidRoute(let route): return "The gateway advertised an invalid route: \(route)."
        }
    }
}

public struct TunnelProfile: Equatable, Sendable {
    public let clientAddress: String
    public let gatewayNodeID: String
    public let gatewayVPNIP: String
    public let gatewayWireGuardPublicKey: String
    public let gatewayEndpoint: String
    public let allowedIPs: [String]

    public init(session: ClientSession, gatewayIndex: Int = 0) throws {
        guard isIPAddress(session.client.vpnIP) else { throw TunnelProfileError.invalidClientAddress }
        guard session.peerMap.peers.indices.contains(gatewayIndex) else {
            throw TunnelProfileError.invalidGatewayCount(session.peerMap.peers.count)
        }
        let gateway = session.peerMap.peers[gatewayIndex]
        guard Data(base64Encoded: gateway.wireGuardPublicKey)?.count == 32 else {
            throw TunnelProfileError.invalidGatewayKey
        }
        guard let endpoint = Self.preferredEndpoint(from: gateway.endpointCandidates) else {
            throw TunnelProfileError.missingGatewayEndpoint
        }

        let hostPrefix = session.client.vpnIP.contains(":") ? 128 : 32
        clientAddress = "\(session.client.vpnIP)/\(hostPrefix)"
        gatewayNodeID = gateway.nodeID
        gatewayVPNIP = gateway.vpnIP
        gatewayWireGuardPublicKey = gateway.wireGuardPublicKey
        gatewayEndpoint = endpoint.address

        let gatewayPrefix = gateway.vpnIP.contains(":") ? 128 : 32
        var routes = ["\(gateway.vpnIP)/\(gatewayPrefix)"]
        routes.append(contentsOf: gateway.routes.map(\.cidr))
        var seen = Set<String>()
        allowedIPs = try routes.filter { route in
            guard Self.isSafeCIDR(route) else { throw TunnelProfileError.invalidRoute(route) }
            return seen.insert(route).inserted
        }
    }

    public static func preferredEndpoint(from candidates: [EndpointCandidate]) -> EndpointCandidate? {
        candidates
            .filter { candidate in
                switch candidate.kind {
                case .ipv6, .publicUDP, .stunReflexive: return true
                case .localUDP, .relay: return false
                }
            }
            .min { left, right in
                candidateScore(left) < candidateScore(right)
            }
    }

    private static func candidateScore(_ candidate: EndpointCandidate) -> CandidateScore {
        let rank: Int
        switch candidate.kind {
        case .ipv6: rank = 0
        case .publicUDP: rank = 1
        case .stunReflexive: rank = 2
        case .localUDP, .relay: rank = 3
        }
        return CandidateScore(
            rank: rank,
            cost: candidate.cost,
            inversePriority: UInt16.max - candidate.priority,
            address: candidate.address
        )
    }

    private static func isSafeCIDR(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              isIPAddress(String(parts[0])),
              let prefix = UInt8(parts[1])
        else {
            return false
        }
        let maximum: UInt8 = parts[0].contains(":") ? 128 : 32
        return prefix > 0 && prefix <= maximum
    }
}

private struct CandidateScore: Comparable {
    let rank: Int
    let cost: UInt32
    let inversePriority: UInt16
    let address: String

    static func < (left: CandidateScore, right: CandidateScore) -> Bool {
        if left.rank != right.rank { return left.rank < right.rank }
        if left.cost != right.cost { return left.cost < right.cost }
        if left.inversePriority != right.inversePriority {
            return left.inversePriority < right.inversePriority
        }
        return left.address < right.address
    }
}

private func isIPAddress(_ value: String) -> Bool {
    var ipv4 = in_addr()
    if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return true }
    var ipv6 = in6_addr()
    return value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1
}
