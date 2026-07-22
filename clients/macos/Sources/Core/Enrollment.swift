import Foundation

public enum EnrollmentError: LocalizedError, Equatable {
    case empty
    case invalidLink
    case oversized
    case malformedToken
    case wrongRole
    case notYetValid
    case expired
    case insufficientControlPlanes

    public var errorDescription: String? {
        switch self {
        case .empty: return "Enrollment link is required."
        case .invalidLink: return "The enrollment link is invalid."
        case .oversized: return "The enrollment token is too large."
        case .malformedToken: return "The enrollment token is malformed."
        case .wrongRole: return "This token is not for a control-only client."
        case .notYetValid: return "The enrollment token is not valid yet."
        case .expired: return "The enrollment token has expired."
        case .insufficientControlPlanes:
            return "The enrollment token does not contain redundant control planes."
        }
    }
}

public enum EnrollmentParser {
    private static let maximumTokenBytes = 64 * 1024

    public static func parse(_ input: String, now: Date = Date()) throws -> SignedJoinToken {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw EnrollmentError.empty }

        let tokenData: Data
        if trimmed.hasPrefix("heteronetwork://") {
            guard let components = URLComponents(string: trimmed),
                  components.scheme == "heteronetwork",
                  components.host == "enroll",
                  let encoded = components.queryItems?.first(where: { $0.name == "token" })?.value,
                  let decoded = Data(base64URLEncoded: encoded)
            else {
                throw EnrollmentError.invalidLink
            }
            tokenData = decoded
        } else if let data = trimmed.data(using: .utf8), trimmed.first == "{" {
            tokenData = data
        } else {
            throw EnrollmentError.invalidLink
        }

        guard tokenData.count <= maximumTokenBytes else { throw EnrollmentError.oversized }
        let token: SignedJoinToken
        do {
            token = try HeteroNetworkCoding.makeDecoder().decode(SignedJoinToken.self, from: tokenData)
        } catch {
            throw EnrollmentError.malformedToken
        }

        guard token.claims.role == "client" else { throw EnrollmentError.wrongRole }
        guard token.claims.notBefore <= now.addingTimeInterval(5) else {
            throw EnrollmentError.notYetValid
        }
        guard token.claims.expiresAt > now else { throw EnrollmentError.expired }
        guard try managementURLs(from: token).count >= 2 else {
            throw EnrollmentError.insufficientControlPlanes
        }
        return token
    }

    public static func controlPlaneURLs(from token: SignedJoinToken) throws -> [URL] {
        try endpointURLs(from: token.claims.bootstrapEndpoints, kinds: [.controlPlane])
    }

    public static func managementURLs(from token: SignedJoinToken) throws -> [URL] {
        try endpointURLs(
            from: token.claims.bootstrapEndpoints,
            kinds: [.webUi, .controlPlane]
        )
    }

    public static func managementURLs(from endpoints: [BootstrapEndpoint]) -> [URL] {
        (try? endpointURLs(from: endpoints, kinds: [.webUi, .controlPlane])) ?? []
    }

    private static func endpointURLs(
        from endpoints: [BootstrapEndpoint],
        kinds: [BootstrapEndpointKind]
    ) throws -> [URL] {
        var seen = Set<String>()
        var urls = [URL]()
        for kind in kinds {
            for endpoint in endpoints where endpoint.kind == kind {
                guard let url = URL(string: endpoint.url),
                      let scheme = url.scheme?.lowercased(),
                      scheme == "https" || scheme == "http",
                      url.host != nil,
                      url.user == nil,
                      url.password == nil,
                      url.query == nil,
                      url.fragment == nil
                else {
                    continue
                }
                let canonical = url.absoluteString.trimmingCharacters(
                    in: CharacterSet(charactersIn: "/")
                )
                if seen.insert(canonical).inserted {
                    urls.append(url)
                }
            }
        }
        return urls
    }
}
