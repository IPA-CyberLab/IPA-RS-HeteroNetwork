import Foundation

public enum ControlPlaneAPIError: LocalizedError {
    case noControlPlane
    case invalidEndpoint
    case transport([String])
    case rejected(statusCode: Int, message: String)
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .noControlPlane: return "No control plane endpoint is available."
        case .invalidEndpoint: return "A control plane endpoint is invalid."
        case .transport(let failures):
            return "All control planes failed: " + failures.joined(separator: "; ")
        case .rejected(let statusCode, let message):
            return "Control plane rejected the request (HTTP \(statusCode)): \(message)"
        case .invalidResponse: return "The control plane returned an invalid response."
        }
    }
}

public final class ControlPlaneClient {
    private let session: URLSession
    private let encoder = HeteroNetworkCoding.makeEncoder()
    private let decoder = HeteroNetworkCoding.makeDecoder()

    public init(session: URLSession? = nil) {
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = 15
            configuration.timeoutIntervalForResource = 30
            configuration.waitsForConnectivity = false
            configuration.httpShouldSetCookies = false
            configuration.urlCache = nil
            self.session = URLSession(configuration: configuration)
        }
    }

    public func join(token: SignedJoinToken, keyMaterial: ClientKeyMaterial) async throws -> ClientSession {
        let controlPlanes = try EnrollmentParser.controlPlaneURLs(from: token)
        guard !controlPlanes.isEmpty else { throw ControlPlaneAPIError.noControlPlane }
        let registration = RegisterClientRequest(
            clientID: try keyMaterial.clientID,
            identityPublicKey: try keyMaterial.identityPublicKey,
            wireGuardPublicKey: try keyMaterial.wireGuardPublicKey
        )
        let request = JoinClientRequest(token: token, registration: registration)
        let response: RegisterClientResponse = try await performFailover(
            bases: controlPlanes,
            path: "/v1/clients/join",
            method: "POST"
        ) { _ in request }
        guard response.client.nodeID == registration.clientID,
              response.client.identityPublicKey == registration.identityPublicKey,
              response.client.wireGuardPublicKey == registration.wireGuardPublicKey,
              response.client.role == "client"
        else {
            throw ControlPlaneAPIError.invalidResponse
        }
        return ClientSession(
            identityPrivateKey: keyMaterial.identityPrivateKey,
            wireGuardPrivateKey: keyMaterial.wireGuardPrivateKey,
            controlPlaneURLs: controlPlanes,
            client: response.client,
            peerMap: response.peerMap,
            enrolledAt: Date()
        )
    }

    public func refresh(_ storedSession: ClientSession) async throws -> ClientSession {
        let keyMaterial = try ClientKeyMaterial(
            identityPrivateKey: storedSession.identityPrivateKey,
            wireGuardPrivateKey: storedSession.wireGuardPrivateKey
        )
        let peerMap: PeerMap = try await performFailover(
            bases: storedSession.controlPlaneURLs,
            path: "/v1/clients/peers/query",
            method: "POST"
        ) { _ in
            ClientControlRequest(
                clientID: storedSession.client.nodeID,
                requestSignature: try keyMaterial.sign(
                    clientID: storedSession.client.nodeID,
                    kind: .peerMap
                )
            )
        }
        guard peerMap.clusterID == storedSession.client.clusterID else {
            throw ControlPlaneAPIError.invalidResponse
        }
        var updated = storedSession
        updated.peerMap = peerMap
        updated.refreshedAt = Date()
        return updated
    }

    public func remove(_ storedSession: ClientSession) async throws {
        let keyMaterial = try ClientKeyMaterial(
            identityPrivateKey: storedSession.identityPrivateKey,
            wireGuardPrivateKey: storedSession.wireGuardPrivateKey
        )
        let path = "/v1/clients/\(storedSession.client.nodeID)"
        let response: RemoveClientResponse = try await performFailover(
            bases: storedSession.controlPlaneURLs,
            path: path,
            method: "DELETE"
        ) { _ in
            ClientControlRequest(
                clientID: storedSession.client.nodeID,
                requestSignature: try keyMaterial.sign(
                    clientID: storedSession.client.nodeID,
                    kind: .remove
                )
            )
        }
        guard response.client.nodeID == storedSession.client.nodeID else {
            throw ControlPlaneAPIError.invalidResponse
        }
    }

    private func performFailover<Request: Encodable, Response: Decodable>(
        bases: [URL],
        path: String,
        method: String,
        requestBody: (URL) throws -> Request
    ) async throws -> Response {
        guard !bases.isEmpty else { throw ControlPlaneAPIError.noControlPlane }
        var failures = [String]()
        var lastRejection: ControlPlaneAPIError?
        for base in bases {
            do {
                let endpoint = try endpointURL(base: base, path: path)
                var request = URLRequest(url: endpoint)
                request.httpMethod = method
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                request.setValue("application/json", forHTTPHeaderField: "Accept")
                request.httpBody = try encoder.encode(requestBody(base))
                let (data, response) = try await session.data(for: request)
                guard let http = response as? HTTPURLResponse else {
                    throw ControlPlaneAPIError.invalidResponse
                }
                guard (200..<300).contains(http.statusCode) else {
                    let message = serverMessage(from: data)
                    let rejection = ControlPlaneAPIError.rejected(
                        statusCode: http.statusCode,
                        message: message
                    )
                    lastRejection = rejection
                    failures.append("\(base.host ?? base.absoluteString): HTTP \(http.statusCode)")
                    continue
                }
                do {
                    return try decoder.decode(Response.self, from: data)
                } catch {
                    throw ControlPlaneAPIError.invalidResponse
                }
            } catch let error as ControlPlaneAPIError {
                failures.append("\(base.host ?? base.absoluteString): \(error.localizedDescription)")
            } catch {
                failures.append("\(base.host ?? base.absoluteString): \(error.localizedDescription)")
            }
        }
        if let lastRejection { throw lastRejection }
        throw ControlPlaneAPIError.transport(failures)
    }

    private func endpointURL(base: URL, path: String) throws -> URL {
        guard var components = URLComponents(url: base, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              components.host != nil
        else {
            throw ControlPlaneAPIError.invalidEndpoint
        }
        let basePath = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        components.path = (basePath.isEmpty ? "" : "/\(basePath)") + path
        components.query = nil
        components.fragment = nil
        guard let url = components.url else { throw ControlPlaneAPIError.invalidEndpoint }
        return url
    }

    private func serverMessage(from data: Data) -> String {
        guard !data.isEmpty else { return "empty response" }
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            for key in ["error", "message", "reason"] {
                if let value = object[key] as? String {
                    return String(value.prefix(512))
                }
            }
        }
        return String(decoding: data.prefix(512), as: UTF8.self)
    }
}
