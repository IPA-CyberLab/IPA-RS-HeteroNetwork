import Foundation

public enum HeteroNetworkConstants {
    public static let keychainService = "jp.go.ipa.cyberlab.heteronetwork.client-session"
    public static let keychainAccount = "active"
    public static let pendingKeychainService =
        "jp.go.ipa.cyberlab.heteronetwork.pending-registration"
    public static let pendingKeychainAccount = "pending"
    public static let sessionSchemaVersion = 1
    public static let overlayDNSZone = "heteronetwork.internal"
    public static let overlayDNSName = "console.\(overlayDNSZone)"
    public static let overlayWebUIPort = 80
    public static let gatewayRefreshInterval: TimeInterval = 5
    public static let gatewayFailureThreshold = 2
    public static let gatewayFailureCooldown: TimeInterval = 60

    public static var overlayWebUIURL: URL {
        URL(string: "http://\(overlayDNSName)/ui/")!
    }
}
