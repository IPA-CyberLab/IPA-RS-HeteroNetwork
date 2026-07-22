import Foundation

public enum HeteroNetworkConstants {
    public static let packetTunnelBundleIdentifier =
        "jp.go.ipa.cyberlab.heteronetwork.PacketTunnel"
    public static let appGroupIdentifier = "group.jp.go.ipa.cyberlab.heteronetwork"
    public static let keychainService = "jp.go.ipa.cyberlab.heteronetwork.client-session"
    public static let keychainAccount = "active"
    public static let sessionSchemaVersion = 1
    public static let overlayDNSName = "console.heteronetwork.internal"
    public static let overlayWebUIPort = 9781
    public static let gatewayRefreshIntervalNanoseconds: UInt64 = 5_000_000_000
    public static let gatewayFailureThreshold = 2
    public static let gatewayFailureCooldown: TimeInterval = 60

    public static var overlayWebUIURL: URL {
        URL(string: "http://\(overlayDNSName):\(overlayWebUIPort)/ui/")!
    }

    public static var keychainAccessGroup: String? {
        Bundle.main.object(forInfoDictionaryKey: "HeteroNetworkKeychainAccessGroup") as? String
    }
}
