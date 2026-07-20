import Foundation

public enum HeteroNetworkConstants {
    public static let packetTunnelBundleIdentifier =
        "jp.go.ipa.cyberlab.heteronetwork.PacketTunnel"
    public static let appGroupIdentifier = "group.jp.go.ipa.cyberlab.heteronetwork"
    public static let keychainService = "jp.go.ipa.cyberlab.heteronetwork.client-session"
    public static let keychainAccount = "active"
    public static let sessionSchemaVersion = 1

    public static var keychainAccessGroup: String? {
        Bundle.main.object(forInfoDictionaryKey: "HeteroNetworkKeychainAccessGroup") as? String
    }
}
