import XCTest
@testable import HeteroNetworkCore

final class ClientSessionStoreTests: XCTestCase {
    func testPendingRegistrationRoundTripsWithoutKeychainEntitlements() throws {
        let namespace = "jp.go.ipa.cyberlab.heteronetwork.tests.\(UUID().uuidString)"
        let store = ClientSessionStore(
            sessionService: "\(namespace).session",
            sessionAccount: "active",
            pendingService: "\(namespace).pending",
            pendingAccount: "pending"
        )
        defer {
            try? store.delete()
            try? store.deletePendingRegistration()
        }

        let pending = try SponsoredEnrollment.makeRegistration()
        try store.savePendingRegistration(pending)

        XCTAssertEqual(try store.loadPendingRegistration(), pending)
        try store.deletePendingRegistration()
        XCTAssertNil(try store.loadPendingRegistration())
    }
}
