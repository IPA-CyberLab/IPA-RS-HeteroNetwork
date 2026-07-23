import XCTest
@testable import HeteroNetworkCore

final class OverlayDNSHealthProbeTests: XCTestCase {
    func testBuildsOverlayAQuery() {
        let query = OverlayDNSHealthProbe.query(id: 0x1234)

        XCTAssertEqual(query.prefix(12), Data([
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        ]))
        XCTAssertNotNil(
            query.range(of: Data([
                0x07, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65,
                0x0d, 0x68, 0x65, 0x74, 0x65, 0x72, 0x6f, 0x6e,
                0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
                0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
                0x00, 0x00, 0x01, 0x00, 0x01,
            ]))
        )
    }

    func testAcceptsSuccessfulResponseWithAnAnswer() {
        let response = Data([
            0x12, 0x34,
            0x81, 0x80,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
        ])

        XCTAssertTrue(OverlayDNSHealthProbe.isHealthyResponse(response, queryID: 0x1234))
    }

    func testRejectsMismatchedErroredOrAnswerlessResponses() {
        XCTAssertFalse(
            OverlayDNSHealthProbe.isHealthyResponse(
                Data([0x12, 0x35, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]),
                queryID: 0x1234
            )
        )
        XCTAssertFalse(
            OverlayDNSHealthProbe.isHealthyResponse(
                Data([0x12, 0x34, 0x81, 0x83, 0, 1, 0, 1, 0, 0, 0, 0]),
                queryID: 0x1234
            )
        )
        XCTAssertFalse(
            OverlayDNSHealthProbe.isHealthyResponse(
                Data([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]),
                queryID: 0x1234
            )
        )
    }
}
