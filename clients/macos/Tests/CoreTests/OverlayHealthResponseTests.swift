import XCTest
@testable import HeteroNetworkCore

final class OverlayHealthResponseTests: XCTestCase {
    func testAcceptsCompleteHealthyResponse() {
        let response = Data(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\n\r\n{\"status\":\"ok\"}".utf8
        )

        XCTAssertEqual(OverlayHealthResponseParser.result(from: response), true)
    }

    func testWaitsForIncompleteBody() {
        let response = Data(
            "HTTP/1.1 200 OK\r\ncontent-length: 15\r\n\r\n{\"status\"".utf8
        )

        XCTAssertNil(OverlayHealthResponseParser.result(from: response))
        XCTAssertEqual(
            OverlayHealthResponseParser.result(from: response, streamClosed: true),
            false
        )
    }

    func testRejectsNonHealthyOrAmbiguousResponses() {
        let unavailable = Data(
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 15\r\n\r\n{\"status\":\"ok\"}".utf8
        )
        let duplicateLength = Data(
            "HTTP/1.1 200 OK\r\ncontent-length: 15\r\ncontent-length: 15\r\n\r\n{\"status\":\"ok\"}".utf8
        )
        let unhealthy = Data(
            "HTTP/1.1 200 OK\r\ncontent-length: 18\r\n\r\n{\"status\":\"error\"}".utf8
        )

        XCTAssertEqual(OverlayHealthResponseParser.result(from: unavailable), false)
        XCTAssertEqual(OverlayHealthResponseParser.result(from: duplicateLength), false)
        XCTAssertEqual(OverlayHealthResponseParser.result(from: unhealthy), false)
    }
}
