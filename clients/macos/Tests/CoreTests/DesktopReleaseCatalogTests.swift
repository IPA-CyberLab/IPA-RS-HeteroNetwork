import Foundation
import XCTest
@testable import HeteroNetworkCore

final class DesktopReleaseCatalogTests: XCTestCase {
    private let assetName = "heteronetwork-client-macos-arm64.zip"

    func testSelectsNewestCompletePublishedRelease() throws {
        let update = try DesktopReleaseCatalog.availableUpdate(
            from: catalog([
                release(tag: "v0.1.15-dev.18", publishedAt: "2026-09-19T12:00:00Z", assets: []),
                release(tag: "v0.1.15-dev.17", publishedAt: "2026-09-19T11:00:00Z"),
                release(tag: "v0.1.15-dev.16", publishedAt: "2026-09-19T10:00:00Z"),
            ]),
            currentTag: "v0.1.15-dev.16",
            assetName: assetName
        )

        XCTAssertEqual(update?.tag, "v0.1.15-dev.17")
        XCTAssertEqual(update?.assetName, assetName)
    }

    func testReportsCurrentWhenNewestCompleteReleaseIsInstalled() throws {
        let update = try DesktopReleaseCatalog.availableUpdate(
            from: catalog([
                release(tag: "v0.1.15-dev.17", publishedAt: "2026-09-19T11:00:00Z"),
                release(tag: "v0.1.15-dev.16", publishedAt: "2026-09-19T10:00:00Z"),
            ]),
            currentTag: "v0.1.15-dev.17",
            assetName: assetName
        )

        XCTAssertNil(update)
    }

    func testDoesNotDowngradeWhenCurrentReleaseAssetsWereWithdrawn() throws {
        let update = try DesktopReleaseCatalog.availableUpdate(
            from: catalog([
                release(tag: "v0.1.15-dev.18", publishedAt: "2026-09-19T12:00:00Z", assets: []),
                release(tag: "v0.1.15-dev.17", publishedAt: "2026-09-19T11:00:00Z"),
            ]),
            currentTag: "v0.1.15-dev.18",
            assetName: assetName
        )

        XCTAssertNil(update)
    }

    func testIgnoresDraftAndUntrustedDownloadURLs() throws {
        var draft = release(tag: "v0.1.15-dev.19", publishedAt: "2026-09-19T13:00:00Z")
        draft["draft"] = true
        var untrusted = release(tag: "v0.1.15-dev.18", publishedAt: "2026-09-19T12:00:00Z")
        untrusted["assets"] = [
            ["name": assetName, "browser_download_url": "https://example.com/client.zip"],
            ["name": "\(assetName).sha256", "browser_download_url": downloadURL(
                tag: "v0.1.15-dev.18",
                name: "\(assetName).sha256"
            )],
        ]

        let update = try DesktopReleaseCatalog.availableUpdate(
            from: catalog([
                draft,
                untrusted,
                release(tag: "v0.1.15-dev.17", publishedAt: "2026-09-19T11:00:00Z"),
            ]),
            currentTag: "v0.1.15-dev.16",
            assetName: assetName
        )

        XCTAssertEqual(update?.tag, "v0.1.15-dev.17")
    }

    func testDevelopmentBuildDoesNotOfferReleaseUpdate() throws {
        let update = try DesktopReleaseCatalog.availableUpdate(
            from: catalog([
                release(tag: "v0.1.15-dev.17", publishedAt: "2026-09-19T11:00:00Z"),
            ]),
            currentTag: "development",
            assetName: assetName
        )

        XCTAssertNil(update)
    }

    func testAtomFeedSelectsNewestReleaseAndBuildsTrustedURLs() throws {
        let update = try DesktopReleaseCatalog.availableUpdate(
            fromAtom: atomFeed([
                atomEntry(tag: "v0.1.15-dev.24", updated: "2026-09-21T08:02:47Z"),
                atomEntry(tag: "v0.1.15-dev.23", updated: "2026-09-21T07:02:47Z"),
            ]),
            currentTag: "v0.1.15-dev.23",
            assetName: assetName
        )

        XCTAssertEqual(update?.tag, "v0.1.15-dev.24")
        XCTAssertEqual(update?.archiveURL.absoluteString, downloadURL(
            tag: "v0.1.15-dev.24",
            name: assetName
        ))
        XCTAssertEqual(update?.checksumURL.absoluteString, downloadURL(
            tag: "v0.1.15-dev.24",
            name: "\(assetName).sha256"
        ))
    }

    func testAtomFeedDoesNotOfferCurrentOrOlderRelease() throws {
        let current = try DesktopReleaseCatalog.availableUpdate(
            fromAtom: atomFeed([
                atomEntry(tag: "v0.1.15-dev.24", updated: "2026-09-21T08:02:47Z"),
                atomEntry(tag: "v0.1.15-dev.23", updated: "2026-09-21T07:02:47Z"),
            ]),
            currentTag: "v0.1.15-dev.24",
            assetName: assetName
        )
        XCTAssertNil(current)

        let newerInstalled = try DesktopReleaseCatalog.availableUpdate(
            fromAtom: atomFeed([
                atomEntry(tag: "v0.1.15-dev.25", updated: "2026-09-21T09:02:47Z"),
                atomEntry(tag: "v0.1.15-dev.24", updated: "2026-09-21T08:02:47Z"),
            ]),
            currentTag: "v0.1.15-dev.25",
            assetName: assetName
        )
        XCTAssertNil(newerInstalled)
    }

    func testAtomFeedIgnoresUntrustedAndUnsafeReleaseLinks() throws {
        let update = try DesktopReleaseCatalog.availableUpdate(
            fromAtom: atomFeed([
                atomEntry(
                    tag: "v0.1.15-dev.25",
                    updated: "2026-09-21T09:02:47Z",
                    href: "https://example.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/tag/v0.1.15-dev.25"
                ),
                atomEntry(
                    tag: "v0.1.15-dev.24",
                    updated: "2026-09-21T08:02:47Z",
                    href: "https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/tag/v0.1.15-dev.24%2Fescape"
                ),
                atomEntry(tag: "v0.1.15-dev.23", updated: "2026-09-21T07:02:47Z"),
            ]),
            currentTag: "v0.1.15-dev.22",
            assetName: assetName
        )

        XCTAssertEqual(update?.tag, "v0.1.15-dev.23")
    }

    func testRejectsMalformedAtomFeed() {
        XCTAssertThrowsError(
            try DesktopReleaseCatalog.availableUpdate(
                fromAtom: Data("<feed><entry>".utf8),
                currentTag: "v0.1.15-dev.23",
                assetName: assetName
            )
        )
    }

    private func release(
        tag: String,
        publishedAt: String,
        assets: [[String: Any]]? = nil
    ) -> [String: Any] {
        [
            "tag_name": tag,
            "published_at": publishedAt,
            "draft": false,
            "assets": assets ?? [
                ["name": assetName, "browser_download_url": downloadURL(tag: tag, name: assetName)],
                [
                    "name": "\(assetName).sha256",
                    "browser_download_url": downloadURL(tag: tag, name: "\(assetName).sha256"),
                ],
            ],
        ]
    }

    private func downloadURL(tag: String, name: String) -> String {
        "https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/download/\(tag)/\(name)"
    }

    private func catalog(_ releases: [[String: Any]]) throws -> Data {
        try JSONSerialization.data(withJSONObject: releases, options: [.sortedKeys])
    }

    private func atomEntry(
        tag: String,
        updated: String,
        href: String? = nil
    ) -> String {
        let releaseURL = href
            ?? "https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/tag/\(tag)"
        return """
        <entry>
          <updated>\(updated)</updated>
          <link rel="alternate" type="text/html" href="\(releaseURL)" />
          <title>HeteroNetwork \(tag)</title>
        </entry>
        """
    }

    private func atomFeed(_ entries: [String]) -> Data {
        Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
        \(entries.joined(separator: "\n"))
        </feed>
        """.utf8)
    }
}
