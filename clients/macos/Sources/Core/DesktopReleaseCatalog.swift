import Foundation

public struct DesktopReleaseUpdate: Equatable {
    public let tag: String
    public let assetName: String
    public let archiveURL: URL
    public let checksumURL: URL

    public init(
        tag: String,
        assetName: String,
        archiveURL: URL,
        checksumURL: URL
    ) {
        self.tag = tag
        self.assetName = assetName
        self.archiveURL = archiveURL
        self.checksumURL = checksumURL
    }
}

public enum DesktopReleaseCatalogError: LocalizedError {
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "GitHub returned an invalid desktop release catalog."
        }
    }
}

public enum DesktopReleaseCatalog {
    private static let repositoryOwner = "IPA-CyberLab"
    private static let repositoryName = "IPA-RS-HeteroNetwork"

    /// Selects the newest published release that contains both the requested
    /// archive and its checksum. Releases are ordered by GitHub's publication
    /// timestamp so prerelease tags such as `v0.1.15-dev.15` work without a
    /// second, subtly different SemVer implementation in the client.
    public static func availableUpdate(
        from data: Data,
        currentTag: String,
        assetName: String
    ) throws -> DesktopReleaseUpdate? {
        guard isSafeReleaseTag(currentTag), isKnownMacAsset(assetName) else {
            return nil
        }

        let decoded: [GitHubRelease]
        do {
            let decoder = JSONDecoder()
            decoded = try decoder.decode([GitHubRelease].self, from: data)
        } catch {
            throw DesktopReleaseCatalogError.invalidResponse
        }

        let candidates = decoded.compactMap { release -> Candidate? in
            guard !release.draft,
                  isSafeReleaseTag(release.tagName),
                  let publishedAt = parseTimestamp(release.publishedAt),
                  let archive = release.assets.first(where: { $0.name == assetName }),
                  let checksum = release.assets.first(where: { $0.name == "\(assetName).sha256" }),
                  isExpectedDownloadURL(
                      archive.browserDownloadURL,
                      tag: release.tagName,
                      assetName: assetName
                  ),
                  isExpectedDownloadURL(
                      checksum.browserDownloadURL,
                      tag: release.tagName,
                      assetName: "\(assetName).sha256"
                  )
            else {
                return nil
            }
            return Candidate(
                tag: release.tagName,
                publishedAt: publishedAt,
                archiveURL: archive.browserDownloadURL,
                checksumURL: checksum.browserDownloadURL
            )
        }

        guard let newest = candidates.max(by: {
            if $0.publishedAt == $1.publishedAt { return $0.tag < $1.tag }
            return $0.publishedAt < $1.publishedAt
        }) else {
            return nil
        }
        if newest.tag == currentTag { return nil }

        // Do not downgrade when a newer installed release is still in the
        // first page of the GitHub catalog but its assets were withdrawn.
        if let current = decoded.first(where: {
            !$0.draft && $0.tagName == currentTag
        }), let currentPublishedAt = parseTimestamp(current.publishedAt),
           currentPublishedAt >= newest.publishedAt {
            return nil
        }

        return DesktopReleaseUpdate(
            tag: newest.tag,
            assetName: assetName,
            archiveURL: newest.archiveURL,
            checksumURL: newest.checksumURL
        )
    }

    private static func parseTimestamp(_ value: String?) -> Date? {
        guard let value else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let parsed = formatter.date(from: value) { return parsed }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }

    private static func isSafeReleaseTag(_ value: String) -> Bool {
        let scalars = Array(value.unicodeScalars)
        guard scalars.count > 1,
              scalars[0].value == 118,
              (48...57).contains(scalars[1].value)
        else {
            return false
        }
        return scalars.allSatisfy { scalar in
            (48...57).contains(scalar.value)
                || (65...90).contains(scalar.value)
                || (97...122).contains(scalar.value)
                || scalar.value == 46
                || scalar.value == 95
                || scalar.value == 45
        }
    }

    private static func isKnownMacAsset(_ value: String) -> Bool {
        value == "heteronetwork-client-macos-arm64.zip"
            || value == "heteronetwork-client-macos-x64.zip"
    }

    private static func isExpectedDownloadURL(
        _ url: URL,
        tag: String,
        assetName: String
    ) -> Bool {
        guard url.scheme == "https",
              url.host?.lowercased() == "github.com",
              url.user == nil,
              url.password == nil,
              url.port == nil,
              url.query == nil,
              url.fragment == nil
        else {
            return false
        }
        return url.pathComponents == [
            "/",
            repositoryOwner,
            repositoryName,
            "releases",
            "download",
            tag,
            assetName,
        ]
    }
}

private struct GitHubRelease: Decodable {
    let tagName: String
    let publishedAt: String?
    let draft: Bool
    let assets: [GitHubReleaseAsset]

    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case publishedAt = "published_at"
        case draft
        case assets
    }
}

private struct GitHubReleaseAsset: Decodable {
    let name: String
    let browserDownloadURL: URL

    enum CodingKeys: String, CodingKey {
        case name
        case browserDownloadURL = "browser_download_url"
    }
}

private struct Candidate {
    let tag: String
    let publishedAt: Date
    let archiveURL: URL
    let checksumURL: URL
}
