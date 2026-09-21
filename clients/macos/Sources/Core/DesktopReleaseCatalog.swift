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

    /// Selects an update from GitHub's public releases Atom feed. This is a
    /// fallback for clients whose unauthenticated API quota is exhausted.
    /// Release asset names are fixed by the release contract, and downloads
    /// remain protected by the separately published SHA-256 checksum.
    public static func availableUpdate(
        fromAtom data: Data,
        currentTag: String,
        assetName: String
    ) throws -> DesktopReleaseUpdate? {
        guard isSafeReleaseTag(currentTag), isKnownMacAsset(assetName) else {
            return nil
        }

        let entries = try AtomReleaseFeedParser.parse(data)
        let candidates = entries.compactMap { entry -> Candidate? in
            guard let publishedAt = parseTimestamp(entry.updated),
                  let tag = releaseTag(from: entry.alternateURL),
                  let archiveURL = expectedDownloadURL(tag: tag, assetName: assetName),
                  let checksumURL = expectedDownloadURL(
                      tag: tag,
                      assetName: "\(assetName).sha256"
                  )
            else {
                return nil
            }
            return Candidate(
                tag: tag,
                publishedAt: publishedAt,
                archiveURL: archiveURL,
                checksumURL: checksumURL
            )
        }

        guard let newest = candidates.max(by: {
            if $0.publishedAt == $1.publishedAt { return $0.tag < $1.tag }
            return $0.publishedAt < $1.publishedAt
        }) else {
            return nil
        }
        if newest.tag == currentTag { return nil }

        if let current = candidates.first(where: { $0.tag == currentTag }),
           current.publishedAt >= newest.publishedAt {
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

    private static func releaseTag(from url: URL) -> String? {
        guard url.scheme == "https",
              url.host?.lowercased() == "github.com",
              url.user == nil,
              url.password == nil,
              url.port == nil,
              url.query == nil,
              url.fragment == nil,
              url.pathComponents.count == 6,
              url.pathComponents[0] == "/",
              url.pathComponents[1] == repositoryOwner,
              url.pathComponents[2] == repositoryName,
              url.pathComponents[3] == "releases",
              url.pathComponents[4] == "tag",
              isSafeReleaseTag(url.pathComponents[5])
        else {
            return nil
        }
        return url.pathComponents[5]
    }

    private static func expectedDownloadURL(tag: String, assetName: String) -> URL? {
        guard isSafeReleaseTag(tag),
              let url = URL(
                  string: "https://github.com/\(repositoryOwner)/\(repositoryName)/releases/download/\(tag)/\(assetName)"
              ),
              isExpectedDownloadURL(url, tag: tag, assetName: assetName)
        else {
            return nil
        }
        return url
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

private struct AtomReleaseEntry {
    let updated: String
    let alternateURL: URL
}

private final class AtomReleaseFeedParser: NSObject, XMLParserDelegate {
    private var entries: [AtomReleaseEntry] = []
    private var insideEntry = false
    private var updated = ""
    private var alternateURL: URL?
    private var capturesUpdated = false

    static func parse(_ data: Data) throws -> [AtomReleaseEntry] {
        let delegate = AtomReleaseFeedParser()
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        guard parser.parse() else {
            throw DesktopReleaseCatalogError.invalidResponse
        }
        return delegate.entries
    }

    func parser(
        _ parser: XMLParser,
        didStartElement elementName: String,
        namespaceURI: String?,
        qualifiedName qName: String?,
        attributes attributeDict: [String: String] = [:]
    ) {
        switch elementName {
        case "entry":
            insideEntry = true
            updated = ""
            alternateURL = nil
            capturesUpdated = false
        case "updated" where insideEntry:
            updated = ""
            capturesUpdated = true
        case "link" where insideEntry:
            if attributeDict["rel"] == "alternate",
               let href = attributeDict["href"] {
                alternateURL = URL(string: href)
            }
        default:
            break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if capturesUpdated {
            updated += string
        }
    }

    func parser(
        _ parser: XMLParser,
        didEndElement elementName: String,
        namespaceURI: String?,
        qualifiedName qName: String?
    ) {
        switch elementName {
        case "updated" where insideEntry:
            capturesUpdated = false
        case "entry" where insideEntry:
            if !updated.isEmpty, let alternateURL {
                entries.append(
                    AtomReleaseEntry(
                        updated: updated.trimmingCharacters(in: .whitespacesAndNewlines),
                        alternateURL: alternateURL
                    )
                )
            }
            insideEntry = false
            capturesUpdated = false
        default:
            break
        }
    }
}
