import AppKit
import CryptoKit
import Foundation
import HeteroNetworkCore

enum AppUpdateStatus: Equatable {
    case idle
    case checking
    case upToDate(String)
    case available(String)
    case downloading(String)
    case restarting(String)
    case unavailableForDevelopmentBuild
    case failed(String)

    var isActive: Bool {
        switch self {
        case .checking, .downloading, .restarting:
            return true
        case .idle, .upToDate, .available, .unavailableForDevelopmentBuild, .failed:
            return false
        }
    }
}

struct PreparedAppUpdate {
    let release: DesktopReleaseUpdate
    let stagedApplicationURL: URL
    let targetApplicationURL: URL
}

enum AppUpdateError: LocalizedError {
    case unsupportedArchitecture
    case invalidHTTPResponse
    case downloadTooLarge
    case invalidChecksum
    case checksumMismatch
    case applicationLocationUnsupported
    case archiveInvalid
    case releaseTagMismatch
    case processFailed(String)
    case updaterLaunchFailed

    var errorDescription: String? {
        switch self {
        case .unsupportedArchitecture:
            return "This Mac architecture does not have a release update asset."
        case .invalidHTTPResponse:
            return "The release server returned an invalid response."
        case .downloadTooLarge:
            return "The release download exceeded the allowed size."
        case .invalidChecksum:
            return "The release checksum file is invalid."
        case .checksumMismatch:
            return "The downloaded release did not match its SHA-256 checksum."
        case .applicationLocationUnsupported:
            return "HeteroNetwork must be installed in a user-writable Applications folder to update automatically."
        case .archiveInvalid:
            return "The release archive did not contain a valid HeteroNetwork application."
        case .releaseTagMismatch:
            return "The downloaded application does not match the selected release."
        case .processFailed(let message):
            return message
        case .updaterLaunchFailed:
            return "The background updater could not be started."
        }
    }
}

final class AppUpdateService {
    private static let catalogURL = URL(
        string: "https://api.github.com/repos/IPA-CyberLab/IPA-RS-HeteroNetwork/releases?per_page=100"
    )!
    private static let atomCatalogURL = URL(
        string: "https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases.atom"
    )!
    private static let maximumCatalogSize = 5 * 1_024 * 1_024
    private static let maximumArchiveSize: UInt64 = 512 * 1_024 * 1_024
    private static let bundleIdentifier = "jp.go.ipa.cyberlab.heteronetwork"
    private static let releaseTagKey = "HeteroNetworkReleaseTag"

    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 600
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.httpAdditionalHeaders = [
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "HeteroNetwork-macOS-updater",
        ]
        session = URLSession(configuration: configuration)
    }

    func availableUpdate(currentTag: String) async throws -> DesktopReleaseUpdate? {
        let assetName = try Self.macAssetName()
        do {
            let data = try await downloadCatalog(
                from: Self.catalogURL,
                accept: "application/vnd.github+json"
            )
            return try DesktopReleaseCatalog.availableUpdate(
                from: data,
                currentTag: currentTag,
                assetName: assetName
            )
        } catch {
            let data = try await downloadCatalog(
                from: Self.atomCatalogURL,
                accept: "application/atom+xml"
            )
            return try DesktopReleaseCatalog.availableUpdate(
                fromAtom: data,
                currentTag: currentTag,
                assetName: assetName
            )
        }
    }

    private func downloadCatalog(from url: URL, accept: String) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue(accept, forHTTPHeaderField: "Accept")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              http.statusCode == 200,
              response.url?.scheme == "https",
              data.count <= Self.maximumCatalogSize
        else {
            throw AppUpdateError.invalidHTTPResponse
        }
        return data
    }

    func prepare(_ release: DesktopReleaseUpdate) async throws -> PreparedAppUpdate {
        let manager = FileManager.default
        let target = Bundle.main.bundleURL.standardizedFileURL
        let targetValues = try target.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
        let parent = target.deletingLastPathComponent()
        guard target.lastPathComponent == "HeteroNetwork.app",
              targetValues.isSymbolicLink != true,
              targetValues.isDirectory == true,
              manager.isWritableFile(atPath: parent.path)
        else {
            throw AppUpdateError.applicationLocationUnsupported
        }

        let work = manager.temporaryDirectory.appendingPathComponent(
            "heteronetwork-update-\(UUID().uuidString)",
            isDirectory: true
        )
        try manager.createDirectory(
            at: work,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? manager.removeItem(at: work) }

        let checksumData = try await downloadData(from: release.checksumURL, maximumSize: 4_096)
        let expectedChecksum = try parseChecksum(checksumData, assetName: release.assetName)
        let archive = work.appendingPathComponent(release.assetName, isDirectory: false)
        try await downloadFile(from: release.archiveURL, to: archive)
        guard try fileSize(at: archive) <= Self.maximumArchiveSize else {
            throw AppUpdateError.downloadTooLarge
        }
        let archiveData = try Data(contentsOf: archive, options: [.mappedIfSafe])
        let actualChecksum = SHA256.hash(data: archiveData)
            .map { String(format: "%02x", $0) }
            .joined()
        guard actualChecksum == expectedChecksum else {
            throw AppUpdateError.checksumMismatch
        }

        let extracted = work.appendingPathComponent("extracted", isDirectory: true)
        try manager.createDirectory(at: extracted, withIntermediateDirectories: false)
        try await runProcess(
            executable: "/usr/bin/ditto",
            arguments: ["-x", "-k", archive.path, extracted.path]
        )
        let source = extracted.appendingPathComponent("HeteroNetwork.app", isDirectory: true)
        try await validateApplication(source, expectedTag: release.tag)

        let staged = parent.appendingPathComponent(
            ".HeteroNetwork.app.update-\(UUID().uuidString)",
            isDirectory: true
        )
        var keepStagedApplication = false
        defer {
            if !keepStagedApplication {
                try? manager.removeItem(at: staged)
            }
        }
        try await runProcess(
            executable: "/usr/bin/ditto",
            arguments: [source.path, staged.path]
        )
        try await validateApplication(staged, expectedTag: release.tag)
        keepStagedApplication = true
        return PreparedAppUpdate(
            release: release,
            stagedApplicationURL: staged,
            targetApplicationURL: target
        )
    }

    func activate(_ prepared: PreparedAppUpdate) throws {
        let manager = FileManager.default
        let support = try manager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("HeteroNetwork", isDirectory: true)
        try manager.createDirectory(
            at: support,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: support.path)
        let script = support.appendingPathComponent(
            "updater-\(UUID().uuidString).sh",
            isDirectory: false
        )
        let log = support.appendingPathComponent("updater.log", isDirectory: false)
        try Self.updaterScript.write(to: script, atomically: true, encoding: .utf8)
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [
            script.path,
            String(ProcessInfo.processInfo.processIdentifier),
            prepared.targetApplicationURL.path,
            prepared.stagedApplicationURL.path,
            prepared.release.tag,
            log.path,
        ]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            try? manager.removeItem(at: script)
            throw AppUpdateError.updaterLaunchFailed
        }
    }

    private func downloadData(from url: URL, maximumSize: Int) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              http.statusCode == 200,
              response.url?.scheme == "https",
              data.count <= maximumSize
        else {
            throw AppUpdateError.invalidHTTPResponse
        }
        return data
    }

    private func downloadFile(from url: URL, to destination: URL) async throws {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (temporary, response) = try await session.download(for: request)
        guard let http = response as? HTTPURLResponse,
              http.statusCode == 200,
              response.url?.scheme == "https"
        else {
            throw AppUpdateError.invalidHTTPResponse
        }
        if let expectedLength = http.value(forHTTPHeaderField: "Content-Length"),
           let length = UInt64(expectedLength),
           length > Self.maximumArchiveSize {
            throw AppUpdateError.downloadTooLarge
        }
        try FileManager.default.moveItem(at: temporary, to: destination)
    }

    private func parseChecksum(_ data: Data, assetName: String) throws -> String {
        guard let value = String(data: data, encoding: .utf8) else {
            throw AppUpdateError.invalidChecksum
        }
        let fields = value.split(whereSeparator: { $0.isWhitespace })
        guard fields.count == 2,
              fields[1] == Substring(assetName),
              fields[0].count == 64,
              fields[0].allSatisfy({ $0.isHexDigit && !$0.isUppercase })
        else {
            throw AppUpdateError.invalidChecksum
        }
        return String(fields[0])
    }

    private func fileSize(at url: URL) throws -> UInt64 {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let size = (attributes[.size] as? NSNumber)?.uint64Value,
              size > 0
        else {
            throw AppUpdateError.archiveInvalid
        }
        return size
    }

    private func validateApplication(_ application: URL, expectedTag: String) async throws {
        let manager = FileManager.default
        let values = try application.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
        let executable = application.appendingPathComponent(
            "Contents/MacOS/HeteroNetwork",
            isDirectory: false
        )
        let helper = application.appendingPathComponent(
            "Contents/Resources/heteronetwork-root-helper",
            isDirectory: false
        )
        let executableValues = try executable.resourceValues(
            forKeys: [.isSymbolicLinkKey, .isRegularFileKey]
        )
        let helperValues = try helper.resourceValues(
            forKeys: [.isSymbolicLinkKey, .isRegularFileKey]
        )
        guard values.isSymbolicLink != true,
              values.isDirectory == true,
              executableValues.isSymbolicLink != true,
              executableValues.isRegularFile == true,
              helperValues.isSymbolicLink != true,
              helperValues.isRegularFile == true,
              manager.isExecutableFile(atPath: executable.path),
              manager.isExecutableFile(atPath: helper.path)
        else {
            throw AppUpdateError.archiveInvalid
        }

        let infoURL = application.appendingPathComponent("Contents/Info.plist", isDirectory: false)
        let infoData = try Data(contentsOf: infoURL, options: [.mappedIfSafe])
        guard let info = try PropertyListSerialization.propertyList(
            from: infoData,
            options: [],
            format: nil
        ) as? [String: Any],
            info["CFBundleIdentifier"] as? String == Self.bundleIdentifier,
            info[Self.releaseTagKey] as? String == expectedTag
        else {
            throw AppUpdateError.releaseTagMismatch
        }

        try await runProcess(
            executable: "/usr/bin/codesign",
            arguments: ["--verify", "--deep", "--strict", application.path]
        )
        try await runProcess(executable: helper.path, arguments: ["self-test"])
    }

    private func runProcess(executable: String, arguments: [String]) async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            let process = Process()
            let errorPipe = Pipe()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = arguments
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice
            process.standardError = errorPipe
            process.terminationHandler = { process in
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                if process.terminationStatus == 0 {
                    continuation.resume()
                    return
                }
                let detail = String(decoding: errorData.prefix(1_024), as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                continuation.resume(throwing: AppUpdateError.processFailed(
                    detail.isEmpty ? "Release validation failed." : detail
                ))
            }
            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private static func macAssetName() throws -> String {
        #if arch(arm64)
        return "heteronetwork-client-macos-arm64.zip"
        #elseif arch(x86_64)
        return "heteronetwork-client-macos-x64.zip"
        #else
        throw AppUpdateError.unsupportedArchitecture
        #endif
    }

    private static let updaterScript = #"""
    #!/bin/sh
    set -eu

    current_pid=$1
    target=$2
    staged=$3
    expected_tag=$4
    log_path=$5
    script_path=$0
    parent=$(/usr/bin/dirname "$target")
    backup="$parent/.HeteroNetwork.app.backup.$$"
    activated=0

    /usr/bin/touch "$log_path"
    /bin/chmod 0600 "$log_path"
    exec >>"$log_path" 2>&1
    printf '%s\n' "Starting HeteroNetwork update to $expected_tag"

    cleanup() {
        if test "$activated" -eq 1; then
            /bin/rm -rf "$backup"
        elif test -d "$backup"; then
            /bin/rm -rf "$target"
            /bin/mv "$backup" "$target" || true
        fi
        /bin/rm -rf "$staged"
        /bin/rm -f "$script_path"
    }
    trap cleanup EXIT
    trap 'exit 1' HUP INT TERM

    test "$target" = "$parent/HeteroNetwork.app"
    test "$(/usr/bin/dirname "$staged")" = "$parent"
    case "$(/usr/bin/basename "$staged")" in
        .HeteroNetwork.app.update-*) ;;
        *) exit 1 ;;
    esac
    test ! -L "$target"
    test ! -L "$staged"
    test -d "$target/Contents"
    test -d "$staged/Contents"

    count=0
    while /bin/kill -0 "$current_pid" 2>/dev/null; do
        count=$((count + 1))
        test "$count" -le 150
        /bin/sleep 0.2
    done

    /usr/bin/codesign --verify --deep --strict "$staged"
    actual_tag=$(/usr/libexec/PlistBuddy -c 'Print :HeteroNetworkReleaseTag' "$staged/Contents/Info.plist")
    test "$actual_tag" = "$expected_tag"
    actual_bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$staged/Contents/Info.plist")
    test "$actual_bundle_id" = 'jp.go.ipa.cyberlab.heteronetwork'
    /bin/rm -rf "$backup"
    /bin/mv "$target" "$backup"
    /bin/mv "$staged" "$target"
    /usr/bin/codesign --verify --deep --strict "$target"
    /usr/bin/open "$target"
    activated=1
    printf '%s\n' "Activated HeteroNetwork $expected_tag"
    """#
}
