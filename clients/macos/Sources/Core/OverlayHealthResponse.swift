import Foundation

public enum OverlayHealthResponseParser {
    public static let maximumResponseBytes = 4_096
    private static let maximumBodyBytes = 1_024
    private static let headerTerminator = Data("\r\n\r\n".utf8)

    public static func result(from response: Data, streamClosed: Bool = false) -> Bool? {
        guard response.count <= maximumResponseBytes else { return false }
        guard let headerRange = response.range(of: headerTerminator) else {
            return streamClosed || response.count == maximumResponseBytes ? false : nil
        }
        guard let header = String(data: response[..<headerRange.lowerBound], encoding: .utf8) else {
            return false
        }
        let lines = header.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else { return false }
        let statusParts = statusLine.split(separator: " ", omittingEmptySubsequences: true)
        guard statusParts.count >= 2,
              statusParts[0] == "HTTP/1.1" || statusParts[0] == "HTTP/1.0",
              statusParts[1] == "200"
        else {
            return false
        }

        var contentLengths = [Int]()
        for line in lines.dropFirst() {
            let fields = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard fields.count == 2 else { return false }
            let name = fields[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = fields[1].trimmingCharacters(in: .whitespaces)
            if name == "transfer-encoding" {
                return false
            }
            if name == "content-length" {
                guard let length = Int(value), (0...maximumBodyBytes).contains(length) else {
                    return false
                }
                contentLengths.append(length)
            }
        }
        guard contentLengths.count == 1, let contentLength = contentLengths.first else {
            return false
        }

        let bodyStart = headerRange.upperBound
        let requiredLength = bodyStart + contentLength
        guard response.count >= requiredLength else {
            return streamClosed ? false : nil
        }
        guard response.count == requiredLength else { return false }
        let body = response[bodyStart..<requiredLength]
        guard let decoded = try? JSONSerialization.jsonObject(with: body),
              let object = decoded as? [String: Any]
        else {
            return false
        }
        return object["status"] as? String == "ok"
    }
}
