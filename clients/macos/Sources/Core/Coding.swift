import Foundation

public enum HeteroNetworkCoding {
    public static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self)
            if let date = date(fromRFC3339: value) {
                return date
            }
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid RFC 3339 timestamp: \(value)"
            )
        }
        return decoder
    }

    public static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(rfc3339String(from: date))
        }
        return encoder
    }

    static func date(fromRFC3339 value: String) -> Date? {
        internetDateFormatter(fractionalSeconds: true).date(from: value)
            ?? internetDateFormatter(fractionalSeconds: false).date(from: value)
    }

    static func rfc3339String(from date: Date) -> String {
        internetDateFormatter(fractionalSeconds: false).string(from: date)
    }

    private static func internetDateFormatter(fractionalSeconds: Bool) -> ISO8601DateFormatter {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = fractionalSeconds
            ? [.withInternetDateTime, .withFractionalSeconds]
            : [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter
    }
}

public extension Data {
    init?(base64URLEncoded value: String) {
        var standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = standard.count % 4
        if remainder != 0 {
            standard.append(String(repeating: "=", count: 4 - remainder))
        }
        self.init(base64Encoded: standard)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
