import Foundation

public enum OverlayDNSHealthProbe {
    public static func query(id: UInt16) -> Data {
        var data = Data()
        data.appendUInt16(id)
        data.appendUInt16(0x0100)
        data.appendUInt16(1)
        data.appendUInt16(0)
        data.appendUInt16(0)
        data.appendUInt16(0)
        for label in HeteroNetworkConstants.overlayDNSName.split(separator: ".") {
            data.append(UInt8(label.utf8.count))
            data.append(contentsOf: label.utf8)
        }
        data.append(0)
        data.appendUInt16(1)
        data.appendUInt16(1)
        return data
    }

    public static func isHealthyResponse(_ data: Data, queryID: UInt16) -> Bool {
        guard data.count >= 12,
              data.uint16(at: 0) == queryID,
              let flags = data.uint16(at: 2),
              flags & 0x8000 != 0,
              flags & 0x000f == 0,
              data.uint16(at: 4) == 1,
              let answerCount = data.uint16(at: 6),
              answerCount > 0
        else {
            return false
        }
        return true
    }
}

private extension Data {
    mutating func appendUInt16(_ value: UInt16) {
        append(UInt8(value >> 8))
        append(UInt8(value & 0xff))
    }

    func uint16(at offset: Int) -> UInt16? {
        guard indices.contains(offset), indices.contains(offset + 1) else { return nil }
        return UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }
}
