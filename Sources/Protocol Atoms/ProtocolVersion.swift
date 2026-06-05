//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift open source project
//
// Copyright (c) 2026 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

struct ProtocolVersion {
    var major: UInt8
    var minor: UInt8

    init(major: UInt8, minor: UInt8) {
        self.major = major
        self.minor = minor
    }
}

extension ProtocolVersion {
    static let sslv3 = ProtocolVersion(major: 3, minor: 0)
    static let tlsv10 = ProtocolVersion(major: 3, minor: 1)
    static let tlsv11 = ProtocolVersion(major: 3, minor: 2)
    static let tlsv12 = ProtocolVersion(major: 3, minor: 3)
    static let tlsv13 = ProtocolVersion(major: 3, minor: 4)
}

extension ProtocolVersion: Hashable { }

extension ProtocolVersion: CustomStringConvertible {
    var description: String {
        switch self {
        case .sslv3:
            return ".sslv3"
        case .tlsv10:
            return ".tlsv10"
        case .tlsv11:
            return ".tlsv11"
        case .tlsv12:
            return ".tlsv12"
        case .tlsv13:
            return ".tlsv13"
        default:
            return "ProtocolVersion(major: \(self.major), minor: \(self.minor))"
        }
    }
}

extension InputBuffer {
    mutating func readProtocolVersion() -> ProtocolVersion? {
        return self.readInteger(as: UInt16.self).map { ProtocolVersion(major: UInt8(truncatingIfNeeded: $0 >> 8) , minor: UInt8(truncatingIfNeeded: $0)) }
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeProtocolVersion(_ protocolVersion: ProtocolVersion) -> Int {
        return self.writeInteger(UInt16(protocolVersion.major) << 8 | UInt16(protocolVersion.minor))
    }

    @discardableResult
    mutating func setProtocolVersion(_ protocolVersion: ProtocolVersion, at index: Int) -> Int {
        return self.setInteger(UInt16(protocolVersion.major) << 8 | UInt16(protocolVersion.minor), at: index)
    }
}
