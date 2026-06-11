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

struct ExtensionType: RawRepresentable, Sendable {
    var rawValue: UInt16

    init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
}

@available(SwiftTLS 0.1.0, *)
extension ExtensionType {
    static let serverName = ExtensionType(rawValue: 0)

    static let supportedGroups = ExtensionType(rawValue: 10)

    static let signatureAlgorithms = ExtensionType(rawValue: 13)

    static let applicationLayerProtocolNegotiation = ExtensionType(rawValue: 16)

    static let clientCertificateType = ExtensionType(rawValue: 19)

    static let serverCertificateType = ExtensionType(rawValue: 20)

    static let earlyData = ExtensionType(rawValue: 42)

    static let supportedVersions = ExtensionType(rawValue: 43)

    static let keyShare = ExtensionType(rawValue: 51)

    static let quicTransportParameters = ExtensionType(rawValue: 57)

    static let preSharedKeyKexModes = ExtensionType(rawValue: 45)

    static let preSharedKey = ExtensionType(rawValue: 41)

    static let ticketRequest = ExtensionType(rawValue: 58)
}

@available(SwiftTLS 0.1.0, *)
extension ExtensionType: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension ExtensionType: CustomStringConvertible {
    var description: String {
        switch self {
        case .serverName:
            return ".serverName"
        case .supportedGroups:
            return ".supportedGroups"
        case .signatureAlgorithms:
            return ".signatureAlgorithms"
        case .applicationLayerProtocolNegotiation:
            return ".applicationLayerProtocolNegotiation"
        case .clientCertificateType:
            return ".clientCertificateType"
        case .serverCertificateType:
            return ".serverCertificateType"
        case .earlyData:
            return ".earlyData"
        case .supportedVersions:
            return ".supportedVersions"
        case .keyShare:
            return ".keyShare"
        case .quicTransportParameters:
            return ".quicTransportParameters"
        case .preSharedKey:
            return ".preSharedKey"
        case .preSharedKeyKexModes:
            return ".preSharedKeyKexModes"
        case .ticketRequest:
            return ".ticketRequest"
        default:
            return "ExtensionType(rawValue: \(self.rawValue))"
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readExtensionType() -> ExtensionType? {
        return self.readInteger().map { ExtensionType(rawValue: $0) }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeExtensionType(_ type: ExtensionType) -> Int {
        return self.writeInteger(type.rawValue)
    }
}
