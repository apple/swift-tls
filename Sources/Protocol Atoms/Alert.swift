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

typealias AlertLevel = UInt8

enum knownTLSAlert: UInt8 {
    case closeNotify = 0
    case unexpectedMessage = 10
    case badRecordMac = 20
    case recordOverflow = 22
    case handshakeFailure = 40
    case badCertificate = 42
    case unsupportedCertificate = 43
    case certificateRevoked = 44
    case certificateExpired = 45
    case certificateUnknown = 46
    case illegalParameter = 47
    case unknownCA = 48
    case accessDenied = 49
    case decodeError = 50
    case decryptError = 51
    case protocolVersion = 70
    case insufficientSecurity = 71
    case internalError = 80
    case inappropriateFallback = 86
    case userCanceled = 90
    case missingExtension = 109
    case unsupportedExtension = 110
    case unrecognizedName = 112
    case badCertificateStatusResponse = 113
    case unknownPskIdentity = 115
    case certificateRequired = 116
    case noApplicationProtocol = 120
}

struct Alert: Sendable {
    let alertLevel: AlertLevel
    public let alertDescription: UInt8
    public var knownAlert: knownTLSAlert? {
        knownTLSAlert(rawValue: alertDescription)
    }

    init(_ alertLevel: AlertLevel, _ alertDescriptionRawValue: UInt8) {
        self.alertLevel = alertLevel
        self.alertDescription = alertDescriptionRawValue
    }
}

extension Alert {
    static let warningLevel: AlertLevel = 1
    static let fatalLevel: AlertLevel = 2

    static let closeNotify = Alert(warningLevel, 0)
    static let unexpectedMessage = Alert(fatalLevel, 10)
    static let badRecordMac = Alert(fatalLevel, 20)
    static let recordOverflow = Alert(fatalLevel, 22)
    static let handshakeFailure = Alert(fatalLevel, 40)
    static let badCertificate = Alert(fatalLevel, 42)
    static let unsupportedCertificate = Alert(fatalLevel, 43)
    static let certificateRevoked = Alert(fatalLevel, 44)
    static let certificateExpired = Alert(fatalLevel, 45)
    static let certificateUnknown = Alert(fatalLevel, 46)
    static let illegalParameter = Alert(fatalLevel, 47)
    static let unknownCA = Alert(fatalLevel, 48)
    static let accessDenied = Alert(fatalLevel, 49)
    static let decodeError = Alert(fatalLevel, 50)
    static let decryptError = Alert(fatalLevel, 51)
    static let protocolVersion = Alert(fatalLevel, 70)
    static let insufficientSecurity = Alert(fatalLevel, 71)
    static let internalError = Alert(fatalLevel, 80)
    static let inappropriateFallback = Alert(fatalLevel, 86)
    static let userCanceled = Alert(fatalLevel, 90)
    static let missingExtension = Alert(fatalLevel, 109)
    static let unsupportedExtension = Alert(fatalLevel, 110)
    static let unrecognizedName = Alert(fatalLevel, 112)
    static let badCertificateStatusResponse = Alert(fatalLevel, 113)
    static let unknownPskIdentity = Alert(fatalLevel, 115)
    static let certificateRequired = Alert(fatalLevel, 116)
    static let noApplicationProtocol = Alert(fatalLevel, 120)
}

extension Alert: Hashable { }

extension Alert: CustomStringConvertible {
    var description: String {
        switch self {
        case .closeNotify:
            return "close notify"
        case .unexpectedMessage:
            return "unexpected message"
        case .badRecordMac:
            return "bad record mac"
        case .recordOverflow:
            return "record overflow"
        case .handshakeFailure:
            return "handshake failure"
        case .badCertificate:
            return "bad certificate"
        case .unsupportedCertificate:
            return "unsupported certificate"
        case .certificateRevoked:
            return "certificate revoked"
        case .certificateExpired:
            return "certificate expired"
        case .certificateUnknown:
            return "certificate unknown"
        case .illegalParameter:
            return "illegal parameter"
        case .unknownCA:
            return "unknown ca"
        case .accessDenied:
            return "access denied"
        case .decodeError:
            return "decode error"
        case .decryptError:
            return "decrypt error"
        case .protocolVersion:
            return "protocol version"
        case .insufficientSecurity:
            return "insufficient security"
        case .internalError:
            return "internal error"
        case .inappropriateFallback:
            return "inappropriate fallback"
        case .userCanceled:
            return "user canceled"
        case .missingExtension:
            return "missing extension"
        case .unsupportedExtension:
            return "unsupported extension"
        case .unrecognizedName:
            return "unrecognized name"
        case .badCertificateStatusResponse:
            return "bad certificate status response"
        case .unknownPskIdentity:
            return "unknown psk identity"
        case .certificateRequired:
            return "certificate required"
        case .noApplicationProtocol:
            return "no application protocol"
        default:
            return "Alert(description: \(self.alertDescription))"
        }
    }
}

extension InputBuffer {
    mutating func readAlert() -> Alert? {
        let level = self.readInteger(as: UInt8.self)
        let description = self.readInteger(as: UInt8.self)
        guard let level, let description else {
            return nil
        }
        return Alert(level, description)
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeAlert(_ alert: Alert) -> Int {
        var written = self.writeInteger(alert.alertLevel, as: UInt8.self)
        written += self.writeInteger(alert.alertDescription)
        return written
    }
}
