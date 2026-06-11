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

struct HandshakeType: RawRepresentable, Sendable {
    var rawValue: UInt8

    init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}

extension HandshakeType {
    static let clientHello = HandshakeType(rawValue: 1)
    static let serverHello = HandshakeType(rawValue: 2)
    static let newSessionTicket = HandshakeType(rawValue: 4)
    static let endOfEarlyData = HandshakeType(rawValue: 5)
    static let encryptedExtensions = HandshakeType(rawValue: 8)
    static let certificate = HandshakeType(rawValue: 11)
    static let certificateRequest = HandshakeType(rawValue: 13)
    static let certificateVerify = HandshakeType(rawValue: 15)
    static let finished = HandshakeType(rawValue: 20)
    static let keyUpdate = HandshakeType(rawValue: 24)
    static let messageHash = HandshakeType(rawValue: 254)
}

extension HandshakeType: Hashable { }

extension HandshakeType: CustomStringConvertible {
    var description: String {
        switch self {
        case .clientHello:
            return ".clientHello"
        case .serverHello:
            return ".serverHello"
        case .newSessionTicket:
            return ".newSessionTicket"
        case .endOfEarlyData:
            return ".endOfEarlyData"
        case .encryptedExtensions:
            return ".encryptedExtensions"
        case .certificate:
            return ".certificate"
        case .certificateRequest:
            return ".certificateRequest"
        case .certificateVerify:
            return ".certificateVerify"
        case .finished:
            return ".finished"
        case .keyUpdate:
            return ".keyUpdate"
        case .messageHash:
            return ".messageHash"
        default:
            return "HandshakeType(rawValue: \(self.rawValue))"
        }
    }
}

@available(anyAppleOS 26, *)
extension InputBuffer {
    mutating func readHandshakeType() -> HandshakeType? {
        return self.readInteger().map { HandshakeType(rawValue: $0) }
    }
}

@available(anyAppleOS 26, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeHandshakeType(_ type: HandshakeType) -> Int {
        return self.writeInteger(type.rawValue)
    }
}
