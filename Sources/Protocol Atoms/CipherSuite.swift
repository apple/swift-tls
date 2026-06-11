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

struct CipherSuite: RawRepresentable {
    var rawValue: UInt16

    init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
}

extension CipherSuite {
    static let TLS_AES_128_GCM_SHA256 = CipherSuite(rawValue: 0x1301)
    static let TLS_AES_256_GCM_SHA384 = CipherSuite(rawValue: 0x1302)
    static let TLS_CHACHA20_POLY1305_SHA256 = CipherSuite(rawValue: 0x1303)
}

extension CipherSuite: Hashable { }

extension CipherSuite: CustomStringConvertible {
    var description: String {
        switch self {
        case .TLS_AES_128_GCM_SHA256: // not actually supported, but used in testing with test vectors
            return "TLS_AES_128_GCM_SHA256"
        case .TLS_AES_256_GCM_SHA384:
            return "TLS_AES_256_GCM_SHA384"
        case .TLS_CHACHA20_POLY1305_SHA256:
            return "TLS_CHACHA20_POLY1305_SHA256"
        default:
            return "0x\(String(self.rawValue, radix: 16))"
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readCipherSuite() -> CipherSuite? {
        return self.readInteger().map { CipherSuite(rawValue: $0) }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeCipherSuite(_ cipherSuite: CipherSuite) -> Int {
        return self.writeInteger(cipherSuite.rawValue)
    }
}
