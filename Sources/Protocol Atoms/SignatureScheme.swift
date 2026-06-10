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

struct SignatureScheme: RawRepresentable {
    var rawValue: UInt16

    init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
}

extension SignatureScheme {
    static let ecdsa_secp256r1_sha256 = SignatureScheme(rawValue: 0x0403)

    static let ecdsa_secp384r1_sha384 = SignatureScheme(rawValue: 0x0503)

    static let rsa_pss_rsae_sha256 = SignatureScheme(rawValue: 0x0804)
}

extension SignatureScheme: Hashable { }

extension SignatureScheme: CustomStringConvertible {
    var description: String {
        switch self {
        case .ecdsa_secp256r1_sha256:
            return ".ecdsa_secp256r1_sha256"
        case .ecdsa_secp384r1_sha384:
            return ".ecdsa_secp384r1_sha384"
        case .rsa_pss_rsae_sha256:
            return ".rsa_pss_rsae_sha256"
        default:
            return "SignatureScheme(rawValue: \(self.rawValue))"
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readSignatureScheme() -> SignatureScheme? {
        return self.readInteger().map { SignatureScheme(rawValue: $0) }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeSignatureScheme(_ type: SignatureScheme) -> Int {
        return self.writeInteger(type.rawValue)
    }
}
