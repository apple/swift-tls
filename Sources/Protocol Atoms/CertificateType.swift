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

@_spi(SwiftTLSProtocol)
@available(SwiftTLS 0.1.0, *)
public struct CertificateType: RawRepresentable, Sendable {
    public var rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}

@available(SwiftTLS 0.1.0, *)
extension CertificateType {
    public static let x509 = CertificateType(rawValue: 0)
    public static let rawPublicKey = CertificateType(rawValue: 2)
}

@available(SwiftTLS 0.1.0, *)
extension CertificateType: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension CertificateType: CustomStringConvertible {
    public var description: String {
        switch self {
        case .x509:
            return ".x509"
        case .rawPublicKey:
            return ".rawPublicKey"
        default:
            return "CertificateType(rawValue: \(self.rawValue))"
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readCertificateType() -> CertificateType? {
        return self.readInteger().map { CertificateType(rawValue: $0) }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeCertificateType(_ type: CertificateType) -> Int {
        return self.writeInteger(type.rawValue)
    }
}
