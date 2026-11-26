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

import XCTest
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif
#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@testable @_spi(SwiftTLSProtocol) import SwiftTLS
#endif

/// Validates `HKDF.expandLabel` against published vectors and against an independent construction of `HkdfLabel`.
// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
final class HKDFExpandLabelTests: XCTestCase {
    private static func bytes(hex: String) -> [UInt8] {
        var result = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            result.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return result
    }

    /// Builds `HkdfLabel` (RFC 8446 Section 7.1) with array appends only.
    private static func referenceHkdfLabel(label: String, context: [UInt8], length: Int) -> [UInt8] {
        let fullLabel = Array("tls13 ".utf8) + Array(label.utf8)
        var result = [UInt8(length >> 8), UInt8(length & 0xff), UInt8(fullLabel.count)]
        result += fullLabel
        result.append(UInt8(context.count))
        result += context
        return result
    }

    private func assertMatchesReference<H: HashFunction>(
        _: H.Type,
        label: String,
        context: [UInt8],
        length: Int,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        let secret = SymmetricKey(data: (0..<H.Digest.byteCount).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) })
        let actual = HKDF<H>.expandLabel(secret: secret, label: label, context: context, length: length)
        let expected = HKDF<H>.expand(
            pseudoRandomKey: secret,
            info: Self.referenceHkdfLabel(label: label, context: context, length: length),
            outputByteCount: length
        )
        XCTAssertEqual(actual, expected, "label \(label.utf8.count) context \(context.count)", file: file, line: line)
    }

    // MARK: RFC 8448 Section 3

    func testRFC8448DerivedSecret() {
        // RFC 8448 Section 3: Derive-Secret(early secret, "derived", "") with SHA-256.
        let earlySecret = SymmetricKey(data: Self.bytes(hex: "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"))
        let derived = HKDF<SHA256>.deriveSecret(secret: earlySecret, label: "derived", transcriptHash: SHA256.hash(data: [UInt8]()))
        XCTAssertEqual(
            derived,
            SymmetricKey(data: Self.bytes(hex: "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"))
        )
    }

    // MARK: RFC 9001 Appendix A.1

    func testRFC9001InitialSecrets() {
        let salt = SymmetricKey(data: Self.bytes(hex: "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"))
        let destinationConnectionID = SymmetricKey(data: Self.bytes(hex: "8394c8f03e515708"))
        let initialSecret = SymmetricKey(data: HKDF<SHA256>.extract(inputKeyMaterial: destinationConnectionID, salt: salt))

        let clientSecret = HKDF<SHA256>.expandLabel(secret: initialSecret, label: "client in", context: [UInt8](), length: 32)
        XCTAssertEqual(
            clientSecret,
            SymmetricKey(data: Self.bytes(hex: "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"))
        )
        XCTAssertEqual(
            HKDF<SHA256>.expandLabel(secret: clientSecret, label: "quic key", context: [UInt8](), length: 16),
            SymmetricKey(data: Self.bytes(hex: "1f369613dd76d5467730efcbe3b1a22d"))
        )
        XCTAssertEqual(
            HKDF<SHA256>.expandLabel(secret: clientSecret, label: "quic iv", context: [UInt8](), length: 12),
            SymmetricKey(data: Self.bytes(hex: "fa044b2f42a3fd3b46fb255c"))
        )
        XCTAssertEqual(
            HKDF<SHA256>.expandLabel(secret: clientSecret, label: "quic hp", context: [UInt8](), length: 16),
            SymmetricKey(data: Self.bytes(hex: "9f50449e04a0e810283a1e9933adedd2"))
        )

        let serverSecret = HKDF<SHA256>.expandLabel(secret: initialSecret, label: "server in", context: [UInt8](), length: 32)
        XCTAssertEqual(
            serverSecret,
            SymmetricKey(data: Self.bytes(hex: "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"))
        )
    }

    // MARK: Reference construction

    func testMatchesReferenceAcrossLabelAndContextLengths() {
        for labelCount in [0, 1, 7, 8, 50, 100, 248] {
            for contextCount in [0, 1, 32, 48, 128, 254, 255] {
                self.assertMatchesReference(
                    SHA256.self,
                    label: String(repeating: "l", count: labelCount),
                    context: (0..<contextCount).map { UInt8(truncatingIfNeeded: $0) },
                    length: 32
                )
                self.assertMatchesReference(
                    SHA384.self,
                    label: String(repeating: "l", count: labelCount),
                    context: (0..<contextCount).map { UInt8(truncatingIfNeeded: $0 &+ 1) },
                    length: 48
                )
            }
        }
    }

    func testMatchesReferenceAtMaximumLabelAndContextLength() {
        // The prefixed label is capped at 255 bytes, and "tls13 " takes 6 of them. The context is capped at 255 bytes.
        let maximumLabel = String(repeating: "m", count: 255 - 6)
        let maximumContext = [UInt8](repeating: 0xa5, count: 255)
        XCTAssertEqual(Self.referenceHkdfLabel(label: maximumLabel, context: maximumContext, length: 32).count, 514)
        self.assertMatchesReference(SHA256.self, label: maximumLabel, context: maximumContext, length: 32)
        self.assertMatchesReference(SHA384.self, label: maximumLabel, context: maximumContext, length: 255)
    }

    func testMatchesReferenceForDigestAndNonDigestOutputLengths() {
        for length in [1, 12, 16, 31, 32, 33, 64, 255] {
            self.assertMatchesReference(SHA256.self, label: "quic key", context: [], length: length)
        }
    }
}
