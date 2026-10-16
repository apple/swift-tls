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

@available(SwiftTLS 0.1.0, *)
final class ExporterTests: XCTestCase {

    /// Exporter output matches independently computed SHA256 vectors.
    func testExporterMatchesIndependentSHA256Vectors() throws {
        let secret = KeyScheduleTests.oneRTTExportMasterSecret

        XCTAssertEqual(
            HKDF<SHA256>.tlsExporter(secret: secret, label: Self.authenticatorHandshakeContextLabel, context: [UInt8](), length: 32),
            SymmetricKey(data: Self.authenticatorHandshakeContextKey)
        )
        XCTAssertEqual(
            HKDF<SHA256>.tlsExporter(secret: secret, label: Self.authenticatorFinishedMACKeyLabel, context: [UInt8](), length: 32),
            SymmetricKey(data: Self.authenticatorFinishedMACKey)
        )
        XCTAssertEqual(
            HKDF<SHA256>.tlsExporter(secret: secret, label: "label a", context: [UInt8](), length: 32),
            SymmetricKey(data: Self.exporterEmptyContext)
        )
        XCTAssertEqual(
            HKDF<SHA256>.tlsExporter(secret: secret, label: "label a", context: Array("context".utf8), length: 32),
            SymmetricKey(data: Self.exporterWithContext)
        )
        XCTAssertEqual(
            HKDF<SHA256>.tlsExporter(secret: secret, label: "label a", context: Array("context".utf8), length: 16),
            SymmetricKey(data: Self.exporterLength16)
        )
        XCTAssertEqual(
            HKDF<SHA256>.tlsExporter(secret: secret, label: "label a", context: Array("context".utf8), length: 64),
            SymmetricKey(data: Self.exporterLength64)
        )
    }

    /// Exporter output matches independently computed SHA384 vectors.
    func testExporterMatchesIndependentSHA384Vectors() throws {
        let secret = SymmetricKey(data: Array(UInt8(0)..<UInt8(48)))

        XCTAssertEqual(
            HKDF<SHA384>.tlsExporter(secret: secret, label: "label a", context: [UInt8](), length: 48),
            SymmetricKey(data: Self.sha384ExporterEmptyContext)
        )
        XCTAssertEqual(
            HKDF<SHA384>.tlsExporter(secret: secret, label: "label a", context: Array("context".utf8), length: 48),
            SymmetricKey(data: Self.sha384ExporterWithContext)
        )
        XCTAssertEqual(
            HKDF<SHA384>.tlsExporter(secret: secret, label: "label a", context: Array("context".utf8), length: 12),
            SymmetricKey(data: Self.sha384ExporterLength12)
        )
    }

    /// Different contexts produce different keys.
    func testContextChangesOutput() throws {
        let secret = KeyScheduleTests.oneRTTExportMasterSecret

        let empty = HKDF<SHA256>.tlsExporter(secret: secret, label: "label a", context: [UInt8](), length: 32)
        let context = HKDF<SHA256>.tlsExporter(secret: secret, label: "label a", context: Array("context".utf8), length: 32)
        let nearlyTheSameContext = HKDF<SHA256>.tlsExporter(secret: secret, label: "label a", context: Array("contexu".utf8), length: 32)

        XCTAssertNotEqual(empty, context)
        XCTAssertNotEqual(context, nearlyTheSameContext)
    }

    /// Different labels produce different keys.
    func testLabelChangesOutput() throws {
        let secret = KeyScheduleTests.oneRTTExportMasterSecret

        XCTAssertNotEqual(
            HKDF<SHA256>.tlsExporter(secret: secret, label: Self.authenticatorHandshakeContextLabel, context: [UInt8](), length: 32),
            HKDF<SHA256>.tlsExporter(secret: secret, label: Self.authenticatorFinishedMACKeyLabel, context: [UInt8](), length: 32)
        )
    }

    /// A shorter export is not a prefix of a longer one, since length is bound into `HkdfLabel`.
    func testShorterOutputIsNotAPrefixOfLongerOutput() throws {
        let secret = KeyScheduleTests.oneRTTExportMasterSecret
        let context = Array("context".utf8)

        let short = Self.bytes(of: try XCTUnwrap(HKDF<SHA256>.tlsExporter(secret: secret, label: "label a", context: context, length: 16)))
        let long = Self.bytes(of: try XCTUnwrap(HKDF<SHA256>.tlsExporter(secret: secret, label: "label a", context: context, length: 64)))

        XCTAssertEqual(short.count, 16)
        XCTAssertEqual(long.count, 64)
        XCTAssertNotEqual(short, Array(long.prefix(16)))
    }

    /// No exporter is available before ServerFinished, in any earlier key-schedule state.
    func testExporterUnavailableBeforeServerFinished() throws {
        let idle = ClientSessionKeyManager<SHA256>()
        XCTAssertNil(idle.exporter)

        var afterClientHello = ClientSessionKeyManager<SHA256>()
        var clientHello = KeyScheduleTests.oneRTTClientHello
        _ = try afterClientHello.sendingClientHello(
            clientHello: &clientHello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil
        )
        XCTAssertNil(afterClientHello.exporter)

        var afterServerHello = afterClientHello
        try afterServerHello.postServerHello(
            ecdheSecret: try Self.oneRTTECDHESecret(), serverHelloBytes: KeyScheduleTests.oneRTTServerHello
        )
        XCTAssertNil(afterServerHello.exporter)
    }

    /// The exporter becomes available after ServerFinished and matches the vectors.
    func testExporterAvailableAfterServerFinished() throws {
        let scheduler = try Self.postServerFinishedScheduler()

        XCTAssertEqual(scheduler.exporterMasterSecret, KeyScheduleTests.oneRTTExportMasterSecret)

        let exporter = try XCTUnwrap(scheduler.exporter)
        XCTAssertEqual(
            exporter.exportKeyingMaterial(label: "label a", context: [], length: 32),
            SymmetricKey(data: Self.exporterEmptyContext)
        )
        XCTAssertEqual(
            exporter.exportKeyingMaterial(label: "label a", context: Array("context".utf8), length: 32),
            SymmetricKey(data: Self.exporterWithContext)
        )
    }

    /// Exported keys do not change when the schedule advances past ClientFinished.
    func testExporterStableAcrossClientFinished() throws {
        var scheduler = try Self.postServerFinishedScheduler()

        let beforeClientFinished = try XCTUnwrap(scheduler.exporter)
            .exportKeyingMaterial(label: "label a", context: Array("context".utf8), length: 32)
        XCTAssertNotNil(beforeClientFinished)

        try scheduler.postClientFinished(clientFinishedBytes: KeyScheduleTests.oneRTTClientFinishedMessage)

        XCTAssertEqual(scheduler.resumptionMasterSecret, KeyScheduleTests.oneRTTResumptionMasterSecret)

        let afterClientFinished = try XCTUnwrap(scheduler.exporter)
            .exportKeyingMaterial(label: "label a", context: Array("context".utf8), length: 32)
        XCTAssertEqual(beforeClientFinished, afterClientFinished)
        XCTAssertEqual(afterClientFinished, SymmetricKey(data: Self.exporterWithContext))
    }

    /// Out-of-range lengths return `nil` rather than trapping.
    func testExporterRejectsInvalidLengths() throws {
        let exporter = try XCTUnwrap(try Self.postServerFinishedScheduler().exporter)
        let maximumLength = 255 * SHA256.Digest.byteCount

        XCTAssertNil(exporter.exportKeyingMaterial(label: "label a", context: [], length: 0))
        XCTAssertNil(exporter.exportKeyingMaterial(label: "label a", context: [], length: -1))
        XCTAssertNil(exporter.exportKeyingMaterial(label: "label a", context: [], length: maximumLength + 1))
        XCTAssertNil(exporter.exportKeyingMaterial(label: "label a", context: [], length: 65536))
    }

    /// The smallest and largest valid lengths both derive correctly.
    func testExporterAcceptsBoundaryLengths() throws {
        let exporter = try XCTUnwrap(try Self.postServerFinishedScheduler().exporter)
        let maximumLength = 255 * SHA256.Digest.byteCount

        let single = exporter.exportKeyingMaterial(label: "label a", context: [], length: 1)
        XCTAssertEqual(Self.bytes(of: try XCTUnwrap(single)).count, 1)

        let maximum = try XCTUnwrap(exporter.exportKeyingMaterial(label: "label a", context: [], length: maximumLength))
        let maximumBytes = Self.bytes(of: maximum)
        XCTAssertEqual(maximumBytes.count, maximumLength)
        XCTAssertEqual(Array(maximumBytes.prefix(16)), Self.exporterMaxLengthPrefix)
    }

    /// Labels over 249 UTF-8 bytes return `nil` rather than trapping.
    func testExporterRejectsOverlongLabel() throws {
        let exporter = try XCTUnwrap(try Self.postServerFinishedScheduler().exporter)
        let maximumLabelLength = 255 - "tls13 ".utf8.count

        let longest = String(repeating: "a", count: maximumLabelLength)
        XCTAssertNotNil(exporter.exportKeyingMaterial(label: longest, context: [], length: 32))

        for count in [maximumLabelLength + 1, 255, 256, 10_000] {
            XCTAssertNil(
                exporter.exportKeyingMaterial(label: String(repeating: "a", count: count), context: [], length: 32),
                "label of \(count) bytes should be rejected"
            )
        }

        XCTAssertNil(exporter.exportKeyingMaterial(label: String(repeating: "é", count: 200), context: [], length: 32))
        XCTAssertNotNil(exporter.exportKeyingMaterial(label: String(repeating: "é", count: 100), context: [], length: 32))
    }

    /// Contexts of any length are accepted, and distinct contexts stay distinct.
    func testExporterAcceptsArbitrarilyLongContext() throws {
        let exporter = try XCTUnwrap(try Self.postServerFinishedScheduler().exporter)

        for count in [0, 255, 256, 100_000] {
            XCTAssertNotNil(
                exporter.exportKeyingMaterial(
                    label: "label a", context: Array(repeating: UInt8(0x61), count: count), length: 32
                ),
                "context of \(count) bytes should be accepted"
            )
        }

        let a = exporter.exportKeyingMaterial(label: "label a", context: Array(repeating: 0x61, count: 300), length: 32)
        var bBytes = Array(repeating: UInt8(0x61), count: 300)
        bBytes[299] = 0x62
        let b = exporter.exportKeyingMaterial(label: "label a", context: bBytes, length: 32)
        XCTAssertNotNil(a)
        XCTAssertNotEqual(a, b)
    }

    /// `SwiftTLSExporter` matches deriving straight from the key schedule.
    func testSwiftTLSExporterMatchesVectors() throws {
        let exporter = SwiftTLSExporter(
            exporterMasterSecret: KeyScheduleTests.oneRTTExportMasterSecret, hashFunction: SHA256.self
        )

        XCTAssertEqual(exporter.exportKeyingMaterial(label: "label a", context: [], length: 32), SymmetricKey(data: Self.exporterEmptyContext))
        XCTAssertEqual(
            exporter.exportKeyingMaterial(label: "label a", context: Array("context".utf8), length: 32),
            SymmetricKey(data: Self.exporterWithContext)
        )
        XCTAssertEqual(
            exporter.exportKeyingMaterial(label: "label a", context: Array("context".utf8), length: 16),
            SymmetricKey(data: Self.exporterLength16)
        )
        XCTAssertEqual(
            exporter.exportKeyingMaterial(label: Self.authenticatorHandshakeContextLabel, context: [], length: 32),
            SymmetricKey(data: Self.authenticatorHandshakeContextKey)
        )
    }

    /// `SwiftTLSExporter` derives with the hash function it was created with.
    func testSwiftTLSExporterHonoursHashFunction() throws {
        let exporter = SwiftTLSExporter(
            exporterMasterSecret: SymmetricKey(data: Array(UInt8(0)..<UInt8(48))), hashFunction: SHA384.self
        )

        XCTAssertEqual(exporter.exportKeyingMaterial(label: "label a", context: [], length: 48), SymmetricKey(data: Self.sha384ExporterEmptyContext))
        XCTAssertEqual(
            exporter.exportKeyingMaterial(label: "label a", context: Array("context".utf8), length: 12),
            SymmetricKey(data: Self.sha384ExporterLength12)
        )
    }

    /// `SwiftTLSExporter` enforces the length limits, which scale with the hash.
    func testSwiftTLSExporterValidatesLength() throws {
        let sha256Exporter = SwiftTLSExporter(
            exporterMasterSecret: KeyScheduleTests.oneRTTExportMasterSecret, hashFunction: SHA256.self
        )
        XCTAssertNil(sha256Exporter.exportKeyingMaterial(label: "label a", context: [], length: 0))
        XCTAssertNil(sha256Exporter.exportKeyingMaterial(label: "label a", context: [], length: -1))
        XCTAssertNil(sha256Exporter.exportKeyingMaterial(label: "label a", context: [], length: 65536))
        XCTAssertNil(sha256Exporter.exportKeyingMaterial(label: "label a", context: [], length: 255 * 32 + 1))
        XCTAssertEqual(sha256Exporter.exportKeyingMaterial(label: "label a", context: [], length: 255 * 32)?.bitCount, 255 * 32 * 8)

        let sha384Exporter = SwiftTLSExporter(
            exporterMasterSecret: SymmetricKey(data: Array(UInt8(0)..<UInt8(48))), hashFunction: SHA384.self
        )
        XCTAssertNil(sha256Exporter.exportKeyingMaterial(label: "label a", context: [], length: 255 * 48))
        XCTAssertEqual(sha384Exporter.exportKeyingMaterial(label: "label a", context: [], length: 255 * 48)?.bitCount, 255 * 48 * 8)
    }

    /// Known-answer vectors for the two exporter labels RFC 9261 defines.
    func testAuthenticatorLabelsPreserveBehaviour() throws {
        let exporter = try XCTUnwrap(try Self.postServerFinishedScheduler().exporter)

        XCTAssertEqual(
            exporter.exportKeyingMaterial(
                label: Self.authenticatorHandshakeContextLabel, context: [], length: SHA256.Digest.byteCount
            ),
            SymmetricKey(data: Self.authenticatorHandshakeContextKey)
        )
        XCTAssertEqual(
            exporter.exportKeyingMaterial(
                label: Self.authenticatorFinishedMACKeyLabel, context: [], length: SHA256.Digest.byteCount
            ),
            SymmetricKey(data: Self.authenticatorFinishedMACKey)
        )
    }
}

@available(SwiftTLS 0.1.0, *)
extension ExporterTests {
    static func bytes(of key: SymmetricKey) -> [UInt8] {
        return key.withUnsafeBytes { Array($0) }
    }

    static func oneRTTECDHESecret() throws -> SymmetricKey {
        return SymmetricKey(
            data: try KeyScheduleTests.oneRTTClientX25519Key.sharedSecretFromKeyAgreement(
                with: KeyScheduleTests.oneRTTServerX25519Key.publicKey
            )
        )
    }

    static func postServerFinishedScheduler() throws -> ClientSessionKeyManager<SHA256> {
        var scheduler = ClientSessionKeyManager<SHA256>()

        var clientHello = KeyScheduleTests.oneRTTClientHello
        _ = try scheduler.sendingClientHello(
            clientHello: &clientHello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil
        )
        try scheduler.postServerHello(
            ecdheSecret: try Self.oneRTTECDHESecret(), serverHelloBytes: KeyScheduleTests.oneRTTServerHello
        )
        try scheduler.addPreFinishedMessageToTransportHash(KeyScheduleTests.oneRTTServerEncryptedExtensions)
        try scheduler.addPreFinishedMessageToTransportHash(KeyScheduleTests.oneRTTServerCertificateMessage)
        try scheduler.addPreFinishedMessageToTransportHash(KeyScheduleTests.oneRTTServerCertificateVerify)
        try scheduler.postServerFinished(serverFinishedBytes: KeyScheduleTests.oneRTTServerFinishedMessage)

        return scheduler
    }
}

@available(SwiftTLS 0.1.0, *)
extension ExporterTests {
    static let authenticatorHandshakeContextLabel = "EXPORTER-server authenticator handshake context"
    static let authenticatorFinishedMACKeyLabel = "EXPORTER-server authenticator finished key"

    static let authenticatorHandshakeContextKey: [UInt8] = [
        0xb5, 0x92, 0x02, 0x28, 0x10, 0x28, 0x85, 0xce, 0x3b, 0xbc, 0x87, 0x92,
        0x52, 0xd7, 0xc4, 0xae, 0x80, 0xf4, 0x76, 0x16, 0xcd, 0xc9, 0x14, 0x56,
        0x33, 0x84, 0x27, 0xe7, 0x89, 0x09, 0x41, 0xb0
    ]

    static let authenticatorFinishedMACKey: [UInt8] = [
        0xd7, 0x57, 0x1c, 0xcc, 0x15, 0x77, 0xb0, 0x42, 0x77, 0x76, 0x5d, 0xa1,
        0xc8, 0x75, 0xd9, 0x33, 0xbe, 0x15, 0x71, 0x7b, 0x3e, 0xcf, 0x45, 0xd0,
        0x70, 0x84, 0x31, 0xfa, 0x07, 0x7d, 0xf5, 0x4d
    ]

    static let exporterEmptyContext: [UInt8] = [
        0x8e, 0x58, 0x5e, 0xc7, 0xfc, 0x4f, 0xa7, 0xcb, 0xcd, 0xe6, 0x30, 0xd9,
        0x88, 0xba, 0x29, 0xd8, 0xb3, 0x20, 0x8c, 0x7f, 0xfa, 0x44, 0x25, 0xc3,
        0x1a, 0xbf, 0xf4, 0x13, 0x9c, 0x37, 0x98, 0x24
    ]

    static let exporterWithContext: [UInt8] = [
        0x6e, 0xaf, 0xfc, 0xfa, 0x8d, 0xbe, 0x3d, 0xc6, 0x35, 0x46, 0x84, 0xc7,
        0x24, 0x81, 0x33, 0x7e, 0x9d, 0x33, 0x68, 0x63, 0xbc, 0x2f, 0xf8, 0x5d,
        0x47, 0x59, 0xf1, 0xab, 0x70, 0xac, 0x15, 0x58
    ]

    static let exporterLength16: [UInt8] = [
        0x44, 0xd8, 0xff, 0xe8, 0x51, 0xb1, 0x5b, 0x84, 0xc0, 0x4d, 0xbc, 0x92,
        0x54, 0x50, 0xdf, 0x9d
    ]

    static let exporterLength64: [UInt8] = [
        0x8f, 0x03, 0x12, 0x8d, 0x7d, 0xad, 0xdb, 0x1d, 0xf0, 0x7e, 0xd5, 0xbe,
        0xcb, 0x13, 0xbe, 0x39, 0x0d, 0xf0, 0xc2, 0xd3, 0x7d, 0xa3, 0xcc, 0x74,
        0x1e, 0x2b, 0xaf, 0xb0, 0x3c, 0xc3, 0xd8, 0xb4, 0x4c, 0x5e, 0xc8, 0x7c,
        0x9d, 0xf1, 0x9b, 0x6a, 0x72, 0xe4, 0xc0, 0xbe, 0x29, 0xa7, 0xa1, 0x1f,
        0x8a, 0x52, 0xc1, 0x94, 0xad, 0xf7, 0xc6, 0xa6, 0x43, 0x49, 0x13, 0x6b,
        0xf1, 0x97, 0xdd, 0x93
    ]

    static let exporterMaxLengthPrefix: [UInt8] = [
        0x51, 0xba, 0xda, 0x53, 0xff, 0x3a, 0x5d, 0x18, 0x77, 0x49, 0x42, 0xab,
        0xd1, 0x87, 0x64, 0xac
    ]

    static let sha384ExporterEmptyContext: [UInt8] = [
        0x4f, 0x85, 0x52, 0xbb, 0xd3, 0x93, 0xe8, 0xa9, 0x17, 0x4f, 0x2b, 0x8f,
        0xcb, 0x5c, 0x6e, 0x50, 0x47, 0xd4, 0xf3, 0x2d, 0x8a, 0x9e, 0x87, 0x3f,
        0x43, 0xfe, 0x37, 0xd0, 0x14, 0x05, 0x73, 0xba, 0x4c, 0x11, 0x41, 0x89,
        0x37, 0x3b, 0xc4, 0x35, 0x7d, 0x27, 0xd1, 0xa1, 0x22, 0xf4, 0x47, 0xd7
    ]

    static let sha384ExporterWithContext: [UInt8] = [
        0x3f, 0xd8, 0xd6, 0x42, 0xac, 0xf6, 0x49, 0x01, 0xcd, 0x2e, 0x97, 0xb3,
        0x76, 0x71, 0x8c, 0x57, 0x71, 0x25, 0x0a, 0x6a, 0x1d, 0x44, 0x70, 0x0b,
        0xe6, 0x73, 0x08, 0xbe, 0xac, 0x11, 0x48, 0xec, 0x76, 0x27, 0x43, 0x03,
        0xea, 0x23, 0x47, 0x16, 0xd4, 0x13, 0xa6, 0xaa, 0x77, 0x13, 0x55, 0xf0
    ]

    static let sha384ExporterLength12: [UInt8] = [
        0x2c, 0x3c, 0x63, 0xea, 0x01, 0xa2, 0xde, 0x0a, 0x84, 0x87, 0x23, 0xf0
    ]
}
