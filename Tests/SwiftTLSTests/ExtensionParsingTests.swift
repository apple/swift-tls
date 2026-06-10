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
class ExtensionParsingTests: XCTestCase {
    /// Handy-dandy temporary key
    let key = P384.KeyAgreement.PrivateKey()

    var buffer: ByteBuffer!

    override func setUp() {
        self.buffer = ByteBuffer()
    }

    override func tearDown() {
        self.buffer = nil
    }

    func assertIncrementalRead<Result: Equatable>(expected: Result, readFunction: (inout ByteBuffer) throws -> Result?) rethrows {
        for length in 0..<self.buffer.readableBytes {
            var slice = ByteBuffer(data: self.buffer.readableBytesView.prefix(length))
            XCTAssertNil(try readFunction(&slice))
        }

        XCTAssertEqual(expected, try readFunction(&self.buffer))
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testKeyShareClientHello() throws {
        let ext = Extension.KeyShare.clientHello(
            [
                .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation)),
                .init(group: .init(rawValue: 1), keyExchange: ByteBuffer("Arbitrary bytes")),
            ]
        )

        let written = self.buffer.writeExtension(.keyShare(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.withInputBuffer { buffer in
            try buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        }
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .keyShare(ext))
    }

    func testKeyShareClientHello_incremental() throws {
        let ext = Extension.KeyShare.clientHello(
            [
                .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation)),
                .init(group: .init(rawValue: 1), keyExchange: ByteBuffer("Arbitrary bytes")),
            ]
        )

        self.buffer.writeExtension(.keyShare(ext))
        try self.assertIncrementalRead(expected: .keyShare(ext), readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testKeyShareClientHello_failsToParseInServerHello() throws {
        let ext = Extension.KeyShare.clientHello(
            [
                .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation)),
                .init(group: .init(rawValue: 1), keyExchange: ByteBuffer("Arbitrary bytes")),
            ]
        )

        self.buffer.writeExtension(.keyShare(ext))
        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: false))
    }

    func testKeyShareClientHello_failsToParseInHelloRetryRequest() throws {
        let ext = Extension.KeyShare.clientHello(
            [
                .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation)),
                .init(group: .init(rawValue: 1), keyExchange: ByteBuffer("Arbitrary bytes")),
            ]
        )

        self.buffer.writeExtension(.keyShare(ext))
        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: true))
    }

    func testKeyShareClientHello_failsToParseInAllOtherMessages() throws {
        let ext = Extension.KeyShare.clientHello(
            [
                .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation)),
                .init(group: .init(rawValue: 1), keyExchange: ByteBuffer("Arbitrary bytes")),
            ]
        )

        self.buffer.writeExtension(.keyShare(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: false))
        }
    }

    func testKeyShareServerHello() throws {
        let ext = Extension.KeyShare.serverHello(
            .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation))
        )

        let written = self.buffer.writeExtension(.keyShare(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .keyShare(ext))
    }

    func testKeyShareServerHello_incremental() throws {
        let ext = Extension.KeyShare.serverHello(
            .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation))
        )

        self.buffer.writeExtension(.keyShare(ext))
        try self.assertIncrementalRead(expected: .keyShare(ext), readFunction: { try $0.readExtension(messageType: .serverHello, helloRetryRequest: false) })
    }

    func testKeyShareServerHello_failsToParseInClientHello() throws {
        let ext = Extension.KeyShare.serverHello(
            .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation))
        )

        self.buffer.writeExtension(.keyShare(ext))
        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testKeyShareServerHello_failsToParseInHelloRetryRequest() throws {
        let ext = Extension.KeyShare.serverHello(
            .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation))
        )

        self.buffer.writeExtension(.keyShare(ext))
        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: true))
    }

    func testKeyShareServerHello_failsToParseInAllOtherMessages() throws {
        let ext = Extension.KeyShare.serverHello(
            .init(group: .secp384, keyExchange: ByteBuffer(data: key.publicKey.x963Representation))
        )

        self.buffer.writeExtension(.keyShare(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: false))
        }
    }

    func testKeyShareHelloRetryRequest() throws {
        let ext = Extension.KeyShare.helloRetryRequest(.secp384)

        let written = self.buffer.writeExtension(.keyShare(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: true)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .keyShare(ext))
    }

    func testKeyShareHelloRetryRequest_incremental() throws {
        let ext = Extension.KeyShare.helloRetryRequest(.secp384)

        self.buffer.writeExtension(.keyShare(ext))
        try self.assertIncrementalRead(expected: .keyShare(ext), readFunction: { try $0.readExtension(messageType: .serverHello, helloRetryRequest: true) })
    }

    func testKeyShareHelloRetryRequest_failsToParseInClientHello() throws {
        let ext = Extension.KeyShare.helloRetryRequest(.secp384)

        self.buffer.writeExtension(.keyShare(ext))
        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testKeyShareHelloRetryRequest_failsToParseInServerHello() throws {
        let ext = Extension.KeyShare.helloRetryRequest(.secp384)

        self.buffer.writeExtension(.keyShare(ext))
        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: false))
    }

    func testKeyShareHelloRetryRequest_failsToParseInAllOtherMessages() throws {
        let ext = Extension.KeyShare.helloRetryRequest(.secp384)

        self.buffer.writeExtension(.keyShare(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: false))
        }
    }

    func testKeyShareHelloRetryRequest_truncatedNamedGroup() throws {
        self.buffer.writeBytes([0, 51, 0, 1, 0])
        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: true))
    }

    func testSupportedGroupsClientHello() throws {
        let ext = Extension.SupportedGroups(groups: [.secp384, .init(rawValue: 0x8765)])

        let written = self.buffer.writeExtension(.supportedGroups(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .supportedGroups(ext))
    }

    func testSupportedGroupsClientHello_incremental() throws {
        let ext = Extension.SupportedGroups(groups: [.secp384, .init(rawValue: 0x8765)])

        self.buffer.writeExtension(.supportedGroups(ext))
        try self.assertIncrementalRead(expected: .supportedGroups(ext), readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testSupportedGroupsEncryptedExtensions() throws {
        let ext = Extension.SupportedGroups(groups: [.secp384, .init(rawValue: 0x8765)])

        let written = self.buffer.writeExtension(.supportedGroups(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .supportedGroups(ext))
    }

    func testSupportedGroupsEncryptedExtensions_incremental() throws {
        let ext = Extension.SupportedGroups(groups: [.secp384, .init(rawValue: 0x8765)])

        self.buffer.writeExtension(.supportedGroups(ext))
        try self.assertIncrementalRead(expected: .supportedGroups(ext), readFunction: { try $0.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false) })
    }

    func testSupportedGroups_failsToParseInAllOtherMessages() throws {
        let ext = Extension.SupportedGroups(groups: [.secp384, .init(rawValue: 0x8765)])

        self.buffer.writeExtension(.supportedGroups(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testSupportedGroups_truncatedGroup() throws {
        // A supported groups message with a truncated group (1 byte)
        self.buffer.writeBytes([0, 10, 0, 3, 0, 23, 0])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .clientHello, helloRetryRequest: false))

        copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false))
    }

    func testSupportedVersionsClientHello() throws {
        let ext = Extension.SupportedVersions.offer([.tlsv10, .tlsv11, .tlsv12, .tlsv13])

        let written = self.buffer.writeExtension(.supportedVersions(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .supportedVersions(ext))
    }

    func testSupportedVersionsClientHello_incremental() throws {
        let ext = Extension.SupportedVersions.offer([.tlsv10, .tlsv11, .tlsv12, .tlsv13])

        self.buffer.writeExtension(.supportedVersions(ext))
        try self.assertIncrementalRead(expected: .supportedVersions(ext), readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testSupportedVersionsClientHello_failsToParseInServerHello() throws {
        let ext = Extension.SupportedVersions.offer([.tlsv10, .tlsv11, .tlsv12, .tlsv13])

        self.buffer.writeExtension(.supportedVersions(ext))
        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: false))
    }

    func testSupportedVersionsClientHello_failsToParseInAllOtherMessages() throws {
        let ext = Extension.SupportedVersions.offer([.tlsv10, .tlsv11, .tlsv12, .tlsv13])

        self.buffer.writeExtension(.supportedVersions(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: messageType == .serverHello ? true : false))
        }
    }

    func testSupportedVersionsServerHello() throws {
        let ext = Extension.SupportedVersions.selection(.tlsv13)

        let written = self.buffer.writeExtension(.supportedVersions(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .supportedVersions(ext))
    }

    func testSupportedVersionsServerHello_incremental() throws {
        let ext = Extension.SupportedVersions.selection(.tlsv13)

        self.buffer.writeExtension(.supportedVersions(ext))
        try self.assertIncrementalRead(expected: .supportedVersions(ext), readFunction: { try $0.readExtension(messageType: .serverHello, helloRetryRequest: false) })
    }

    func testSupportedVersionsHelloRetryRequest() throws {
        let ext = Extension.SupportedVersions.selection(.tlsv13)

        let written = self.buffer.writeExtension(.supportedVersions(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: true)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .supportedVersions(ext))
    }

    func testSupportedVersionsHelloRetryRequest_incremental() throws {
        let ext = Extension.SupportedVersions.selection(.tlsv13)

        self.buffer.writeExtension(.supportedVersions(ext))
        try self.assertIncrementalRead(expected: .supportedVersions(ext), readFunction: { try $0.readExtension(messageType: .serverHello, helloRetryRequest: true) })
    }

    func testSupportedVersionsServerHello_failsToParseInAllOtherMessages() throws {
        let ext = Extension.SupportedVersions.selection(.tlsv13)

        self.buffer.writeExtension(.supportedVersions(ext))

        // We skip testing clientHello here because this extensions parses as `nil` there. That will still error in meta code, where extensions
        // may not parse nil.
        let unsupportedMessageTypes: [HandshakeType] = [
            .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: messageType == .serverHello ? true : false))
        }
    }

    func testSupportedVersionsClientHello_truncatedVersion() throws {
        // A supported versions message with a truncated version (1 byte)
        self.buffer.writeBytes([0, 43, 0, 3, 3, 1, 3])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testSupportedVersionsServerHello_truncatedVersion() throws {
        // A supported versions message with a truncated version (1 byte)
        self.buffer.writeBytes([0, 43, 0, 1, 3])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .serverHello, helloRetryRequest: false))
    }

    func testSupportedVersionsHelloRetryRequest_truncatedVersion() throws {
        // A supported versions message with a truncated version (1 byte)
        self.buffer.writeBytes([0, 43, 0, 1, 3])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .serverHello, helloRetryRequest: false))
    }

    func testSignatureAlgorithmsClientHello() throws {
        let ext = Extension.SignatureAlgorithms(schemes: [.ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha256])

        let written = self.buffer.writeExtension(.signatureAlgorithms(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .signatureAlgorithms(ext))
    }

    func testSignatureAlgorithmsClientHello_incremental() throws {
        let ext = Extension.SignatureAlgorithms(schemes: [.ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha256])

        self.buffer.writeExtension(.signatureAlgorithms(ext))
        try self.assertIncrementalRead(expected: .signatureAlgorithms(ext), readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testSignatureAlgorithmsCertificateRequest() throws {
        let ext = Extension.SignatureAlgorithms(schemes: [.ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha256])

        let written = self.buffer.writeExtension(.signatureAlgorithms(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .certificateRequest, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .signatureAlgorithms(ext))
    }

    func testSignatureAlgorithmsCertificateRequest_incremental() throws {
        let ext = Extension.SignatureAlgorithms(schemes: [.ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha256])

        self.buffer.writeExtension(.signatureAlgorithms(ext))
        try self.assertIncrementalRead(expected: .signatureAlgorithms(ext), readFunction: { try $0.readExtension(messageType: .certificateRequest, helloRetryRequest: false) })
    }

    func testSignatureAlgorithms_failsToParseInAllOtherMessages() throws {
        let ext = Extension.SignatureAlgorithms(schemes: [.ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha256])

        self.buffer.writeExtension(.signatureAlgorithms(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .encryptedExtensions, .certificate, .certificateVerify, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testSignatureAlgorithmsClientHello_truncatedVersion() throws {
        // A supported versions message with a truncated algorithm (1 byte)
        self.buffer.writeBytes([0, 13, 0, 5, 0, 3, 4, 3, 3])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testSignatureAlgorithmsCertificateRequest_truncatedVersion() throws {
        // A supported versions message with a truncated algorithm (1 byte)
        self.buffer.writeBytes([0, 13, 0, 5, 0, 3, 4, 3, 3])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .certificateRequest, helloRetryRequest: false))
    }

    func testSignatureAlgorithmsClientHello_truncatedVersionsLength() throws {
        // A supported versions message with an excessive length of the versions field.
        self.buffer.writeBytes([0, 13, 0, 4, 0, 4, 4, 3])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testSignatureAlgorithmsCertificateRequest_truncatedVersionsLength() throws {
        // A supported versions message with an excessive length of the versions field.
        self.buffer.writeBytes([0, 13, 0, 4, 0, 4, 4, 3])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .certificateRequest, helloRetryRequest: false))
    }

    func testTolerateUnknownExtensionsInAllMessages() throws {
        self.buffer.writeBytes([255, 255, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8])
        let expected = Extension.unknownExtension(ExtensionType(rawValue: 0xffff), ByteBuffer(bytes: [1, 2, 3, 4, 5, 6, 7, 8]))

        let messageTypes: [HandshakeType] = [
            .clientHello, .serverHello, .encryptedExtensions, .certificateRequest, .certificate, .certificateVerify, .finished, .endOfEarlyData
        ]

        for messageType in messageTypes {
            var copy = self.buffer!
            let result = try copy.readExtension(messageType: messageType, helloRetryRequest: false)
            XCTAssertEqual(result, expected)


            if messageType == .serverHello {
                var copy = self.buffer!
                let result = try copy.readExtension(messageType: messageType, helloRetryRequest: true)
                XCTAssertEqual(result, expected)
            }
        }
    }

    func testServerCertificateTypeClientHello() throws {
        let ext = Extension.CertificateTypeExt.offer([.rawPublicKey, .x509])

        let written = self.buffer.writeExtension(.serverCertificateType(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .serverCertificateType(ext))
    }

    func testServerCertificateTypeClientHello_incremental() throws {
        let ext = Extension.CertificateTypeExt.offer([.rawPublicKey, .x509])

        self.buffer.writeExtension(.serverCertificateType(ext))
        try self.assertIncrementalRead(expected: .serverCertificateType(ext), readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testServerCertificateTypeEncryptedExtensions() throws {
        let ext = Extension.CertificateTypeExt.selection(.x509)

        let written = self.buffer.writeExtension(.serverCertificateType(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .serverCertificateType(ext))
    }

    func testServerCertificateTypeEncryptedExtensions_incremental() throws {
        let ext = Extension.CertificateTypeExt.selection(.x509)

        self.buffer.writeExtension(.serverCertificateType(ext))
        try self.assertIncrementalRead(expected: .serverCertificateType(ext), readFunction: { try $0.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false) })
    }

    func testServerCertificateTypeOffer_failsToParseInAllOtherMessages() throws {
        let ext = Extension.CertificateTypeExt.offer([.rawPublicKey, .x509])

        self.buffer.writeExtension(.serverCertificateType(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .certificateRequest, .certificate, .certificateVerify, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testServerCertificateTypeSelection_failsToParseInAllOtherMessages() throws {
        let ext = Extension.CertificateTypeExt.selection(.x509)

        self.buffer.writeExtension(.serverCertificateType(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .certificateRequest, .certificate, .certificateVerify, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testServerCertificateTypeClientHello_truncatedCertificateTypesLength() throws {
        // A supported versions message with an excessive length of the certificate type field.
        self.buffer.writeBytes([0, 20, 0, 4, 4, 3, 2, 1])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testServerCertificateTypeEncryptedExtensions_missingCertificateType() throws {
        // A supported versions message missing the certificate type field
        self.buffer.writeBytes([0, 20, 0, 0])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false))
    }

    func testALPNClientHello() throws {
        let ext = Extension.ApplicationLayerProtocolNegotiation.offer(["a protocol", "anotha one"])

        let written = self.buffer.writeExtension(.alpn(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .alpn(ext))
    }

    func testALPNClientHello_incremental() throws {
        let ext = Extension.ApplicationLayerProtocolNegotiation.offer(["a protocol", "anotha one"])

        self.buffer.writeExtension(.alpn(ext))
        try self.assertIncrementalRead(expected: .alpn(ext), readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testALPNEncryptedExtensions() throws {
        let ext = Extension.ApplicationLayerProtocolNegotiation.selection("a protocol")

        let written = self.buffer.writeExtension(.alpn(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .alpn(ext))
    }

    func testALPNEncryptedExtensionsOfferFailsToParse() throws {
        let ext = Extension.ApplicationLayerProtocolNegotiation.offer(["a protocol", "anotha one"])

        let written = self.buffer.writeExtension(.alpn(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false))
    }

    func testALPNEncryptedExtensions_incremental() throws {
        let ext = Extension.ApplicationLayerProtocolNegotiation.selection("a protocol")

        self.buffer.writeExtension(.alpn(ext))
        try self.assertIncrementalRead(expected: .alpn(ext), readFunction: { try $0.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false) })
    }

    func testALPN_failsToParseInAllOtherMessages() throws {
        let ext = Extension.ApplicationLayerProtocolNegotiation.offer(["a protocol", "anotha one"])

        self.buffer.writeExtension(.alpn(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .certificateRequest, .certificate, .certificateVerify, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testALPN_truncatedOpaqueLengthClientHello() throws {
        // A supported versions message with an excessive length of the opaque bytes field.
        self.buffer.writeBytes([0, 16, 0, 5, 0, 4, 3, 2, 1])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testALPN_truncatedOpaqueLengthEncryptedExtensions() throws {
        // A supported versions message with an excessive length of the opaque bytes field.
        self.buffer.writeBytes([0, 16, 0, 5, 0, 4, 3, 2, 1])

        var copy = self.buffer!
        XCTAssertThrowsError(try copy.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false))
    }

    func testQUICTransportParametersClientHello() throws {
        let ext = Extension.QUICTransportParameters(opaqueOffer: ByteBuffer("some strings"))

        let written = self.buffer.writeExtension(.quicTransportParameters(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .quicTransportParameters(ext))
    }

    func testQUICTransportParametersClientHello_incremental() throws {
        let ext = Extension.QUICTransportParameters(opaqueOffer: ByteBuffer("some strings"))

        self.buffer.writeExtension(.quicTransportParameters(ext))
        try self.assertIncrementalRead(expected: .quicTransportParameters(ext), readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testQUICTransportParametersEncryptedExtensions() throws {
        let ext = Extension.QUICTransportParameters(opaqueOffer: ByteBuffer("some strings"))

        let written = self.buffer.writeExtension(.quicTransportParameters(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .quicTransportParameters(ext))
    }

    func testQUICTransportParametersEncryptedExtensions_incremental() throws {
        let ext = Extension.QUICTransportParameters(opaqueOffer: ByteBuffer("some strings"))

        self.buffer.writeExtension(.quicTransportParameters(ext))
        try self.assertIncrementalRead(expected: .quicTransportParameters(ext), readFunction: { try $0.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false) })
    }

    func testQUICTransportParameters_failsToParseInAllOtherMessages() throws {
        let ext = Extension.QUICTransportParameters(opaqueOffer: ByteBuffer("some strings"))

        self.buffer.writeExtension(.quicTransportParameters(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .certificateRequest, .certificate, .certificateVerify, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testEarlyDataClientHello() throws {
        let ext = Extension.EarlyData()

        let written = self.buffer.writeExtension(.earlyData(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .earlyData(ext))
    }

    func testEarlyDataClientHello_incremental() throws {
        let ext = Extension.EarlyData()

        self.buffer.writeExtension(.earlyData(ext))
        try self.assertIncrementalRead(expected: .earlyData(ext), readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testEarlyDataEncryptedExtensions() throws {
        let ext = Extension.EarlyData()

        let written = self.buffer.writeExtension(.earlyData(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .earlyData(ext))
    }

    func testEarlyDataEncryptedExtensions_incremental() throws {
        let ext = Extension.EarlyData()

        self.buffer.writeExtension(.earlyData(ext))
        try self.assertIncrementalRead(expected: .earlyData(ext), readFunction: { try $0.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false) })
    }

    func testEarlyDataClientHelloEncryptedExtensions_failsToParseInNewSessionTicket() throws {
        let ext = Extension.EarlyData()

        self.buffer.writeExtension(.earlyData(ext))
        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .newSessionTicket, helloRetryRequest: false))
    }

    func testEarlyDataClientHelloEncryptedExtensions_failsToParseInAllOtherMessages() throws {
        let ext = Extension.EarlyData()

        self.buffer.writeExtension(.earlyData(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: messageType == .serverHello ? true : false))
        }
    }

    func testEarlyDataNewSessionTicket() throws {
        let ext = Extension.EarlyData(maxEarlyDataSize: 0x01020304)

        let written = self.buffer.writeExtension(.earlyData(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .newSessionTicket, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .earlyData(ext))
    }

    func testEarlyDataNewSessionTicket_incremental() throws {
        let ext = Extension.EarlyData(maxEarlyDataSize: 0x01020304)

        self.buffer.writeExtension(.earlyData(ext))
        try self.assertIncrementalRead(expected: .earlyData(ext), readFunction: { try $0.readExtension(messageType: .newSessionTicket, helloRetryRequest: false) })
    }

    func testEarlyDataNewSessionTicket_failsToParseInAllOtherMessages() throws {
        let ext = Extension.EarlyData(maxEarlyDataSize: 0x01020304)

        self.buffer.writeExtension(.earlyData(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .clientHello, .serverHello, .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: messageType == .serverHello ? true : false))
        }
    }

    func testPreSharedKeyClientHello() throws {
        let ext = Extension.PreSharedKey.clientHello(
            .init(
                identities: [
                    .init(identity: ByteBuffer(bytes: [1, 2, 3, 4]), obfuscatedTicketAge: 0x05060708),
                    .init(identity: ByteBuffer(bytes: [9, 10, 11, 12]), obfuscatedTicketAge: 0x0d0e0f10),
                ],
                binders: [
                    .init(serializedBinder: ByteBuffer(bytes: repeatElement(0x11, count: 32))),
                    .init(serializedBinder: ByteBuffer(bytes: repeatElement(0x12, count: 32))),
                ]
            )
        )

        let written = self.buffer.writeExtension(.preSharedKey(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .preSharedKey(ext))
    }

    func testPreSharedKeyClientHello_incremental() throws {
        let ext = Extension.PreSharedKey.clientHello(
            .init(
                identities: [
                    .init(identity: ByteBuffer(bytes: [1, 2, 3, 4]), obfuscatedTicketAge: 0x05060708),
                    .init(identity: ByteBuffer(bytes: [9, 10, 11, 12]), obfuscatedTicketAge: 0x0d0e0f10),
                ],
                binders: [
                    .init(serializedBinder: ByteBuffer(bytes: repeatElement(0x11, count: 32))),
                    .init(serializedBinder: ByteBuffer(bytes: repeatElement(0x12, count: 32))),
                ]
            )
        )

        self.buffer.writeExtension(.preSharedKey(ext))
        try self.assertIncrementalRead(expected: .preSharedKey(ext), readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testPreSharedKeyClientHello_failsToParseInAllOtherMessages() throws {
        let ext = Extension.PreSharedKey.clientHello(
            .init(
                identities: [
                    .init(identity: ByteBuffer(bytes: [1, 2, 3, 4]), obfuscatedTicketAge: 0x05060708),
                    .init(identity: ByteBuffer(bytes: [9, 10, 11, 12]), obfuscatedTicketAge: 0x0d0e0f10),
                ],
                binders: [
                    .init(serializedBinder: ByteBuffer(bytes: repeatElement(0x11, count: 32))),
                    .init(serializedBinder: ByteBuffer(bytes: repeatElement(0x12, count: 32))),
                ]
            )
        )

        self.buffer.writeExtension(.preSharedKey(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testPreSharedKeyClientHello_rejectsShortBinder() throws {
        let ext = Extension.PreSharedKey.clientHello(
            .init(
                identities: [
                    .init(identity: ByteBuffer(bytes: [1, 2, 3, 4]), obfuscatedTicketAge: 0x05060708),
                    .init(identity: ByteBuffer(bytes: [9, 10, 11, 12]), obfuscatedTicketAge: 0x0d0e0f10),
                ],
                binders: [
                    .init(serializedBinder: ByteBuffer(bytes: repeatElement(0x11, count: 31))),
                    .init(serializedBinder: ByteBuffer(bytes: repeatElement(0x12, count: 32))),
                ]
            )
        )

        let written = self.buffer.writeExtension(.preSharedKey(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        XCTAssertThrowsError(try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testPreSharedKeyServerHello() throws {
        let ext = Extension.PreSharedKey.serverHello(0xffff)

        let written = self.buffer.writeExtension(.preSharedKey(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .serverHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .preSharedKey(ext))
    }

    func testPreSharedKeyServerHello_incremental() throws {
        let ext = Extension.PreSharedKey.serverHello(0xffff)

        self.buffer.writeExtension(.preSharedKey(ext))
        try self.assertIncrementalRead(expected: .preSharedKey(ext), readFunction: { try $0.readExtension(messageType: .serverHello, helloRetryRequest: false) })
    }

    func testPreSharedKeyServerHello_failsToParseInAllOtherMessages() throws {
        let ext = Extension.PreSharedKey.serverHello(0xffff)

        self.buffer.writeExtension(.preSharedKey(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .clientHello, .serverHello, .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: messageType == .serverHello ? true : false))
        }
    }

    func testPreSharedKeyKexModesClientHello() throws {
        let ext = Extension.PreSharedKeyKexModes(modes: [.pskAndDHE, .pskOnly])

        let written = self.buffer.writeExtension(.preSharedKeyKexModes(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .preSharedKeyKexModes(ext))
    }

    func testPreSharedKeyKexModesClientHello_incremental() throws {
        let ext = Extension.PreSharedKeyKexModes(modes: [.pskAndDHE, .pskOnly])

        self.buffer.writeExtension(.preSharedKeyKexModes(ext))
        try self.assertIncrementalRead(expected: .preSharedKeyKexModes(ext),
                                       readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testPreSharedKeyKexModesClientHello_failsToParseInAllOtherMessages() throws {
        let ext = Extension.PreSharedKeyKexModes(modes: [.pskAndDHE, .pskOnly])

        self.buffer.writeExtension(.preSharedKeyKexModes(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testServerNameClientHello() throws {
        let ext = Extension.ServerName.clientHello(.init(hostName: ByteBuffer("example.com")))

        let written = self.buffer.writeExtension(.serverName(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .serverName(ext))
    }

    func testServerNameClientHello_incremental() throws {
        let ext = Extension.ServerName.clientHello(.init(hostName: ByteBuffer("example.com")))

        self.buffer.writeExtension(.serverName(ext))
        try self.assertIncrementalRead(expected: .serverName(ext),
                                       readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testServerNameClientHello_failsToParseInAllOtherMessages() throws {
        let ext = Extension.ServerName.clientHello(.init(hostName: ByteBuffer("example.com")))

        self.buffer.writeExtension(.serverName(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .encryptedExtensions, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testParsingServerNameWithoutAnyHostNameEntries() throws {
        var serializedExt = ByteBuffer(bytes: [0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0x00, 0x03, 0x05, 0x06, 0x07])
        XCTAssertThrowsError(try serializedExt.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testParsingServerNameWithDuplicateHostNameEntries() throws {
        var serializedExt = ByteBuffer(bytes: [0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x03, 0x05, 0x06, 0x07])
        XCTAssertThrowsError(try serializedExt.readExtension(messageType: .clientHello, helloRetryRequest: false))
    }

    func testParsingServerNameWithExtraNonHostNameEntries() throws {
        var serializedExt = ByteBuffer(bytes: [0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x03, 0x05, 0x06, 0x07])

        let read = try serializedExt.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(serializedExt.readableBytes, 0)
        XCTAssertEqual(read, .serverName(Extension.ServerName.clientHello(.init(hostName: ByteBuffer(bytes: [0x05, 0x06, 0x07])))))
    }

    func testParsingNonASCIIHostName() throws {
        let ext = Extension.ServerName.clientHello(.init(hostName: ByteBuffer("😈")))

        let written = self.buffer.writeExtension(.serverName(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        XCTAssertThrowsError(
            try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false),
            "The hostname is represented as a byte string using ASCII encoding without a trailing dot.",
            { error in
                guard case TLSError.illegalParameter = error else {
                    XCTFail("unexpected error: \(error)")
                    return
                }
            }
        )
    }

    func testServerNameEncryptedExtensions() throws {
        let ext = Extension.ServerName.encryptedExtensions

        let written = self.buffer.writeExtension(.serverName(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .serverName(ext))
    }

    func testServerNameEncryptedExtensions_incremental() throws {
        let ext = Extension.ServerName.encryptedExtensions

        self.buffer.writeExtension(.serverName(ext))
        try self.assertIncrementalRead(expected: .serverName(ext),
                                       readFunction: { try $0.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false) })
    }

    func testServerNameEncryptedExtensions_failsToParseInAllOtherMessages() throws {
        let ext = Extension.ServerName.encryptedExtensions

        self.buffer.writeExtension(.serverName(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .clientHello, .serverHello, .certificate, .certificateVerify, .certificateRequest, .finished, .endOfEarlyData, .newSessionTicket
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testTicketRequest() throws {
        let clientTicketRequest = ClientTicketRequest(newSessionCount: 1, resumptionCount: 0)
        let ext = Extension.TicketRequest.clientHello(clientTicketRequest)

        let written = self.buffer.writeExtension(.ticketRequest(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .clientHello, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .ticketRequest(ext))
    }

    func testTicketRequest_incremental() throws {
        let clientTicketRequest = ClientTicketRequest(newSessionCount: 1, resumptionCount: 0)
        let ext = Extension.TicketRequest.clientHello(clientTicketRequest)

        self.buffer.writeExtension(.ticketRequest(ext))
        try self.assertIncrementalRead(expected: .ticketRequest(ext),
                                       readFunction: { try $0.readExtension(messageType: .clientHello, helloRetryRequest: false) })
    }

    func testTicketRequest_failsToParseInAllOtherMessages() throws {
        let clientTicketRequest = ClientTicketRequest(newSessionCount: 1, resumptionCount: 0)
        let ext = Extension.TicketRequest.clientHello(clientTicketRequest)

        self.buffer.writeExtension(.ticketRequest(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .serverHello, .newSessionTicket, .endOfEarlyData, .encryptedExtensions, .certificate, .certificateRequest, .certificateVerify, .finished, .keyUpdate,
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }

    func testTicketRequestResponse() throws {
        let serverTicketRequestHint = Extension.TicketRequest.ServerTicketRequestHint(expectedCount: 1)
        let ext = Extension.TicketRequest.encryptedExtensions(serverTicketRequestHint)

        let written = self.buffer.writeExtension(.ticketRequest(ext))
        XCTAssertEqual(written, self.buffer.readableBytes)
        XCTAssertGreaterThan(written, 0)

        let read = try self.buffer.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false)
        XCTAssertEqual(self.buffer.readableBytes, 0)
        XCTAssertEqual(read, .ticketRequest(ext))
    }

    func testTicketRequestResponse_incremental() throws {
        let serverTicketRequestHint = Extension.TicketRequest.ServerTicketRequestHint(expectedCount: 1)
        let ext = Extension.TicketRequest.encryptedExtensions(serverTicketRequestHint)

        self.buffer.writeExtension(.ticketRequest(ext))
        try self.assertIncrementalRead(expected: .ticketRequest(ext),
                                       readFunction: { try $0.readExtension(messageType: .encryptedExtensions, helloRetryRequest: false) })
    }

    func testTicketRequestResponse_failsToParseInAllOtherMessages() throws {
        let serverTicketRequestHint = Extension.TicketRequest.ServerTicketRequestHint(expectedCount: 1)
        let ext = Extension.TicketRequest.encryptedExtensions(serverTicketRequestHint)

        self.buffer.writeExtension(.ticketRequest(ext))

        let unsupportedMessageTypes: [HandshakeType] = [
            .clientHello, .serverHello, .newSessionTicket, .endOfEarlyData, .certificate, .certificateRequest, .certificateVerify, .finished, .keyUpdate,
        ]

        for messageType in unsupportedMessageTypes {
            var copy = self.buffer!
            XCTAssertThrowsError(try copy.readExtension(messageType: messageType,
                                                        helloRetryRequest: false))

            if messageType == .serverHello {
                var copy = self.buffer!
                XCTAssertThrowsError(try copy.readExtension(messageType: messageType, helloRetryRequest: true))
            }
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    mutating func readExtension(messageType: HandshakeType, helloRetryRequest: Bool) throws(TLSError) -> Extension? {
        try withInputBuffer { inputBuffer throws(TLSError) in
            try inputBuffer.readExtension(messageType: messageType, helloRetryRequest: helloRetryRequest)
        }
    }
}
