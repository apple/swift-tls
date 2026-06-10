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
#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@testable import SwiftTLS
#endif


@available(SwiftTLS 0.1.0, *)
class RoundTripParserTests: XCTestCase {
    private func roundTripTest_oneShot(_ message: HandshakeMessage) throws {
        var buffer = ByteBuffer()
        var parser = HandshakeMessageParser()
        let serializer = TLSMessageSerializer()

        // To confirm we're getting the reader index stuff right, stuff some garbage in the front.
        buffer.writeBytes(repeatElement(0, count: Int.random(in: 0..<15)))
        buffer.moveReaderIndex(to: buffer.writerIndex)

        let byteCount = serializer.writeHandshakeMessage(message, into: &buffer)
        XCTAssertEqual(byteCount, buffer.readableBytes)
        let originalMessageBytes = buffer

        parser.appendBytes(&buffer)
        let reParsed = try parser.parseHandshakeMessage()
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(reParsed?.messageBytes, originalMessageBytes)
        XCTAssertEqual(reParsed?.message, message)
    }

    private func roundTripTest_dripFeed(_ message: HandshakeMessage) throws {
        var buffer = ByteBuffer()
        var parser = HandshakeMessageParser()
        let serializer = TLSMessageSerializer()

        // To confirm we're getting the reader index stuff right, stuff some garbage in the front.
        buffer.writeBytes(repeatElement(0, count: Int.random(in: 0..<15)))
        buffer.moveReaderIndex(to: buffer.writerIndex)

        let byteCount = serializer.writeHandshakeMessage(message, into: &buffer)
        XCTAssertEqual(byteCount, buffer.readableBytes)
        let originalMessageBytes = buffer

        repeat {
            var singleByteBuffer = buffer.readSlice(length: 1)!
            parser.appendBytes(&singleByteBuffer)
            XCTAssertNil(try parser.parseHandshakeMessage())
        } while buffer.readableBytes > 1

        parser.appendBytes(&buffer)
        let reParsed = try parser.parseHandshakeMessage()
        XCTAssertEqual(buffer.readableBytes, 0)
        XCTAssertEqual(reParsed?.messageBytes, originalMessageBytes)
        XCTAssertEqual(reParsed?.message, message)
    }

    private func roundTripTest_excessivelyLongLengthField(_ message: HandshakeMessage) throws {
        var buffer = ByteBuffer()
        var parser = HandshakeMessageParser()
        let serializer = TLSMessageSerializer()

        let byteCount = serializer.writeHandshakeMessage(message, into: &buffer)
        XCTAssertEqual(byteCount, buffer.readableBytes)

        // Now we're going to "tweak" the length by adding one byte to the length field. The length is
        // the last 3 of the first 4 bytes. We'll add one to the fourth byte. This also requires appending a byte.
        buffer.setInteger(buffer.readableBytesView[3] + 1, at: 3)
        buffer.writeInteger(UInt8(0))

        parser.appendBytes(&buffer)
        XCTAssertThrowsError(try parser.parseHandshakeMessage())
    }

    private func roundTripTest_shortLengthField(_ message: HandshakeMessage) throws {
        var buffer = ByteBuffer()
        let parser = HandshakeMessageParser()
        let serializer = TLSMessageSerializer()

        let byteCount = serializer.writeHandshakeMessage(message, into: &buffer)
        XCTAssertEqual(byteCount, buffer.readableBytes)

        // Now we're going to "tweak" the length and use short body lengths. These should all error.
        for length in 0..<(byteCount - 4) {
            var parserCopy = parser
            var copy = buffer
            copy.setUInt24(length, at: copy.readerIndex + 1)
            parserCopy.appendBytes(&copy)
            XCTAssertThrowsError(try parserCopy.parseHandshakeMessage())
        }
    }

    private func roundTripTest_unrealisticallyLongLengthField(_ message: HandshakeMessage) throws {
        var buffer = ByteBuffer()
        var parser = HandshakeMessageParser()
        let serializer = TLSMessageSerializer()

        let byteCount = serializer.writeHandshakeMessage(message, into: &buffer)
        XCTAssertEqual(byteCount, buffer.readableBytes)

        // Setting the 24-bit length value to the unrealistic number 2^24 - 1.
        // The length field is located past the 1st byte in the buffer.
        buffer.setUInt24(0xFFFFFF, at: 1)

        parser.appendBytes(&buffer)
        XCTAssertThrowsError(try parser.parseHandshakeMessage())
    }

    func testRoundTrip_clientHello() throws {
        let message = ClientHello(legacyVersion: .tlsv12,
                                  random: .init(),
                                  legacySessionID: .random(),
                                  cipherSuites: [.TLS_AES_256_GCM_SHA384],
                                  legacyCompressionMethods: [],
                                  extensions: [
                                    .keyShare(.clientHello([.init(group: .secp384, keyExchange: ByteBuffer("random key exchange"))])),
                                    .signatureAlgorithms(.init(schemes: [.ecdsa_secp384r1_sha384])),
                                    .supportedGroups(.init(groups: [.secp384])),
                                    .supportedVersions(.offer([.tlsv13])),
                                  ])
        try self.roundTripTest_oneShot(.clientHello(message))
        try self.roundTripTest_dripFeed(.clientHello(message))
        try self.roundTripTest_excessivelyLongLengthField(.clientHello(message))
        try self.roundTripTest_shortLengthField(.clientHello(message))
    }

    func testRoundTrip_serverHello() throws {
        let message = ServerHello(legacyVersion: .tlsv12,
                                  random: .init(),
                                  legacySessionIDEcho: .random(),
                                  cipherSuite: .TLS_AES_256_GCM_SHA384,
                                  legacyCompressionMethod: 0,
                                  extensions: [
                                    .keyShare(.serverHello(.init(group: .secp384, keyExchange: ByteBuffer("random key exchange")))),
                                    .supportedVersions(.selection(.tlsv13)),
                                  ])
        try self.roundTripTest_oneShot(.serverHello(message))
        try self.roundTripTest_dripFeed(.serverHello(message))
        try self.roundTripTest_excessivelyLongLengthField(.serverHello(message))
        try self.roundTripTest_shortLengthField(.serverHello(message))
        try self.roundTripTest_unrealisticallyLongLengthField(.serverHello(message))
    }

    func testRoundTrip_helloRetryRequest() throws {
        let message = ServerHello(legacyVersion: .tlsv12,
                                  random: .helloRetryRequest,
                                  legacySessionIDEcho: .random(),
                                  cipherSuite: .TLS_AES_256_GCM_SHA384,
                                  legacyCompressionMethod: 0,
                                  extensions: [
                                    .keyShare(.helloRetryRequest(.secp384)),
                                    .supportedVersions(.selection(.tlsv13)),
                                  ])
        try self.roundTripTest_oneShot(.serverHello(message))
        try self.roundTripTest_dripFeed(.serverHello(message))
        try self.roundTripTest_excessivelyLongLengthField(.serverHello(message))
        try self.roundTripTest_shortLengthField(.serverHello(message))
    }

    func testRoundTrip_encryptedExtensions() throws {
        let message = EncryptedExtensions(extensions: [
            .supportedGroups(.init(groups: [.secp384])),
        ])
        try self.roundTripTest_oneShot(.encryptedExtensions(message))
        try self.roundTripTest_dripFeed(.encryptedExtensions(message))
        try self.roundTripTest_excessivelyLongLengthField(.encryptedExtensions(message))
        try self.roundTripTest_shortLengthField(.encryptedExtensions(message))
    }

    func testRoundTrip_certificateRequest() throws {
        let message = CertificateRequest(certificateRequestContext: ByteBuffer(),
                                         extensions: [
                                            .signatureAlgorithms(.init(schemes: [.rsa_pss_rsae_sha256])),
                                         ])
        try self.roundTripTest_oneShot(.certificateRequest(message))
        try self.roundTripTest_dripFeed(.certificateRequest(message))
        try self.roundTripTest_excessivelyLongLengthField(.certificateRequest(message))
        try self.roundTripTest_shortLengthField(.certificateRequest(message))
    }

    func testRoundTrip_certificate() throws {
        let message = CertificateMessage(certificateRequestContext: ByteBuffer(),
                                         certificateList: [
                                            .init(opaqueCertificateData: ByteBuffer("some opaque data"), extensions: []),
                                            .init(opaqueCertificateData: ByteBuffer("some more opaque data"), extensions: []),
                                         ])
        try self.roundTripTest_oneShot(.certificate(message))
        try self.roundTripTest_dripFeed(.certificate(message))
        try self.roundTripTest_excessivelyLongLengthField(.certificate(message))
        try self.roundTripTest_shortLengthField(.certificate(message))
    }

    func testRoundTrip_certificateVerify() throws {
        let message = CertificateVerify(algorithm: .ecdsa_secp384r1_sha384, signature: ByteBuffer("a signature"))
        try self.roundTripTest_oneShot(.certificateVerify(message))
        try self.roundTripTest_dripFeed(.certificateVerify(message))
        try self.roundTripTest_excessivelyLongLengthField(.certificateVerify(message))
        try self.roundTripTest_shortLengthField(.certificateVerify(message))
    }

    func testRoundTrip_finished() throws {
        let message = FinishedMessage(verifyData: ByteBuffer("verify content"))
        try self.roundTripTest_oneShot(.finished(message))
        try self.roundTripTest_dripFeed(.finished(message))
        // No excessively long test here: finished is just opaque bytes to us.
        // No short test here: finished is just opaque bytes to us.
    }

    func testRoundTrip_newSessionTicket() throws {
        let message = NewSessionTicket(ticketLifetime: 0x01020304,
                                       ticketAgeAdd: 0x05060708,
                                       ticketNonce: ByteBuffer("nonce"),
                                       ticket: ByteBuffer("ticket"),
                                       extensions: [.earlyData(.init(maxEarlyDataSize: 12345))])
        try self.roundTripTest_oneShot(.newSessionTicket(message))
        try self.roundTripTest_dripFeed(.newSessionTicket(message))
        try self.roundTripTest_excessivelyLongLengthField(.newSessionTicket(message))
        try self.roundTripTest_shortLengthField(.newSessionTicket(message))
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    init(_ string: String) {
        self = ByteBuffer(data: Data(string.utf8))
    }
}
