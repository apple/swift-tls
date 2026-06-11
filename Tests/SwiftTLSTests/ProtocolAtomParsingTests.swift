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
@testable @_spi(SwiftTLSProtocol) import SwiftTLS
#endif


@available(anyAppleOS 26, *)
class ProtocolAtomParsingTests: XCTestCase {
    var buffer: ByteBuffer!

    override func setUp() {
        self.buffer = ByteBuffer()
    }

    override func tearDown() {
        self.buffer = nil
    }

    private func assertIncrementalRead<Result: Equatable>(expected: Result, readFunction: (inout InputBuffer) throws -> Result?) rethrows {
        for length in 0..<self.buffer.readableBytes {
            var slice = InputBuffer(storage: self.buffer.readableBytesSpan.extracting(first: length))
            XCTAssertNil(try readFunction(&slice))
            XCTAssertEqual(slice.byteCount, length)
        }

        try self.buffer.withInputBuffer { inputBuffer in
            XCTAssertEqual(expected, try readFunction(&inputBuffer))
        }
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testZeroLengthSessionID() throws {
        let written = self.buffer.writeLegacySessionID(.zero)
        XCTAssertEqual(written, 1)
        XCTAssertEqual(Array(self.buffer.readableBytesView), [0])

        let read = try self.buffer.withInputBuffer { buffer in
            try buffer.readLegacySessionID()
        }
        XCTAssertEqual(read, .zero)
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testRandomSessionID() throws {
        let id = LegacySessionID.random()
        let written = self.buffer.writeLegacySessionID(id)
        XCTAssertEqual(written, 33)
        XCTAssertEqual(self.buffer.readableBytesView.first, 32)

        let read = try self.buffer.withInputBuffer { buffer in
            try buffer.readLegacySessionID()
        }
        XCTAssertEqual(read, id)
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testShortSessionID() throws {
        let id = LegacySessionID(([1, 2, 3, 4, 5, 6, 7] as [UInt8]).span.bytes)
        let written = self.buffer.writeLegacySessionID(id)
        XCTAssertEqual(written, 8)
        XCTAssertEqual(Array(self.buffer.readableBytesView), [7, 1, 2, 3, 4, 5, 6, 7])

        let read = try self.buffer.withInputBuffer { buffer in
            try buffer.readLegacySessionID()
        }
        XCTAssertEqual(read, id)
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testExcessivelyLargeSessionID() throws {
        self.buffer.writeInteger(UInt8(33))
        self.buffer.writeBytes(repeatElement(0, count: 33))
        try self.buffer.withInputBuffer { buffer in
            XCTAssertThrowsError(try buffer.readLegacySessionID())
        }
    }

    func testIncrementalSessionID() throws {
        let id = LegacySessionID.random()
        self.buffer.writeLegacySessionID(id)
        try self.assertIncrementalRead(expected: id, readFunction: { try $0.readLegacySessionID() })
    }

    func testRandom() throws {
        let random = Random()
        let written = self.buffer.writeRandom(random)
        XCTAssertEqual(written, 32)

        let read = self.buffer.withInputBuffer { buffer in
            buffer.readRandom()
        }
        XCTAssertEqual(read, random)
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testIncrementalRandom() throws {
        let random = Random()
        self.buffer.writeRandom(random)
        self.assertIncrementalRead(expected: random, readFunction: { $0.readRandom() })
    }

    func testSignatureScheme() throws {
        let written = self.buffer.writeSignatureScheme(.ecdsa_secp384r1_sha384)
        XCTAssertEqual(written, 2)
        XCTAssertEqual(self.buffer.readableBytes, 2)

        let read = self.buffer.withInputBuffer { buffer in
            buffer.readSignatureScheme()
        }
        XCTAssertEqual(read, .ecdsa_secp384r1_sha384)
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testIncrementalSignatureScheme() throws {
        self.buffer.writeSignatureScheme(.rsa_pss_rsae_sha256)
        self.assertIncrementalRead(expected: .rsa_pss_rsae_sha256, readFunction: { $0.readSignatureScheme() })
    }

    func testSignatureSchemeEquality() throws {
        let scheme = SignatureScheme(rawValue: SignatureScheme.ecdsa_secp256r1_sha256.rawValue)
        XCTAssertEqual(scheme, SignatureScheme.ecdsa_secp256r1_sha256)
    }

    func testProtocolVersion() throws {
        let written = self.buffer.writeProtocolVersion(.tlsv13)
        XCTAssertEqual(written, 2)
        XCTAssertEqual(self.buffer.readableBytes, 2)
        XCTAssertEqual(Array(self.buffer.readableBytesView), [0x03, 0x04])

        let read = self.buffer.withInputBuffer { buffer in
            buffer.readProtocolVersion()
        }
        XCTAssertEqual(read, .tlsv13)
        XCTAssertEqual(self.buffer.readableBytes, 0)

        self.buffer.writeProtocolVersion(.tlsv10)
        self.buffer.writeProtocolVersion(.tlsv11)
        self.buffer.writeProtocolVersion(.tlsv12)

        self.buffer.setProtocolVersion(.tlsv13, at: self.buffer.readerIndex + 2)

        self.buffer.withInputBuffer { buffer in
            XCTAssertEqual(buffer.readProtocolVersion(), .tlsv10)
            XCTAssertEqual(buffer.readProtocolVersion(), .tlsv13)
            XCTAssertEqual(buffer.readProtocolVersion(), .tlsv12)
        }
    }

    func testIncrementalProtocolVersion() throws {
        self.buffer.writeProtocolVersion(.tlsv10)
        self.assertIncrementalRead(expected: .tlsv10, readFunction: { $0.readProtocolVersion() })
    }

    func testCipherSuite() throws {
        let written = self.buffer.writeCipherSuite(.TLS_AES_256_GCM_SHA384)
        XCTAssertEqual(written, 2)
        XCTAssertEqual(self.buffer.readableBytes, 2)
        XCTAssertEqual(Array(self.buffer.readableBytesView), [0x13, 0x02])

        let read = self.buffer.withInputBuffer { buffer in
            buffer.readCipherSuite()
        }
        XCTAssertEqual(read, .TLS_AES_256_GCM_SHA384)
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testIncrementalCipherSuite() throws {
        self.buffer.writeCipherSuite(.TLS_AES_256_GCM_SHA384)
        self.assertIncrementalRead(expected: .TLS_AES_256_GCM_SHA384, readFunction: { $0.readCipherSuite() })
    }

    func testNamedGroup() throws {
        let written = self.buffer.writeNamedGroup(.secp384)
        XCTAssertEqual(written, 2)
        XCTAssertEqual(self.buffer.readableBytes, 2)
        XCTAssertEqual(Array(self.buffer.readableBytesView), [0x00, 0x18])

        let read = self.buffer.withInputBuffer { buffer in
            buffer.readNamedGroup()
        }
        XCTAssertEqual(read, .secp384)
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testIncrementalNamedGroup() throws {
        self.buffer.writeNamedGroup(.secp384)
        self.assertIncrementalRead(expected: .secp384, readFunction: { $0.readNamedGroup() })
    }

    func testCertificateType() throws {
        let written = self.buffer.writeCertificateType(.rawPublicKey)
        XCTAssertEqual(written, 1)
        XCTAssertEqual(self.buffer.readableBytes, 1)
        XCTAssertEqual(Array(self.buffer.readableBytesView), [2])

        let read = self.buffer.withInputBuffer { buffer in
            buffer.readCertificateType()
        }
        XCTAssertEqual(read, .rawPublicKey)
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testIncrementalCertificateType() throws {
        self.buffer.writeCertificateType(.x509)
        self.assertIncrementalRead(expected: .x509, readFunction: { $0.readCertificateType() })
    }

    func testContentType() throws {
        let written = self.buffer.writeContentType(.changeCipherSpec)
        XCTAssertEqual(written, 1)
        XCTAssertEqual(self.buffer.readableBytes, 1)
        XCTAssertEqual(Array(self.buffer.readableBytesView), [20])

        self.buffer.withInputBuffer { inputBuffer in
            let read = inputBuffer.readContentType()
            XCTAssertEqual(read, .changeCipherSpec)
        }
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testIncrementalContentType() throws {
        self.buffer.writeContentType(.handshake)
        self.assertIncrementalRead(expected: .handshake, readFunction: { $0.readContentType() })
    }

    func testHandshakeType() throws {
        let written = self.buffer.writeHandshakeType(.certificate)
        XCTAssertEqual(written, 1)
        XCTAssertEqual(self.buffer.readableBytes, 1)
        XCTAssertEqual(Array(self.buffer.readableBytesView), [11])

        let read = self.buffer.withInputBuffer { buffer in
            buffer.readHandshakeType()
        }
        XCTAssertEqual(read, .certificate)
        XCTAssertEqual(self.buffer.readableBytes, 0)
    }

    func testIncrementalHandshakeType() throws {
        self.buffer.writeHandshakeType(.finished)
        self.assertIncrementalRead(expected: .finished, readFunction: { $0.readHandshakeType() })
    }

    func testAlertParsing() throws {
        let alert = Alert.closeNotify
        XCTAssertEqual(self.buffer.writeAlert(alert), 2)
        self.buffer.withInputBuffer { inputBuffer in
            let res = inputBuffer.readAlert()
            XCTAssertEqual(res, alert)
        }
    }
}
