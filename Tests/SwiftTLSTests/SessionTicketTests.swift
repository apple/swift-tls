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
#if canImport(Foundation)
import Foundation
#endif
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif
#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@testable @_spi(SwiftTLSProtocol) import SwiftTLS
#endif


final class SessionTicketTests: XCTestCase {
    // A helper function that lets us tweak one parameter at a time.
    private static func baselineNewSessionTicket(ticketLifetime: UInt32 = .max,
                                                 ticketAgeAdd: UInt32 = .random(in: 0...(.max)),
                                                 ticketNonce: ByteBuffer = ByteBuffer(data: Data("this is a nonce".utf8)),
                                                 ticket: ByteBuffer = ByteBuffer(data: Data("this is a ticket".utf8)),
                                                 extensions: [Extension] = [.earlyData(.init(maxEarlyDataSize: .max))]) -> NewSessionTicket {
        NewSessionTicket(ticketLifetime: ticketLifetime,
                         ticketAgeAdd: ticketAgeAdd,
                         ticketNonce: ticketNonce,
                         ticket: ticket,
                         extensions: extensions)
    }

    // A helper function that hides the awkwardness of creating a peer certificate bundle.
    private static func baselineRawPublicKeyCertificateBundle(_ key: P256.Signing.PublicKey? = nil) -> PeerCertificateBundle {
        let serialized = key?.derRepresentation ?? P256.Signing.PrivateKey().publicKey.derRepresentation
        return try! PeerCertificateBundle(
            expectedCertificateType: .rawPublicKey,
            peerCertificateMessage: .init(certificateRequestContext: ByteBuffer(),
                                          certificateList: [.init(opaqueCertificateData: ByteBuffer(data: serialized), extensions: [])]),
            fromClient: false
        )
    }

    private static func baselineX509CertificateBundle(_ certificates: [Data]? = nil) -> PeerCertificateBundle {
        // Dummy data that represents a certificate.
        let certificatesData: [Data] = (certificates ?? [Data(repeating: 0x2a, count: 128)])
        return try! PeerCertificateBundle(
            expectedCertificateType: .x509,
            peerCertificateMessage: .init(certificateRequestContext: ByteBuffer(),
                                          certificateList: certificatesData.map {
                                              .init(opaqueCertificateData: ByteBuffer(data: $0), extensions: [])
                                          }),
            fromClient: false
        )
    }

    private func assertRoundTrip(_ ticket: SessionTicket) throws {
        let serialized = ticket.serialize()
        let parsed = try SessionTicket(serialized: serialized.bytes)
        XCTAssertEqual(ticket, parsed)
    }

    func assertDripFeed(_ ticket: SessionTicket) throws {
        let serialized = ticket.serialize()
        for length in 0..<serialized.count {
            let slice = serialized.prefix(length)
            XCTAssertThrowsError(try SessionTicket(serialized: slice.bytes), "unexpected early parse of \(ticket)")
        }
    }

    func testMissingMaxEarlyDataGivesUsZero() throws {
        let ticket = try SessionTicket(
            message: Self.baselineNewSessionTicket(extensions: []),
            psk: SymmetricKey(size: .bits128),
            cipherSuite: .TLS_AES_256_GCM_SHA384,
            group: .secp384,
            alpn: "h2",
            certificateBundle: Self.baselineRawPublicKeyCertificateBundle(),
            currentTime: Date()
        )
        XCTAssertEqual(ticket.maxEarlyDataSize, 0)
    }

    func testIgnoresUnknownExtensions() throws {
        let ticket = try SessionTicket(
            message: Self.baselineNewSessionTicket(extensions: [.alpn(.selection("")), .earlyData(.init(maxEarlyDataSize: 1))]),
            psk: SymmetricKey(size: .bits128),
            cipherSuite: .TLS_AES_256_GCM_SHA384,
            group: .secp384,
            alpn: "h2",
            certificateBundle: Self.baselineRawPublicKeyCertificateBundle(),
            currentTime: Date()
        )
        XCTAssertEqual(ticket.maxEarlyDataSize, 1)
    }

    func testClampMaxLifetime() throws {
        let ticket = try SessionTicket(
            message: Self.baselineNewSessionTicket(ticketLifetime: .max),
            psk: SymmetricKey(size: .bits128),
            cipherSuite: .TLS_AES_256_GCM_SHA384,
            group: .secp384,
            alpn: "h2",
            certificateBundle: Self.baselineRawPublicKeyCertificateBundle(),
            currentTime: Date()
        )
        XCTAssertEqual(ticket.lifetime, 604800)
    }

    func testAttemptingToResumeTicketFromTheFuture() throws {
        let interval = 1.0
        let issuanceDate = Date()
        let resumptionDate = issuanceDate - interval

        let key = P256.Signing.PrivateKey()

        let ticket = try SessionTicket(
            message: Self.baselineNewSessionTicket(ticketLifetime: .max),
            psk: SymmetricKey(size: .bits128),
            cipherSuite: .TLS_AES_256_GCM_SHA384,
            group: .secp384,
            alpn: "h2",
            certificateBundle: Self.baselineRawPublicKeyCertificateBundle(key.publicKey),
            currentTime: issuanceDate
        )
        XCTAssertEqual(ticket.lifetime, 604800)

        let clientHello = ClientHello(
            legacyVersion: .tlsv12,
            random: .init(),
            legacySessionID: .zero,
            cipherSuites: [.TLS_AES_256_GCM_SHA384],
            legacyCompressionMethods: [0],
            extensions: []
        )
        let config = HandshakeStateMachine.Configuration(
            serverName: nil,
            quicTransportParameters: nil,
            alpn: nil,
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            validPeerPublicKeys: [key.publicKey],
            ticketRequest: nil,
            useRawEPSKs: false,
            enableEarlyData: false
        )

        XCTAssertFalse(ticket.isCompatibleWith(clientHello, configuration: config, currentTime: resumptionDate))
    }
}
