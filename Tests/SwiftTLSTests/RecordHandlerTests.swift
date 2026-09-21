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
import Synchronization
#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@testable @_spi(SwiftTLSTesting) @_spi(SwiftTLSOptions) @_spi(SwiftTLSProtocol) import SwiftTLS
#endif

#if canImport(Darwin)
import os.log
// Availability due to `os.log`'s `Logger`
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "RecordLayerTests")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.RecordLayerTests")
#endif

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif

#if canImport(Foundation)
import Foundation
#endif

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
class TLSRecordHandlerTests: XCTestCase {
    var serverSigningKey = P256.Signing.PrivateKey()
    var clientSigningKey = P256.Signing.PrivateKey()

    // Initialize record handlers with temporary keys so the type can be non-null
    var clientRecordHandler = TLSRecordHandler(stateMachine: .client(try! HandshakeStateMachine(configuration: HandshakeStateMachine.Configuration (
        alpn: ["proto A"],
        fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
        validPeerPublicKeys: [P256.Signing.PrivateKey().publicKey]
    ))))

    var serverRecordHandler = TLSRecordHandler(stateMachine: .server(try! ServerHandshakeStateMachine(configuration: ServerHandshakeStateMachine .Configuration(
        quicTransportParameters: nil,
        alpn: ["proto A", "proto B"],
        signingKey: .p256(P256.Signing.PrivateKey()),
        validPeerPublicKeys: nil))))

    var validClientConfiguration: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration (
                serverName: nil,
                quicTransportParameters: nil,
                alpn: ["proto A"],
                fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
                signingKey: nil,
                validPeerPublicKeys: [serverSigningKey.publicKey],
                ticketRequest: nil,
                epsk: nil,
                useRawEPSKs: false,
                enableEarlyData: false
            )
    }

    var validClientRPKConfiguration: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
                serverName: nil,
                quicTransportParameters: nil,
                alpn: ["proto A"],
                fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
                signingKey: .p256(clientSigningKey),
                validPeerPublicKeys: [serverSigningKey.publicKey],
                ticketRequest: nil,
                epsk: nil,
                useRawEPSKs: false,
                enableEarlyData: false
            )
    }

    var validServerConfiguration: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
                .Configuration(
                    serverName: nil,
                    quicTransportParameters: nil,
                    alpn: ["proto A", "proto B"],
                    transportIsQUIC: false,
                    signingKey: .p256(serverSigningKey),
                    validPeerPublicKeys: nil,
                    useRawEPSKs: false,
                    clientAuthRequired: false,
                    enableEarlyData: false,
                )
    }

    var validServerConfigurationRequireClientRPK: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
                .Configuration(
                    serverName: nil,
                    quicTransportParameters: nil,
                    alpn: ["proto A", "proto B"],
                    transportIsQUIC: false,
                    signingKey: .p256(serverSigningKey),
                    validPeerPublicKeys: [clientSigningKey.publicKey],
                    useRawEPSKs: false,
                    clientAuthRequired: true,
                    enableEarlyData: false,
                )
    }

    static let oneRTTServerHelloFullRecord: [UInt8] =
        [0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06,
        0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93,
        0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69,
        0x28, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00,
        0x20, 0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7,
        0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1,
        0xb0, 0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]

    static let oneRTTClientHelloFullRecord: [UInt8] =
                [// ContentType: handshake(22)
                0x16,

                // Legacy Protocol Version = TLS 1.0
                0x03, 0x01,

                // Length = 196 bytes
                0x00, 0xc4,

                // Content
                0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec,
                0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff,
                0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec,
                0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91,
                0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,
                0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d,
                0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
                0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d,
                0x00, 0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43,
                0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13,
                0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
                0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08,
                0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04,
                0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00,
                0x1c, 0x00, 0x02, 0x40, 0x01]

    override func setUp() {
        let clientStateMachine = try! HandshakeStateMachine(configuration: self.validClientConfiguration)
        let serverStateMachine = try! ServerHandshakeStateMachine(configuration: self.validServerConfiguration)

        self.clientRecordHandler = TLSRecordHandler(stateMachine: .client(clientStateMachine))
        self.serverRecordHandler = TLSRecordHandler(stateMachine: .server(serverStateMachine))
    }

    override func tearDown() {
    }

    func runSuccessfulHandshake() throws {
        var buffer = ByteBuffer()

        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        // client hello should be in clientRecordHandler.outgoingBytes
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))

        // server hello, ee, certificate, certificate verify, finished messages should be in
        // serverRecordHandler.outgoingBytes
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)
        buffer.writeBuffer(&serverRecordHandler.outgoingBytes)

        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &buffer))

        // client processes server second flight and sends client finished
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)
        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)

        // server processes client finished
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))
        XCTAssertEqual(serverRecordHandler.outgoingBytes.readableBytes, 0)
    }

    func runSuccessfulRPKHandshake() throws {
        let clientStateMachine = try HandshakeStateMachine(configuration: self.validClientRPKConfiguration)
        let serverStateMachine = try ServerHandshakeStateMachine(configuration: self.validServerConfigurationRequireClientRPK)

        self.clientRecordHandler = TLSRecordHandler(stateMachine: .client(clientStateMachine))
        self.serverRecordHandler = TLSRecordHandler(stateMachine: .server(serverStateMachine))

        var buffer = ByteBuffer()

        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        // client hello should be in clientRecordHandler.outgoingBytes
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))

        // server hello, ee, certificate request, certificate, certificate verify, and finished messages should be in
        // serverRecordHandler.outgoingBytes
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)
        buffer.writeBuffer(&serverRecordHandler.outgoingBytes)

        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &buffer))

        // client processes server second flight and sends client certificate, certificate verify, and finished
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)
        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)

        // server processes client finished
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))
        XCTAssertEqual(serverRecordHandler.outgoingBytes.readableBytes, 0)
    }

    static func expectedCiphertextLength(_ plaintextLength: Int, paddingLength: Int = 0) -> Int {
        return 5 /* header */ + plaintextLength + 1 /* content type */ + paddingLength + TLSRecordProtector.aesTagLengthBytes
    }

    func testHandlerHappyPath() throws {
        // run handshake
        try runSuccessfulHandshake()

        // send app data client --> server
        let testAppData = ByteBuffer("Hello World!")
        var testAppDataCopy = testAppData
        XCTAssertNoThrow(try clientRecordHandler.addApplicationData(&testAppDataCopy))

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &self.clientRecordHandler.outgoingBytes))
        XCTAssertGreaterThan(serverRecordHandler.receivedApplicationData.readableBytes, 0)
        XCTAssertEqual(serverRecordHandler.receivedApplicationData, testAppData)

        // send app data server <-- client
        testAppDataCopy = testAppData
        XCTAssertNoThrow(try serverRecordHandler.addApplicationData(&testAppDataCopy))

        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &self.serverRecordHandler.outgoingBytes))
        XCTAssertGreaterThan(clientRecordHandler.receivedApplicationData.readableBytes, 0)
        XCTAssertEqual(clientRecordHandler.receivedApplicationData, testAppData)
    }

    // RFC 9846 §5.5 - confirms the key-usage-limit guard is wired up end-to-end through
    // TLSRecordHandler, and that it surfaces as the specific TLSError once the write side's
    // application traffic key has protected exactly `limit` records. The limit is enforced on
    // the write side only, per the RFC's send/receive asymmetry; the read side is seeded
    // here to keep the client's nonce counter in sync with the server's for decryption.
    func testHandlerKeyUsageLimit() throws {
        try runSuccessfulHandshake()

        let limit: UInt64 = 23_726_566
        serverRecordHandler.setWriteSequenceNumberForTesting(limit - 1)
        clientRecordHandler.setReadSequenceNumberForTesting(limit - 1)

        // the `limit`-th record still succeeds and is delivered correctly.
        let testAppData = ByteBuffer("Hello World!")
        var testAppDataCopy = testAppData
        XCTAssertNoThrow(try serverRecordHandler.addApplicationData(&testAppDataCopy))
        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &self.serverRecordHandler.outgoingBytes))
        XCTAssertEqual(clientRecordHandler.receivedApplicationData, testAppData)

        // the (limit + 1)-th record throws instead of silently continuing.
        testAppDataCopy = testAppData
        XCTAssertThrowsError(try serverRecordHandler.addApplicationData(&testAppDataCopy)) { error in
            XCTAssertEqual(error as? TLSError, .keyUsageLimitExceeded)
        }
    }

    func testHandlerHappyPathCloseNotify() throws {
        // run handshake
        try runSuccessfulHandshake()

        // send app data client --> server
        let testAppData = ByteBuffer("Hello World!")
        var testAppDataCopy = testAppData
        XCTAssertNoThrow(try clientRecordHandler.addApplicationData(&testAppDataCopy))
        clientRecordHandler.sendCloseNotify()

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &self.clientRecordHandler.outgoingBytes))
        XCTAssertGreaterThan(serverRecordHandler.receivedApplicationData.readableBytes, 0)
        XCTAssertEqual(serverRecordHandler.receivedApplicationData, testAppData)
        XCTAssertTrue(serverRecordHandler.closureAlertReceived)

        // send app data server <-- client
        testAppDataCopy = testAppData
        XCTAssertNoThrow(try serverRecordHandler.addApplicationData(&testAppDataCopy))
        serverRecordHandler.sendCloseNotify()

        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &self.serverRecordHandler.outgoingBytes))
        XCTAssertGreaterThan(clientRecordHandler.receivedApplicationData.readableBytes, 0)
        XCTAssertEqual(clientRecordHandler.receivedApplicationData, testAppData)
        XCTAssertTrue(clientRecordHandler.closureAlertReceived)
    }

    func testHandlerHappyPathClientRPKAuth() throws {
        // run handshake
        try runSuccessfulRPKHandshake()

        // send app data client --> server
        let testAppData = ByteBuffer("Hello World!")
        var testAppDataCopy = testAppData
        XCTAssertNoThrow(try clientRecordHandler.addApplicationData(&testAppDataCopy))

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &self.clientRecordHandler.outgoingBytes))
        XCTAssertGreaterThan(serverRecordHandler.receivedApplicationData.readableBytes, 0)
        XCTAssertEqual(serverRecordHandler.receivedApplicationData, testAppData)

        // send app data server <-- client
        testAppDataCopy = testAppData
        XCTAssertNoThrow(try serverRecordHandler.addApplicationData(&testAppDataCopy))

        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &self.serverRecordHandler.outgoingBytes))
        XCTAssertGreaterThan(clientRecordHandler.receivedApplicationData.readableBytes, 0)
        XCTAssertEqual(clientRecordHandler.receivedApplicationData, testAppData)
    }

    func testClientPlaintextAlert() throws {
        var buffer = ByteBuffer()

        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        // client hello should be in clientRecordHandler.outgoingBytes
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))

        // server hello, ee, certificate, certificate verify, finished messages should be in
        // serverRecordHandler.outgoingBytes
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)

        // pretend handshake failed and client sends a plaintext alert to server
        let alert = Alert.handshakeFailure
        var alertBuffer = ByteBuffer(bytes: [])
        alertBuffer.writeAlert(alert)
        let record = TLSPlaintext(contentType: .alert, protocolVersion: .tlsv12, fragment: [UInt8](alertBuffer.readableBytesView))
        buffer.writeRecord(record)

        // server processes client alert
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))
        XCTAssert(serverRecordHandler.alertRead != nil)
    }

    // Ensure we reject a record that coalesces two complete alerts
    // together (instead of silently reading only the first and dropping
    // the second)
    //
    // RFC 9846 §6: "a record with an Alert type MUST contain exactly one
    // message"
    func testCoalescedAlertsInOneRecordAreRejected() throws {
        var buffer = ByteBuffer()
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))

        var alertBuffer = ByteBuffer(bytes: [])
        alertBuffer.writeAlert(.handshakeFailure)
        alertBuffer.writeAlert(.handshakeFailure)
        let record = TLSPlaintext(contentType: .alert, protocolVersion: .tlsv12, fragment: [UInt8](alertBuffer.readableBytesView))
        buffer.writeRecord(record)

        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .excessBytes)
        }
        XCTAssertEqual(serverRecordHandler.alertWrote, .decodeError)
        XCTAssertNil(serverRecordHandler.alertRead, "a coalesced alert record must never be recorded as read")
    }

    // Splits a single 2-byte alert into two 1-byte records and confirms the
    // first (incomplete) record is rejected outright rather than buffered
    // and completed by the second.
    //
    // RFC 9846 §6: "alert messages MUST NOT be fragmented across records."
    func testAlertFragmentedAcrossRecordsIsRejected() throws {
        var buffer = ByteBuffer()
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))

        var alertBuffer = ByteBuffer(bytes: [])
        alertBuffer.writeAlert(.handshakeFailure)
        let alertBytes = [UInt8](alertBuffer.readableBytesView)
        let firstHalf = TLSPlaintext(contentType: .alert, protocolVersion: .tlsv12, fragment: [alertBytes[0]])
        let secondHalf = TLSPlaintext(contentType: .alert, protocolVersion: .tlsv12, fragment: [alertBytes[1]])
        buffer.writeRecord(firstHalf)
        buffer.writeRecord(secondHalf)

        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .truncatedMessage)
        }
        XCTAssertEqual(serverRecordHandler.alertWrote, .decodeError)
        XCTAssertNil(serverRecordHandler.alertRead, "an incomplete alert must never be recorded as read")
    }

    // Receiving a non-closeNotify alert only ever sets `alertRead` (readAlert doesn't send one
    // back). Any record bundled after the alert in the same processNetworkData call needs to be
    // dropped rather than handed to the handshake state machine.
    // This test ensures we act in accordance with RFC 8446 6.2 ("Upon transmission or receipt of
    // a fatal alert message, both parties MUST immediately close the connection") even if there
    // are records in the same processNetworkData call as the non-closeNotify alert.
    func testHandshakeDropsRecordBundledAfterAlertInSameBuffer() throws {
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        // The client hasn't processed a ServerHello yet, so currentReadEncryptionLevel is still
        // nil and incoming records of any content type are parsed as plaintext (parseOneRecord).

        var buffer = ByteBuffer()

        // Record 1: a plaintext fatal alert, simulating the peer aborting the handshake.
        let alert = Alert.handshakeFailure
        var alertBuffer = ByteBuffer(bytes: [])
        alertBuffer.writeAlert(alert)
        let alertRecord = TLSPlaintext(contentType: .alert, protocolVersion: .tlsv12,
                                        fragment: [UInt8](alertBuffer.readableBytesView))
        buffer.writeRecord(alertRecord)

        // Record 2: bundled in the SAME buffer immediately after the alert. Reuse an
        // invalid server hello (from RFC test vector). Its content doesn't matter,
        // since per RFC 8446 6.2 it should never be looked at once a fatal alert
        // has been received.
        buffer.writeBytes(TLSRecordHandlerTests.oneRTTServerHelloFullRecord)

        // Record 2 must never reach the client handshake state machine once record 1's alert has
        // been read, so this call must not throw.
        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &buffer))

        XCTAssert(clientRecordHandler.alertRead != nil, "alert from record 1 should have been recorded")
        // If record 2 had reached the handshake state machine, its validation failure would have
        // caused the client to queue its own alert in response. Confirm that never happened.
        XCTAssertNil(clientRecordHandler.alertWrote, "record 2 should never have reached validation")
    }

    func testClientSendsPlaintextAlertOnServerHelloValidationFailure() throws {
        var buffer = ByteBuffer()

        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        // client hello should be in clientRecordHandler.outgoingBytes
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)
        // server processes client hello
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))

        // server hello, ee, certificate, certificate verify, finished messages should be in
        // serverRecordHandler.outgoingBytes
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)

        // pass client an invalid server hello (from RFC test vector)
        var serverHello = ByteBuffer(bytes: TLSRecordHandlerTests.oneRTTServerHelloFullRecord)
        XCTAssertThrowsError(try clientRecordHandler.processNetworkData(networkDataIn: &serverHello))

        // check that alert is written out
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)
        // server processes client alert
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))
        XCTAssert(serverRecordHandler.alertRead != nil)
    }

    func testClientSendsAlertAsFirstMessage() throws {
        var buffer = ByteBuffer()
        let alert = Alert.handshakeFailure
        var alertBuffer = ByteBuffer(bytes: [])
        alertBuffer.writeAlert(alert)
        let record = TLSPlaintext(contentType: .alert, protocolVersion: .tlsv12, fragment: [UInt8](alertBuffer.readableBytesView))
        buffer.writeRecord(record)

        // server processes client alert
        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))
        // don't count as a valid alert since it is before hs start
        XCTAssert(serverRecordHandler.alertRead == nil)
    }

    func testClientSendsGarbageAsFirstMessage() throws {
        var garbage = ByteBuffer(data: Data("hello world this is garbage".utf8))

        // server should throw an error but not try to send an alert since there is no connection
        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &garbage))
        XCTAssert(serverRecordHandler.alertWrote == nil)
    }

    func testServerSendsAlertForBadClientHello() throws {
        // make sure clientRecordHandler is started even though we discard it's client hello
        // otherwise can't parse server alert
        try clientRecordHandler.startHandshake()

        // pass server a client hello it can't support
        var clientHello = goodClientHello
        clientHello.extensions.remove(at: 0) // remove supported_versions extension
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.clientHello(clientHello), into: &buffer)
        let record = TLSPlaintext(contentType: .handshake, protocolVersion: .tlsv10, fragment: [UInt8](buffer.readableBytesView))
        var serverBuffer = ByteBuffer()
        serverBuffer.writeRecord(record)

        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &serverBuffer)) { error in
            XCTAssertEqual(error as? TLSError, .protocolVersion)
        }

        // server should have alert to send
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)

        // client processes server alert
        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &serverRecordHandler.outgoingBytes))
        XCTAssert(clientRecordHandler.alertRead != nil)
    }

    func testHandlerHappyPathServerSendAppDataFirst() throws {
        // run handshake
        try runSuccessfulHandshake()

        // send app data client --> server
        let testAppData = ByteBuffer("Hello World!")
        var testAppDataCopy = testAppData
        XCTAssertNoThrow(try serverRecordHandler.addApplicationData(&testAppDataCopy))

        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &self.serverRecordHandler.outgoingBytes))
        XCTAssertGreaterThan(clientRecordHandler.receivedApplicationData.readableBytes, 0)
        XCTAssertEqual(clientRecordHandler.receivedApplicationData, testAppData)

        // send app data server <-- client
        testAppDataCopy = testAppData

        XCTAssertNoThrow(try clientRecordHandler.addApplicationData(&testAppDataCopy))

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &self.clientRecordHandler.outgoingBytes))
        XCTAssertGreaterThan(serverRecordHandler.receivedApplicationData.readableBytes, 0)
        XCTAssertEqual(serverRecordHandler.receivedApplicationData, testAppData)
    }

    func testHandlerHappyPathIncrementalDelivery() throws {
        let clientStateMachine = try HandshakeStateMachine(configuration: self.validClientConfiguration)
        let serverStateMachine = try ServerHandshakeStateMachine(configuration: self.validServerConfiguration)

        var clientRecordHandler = TLSRecordHandler(stateMachine: .client(clientStateMachine))
        var serverRecordHandler = TLSRecordHandler(stateMachine: .server(serverStateMachine))

        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        // client hello should be in clientRecordHandler.outgoingBytes
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        // We're going to _very slowly_ deliver the ClientHello.
        while var byte = clientRecordHandler.outgoingBytes.readSlice(length: 1) {
            XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &byte))
        }

        // server hello, ee, certificate, certificate verify, finished messages should be in
        // serverRecordHandler.outgoingBytes
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)

        // We're going to _very slowly_ deliver the server first flight.
        while var byte = serverRecordHandler.outgoingBytes.readSlice(length: 1) {
            XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &byte))
        }

        // client processes server second flight and sends client finished
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        // We're going to _very slowly_ deliver the client finished.
        while var byte = clientRecordHandler.outgoingBytes.readSlice(length: 1) {
            XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &byte))
        }

        XCTAssertEqual(serverRecordHandler.outgoingBytes.readableBytes, 0)
    }

    func testSendingApplicationDataLargerThanMaxRecordSize() throws {
        try runSuccessfulHandshake()

        // record handler should appropriate split this into two records.
        let rawData = Array<UInt8>(repeating: 0xff, count: Int(maxCiphertextEncryptedRecordLength))
        let testAppData = ByteBuffer(bytes: rawData)
        var testAppDataCopy = testAppData
        XCTAssertNoThrow(try clientRecordHandler.addApplicationData(&testAppDataCopy))

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &self.clientRecordHandler.outgoingBytes))
        XCTAssertGreaterThan(serverRecordHandler.receivedApplicationData.readableBytes, 0)
        XCTAssertEqual(serverRecordHandler.receivedApplicationData, testAppData)
    }

    // According to RFC 8446 if the client is not required to Authenticate then the server may send app data immediately after
    // sending ServerFinished (before receiving ClientFinished), but boringssl does not seem to support this mode so it is not
    // allowed for now.
    func testServerDoesntSendAppDataBeforeValidatingClientFinished() {
        var buffer = ByteBuffer()

        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        // client hello should be in clientRecordHandler.outgoingBytes
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))

        // server hello, ee, certificate, certificate verify, finished messages should be in
        // serverRecordHandler.outgoingBytes
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)
        buffer.writeBuffer(&serverRecordHandler.outgoingBytes)

        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &buffer))

        // client processes server second flight and sends client finished
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)
        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)

        // server should not send application data before receiving client finished
        let appDataString = "Hello World!"
        var testAppData = ByteBuffer(appDataString)
        XCTAssertNoThrow(try serverRecordHandler.addApplicationData(&testAppData))
        XCTAssertEqual(serverRecordHandler.pendingApplicationDataBytes, appDataString.count)

        // server processes client finished and then sends pending application data
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))
        XCTAssertEqual(serverRecordHandler.pendingApplicationDataBytes, 0)
        XCTAssertEqual(serverRecordHandler.outgoingBytes.readableBytes, TLSRecordHandlerTests.expectedCiphertextLength(appDataString.count))
    }

    // Definitely need to ensure that the server won't send app data
    // before validating the client certificate when it is required.
    func testClientRPKServerDoesntSendAppDataBeforeValidatingClientFinished() throws {
        let clientStateMachine = try HandshakeStateMachine(configuration: self.validClientRPKConfiguration)
        let serverStateMachine = try ServerHandshakeStateMachine(configuration: self.validServerConfigurationRequireClientRPK)

        self.clientRecordHandler = TLSRecordHandler(stateMachine: .client(clientStateMachine))
        self.serverRecordHandler = TLSRecordHandler(stateMachine: .server(serverStateMachine))

        var buffer = ByteBuffer()

        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        // client hello should be in clientRecordHandler.outgoingBytes
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))

        // server hello, ee, certificate request, certificate, certificate verify, and finished messages should be in
        // serverRecordHandler.outgoingBytes
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)
        buffer.writeBuffer(&serverRecordHandler.outgoingBytes)

        // check that the server won't send app data after sending finished, but before getting client second flight
        let appDataString = "Hello World!"
        var testAppData = ByteBuffer(appDataString)
        XCTAssertNoThrow(try serverRecordHandler.addApplicationData(&testAppData))
        XCTAssertEqual(
            serverRecordHandler.pendingApplicationDataBytes,
            appDataString.count
        )

        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &buffer))

        // client processes server second flight and sends client certificate, certificate verify, and finished
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)
        let bytesToWriteCount = clientRecordHandler.outgoingBytes.readableBytes
        var allButOneByte = ByteBuffer(data: clientRecordHandler.getOutputData(bytesToWriteCount - 1)!)
        buffer.writeBuffer(&allButOneByte)

        // server processes client certificate, certificate verify, and most of
        // the finished message
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))
        XCTAssertEqual(serverRecordHandler.outgoingBytes.readableBytes, 0)

        // server should not send application data before receiving all of client finished
        testAppData = ByteBuffer(appDataString)
        XCTAssertNoThrow(try serverRecordHandler.addApplicationData(&testAppData))
        XCTAssertEqual(
            serverRecordHandler.pendingApplicationDataBytes,
            appDataString.count * 2
        )

        // add the last byte
        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)
        // server processes client finished and then sends pending application data
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))
        XCTAssertEqual(serverRecordHandler.pendingApplicationDataBytes, 0)
        XCTAssertEqual(
            serverRecordHandler.outgoingBytes.readableBytes,
            TLSRecordHandlerTests
                .expectedCiphertextLength(appDataString.count * 2)
        )
    }

    func testClientDoesntSendAppDataBeforeValidatingServerFinished() {
        var buffer = ByteBuffer()

        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        // client hello should be in clientRecordHandler.outgoingBytes
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        buffer.writeBuffer(&clientRecordHandler.outgoingBytes)

        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &buffer))

        // server hello, ee, certificate, certificate verify, finished messages should be in
        // serverRecordHandler.outgoingBytes
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)
        guard var mostServerFlight = serverRecordHandler.outgoingBytes.readSlice(length: serverRecordHandler.outgoingBytes.readableBytes - 1) else {
            XCTFail("failed to read server second flight bytes")
            return
        }
        // read all but last byte of server finished (so finished not processed by Client)
        buffer.writeBuffer(&mostServerFlight)

        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &buffer))

        // client should hold application data until it receives server finished and sends client finished
        let appDataString = "Hello World!"
        var testAppData = ByteBuffer(appDataString)
        XCTAssertNoThrow(try clientRecordHandler.addApplicationData(&testAppData))
        XCTAssertEqual(
            clientRecordHandler.pendingApplicationDataBytes,
            appDataString.count
        )

        // client processes server finished and then sends client hello pending application data
        XCTAssertNoThrow(try clientRecordHandler.processNetworkData(networkDataIn: &serverRecordHandler.outgoingBytes))
        XCTAssertEqual(clientRecordHandler.pendingApplicationDataBytes, 0)
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, TLSRecordHandlerTests.expectedCiphertextLength(appDataString.count))

    }

    // Regression test for binder truncation bug with multiple binder values.
    //
    // This ClientHello is captured from upstream boringssl configured like:
    // ./bssl client -psk-hex a3f8c2d1e4b7960f5a2e8d3c1b4f7a9e  -psk-identity id
    //
    // The pre_shared_key extension contains two binders: a 32-byte SHA-256
    // binder and a 48-byte SHA-384 binder, giving a total bindersArrayLength of 82
    // (80 raw binder bytes + 2 per-entry length prefix bytes). Before
    // the fix the truncation formula dropped one too few bytes of the ClientHello, corrupting the
    // transcript hash used in binder verification.
    func testInteropMultipleBinders_binderTruncationIsCorrect() throws {
        // ClientHello from an external TLS 1.3 implementation offering two binder values (one for TLS_AES_128_GCM_SHA256 and one for TLS_AES_256_GCM_SHA384)
        let clientHelloRecordHex =
            "1603010200010001fc03037443dc1b0516e27a10259e061b949e4ad9545c655d60" +
            "30e60fd5e50d0da900dc208f2529a0f1a7f5306b56dd2521d0853bbc09311ea474" +
            "3950e4b268d0f901e6900022130113021303c02bc02fc02cc030cca9cca8c009c0" +
            "13c00ac014009c009d002f00350100019100170000ff01000100000a0008000600" +
            "1d00170018000b0002010000230000003300260024001d00205bbb116ccc307ca2" +
            "dabfe247029a4540a6813043258195ec32be9ed1f08c8b3b002d00020101002b00" +
            "050403040303001500bb0000000000000000000000000000000000000000000000" +
            "000000000000000000000000000000000000000000000000000000000000000000" +
            "000000000000000000000000000000000000000000000000000000000000000000" +
            "000000000000000000000000000000000000000000000000000000000000000000" +
            "000000000000000000000000000000000000000000000000000000000000000000" +
            "000000000000000000000000000000000000000000000000000000000000000000" +
            "2900760020000a0002696400000304000100000000000a00026964000003040002" +
            "0000000000522089c4d1037ff708e13a2449a4e08145a7efe26dd0d86b11a74e7c" +
            "e595d829c8bf30f84f7b9f47567f4d47eed0166dc2f39f27b43bdb6eeabae1b703" +
            "73ec652fc7fceb03e31b9ce9d0082a39d5d0780876e7";

        let epskRawBytes: [UInt8] = [
            0xa3, 0xf8, 0xc2, 0xd1, 0xe4, 0xb7, 0x96, 0x0f,
            0x5a, 0x2e, 0x8d, 0x3c, 0x1b, 0x4f, 0x7a, 0x9e,
        ]
        let epsk = try EPSK(
            externalIdentity: ByteBuffer("id"),
            epsk: SymmetricKey(data: epskRawBytes),
            context: ByteBuffer("")
        )
        let serverConfig = ServerHandshakeStateMachine.Configuration(
            serverName: nil,
            quicTransportParameters: nil,
            alpn: nil,
            signingKey: nil,
            validPeerPublicKeys: nil,
            epsks: [epsk],
            useRawEPSKs: false,
            clientAuthRequired: false,
            enableEarlyData: false
        )
        let serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var serverRecordHandler = TLSRecordHandler(stateMachine: .server(serverStateMachine))

        var clientHelloRecord = ByteBuffer(data: try Data(hexString: clientHelloRecordHex))
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &clientHelloRecord))
    }

    // Ensure we reject alerts interleaved between two handshake messages.
    //
    // RFC 9846 §5.1: "Handshake messages MUST NOT be interleaved with other
    // record types. That is, if a handshake message is split over two or more
    // records, there MUST NOT be any other records between them."
    func testInterleavedRecordDuringPartialHandshakeMessageIsRejected() throws {
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &clientRecordHandler.outgoingBytes))

        guard let header = serverRecordHandler.outgoingBytes.readBytes(length: 5) else {
            XCTFail("expected server hello record header")
            return
        }
        let contentLength = Int(header[3]) << 8 | Int(header[4])
        guard let serverHelloFragment = serverRecordHandler.outgoingBytes.readBytes(length: contentLength) else {
            XCTFail("expected server hello record body")
            return
        }

        let splitPoint = serverHelloFragment.count / 2
        let firstHalf = TLSPlaintext(contentType: .handshake, protocolVersion: .tlsv12, fragment: Array(serverHelloFragment[0..<splitPoint]))
        let secondHalf = TLSPlaintext(contentType: .handshake, protocolVersion: .tlsv12, fragment: Array(serverHelloFragment[splitPoint...]))

        var alertBuffer = ByteBuffer(bytes: [])
        alertBuffer.writeAlert(.closeNotify)
        let injectedAlert = TLSPlaintext(contentType: .alert, protocolVersion: .tlsv12, fragment: [UInt8](alertBuffer.readableBytesView))

        var buffer = ByteBuffer()
        buffer.writeRecord(firstHalf)
        buffer.writeRecord(injectedAlert)
        buffer.writeRecord(secondHalf)
        buffer.writeBuffer(&serverRecordHandler.outgoingBytes) // remaining EE/Cert/.../Finished records, unchanged

        XCTAssertThrowsError(try clientRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
        XCTAssertEqual(clientRecordHandler.alertWrote, .unexpectedMessage)
    }

    // Ensure a key change is rejected when the message immediately preceding
    // it is not aligned with a record boundary.
    //
    // RFC 9846 §5.1: "Implementations MUST verify that all messages
    // immediately preceding a key change align with a record boundary; if
    // not, then they MUST terminate the connection with an 'unexpected_message'
    // alert."
    func testUnalignedMessagePrecedingKeyChangeIsRejected() throws {
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &clientRecordHandler.outgoingBytes))

        guard let header = serverRecordHandler.outgoingBytes.readBytes(length: 5) else {
            XCTFail("expected server hello record header")
            return
        }
        let contentLength = Int(header[3]) << 8 | Int(header[4])
        guard var tamperedFragment = serverRecordHandler.outgoingBytes.readBytes(length: contentLength) else {
            XCTFail("expected server hello record body")
            return
        }
        // A valid handshake header (type=Finished, length=32) with no body
        // attached, so the parser buffers it as an in-progress message
        // instead of rejecting it as malformed. This leaves an incomplete
        // message pending right when the client tries to apply the key
        // change ServerHello triggers. This sets us up to ensure the unaligned
        // message is terminated with 'unexpected_message'
        tamperedFragment.append(contentsOf: [HandshakeType.finished.rawValue, 0x00, 0x00, 0x20])
        let tamperedServerHello = TLSPlaintext(contentType: .handshake, protocolVersion: .tlsv12, fragment: tamperedFragment)

        var buffer = ByteBuffer()
        buffer.writeRecord(tamperedServerHello)

        XCTAssertThrowsError(try clientRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
        XCTAssertEqual(clientRecordHandler.alertWrote, .unexpectedMessage)
    }

    // Ensure we do not send zero-length fragments of Handshake types.
    //
    // RFC 9846 §5.1: "Implementations MUST NOT send zero-length fragments of
    // Handshake types, even if those fragments contain padding." The
    // handshake state machine can't currently produce an empty message, so
    // this fragments directly with an explicit empty buffer to confirm it
    // still refuses to write anything.
    func testProcessPartialHandshakeResultWithZeroLengthBytesSendsNothing() throws {
        XCTAssertEqual(clientRecordHandler.outgoingBytesCount, 0)
        XCTAssertNoThrow(try clientRecordHandler.processPartialHandshakeResult(
            partialHandshakeResult: PartialHandshakeResult(handshakeBytesToSend: ByteBuffer())
        ))
        XCTAssertEqual(clientRecordHandler.outgoingBytesCount, 0)
    }

    // Ensure a message that could immediately precede a key change does not
    // coalesce its last record with whatever follows. Tested by creating
    // a ClientHello sized to leave a 100-byte tail record, then a small
    // 10 byte follow up message. These messages should not be coalesced,
    // and should produce 3 records.
    //
    // RFC 9846 §5.1: "Because the ClientHello, EndOfEarlyData, ServerHello,
    // Finished, and KeyUpdate messages can immediately precede a key change,
    // implementations MUST send these messages in alignment with a record
    // boundary."
    func testClientHelloAndFollowingMessageAreNotCoalescedAcrossKeyChange() throws {
        let clientHelloStandIn = [UInt8](repeating: 0xAB, count: Int(maxPlaintextFragmentLength) + 100)
        XCTAssertNoThrow(try clientRecordHandler.processPartialHandshakeResult(
            partialHandshakeResult: PartialHandshakeResult(
                handshakeBytesToSend: ByteBuffer(bytes: clientHelloStandIn),
                newWriteEncryptionLevel: .earlyData(secret: SymmetricKey(size: .bits256))
            )
        ))

        let followingMessage = [UInt8](repeating: 0xCD, count: 10)
        XCTAssertNoThrow(try clientRecordHandler.processPartialHandshakeResult(
            partialHandshakeResult: PartialHandshakeResult(handshakeBytesToSend: ByteBuffer(bytes: followingMessage))
        ))

        var parser = TLSRecordParser()
        parser.appendBytes(&clientRecordHandler.outgoingBytes)

        var records: [[UInt8]] = []
        while let plaintext = try parser.parsePlaintextRecord() {
            XCTAssertEqual(plaintext.contentType, .handshake)
            records.append(plaintext.fragment)
        }

        XCTAssertEqual(parser.numberOfBytesBuffered, 0)
        XCTAssertEqual(records.count, 3, "expected 2 records for the first message and 1 for the second, with none merged")
        XCTAssertEqual(records[0] + records[1], clientHelloStandIn)
        XCTAssertEqual(records[2], followingMessage)
    }

    // Ensure we terminate the connection if we receive a message
    // whose decrypted content is all zero.
    //
    // RFC 9846 §5.4: "If a receiving implementation does not find a
    // non-zero octet in the cleartext, it MUST terminate the connection
    // with an 'unexpected_message' alert."
    func testAllZeroDecryptedContentIsRejected() throws {
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())

        let key = SymmetricKey(size: .bits256)
        let iv = [UInt8](repeating: 0, count: TLSRecordProtector.IVlengthBytes)
        XCTAssertNoThrow(try clientRecordHandler.setReadKeyAndIVForTesting(key, iv, ciphersuite: CipherSuite.TLS_AES_256_GCM_SHA384.rawValue))

        var maliciousProtector = try TLSRecordProtector(writeKey: key, writeIV: iv, ciphersuite: .TLS_AES_256_GCM_SHA384)
        // 5 zero content bytes + a zero (.invalid) content-type byte = a
        // fully zero decrypted cleartext, exercising the backward scan
        // through several zero bytes.
        let allZeroContent = [UInt8](repeating: 0, count: 5)
        let ciphertext = try maliciousProtector.protect(plaintext: allZeroContent.span.bytes, actualContentType: .invalid)

        var buffer = ByteBuffer()
        buffer.writeRecord(ciphertext)

        XCTAssertThrowsError(try clientRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
        XCTAssertEqual(clientRecordHandler.alertWrote, .unexpectedMessage)
    }

    // Ensure we do not accept empty Handshake records.
    //
    // RFC 9846 §5.4: "Implementations MUST NOT send Handshake and Alert
    // records that have a zero-length TLSInnerPlaintext.content; if such a
    // message is received, the receiving implementation MUST terminate the
    // connection with an 'unexpected_message' alert."
    func testZeroLengthHandshakeCiphertextIsRejected() throws {
        // processNetworkData's error path checks handshakeStarted before it
        // will send an alert
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())

        let key = SymmetricKey(size: .bits256)
        let iv = [UInt8](repeating: 0, count: TLSRecordProtector.IVlengthBytes)
        XCTAssertNoThrow(try clientRecordHandler.setReadKeyAndIVForTesting(key, iv, ciphersuite: CipherSuite.TLS_AES_256_GCM_SHA384.rawValue))

        var maliciousProtector = try TLSRecordProtector(writeKey: key, writeIV: iv, ciphersuite: .TLS_AES_256_GCM_SHA384)
        let emptyContent: [UInt8] = []
        let ciphertext = try maliciousProtector.protect(plaintext: emptyContent.span.bytes, actualContentType: .handshake)

        var buffer = ByteBuffer()
        buffer.writeRecord(ciphertext)

        XCTAssertThrowsError(try clientRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
        XCTAssertEqual(clientRecordHandler.alertWrote, .unexpectedMessage)
    }

    // Ensure we do not accept empty Alert records.
    //
    // RFC 9846 §5.4: "Implementations MUST NOT send Handshake and Alert
    // records that have a zero-length TLSInnerPlaintext.content; if such a
    // message is received, the receiving implementation MUST terminate the
    // connection with an 'unexpected_message' alert."
    func testZeroLengthAlertCiphertextIsRejected() throws {
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())

        let key = SymmetricKey(size: .bits256)
        let iv = [UInt8](repeating: 0, count: TLSRecordProtector.IVlengthBytes)
        XCTAssertNoThrow(try clientRecordHandler.setReadKeyAndIVForTesting(key, iv, ciphersuite: CipherSuite.TLS_AES_256_GCM_SHA384.rawValue))

        var maliciousProtector = try TLSRecordProtector(writeKey: key, writeIV: iv, ciphersuite: .TLS_AES_256_GCM_SHA384)
        let emptyContent: [UInt8] = []
        let ciphertext = try maliciousProtector.protect(plaintext: emptyContent.span.bytes, actualContentType: .alert)

        var buffer = ByteBuffer()
        buffer.writeRecord(ciphertext)

        XCTAssertThrowsError(try clientRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
        XCTAssertEqual(clientRecordHandler.alertWrote, .unexpectedMessage)
    }

    // Flips a bit in the AEAD tag of an otherwise-valid application data
    // record and confirms the resulting AEAD authentication failure is
    // reported as bad_record_mac rather than internal_error.
    //
    // RFC 9846 §5.2: "If decryption fails, the receiver MUST terminate the
    // connection with a 'bad_record_mac' alert."
    func testTamperedCiphertextIsRejectedWithBadRecordMac() throws {
        try runSuccessfulHandshake()

        let testAppData = ByteBuffer("Hello World!")
        var testAppDataCopy = testAppData
        XCTAssertNoThrow(try clientRecordHandler.addApplicationData(&testAppDataCopy))

        guard var bytes = clientRecordHandler.outgoingBytes.readBytes(length: clientRecordHandler.outgoingBytes.readableBytes) else {
            XCTFail("expected an outgoing application data record")
            return
        }
        XCTAssertGreaterThan(bytes.count, 5, "expected more than just a record header")
        // Flip the last byte -- the tail of the AEAD tag -- so authentication
        // fails without corrupting the record-layer framing itself.
        bytes[bytes.count - 1] ^= 0x01

        var tamperedBuffer = ByteBuffer(bytes: bytes)
        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &tamperedBuffer)) { error in
            XCTAssertEqual(error as? TLSError, .badRecordMac)
        }
        XCTAssertEqual(serverRecordHandler.alertWrote, .badRecordMac)
    }

    // Runs a handshake, then hands back the wire bytes of an application data
    // record the client just wrote, so a test can tamper with its header.
    private func protectedApplicationDataRecordBytes() throws -> [UInt8] {
        try runSuccessfulHandshake()

        var testAppData = ByteBuffer("Hello World!")
        XCTAssertNoThrow(try clientRecordHandler.addApplicationData(&testAppData))

        guard let bytes = clientRecordHandler.outgoingBytes.readBytes(length: clientRecordHandler.outgoingBytes.readableBytes) else {
            throw TLSError.internalError(reason: "expected an outgoing application data record")
        }
        XCTAssertGreaterThan(bytes.count, 5, "expected more than just a record header")
        return bytes
    }

    // Rewrites the outer content type of an otherwise-valid application data
    // record. The header is the AEAD additional_data, so the modification must
    // be caught as an authentication failure.
    //
    // RFC 9846 §5.2: "additional_data = TLSCiphertext.opaque_type ||
    // TLSCiphertext.legacy_record_version || TLSCiphertext.length" and "If
    // decryption fails, the receiver MUST terminate the connection with a
    // 'bad_record_mac' alert."
    func testTamperedOuterContentTypeIsRejectedWithBadRecordMac() throws {
        var bytes = try protectedApplicationDataRecordBytes()
        XCTAssertEqual(bytes[0], ContentType.applicationData.rawValue)
        bytes[0] = ContentType.alert.rawValue

        var tamperedBuffer = ByteBuffer(bytes: bytes)
        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &tamperedBuffer)) { error in
            XCTAssertEqual(error as? TLSError, .badRecordMac)
        }
        XCTAssertEqual(serverRecordHandler.alertWrote, .badRecordMac)
    }

    // As above, for the legacy_record_version bytes of the received header.
    //
    // RFC 9846 §5.2: "The value of TLSCiphertext.legacy_record_version is
    // included in the additional data for deprotection."
    func testTamperedLegacyRecordVersionIsRejectedWithBadRecordMac() throws {
        var bytes = try protectedApplicationDataRecordBytes()
        bytes[1] = 0xab
        bytes[2] = 0xcd

        var tamperedBuffer = ByteBuffer(bytes: bytes)
        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &tamperedBuffer)) { error in
            XCTAssertEqual(error as? TLSError, .badRecordMac)
        }
        XCTAssertEqual(serverRecordHandler.alertWrote, .badRecordMac)
    }

    // Ensure a protected CCS record is rejected.
    //
    // RFC 9846: "An implementation which ... receives a protected
    // change_cipher_spec record MUST abort the handshake with an
    // "unexpected_message" alert."
    func testProtectedChangeCipherSpecIsRejected() throws {
        try runSuccessfulHandshake()

        let ciphertext = try clientRecordHandler.protectForTesting(plaintext: [0x01], actualContentType: .changeCipherSpec)
        var buffer = ByteBuffer()
        buffer.writeRecord(ciphertext)

        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
        XCTAssertEqual(serverRecordHandler.alertWrote, .unexpectedMessage)
    }

    // Ensure a CCS before Client Hello is rejected.
    //
    // RFC 9846 §5: "If an implementation detects a change_cipher_spec record
    // received before the first ClientHello message or after the peer's Finished
    // message, it MUST be treated as an unexpected record type"
    //
    // Note: since the server hasn't started a handshake yet, the generic
    // "no connection exists" guard in processNetworkData normalizes
    // the underlying error to processNetworkDataErrorBeforeHandshakeStart and
    // suppresses sending an alert, same as it does for a plaintext alert
    // arriving before handshake start.
    func testChangeCipherSpecBeforeFirstClientHelloIsRejected() throws {
        var buffer = ByteBuffer(data: try Data(hexString: "140303000101"))

        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .processNetworkDataErrorBeforeHandshakeStart)
        }
        XCTAssertNil(serverRecordHandler.alertWrote)
    }

    // Ensure a CCS after peer Finished is rejected.
    //
    // RFC 9846 §5: "If an implementation detects a change_cipher_spec record
    // received before the first ClientHello message or after the peer's Finished
    // message, it MUST be treated as an unexpected record type"
    func testChangeCipherSpecAfterPeerFinishedIsRejected() throws {
        try runSuccessfulHandshake()

        var buffer = ByteBuffer(data: try Data(hexString: "140303000101"))
        XCTAssertThrowsError(try serverRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
        XCTAssertEqual(serverRecordHandler.alertWrote, .unexpectedMessage)
    }

    // Client-side: Ensure a CCS before Client Hello is rejected.
    //
    // RFC 9846 §5: "If an implementation detects a change_cipher_spec record
    // received before the first ClientHello message or after the peer's Finished
    // message, it MUST be treated as an unexpected record type"

    func testChangeCipherSpecBeforeFirstClientHelloIsRejectedOnClient() throws {
        var buffer = ByteBuffer(data: try Data(hexString: "140303000101"))

        XCTAssertThrowsError(try clientRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .processNetworkDataErrorBeforeHandshakeStart)
        }
        XCTAssertNil(clientRecordHandler.alertWrote)
    }

    // Client-side: Ensure a CCS after peer Finished is rejected.
    //
    // RFC 9846 §5: "If an implementation detects a change_cipher_spec record
    // received before the first ClientHello message or after the peer's Finished
    // message, it MUST be treated as an unexpected record type"
    func testChangeCipherSpecAfterPeerFinishedIsRejectedOnClient() throws {
        try runSuccessfulHandshake()

        var buffer = ByteBuffer(data: try Data(hexString: "140303000101"))
        XCTAssertThrowsError(try clientRecordHandler.processNetworkData(networkDataIn: &buffer)) { error in
            XCTAssertEqual(error as? TLSError, .handshakeUnexpectedMessage)
        }
        XCTAssertEqual(clientRecordHandler.alertWrote, .unexpectedMessage)
    }

    // RFC 9846 §5.1: "The value of TLSPlaintext.legacy_record_version MUST
    // be 0x0303 for all records generated by a TLS 1.3 implementation other
    // than an initial ClientHello, where it MAY also be 0x0301 for
    // compatibility purposes."
    //
    // Unlike the ServerHello test below (where only one value is
    // compliant), this accepts either value permitted for a ClientHello.
    func testOutgoingClientHelloLegacyRecordVersionIsPermitted() throws {
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())

        var parser = TLSRecordParser()
        parser.appendBytes(&clientRecordHandler.outgoingBytes)
        guard let record = try parser.parsePlaintextRecord() else {
            XCTFail("expected a parseable ClientHello record")
            return
        }
        // Check the literal wire bytes directly (rather than only comparing
        // against the .tlsv12/.tlsv10 constants) in case the constants happen
        // to change from what is specified in the RFC.
        let version = record.protocolVersion
        let isTLS12Encoding = version.major == 0x03 && version.minor == 0x03
        let isTLS10Encoding = version.major == 0x03 && version.minor == 0x01
        XCTAssertTrue(isTLS12Encoding || isTLS10Encoding,
                      "ClientHello legacy_record_version must be 0x0303 or 0x0301, got \(version.major).\(version.minor)")
    }

    // RFC 9846 §5.1: unlike the initial ClientHello (which MAY be 0x0303 or
    // 0x0301), a ServerHello has no such allowance, it MUST be exactly
    // 0x0303. Confirms the server's outgoing ServerHello record enforces
    // this requirement.
    func testOutgoingServerHelloUsesTLS12LegacyRecordVersion() throws {
        XCTAssertNoThrow(try clientRecordHandler.startHandshake())
        XCTAssertNoThrow(try serverRecordHandler.processNetworkData(networkDataIn: &clientRecordHandler.outgoingBytes))

        var parser = TLSRecordParser()
        parser.appendBytes(&serverRecordHandler.outgoingBytes)
        guard let record = try parser.parsePlaintextRecord() else {
            XCTFail("expected a parseable ServerHello record")
            return
        }
        XCTAssertEqual(record.protocolVersion, .tlsv12)
        XCTAssertEqual(record.protocolVersion.major, 0x03)
        XCTAssertEqual(record.protocolVersion.minor, 0x03)
    }

    func testAsyncCertificateDeliveryContinuation() throws {
        let dummySignatureAlgorithm = SignatureScheme.ecdsa_secp256r1_sha256.rawValue
        let dummySignature = Data(repeating: 0xAB, count: 64)
        let dummyCertificates = [Data(repeating: 0xCD, count: 128)]

        let capturedCertClosure = Mutex<(@Sendable (CertificateResult) -> Void)?>(nil)

        let serverConfig = ServerHandshakeStateMachine.Configuration(
            serverName: nil,
            quicTransportParameters: nil,
            alpn: ["proto A", "proto B"],
            transportIsQUIC: false,
            asyncAuthenticator: AsyncAuthenticator(
                supportedCertificateTypes: [.x509],
                getCertificateChain: { certInfo in
                    capturedCertClosure.withLock { $0 = certInfo.deliverResult }
                    return .waiting
                },
                signTranscriptHash: { _ in
                    .available(signature: dummySignature, algorithm: dummySignatureAlgorithm)
                }
            )
        )

        let clientConfig = HandshakeStateMachine.Configuration(
            serverName: nil,
            quicTransportParameters: nil,
            alpn: ["proto A"],
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(
                availableCertificateTypes: [.x509],
                verificationCallback: { _ in .valid }
            )
        )

        let clientStateMachine = try HandshakeStateMachine(configuration: clientConfig)
        let serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)
        var clientRecordHandler = TLSRecordHandler(stateMachine: .client(clientStateMachine))
        var serverRecordHandler = TLSRecordHandler(stateMachine: .server(serverStateMachine))

        // Set up the deliver result callback to capture the PendingAsyncResult.
        let pendingResultMutex = Mutex<PendingAsyncResult?>(nil)
        serverRecordHandler.setDeliverResultCallback { result in
            pendingResultMutex.withLock { $0 = result }
        }

        // ClientHello
        try clientRecordHandler.startHandshake()
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        // Server processes ClientHello: produces ServerHello + EncryptedExtensions,
        // then hits the certificate callback which returns .waiting.
        try serverRecordHandler.processNetworkData(networkDataIn: &clientRecordHandler.outgoingBytes)

        // Server produced ServerHello + EncryptedExtensions before pausing.
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)

        // Client processes ServerHello + EncryptedExtensions.
        try clientRecordHandler.processNetworkData(networkDataIn: &serverRecordHandler.outgoingBytes)

        // The certificate callback captured the deliverResult closure.
        let deliverCert = capturedCertClosure.withLock { $0 }
        XCTAssertNotNil(deliverCert)

        // Simulate async certificate delivery.
        deliverCert!(.available(.init(type: .x509, entries: dummyCertificates)))

        // The deliverResultCallback should have received the pending result.
        let pendingResult = pendingResultMutex.withLock { $0 }
        XCTAssertNotNil(pendingResult)

        // Apply the result and continue the handshake.
        serverRecordHandler.applyAsyncResult(pendingResult!)
        try serverRecordHandler.continueHandshake()

        // Server should have produced Certificate + CertificateVerify + Finished.
        XCTAssertGreaterThan(serverRecordHandler.outgoingBytes.readableBytes, 0)

        // Client processes server's Certificate + CertificateVerify + Finished.
        try clientRecordHandler.processNetworkData(networkDataIn: &serverRecordHandler.outgoingBytes)
        // Client sends Finished.
        XCTAssertGreaterThan(clientRecordHandler.outgoingBytes.readableBytes, 0)

        // Server processes client Finished.
        try serverRecordHandler.processNetworkData(networkDataIn: &clientRecordHandler.outgoingBytes)

        // Handshake complete on both sides.
        XCTAssertTrue(clientRecordHandler.handshakeComplete)
        XCTAssertTrue(serverRecordHandler.handshakeComplete)

        // Verify application data flows.
        let testData = ByteBuffer("hello from client")
        var testDataCopy = testData
        try clientRecordHandler.addApplicationData(&testDataCopy)
        try serverRecordHandler.processNetworkData(networkDataIn: &clientRecordHandler.outgoingBytes)
        XCTAssertEqual(serverRecordHandler.receivedApplicationData, testData)
    }
}
