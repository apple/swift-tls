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
class HandshakeStateMachineTests: XCTestCase {

    var serverPrivateKey = P384EphemeralKey()
    var serverX25519PrivateKey = Curve25519EphemeralKey()

    var serverSigningKey: P256.Signing.PrivateKey {
        configurationGenerator.serverSigningKey
    }

    var configurationGenerator = try! TestConfigurationGenerator()

    var validConfigurationNoClientAuth: HandshakeStateMachine.Configuration {
        configurationGenerator.getClientConfigWithOptions()
    }

    var validConfigurationWithEarlyData: HandshakeStateMachine.Configuration {
        configurationGenerator.getClientConfigWithOptions(enableEarlyData: true)
    }

    var validConfigurationWithX25519: HandshakeStateMachine.Configuration {
        configurationGenerator.getClientConfigWithOptions(fixedKeyExchangeGroup: NamedGroup.x25519)
    }

    var validConfigurationWithX25519MLKEM768: HandshakeStateMachine.Configuration {
        configurationGenerator.getClientConfigWithOptions(fixedKeyExchangeGroup: NamedGroup.x25519MLKEM768)
    }

    var validConfigurationWithChaCha20: HandshakeStateMachine.Configuration {
        configurationGenerator.getClientConfigWithOptions(supportedCipherSuites: [.TLS_CHACHA20_POLY1305_SHA256])
    }

    var goodServerHello: ServerHello {
        return ServerHello(
            legacyVersion: .tlsv12,
            random: Random(),
            legacySessionIDEcho: .zero,
            cipherSuite: .TLS_AES_256_GCM_SHA384,
            legacyCompressionMethod: .zero,
            extensions: [
                .supportedVersions(.selection(.tlsv13)),
                .keyShare(.serverHello(.init(group: self.serverPrivateKey.namedGroup, keyExchange: ByteBuffer(data: self.serverPrivateKey.publicKeyData)))),
            ]
        )
    }

    var goodServerHelloWithX25519: ServerHello {
        return ServerHello(
            legacyVersion: .tlsv12,
            random: Random(),
            legacySessionIDEcho: .zero,
            cipherSuite: .TLS_AES_256_GCM_SHA384,
            legacyCompressionMethod: .zero,
            extensions: [
                .supportedVersions(.selection(.tlsv13)),
                .keyShare(.serverHello(.init(group: self.serverX25519PrivateKey.namedGroup, keyExchange: ByteBuffer(data: self.serverX25519PrivateKey.publicKeyData)))),
            ]
        )
    }

    var goodServerHelloWithChaCha20: ServerHello {
        return ServerHello(
            legacyVersion: .tlsv12,
            random: Random(),
            legacySessionIDEcho: .zero,
            cipherSuite: .TLS_CHACHA20_POLY1305_SHA256,
            legacyCompressionMethod: .zero,
            extensions: [
                .supportedVersions(.selection(.tlsv13)),
                .keyShare(.serverHello(.init(group: self.serverPrivateKey.namedGroup, keyExchange: ByteBuffer(data: self.serverPrivateKey.publicKeyData)))),
            ]
        )
    }

    var stub_serverHelloBuffer: ByteBuffer {
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.serverHello(self.goodServerHello), into: &buffer)
        return buffer
    }

    var stub_serverHelloWithX25519Buffer: ByteBuffer {
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.serverHello(self.goodServerHelloWithX25519), into: &buffer)
        return buffer
    }

    var stub_serverHelloWithChaCha20Buffer: ByteBuffer {
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.serverHello(self.goodServerHelloWithChaCha20), into: &buffer)
        return buffer
    }

    var goodServerHelloWithPSKIndexZeroSelected: ServerHello {
        return ServerHello(
            legacyVersion: .tlsv12,
            random: Random(),
            legacySessionIDEcho: .zero,
            cipherSuite: .TLS_AES_256_GCM_SHA384,
            legacyCompressionMethod: .zero,
            extensions: [
                .supportedVersions(.selection(.tlsv13)),
                .keyShare(.serverHello(.init(group: self.serverPrivateKey.namedGroup, keyExchange: ByteBuffer(data: self.serverPrivateKey.publicKeyData)))),
                .preSharedKey(.serverHello(0))
            ]
        )
    }
    
    var stub_serverHelloBufferWithPSKIndexZeroSelected: ByteBuffer {
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.serverHello(self.goodServerHelloWithPSKIndexZeroSelected), into: &buffer)
        return buffer
    }

    func makeEncryptedExtensionsBuffer(
        serverCertificateType: CertificateType? = .rawPublicKey,
        quicTransportParameters: ByteBuffer? = nil,
        alpnSelection: ApplicationLayerProtocol? = nil,
        sendEmptySNI: Bool = false,
        additionalExtensions: [Extension]? = nil
    ) -> ByteBuffer {
        var buffer = ByteBuffer()
        var extensions: [Extension] = [
            .supportedGroups(.init(groups: [.secp384])),
        ]

        if let serverCertificateType {
            extensions.append(.serverCertificateType(.selection(serverCertificateType)))
        }

        if let quicTransportParameters = quicTransportParameters {
            extensions.append(.quicTransportParameters(.init(opaqueOffer: quicTransportParameters)))
        }

        if let alpnSelection = alpnSelection {
            extensions.append(.alpn(.selection(alpnSelection)))
        }

        if sendEmptySNI {
            extensions.append(.serverName(.encryptedExtensions))
        }

        if let additionalExtensions = additionalExtensions {
            extensions.append(contentsOf: additionalExtensions)
        }

        TLSMessageSerializer().writeHandshakeMessage(.encryptedExtensions(.init(extensions: extensions)), into: &buffer)
        return buffer
    }

    func makeEncryptedExtensionsForPSKBuffer(quicTransportParameters: ByteBuffer? = nil, alpnSelection: ApplicationLayerProtocol? = nil, earlyDataAccepted: Bool = false) -> ByteBuffer {
        var buffer = ByteBuffer()
        var extensions: [Extension] = [
            .supportedGroups(.init(groups: [.secp384])),
        ]

        if let quicTransportParameters = quicTransportParameters {
            extensions.append(.quicTransportParameters(.init(opaqueOffer: quicTransportParameters)))
        }

        if let alpnSelection = alpnSelection {
            extensions.append(.alpn(.selection(alpnSelection)))
        }

        if earlyDataAccepted {
            extensions.append(.earlyData(.init()))
        }

        TLSMessageSerializer().writeHandshakeMessage(.encryptedExtensions(.init(extensions: extensions)), into: &buffer)
        return buffer
    }

    var stub_serverCertificateBuffer: ByteBuffer {
        var buffer = ByteBuffer()
        let message = CertificateMessage(
            certificateRequestContext: ByteBuffer(),
            certificateList: [
                .init(opaqueCertificateData: ByteBuffer(data: serverSigningKey.publicKey.derRepresentation), extensions: []),
            ]
        )
        TLSMessageSerializer().writeHandshakeMessage(.certificate(message), into: &buffer)
        return buffer
    }

    func makeServerCertificateVerifyBuffer(
        signingKey: P256.Signing.PrivateKey,
        keyScheduler: ClientSessionKeyManager<SHA384>,
        algorithm: SignatureScheme = .ecdsa_secp256r1_sha256) throws -> ByteBuffer {
        var buffer = ByteBuffer()
        let certificateVerify = CertificateVerify(
            algorithm: algorithm,
            signature: ByteBuffer(data: try signingKey.signature(for: keyScheduler.dataToSignInServerCertificateVerify().readableBytesView).derRepresentation)
        )
        TLSMessageSerializer().writeHandshakeMessage(.certificateVerify(certificateVerify), into: &buffer)
        return buffer
    }

    func makeServerFinished(scheduler: ClientSessionKeyManager<SHA384>) throws -> ByteBuffer {
        var buffer = ByteBuffer()
        let finished = Data(try scheduler.serverFinishedPayload())
        TLSMessageSerializer().writeHandshakeMessage(.finished(FinishedMessage.init(verifyData: ByteBuffer(data: finished))), into: &buffer)
        return buffer
    }

    var goodNewSessionTicket: NewSessionTicket {
        NewSessionTicket(ticketLifetime: 1,
                                       ticketAgeAdd: 2,
                                       ticketNonce: ByteBuffer("nonce"),
                                       ticket: ByteBuffer("ticket"),
                                       extensions: [])
    }

    var stub_newSessionTicket: ByteBuffer {
        var buffer = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.newSessionTicket(self.goodNewSessionTicket), into: &buffer)
        return buffer
    }

    var stubSerializedSessionTicket: Data {
        let ticket = try! SessionTicket(
            message: NewSessionTicket(
                ticketLifetime: 700,
                ticketAgeAdd: 0xffffffff,
                ticketNonce: ByteBuffer(bytes: "ticket nonce".utf8),
                ticket: ByteBuffer(bytes: "ticket".utf8),
                extensions: []
            ),
            psk: .init(size: .init(bitCount: SHA384Digest.byteCount / 8)),
            cipherSuite: .TLS_AES_256_GCM_SHA384,
            group: .secp384,
            alpn: nil,
            certificateBundle: PeerCertificateBundle(
                expectedCertificateType: .x509,
                peerCertificateMessage: CertificateMessage(
                    certificateRequestContext: ByteBuffer(bytes: []),
                    certificateList: [.init(opaqueCertificateData: ByteBuffer(bytes: []), extensions: [])]
                ),
                fromClient: false
            ),
            currentTime: Date()
        )
        return ticket.serialize()
    }

    func testStartHandshake() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)

        // first start shouldn't throw
        do {
            var buffer = try stateMachine.startHandshake().handshakeBytesToSend!
            var parser = HandshakeMessageParser()
            parser.appendBytes(&buffer)
            guard let message = try parser.parseHandshakeMessage(), case .clientHello(_) = message.message else {
                XCTFail("Didn't get a ClientHello")
                return
            }
        } catch {
            XCTFail("\(error)")
            return
        }

        // calling start twice should error because of the internal state
        XCTAssertThrowsError(try stateMachine.startHandshake())
    }

    // run the happy path
    // server hello                 -> nil
    // server extensions            -> nil
    // server certificate           -> nil
    // server certificate verify    -> nil
    // server finish                -> client finished
    // new session ticket (a few times) -> nil
    func testReadNetworkDataHappyPath() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertNil(stateMachine.earlyDataAccepted)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // check that client finished is returned
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // Feed in the new session ticket. It should be consumed, and produce a new session ticket.
        inputBuffer = stub_newSessionTicket
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
#if !SWIFTTLS_DRIVERKIT
        try stateMachine.processHandshake().assertNewSessionTicket()
#else
        // DriverKit client can't process session tickets (no Date)
        try stateMachine.processHandshake().assertNoNewSessionTicket()
#endif
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
    }

    // run the happy path where both client and server agree on the key exchange algorithm
    // server hello                 -> nil
    // server extensions            -> nil
    // server certificate           -> nil
    // server certificate verify    -> nil
    // server finish                -> client finished
    // new session ticket (a few times) -> nil
    func testReadNetworkDataHappyPathWithX25519() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationWithX25519)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

        // server hello
        var inputBuffer = stub_serverHelloWithX25519Buffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverX25519PrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.negotiatedGroup, NamedGroup.x25519.metadataDescription)
        XCTAssertNil(stateMachine.earlyDataAccepted)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // check that client finished is returned
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // Feed in the new session ticket. It should be consumed, and produce a new session ticket.
        inputBuffer = stub_newSessionTicket
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
#if !SWIFTTLS_DRIVERKIT
        try stateMachine.processHandshake().assertNewSessionTicket()
#else
        // DriverKit client can't process session tickets (no Date)
        try stateMachine.processHandshake().assertNoNewSessionTicket()
#endif
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
    }

    // run the happy path where both client and server agree on the ciphersuite
    // server hello                 -> nil
    // server extensions            -> nil
    // server certificate           -> nil
    // server certificate verify    -> nil
    // server finish                -> client finished
    // new session ticket (a few times) -> nil
    func testReadNetworkDataHappyPathWithChaCha20() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationWithChaCha20)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

        // server hello
        var inputBuffer = stub_serverHelloWithChaCha20Buffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_CHACHA20_POLY1305_SHA256.rawValue)
        XCTAssertNil(stateMachine.earlyDataAccepted)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_CHACHA20_POLY1305_SHA256.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_CHACHA20_POLY1305_SHA256.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_CHACHA20_POLY1305_SHA256.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_CHACHA20_POLY1305_SHA256.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // check that client finished is returned
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // Feed in the new session ticket. It should be consumed, and produce a new session ticket.
        inputBuffer = stub_newSessionTicket
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
#if !SWIFTTLS_DRIVERKIT
        try stateMachine.processHandshake().assertNewSessionTicket()
#else
        // DriverKit client can't process session tickets (no Date)
        try stateMachine.processHandshake().assertNoNewSessionTicket()
#endif
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_CHACHA20_POLY1305_SHA256.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
    }

    // run a failure case where both parties disagree on the group (misconfiguration)
    // server hello                 -> nil
    // fail
    func testFailedHandshakeWithGroupDisagreement() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

        // server hello
        var inputBuffer = stub_serverHelloWithX25519Buffer
        networkBuffer.writeBuffer(&inputBuffer)
        XCTAssertThrowsError(try self.serverX25519PrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView))
    }

    func testReadNetworkDataHappyPathSlabData() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(makeEncryptedExtensionsBuffer())

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(stub_serverCertificateBuffer)

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        try scheduler.addPreFinishedMessageToTransportHash(inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)

        // server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)

        // new session ticket
        inputBuffer = stub_newSessionTicket
        networkBuffer.writeBuffer(&inputBuffer)

        // Ok, dump all the messages in.
        stateMachine.receivedNetworkData(&networkBuffer)

        // Now spin the state machine. This will initially go up to the handshake keys.
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // Spin again, we'll go through to the application keys and finished message.
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = try scheduler.clientFinishedPayload()
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage.init(verifyData: ByteBuffer(data: Data(clientFinishedPayload)))), into: &expectedBuffer)
        result = try stateMachine.processHandshake()
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)

        // Spin again, this will pull out the new session ticket.
#if !SWIFTTLS_DRIVERKIT
        try stateMachine.processHandshake().assertNewSessionTicket()
#else
        // DriverKit client can't process session tickets (no Date)
        try stateMachine.processHandshake().assertNoNewSessionTicket()
#endif
    }

    func testReadNetworkDataHappyPathIncrementalDelivery() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)

        // We're going to _very slowly_ deliver the ServerHello.
        while var byte = networkBuffer.readSlice(length: 1) {
            stateMachine.receivedNetworkData(&byte)
            let result = try stateMachine.processHandshake()

            if networkBuffer.readableBytes > 0 {
                XCTAssertNil(result)
            } else {
                XCTAssertNil(result?.handshakeBytesToSend)
                result.assertNewReadAndWriteEncryptionLevel(.handshake)
            }
        }

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(makeEncryptedExtensionsBuffer())

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(stub_serverCertificateBuffer)

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        try scheduler.addPreFinishedMessageToTransportHash(inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)

        // server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)

        // Again, we're going to _very slowly_ deliver these messages.
        while var byte = networkBuffer.readSlice(length: 1) {
            stateMachine.receivedNetworkData(&byte)
            let result = try stateMachine.processHandshake()

            if networkBuffer.readableBytes > 0 {
                XCTAssertNil(result)
            } else {
                var expectedBuffer = ByteBuffer()
                let clientFinishedPayload = try scheduler.clientFinishedPayload()
                TLSMessageSerializer().writeHandshakeMessage(.finished(FinishedMessage.init(verifyData: ByteBuffer(data: Data(clientFinishedPayload)))), into: &expectedBuffer)
                XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
                result.assertNewReadAndWriteEncryptionLevel(.application)
            }
        }

        #if !SWIFTTLS_DRIVERKIT
        // new session ticket
        inputBuffer = stub_newSessionTicket
        networkBuffer.writeBuffer(&inputBuffer)

        // We're going to _very slowly_ deliver the NewSessionTicket.
        while var byte = networkBuffer.readSlice(length: 1) {
            stateMachine.receivedNetworkData(&byte)
            let result = try stateMachine.processHandshake()

            if networkBuffer.readableBytes > 0 {
                XCTAssertNil(result)
            } else {
                result.assertNewSessionTicket()
            }
        }
        #endif
    }

    func testReadNetworkDataSadPathInvalidServerSignature() throws {

        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate verify
        // invalid signing key
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: .init(), keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .certificateError)
        }
    }

    func testReadNetworkDataSadPathInvalidSignatureAlgorithm() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(
            signingKey: self.serverSigningKey,
            keyScheduler: scheduler,
            algorithm: SignatureScheme(rawValue: 0xFFFF) // signature algorithm mismatch
        )
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .illegalParameter)
        }
    }

    func testReadNetworkDataSadPathInvalidFinished() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(makeEncryptedExtensionsBuffer())

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(stub_serverCertificateBuffer)

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        try scheduler.addPreFinishedMessageToTransportHash(inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)

        // server finished
        var serverFinishedInput = ByteBuffer("bogus bytes")
        try serverFinishedInput.withInputBuffer { serverFinishedInput in
            var serverFinishedOutput = ByteBuffer(data: Data())
            try TLSMessageSerializer().writeHandshakeMessage(.finished(.init(bytes: &serverFinishedInput)), into: &serverFinishedOutput)
            try scheduler.postServerFinished(serverFinishedBytes: try self.makeServerFinished(scheduler: scheduler))
            networkBuffer.writeBuffer(&serverFinishedOutput)
        }

        // Ok, dump all the messages in.
        stateMachine.receivedNetworkData(&networkBuffer)

        // Now spin the state machine. This will initially go up to the handshake keys.
        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // Spin again, we'll go through to the application keys and finished message.
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = try scheduler.clientFinishedPayload()
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage.init(verifyData: ByteBuffer(data: Data(clientFinishedPayload)))), into: &expectedBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    // a valid server hello message, but the internal state is expected to have progressed past `.idle`
    func testReadNetworkDataSadPathIdle() throws {
        var networkBuffer = ByteBuffer()

        // server hello
        networkBuffer = stub_serverHelloBuffer
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, TLSError.handshakeUnexpectedRead)
        }
    }

    // expected server hello message, got a different (but valid) message
    func testReadNetworkDataServerHelloNonsenseMessage() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        XCTAssertNoThrow(try stateMachine.startHandshake())

        var networkBuffer = ByteBuffer()

        // server hello
        networkBuffer = makeEncryptedExtensionsBuffer()
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, TLSError.handshakeUnexpectedMessage)
        }
    }

    func testReadNetworkDataServerHelloInvalidMessage() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        XCTAssertNoThrow(try stateMachine.startHandshake())

        var networkBuffer = ByteBuffer(bytes: [0xFF, 0x00, 0x00, 0x00])

        // server hello
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, TLSError.handshakeInvalidMessage)
        }
    }

    private func assertBogusServerHelloRejected(_ bogoServerHello: ServerHello) throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        XCTAssertNoThrow(try stateMachine.startHandshake())

        var bytes = ByteBuffer()
        TLSMessageSerializer().writeHandshakeMessage(.serverHello(bogoServerHello), into: &bytes)

        stateMachine.receivedNetworkData(&bytes)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testReadNetworkDataHelloRetryRequest() throws {
        let bogoServerHello = ServerHello(legacyVersion: .tlsv12,
                                          random: .helloRetryRequest,
                                          legacySessionIDEcho: .zero,
                                          cipherSuite: .TLS_AES_256_GCM_SHA384,
                                          legacyCompressionMethod: .zero,
                                          extensions: [
                                            .supportedVersions(.selection(.tlsv13)),
                                            .keyShare(.helloRetryRequest(.init(rawValue: 0xffff))),
                                          ])
        try self.assertBogusServerHelloRejected(bogoServerHello)
    }

    func testInvalidLegacySessionID() throws {
        var bogoServerHello = self.goodServerHello
        bogoServerHello.legacySessionIDEcho = .random()
        try self.assertBogusServerHelloRejected(bogoServerHello)
    }

    func testInvalidLegacyVersion() throws {
        var bogoServerHello = self.goodServerHello
        bogoServerHello.legacyVersion = .tlsv10
        try self.assertBogusServerHelloRejected(bogoServerHello)
    }

    func testInvalidLegacyCompression() throws {
        var bogoServerHello = self.goodServerHello
        bogoServerHello.legacyCompressionMethod = 5
        try self.assertBogusServerHelloRejected(bogoServerHello)
    }

    func testInvalidSupportedVersions() throws {
        var bogoServerHello = self.goodServerHello
        bogoServerHello.extensions = bogoServerHello.extensions.map {
            switch $0 {
            case .supportedVersions:
                return .supportedVersions(.selection(.tlsv12))
            default:
                return $0
            }
        }
        try self.assertBogusServerHelloRejected(bogoServerHello)
    }

    func testMismatchedCipherSuites() throws {
        var bogoServerHello = self.goodServerHello
        bogoServerHello.cipherSuite = .init(rawValue: 0xffff)
        try self.assertBogusServerHelloRejected(bogoServerHello)
    }

    func testUnacceptableKeyShare() throws {
        let p521Curve = P521.KeyAgreement.PrivateKey().publicKey.x963Representation

        var bogoServerHello = self.goodServerHello
        bogoServerHello.extensions = bogoServerHello.extensions.map {
            switch $0 {
            case .keyShare:
                // 0x0019 is the P521 key share code point.
                return .keyShare(.serverHello(.init(group: .init(rawValue: 0x0019), keyExchange: ByteBuffer(data: p521Curve))))
            default:
                return $0
            }
        }
        try self.assertBogusServerHelloRejected(bogoServerHello)
    }

    func testMissingKeyShare() throws {
        var bogoServerHello = self.goodServerHello
        bogoServerHello.extensions = bogoServerHello.extensions.filter {
            switch $0 {
            case .keyShare:
                return false
            default:
                return true
            }
        }
        try self.assertBogusServerHelloRejected(bogoServerHello)
    }

    func testInvalidKeyShareBytes() throws {
        var bogoServerHello = self.goodServerHello
        bogoServerHello.extensions = bogoServerHello.extensions.map {
            switch $0 {
            case .keyShare:
                return .keyShare(.serverHello(.init(group: .secp384, keyExchange: ByteBuffer("some invalid nonsense"))))
            default:
                return $0
            }
        }
        try self.assertBogusServerHelloRejected(bogoServerHello)
    }

    private func assertBogusEncryptedExtensions(_ bogoEncryptedExtensions: EncryptedExtensions) throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        XCTAssertNoThrow(try stateMachine.startHandshake())

        var bytes = ByteBuffer()
        var inputBuffer = stub_serverHelloBuffer
        bytes.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&bytes)

        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        TLSMessageSerializer().writeHandshakeMessage(.encryptedExtensions(bogoEncryptedExtensions), into: &bytes)
        stateMachine.receivedNetworkData(&bytes)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testDisagreeOnCertificateType() throws {
        let bogoEncryptedExtensions = EncryptedExtensions(extensions: [
            .serverCertificateType(.selection(.init(rawValue: 0xff)))
        ])
        try self.assertBogusEncryptedExtensions(bogoEncryptedExtensions)
    }

    func testX509Forbidden() throws {
        guard case .offer(let offers) = PeerCertificateBundle.verificationCertificateTypes else {
            XCTFail("Unexpected server certificate type offer")
            return
        }

        let bogoEncryptedExtensions = EncryptedExtensions(extensions: [
            .serverCertificateType(.selection(.x509))
        ])
        try self.assertBogusEncryptedExtensions(bogoEncryptedExtensions)
    }

    private func assertBogusCertificateMessage(_ bogoCertMessage: CertificateMessage) throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        XCTAssertNoThrow(try stateMachine.startHandshake())

        var bytes = ByteBuffer()
        var inputBuffer = stub_serverHelloBuffer
        bytes.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&bytes)

        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        inputBuffer = makeEncryptedExtensionsBuffer()
        bytes.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&bytes)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        TLSMessageSerializer().writeHandshakeMessage(.certificate(bogoCertMessage), into: &bytes)
        stateMachine.receivedNetworkData(&bytes)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testRawKeyCertificateMessageWithoutElements() throws {
        let bogoCertificateMessage = CertificateMessage(
            certificateRequestContext: ByteBuffer(""),
            certificateList: []
        )
        try self.assertBogusCertificateMessage(bogoCertificateMessage)
    }

    func testRawKeyCertificateMessageWithTwoElements() throws {
        let bogoCertificateMessage = CertificateMessage(
            certificateRequestContext: ByteBuffer(""),
            certificateList: [
                .init(opaqueCertificateData: ByteBuffer("some opaque data"), extensions: []),
                .init(opaqueCertificateData: ByteBuffer("some other opaque data"), extensions: []),
            ]
        )
        try self.assertBogusCertificateMessage(bogoCertificateMessage)
    }

    func testRawKeyCertificateMessageWithInvalidKeyData() throws {
        // P521 isn't supported!
        let key = P521.Signing.PrivateKey()

        let bogoCertificateMessage = CertificateMessage(
            certificateRequestContext: ByteBuffer(""),
            certificateList: [
                .init(opaqueCertificateData: ByteBuffer(data: key.publicKey.derRepresentation), extensions: []),
            ]
        )

        try self.assertBogusCertificateMessage(bogoCertificateMessage)
    }

    func testServerCertificateContextMustBeEmpty() throws {
        let key = P384.Signing.PrivateKey()

        let bogoCertificateMessage = CertificateMessage(
            certificateRequestContext: ByteBuffer("some data"),
            certificateList: [
                .init(opaqueCertificateData: ByteBuffer(data: key.publicKey.derRepresentation), extensions: []),
            ]
        )

        try self.assertBogusCertificateMessage(bogoCertificateMessage)
    }

    func testRejectServerPreSharedKeyWhenNotResumingOrUsingExternalPSK() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBufferWithPSKIndexZeroSelected
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testServerPresentsInvalidKey() throws {
        // We generate a random key and say that we only trust that. This should fail the handshake.
        let randomKey = P256.Signing.PrivateKey()
        let config = HandshakeStateMachine.Configuration(
                        serverName: nil,
                        quicTransportParameters: nil,
                        alpn: nil,
                        fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
                        signingKey: nil,
                        validPeerPublicKeys: [randomKey.publicKey],
                        ticketRequest: nil,
                        epsk: nil,
                        useRawEPSKs: false,
                        enableEarlyData: false
                    )

        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate verify. This fails.
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testSendingSNIValue() throws {
        let config = configurationGenerator.getClientConfigWithOptions(serverName: "apple.com")

        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(let hello) = message.message else {
            XCTFail()
            return
        }

        XCTAssertEqual(hello.serverNameExtension, Extension.ServerName.clientHello(.init(hostName: ByteBuffer("apple.com"))))
    }

    func testNoSNIValue() throws {
        let config = self.validConfigurationNoClientAuth

        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(let hello) = message.message else {
            XCTFail()
            return
        }

        XCTAssertNil(hello.serverNameExtension)
    }

    func testSendingQUICTransportParametersValue() throws {
        let config = configurationGenerator.getClientConfigWithOptions(quicTransportParams: ByteBuffer("a random string"))

        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(let hello) = message.message else {
            XCTFail()
            return
        }

        XCTAssertEqual(hello.quicTransportParametersExtension, Extension.QUICTransportParameters(opaqueOffer: ByteBuffer("a random string")))
    }

    func testNoQUICTransportParameters() throws {
        let config = configurationGenerator.getClientConfigWithOptions()

        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(let hello) = message.message else {
            XCTFail()
            return
        }

        XCTAssertNil(hello.quicTransportParametersExtension)
    }

    func testCanReadQUICTransportParametersFullHandshake() throws {
        let config = configurationGenerator.getClientConfigWithOptions(quicTransportParams: ByteBuffer("a value"))
        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer(quicTransportParameters: ByteBuffer("some opaque bytes"))
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertEqual(stateMachine.peerQUICTransportParameters, ByteBuffer("some opaque bytes"))

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertEqual(stateMachine.peerQUICTransportParameters, ByteBuffer("some opaque bytes"))

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertEqual(stateMachine.peerQUICTransportParameters, ByteBuffer("some opaque bytes"))

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()

        XCTAssertEqual(stateMachine.peerQUICTransportParameters, ByteBuffer("some opaque bytes"))

        // check that client finished is returned
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)

        XCTAssertEqual(stateMachine.peerQUICTransportParameters, ByteBuffer("some opaque bytes"))

        // Feed in the new session ticket. It should be consumed, and produce a new session ticket.
        inputBuffer = stub_newSessionTicket
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
#if !SWIFTTLS_DRIVERKIT
        try stateMachine.processHandshake().assertNewSessionTicket()
#else
        // DriverKit client can't process session tickets (no Date)
        try stateMachine.processHandshake().assertNoNewSessionTicket()
#endif

        XCTAssertEqual(stateMachine.peerQUICTransportParameters, ByteBuffer("some opaque bytes"))
    }

    func testCanReadQUICTransportParametersFullHandshakeNotProvided() throws {
        let config = configurationGenerator.getClientConfigWithOptions(quicTransportParams: ByteBuffer("a random string"))
        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // check that client finished is returned
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // Feed in the new session ticket. It should be consumed, and produce a new session ticket.
        inputBuffer = stub_newSessionTicket
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
#if !SWIFTTLS_DRIVERKIT
        try stateMachine.processHandshake().assertNewSessionTicket()
#else
        // DriverKit client can't process session tickets (no Date)
        try stateMachine.processHandshake().assertNoNewSessionTicket()
#endif

        XCTAssertNil(stateMachine.peerQUICTransportParameters)
    }

    func testRejectTransportParametersWhenNotOfferedByUs() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        XCTAssertNil(stateMachine.peerQUICTransportParameters)

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer(quicTransportParameters: ByteBuffer("some opaque bytes"))
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testSendingALPNValue() throws {
        let config = configurationGenerator.getClientConfigWithOptions(alpn: ["a random string"])

        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(let hello) = message.message else {
            XCTFail()
            return
        }

        XCTAssertEqual(hello.alpnExtension, Extension.ApplicationLayerProtocolNegotiation.offer(["a random string"]))
    }

    func testNoALPN() throws {
        let config = configurationGenerator.getClientConfigWithOptions()

        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(let hello) = message.message else {
            XCTFail()
            return
        }

        XCTAssertNil(hello.alpnExtension)
    }

    func testCanReadALPNFullHandshake() throws {
        let config = configurationGenerator.getClientConfigWithOptions(alpn:["a value"])

        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        XCTAssertNil(stateMachine.peerALPN)

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        XCTAssertNil(stateMachine.peerALPN)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        XCTAssertNil(stateMachine.peerALPN)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer(alpnSelection: "protocol")
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertEqual(stateMachine.peerALPN, "protocol")

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertEqual(stateMachine.peerALPN, "protocol")

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertEqual(stateMachine.peerALPN, "protocol")

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()

        XCTAssertEqual(stateMachine.peerALPN, "protocol")

        // check that client finished is returned
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)

        XCTAssertEqual(stateMachine.peerALPN, "protocol")

        // Feed in the new session ticket. It should be consumed, and produce a new session ticket.
        inputBuffer = stub_newSessionTicket
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
#if !SWIFTTLS_DRIVERKIT
        try stateMachine.processHandshake().assertNewSessionTicket()
#else
        // DriverKit client can't process session tickets (no Date)
        try stateMachine.processHandshake().assertNoNewSessionTicket()
#endif

        XCTAssertEqual(stateMachine.peerALPN, "protocol")
    }

    func testCanReadALPNFullHandshakeNotProvided() throws {
        let config = configurationGenerator.getClientConfigWithOptions(alpn: ["a value"])

        var stateMachine = try HandshakeStateMachine(configuration: config)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        XCTAssertNil(stateMachine.peerALPN)

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        XCTAssertNil(stateMachine.peerALPN)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        XCTAssertNil(stateMachine.peerALPN)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertNil(stateMachine.peerALPN)

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertNil(stateMachine.peerALPN)

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        XCTAssertNil(stateMachine.peerALPN)

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()

        XCTAssertNil(stateMachine.peerALPN)

        // check that client finished is returned
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)

        XCTAssertNil(stateMachine.peerALPN)

        // Feed in the new session ticket. It should be consumed, and produce a new session ticket.
        inputBuffer = stub_newSessionTicket
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
#if !SWIFTTLS_DRIVERKIT
        try stateMachine.processHandshake().assertNewSessionTicket()
#else
        // DriverKit client can't process session tickets (no Date)
        try stateMachine.processHandshake().assertNoNewSessionTicket()
#endif

        XCTAssertNil(stateMachine.peerALPN)
    }

    func testTolerateSNIOnEE() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer(sendEmptySNI: true)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
    }

    func testForbidDuplicateKnownExtensionOnEE() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer(additionalExtensions: [
            .serverName(.encryptedExtensions),
            .serverName(.encryptedExtensions)
        ])
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testForbidDuplicateUnknownExtensionOnEE() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer(additionalExtensions: [
            .unknownExtension(.init(rawValue: 0xAFAF), ByteBuffer()),
            .unknownExtension(.init(rawValue: 0xAFAF), ByteBuffer())
        ])
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testForbidDuplicateKnownExtensionOnServerHello() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var serverHello = self.goodServerHello

        // This extension is already present.
        serverHello.extensions.append(.supportedVersions(.selection(.tlsv13)))
        TLSMessageSerializer().writeHandshakeMessage(.serverHello(serverHello), into: &networkBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testForbidDuplicateUnknownExtensionOnServerHello() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var serverHello = self.goodServerHello
        serverHello.extensions.append(contentsOf: [
            .unknownExtension(.init(rawValue: 0xAFAF), ByteBuffer()),
            .unknownExtension(.init(rawValue: 0xAFAF), ByteBuffer())
        ])
        TLSMessageSerializer().writeHandshakeMessage(.serverHello(serverHello), into: &networkBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

#if !SWIFTTLS_DRIVERKIT
    func testForbidDuplicateKnownExtensionOnNewSessionTicket() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()

        // check that client finished is returned
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)

        // Feed in the new session ticket. It should be consumed, and produce a new session ticket.
        var nst = self.goodNewSessionTicket
        nst.extensions.append(contentsOf: [
            .earlyData(.init(maxEarlyDataSize: 100)),
            .earlyData(.init(maxEarlyDataSize: 200))
        ])
        TLSMessageSerializer().writeHandshakeMessage(.newSessionTicket(nst), into: &networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }

    func testForbidDuplicateUnknownExtensionOnNewSessionTicket() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        var result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer()
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate
        inputBuffer = stub_serverCertificateBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate verify
        inputBuffer = try self.makeServerCertificateVerifyBuffer(signingKey: self.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()

        // check that client finished is returned
        var expectedBuffer = ByteBuffer()
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)

        // Feed in the new session ticket. It should be consumed, and produce a new session ticket.
        var nst = self.goodNewSessionTicket
        nst.extensions.append(contentsOf: [
            .unknownExtension(.init(rawValue: 0xAFAF), ByteBuffer()),
            .unknownExtension(.init(rawValue: 0xAFAF), ByteBuffer())
        ])
        TLSMessageSerializer().writeHandshakeMessage(.newSessionTicket(nst), into: &networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }
#endif

    func testRejectServerEarlyDataExtensionWhenNotResuming() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.validConfigurationNoClientAuth)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer()

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: nil)
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)
        XCTAssertNil(hello.earlyDataExtension)

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        let result = try stateMachine.processHandshake()
        XCTAssertNil(result?.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertNil(stateMachine.earlyDataAccepted)

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer(additionalExtensions: [.earlyData(.init())])
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake())
    }
}

@available(SwiftTLS 0.1.0, *)
extension ClientHello {

    var clientKeyShare: Extension.KeyShare.KeyShareEntry {
        for ext in self.extensions {
            switch ext {
            case .keyShare(.clientHello(let offeredKeyShare)):
                precondition(offeredKeyShare.count == 1)
                return offeredKeyShare.first!

            default:
                // We ignore other extensions here
                ()
            }
        }
        fatalError()
    }

    var preSharedKeyExtension: Extension.PreSharedKey? {
        for ext in self.extensions {
            switch ext {
            case .preSharedKey(let psk):
                return psk
            default:
                // Ignore other extensions
                ()
            }
        }
        return nil
    }

    var serverNameExtension: Extension.ServerName? {
        for ext in self.extensions {
            switch ext {
            case .serverName(let serverName):
                return serverName
            default:
                // Ignore other extensions
                ()
            }
        }
        return nil
    }

    var quicTransportParametersExtension: Extension.QUICTransportParameters? {
        for ext in self.extensions {
            switch ext {
            case .quicTransportParameters(let transportParams):
                return transportParams
            default:
                // Ignore other extensions
                ()
            }
        }
        return nil
    }

    var alpnExtension: Extension.ApplicationLayerProtocolNegotiation? {
        for ext in self.extensions {
            switch ext {
            case .alpn(let alpn):
                return alpn
            default:
                // Ignore other extensions
                ()
            }
        }
        return nil
    }

    var earlyDataExtension: Extension.EarlyData? {
        for ext in self.extensions {
            switch ext {
            case .earlyData(let earlyData):
                return earlyData
            default:
                // Ignore other extensions
                ()
            }
        }
        return nil
    }
}

@available(SwiftTLS 0.1.0, *)
extension Optional where Wrapped == PartialHandshakeResult {
    enum EncryptionLevelType {
        case earlyData
        case handshake
        case application
    }

    enum ReadOrWrite {
        case read
        case write
    }

func assertNewReadAndWriteEncryptionLevel(_ level: EncryptionLevelType, file: StaticString = #filePath, line: UInt = #line) {
    assertNewEncryptionLevel(level, .write)
    assertNewEncryptionLevel(level, .read)
}

func assertNewEncryptionLevel(_ level: EncryptionLevelType, _ readOrWrite: ReadOrWrite, file: StaticString = #filePath, line: UInt = #line) {
    var descr = "write"
    var gotLevel: EncryptionLevel? = nil;
    switch (readOrWrite) {
    case .read:
        gotLevel = self?.newReadEncryptionLevel;
        descr = "read"
    case .write:
        gotLevel = self?.newWriteEncryptionLevel;
    }

    switch (gotLevel, level) {
    case (.some(.earlyData), .earlyData),
         (.some(.handshake), .handshake),
         (.some(.application), .application):
        // All good
        ()
    case (.earlyData, _):
        XCTFail("Expected new \(descr) encryption level \(level), got .earlyData", file: file, line: line)
    case (.handshake, _):
        XCTFail("Expected new \(descr) encryption level \(level), got .handshake", file: file, line: line)
    case (.application, _):
        XCTFail("Expected new \(descr) encryption level \(level), got .application", file: file, line: line)
    case (.none, _):
        XCTFail("Expected new \(descr) encryption level \(level), no change happened", file: file, line: line)
    }
}

    func assertNewSessionTicket(file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(self?.sessionTicket != nil, file: file, line: line)
    }

    func assertNoNewSessionTicket(file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(self?.sessionTicket == nil, file: file, line: line)
    }
}

@available(SwiftTLS 0.1.0, *)
extension PartialHandshakeResult {
    func assertNewEncryptionLevel(_ level: Optional<PartialHandshakeResult>.EncryptionLevelType, _ readOrWrite: Optional<PartialHandshakeResult>.ReadOrWrite, file: StaticString = #filePath, line: UInt = #line) {
        Optional(self).assertNewEncryptionLevel(level, readOrWrite, file: file, line: line)
    }

    func assertNewReadAndWriteEncryptionLevel(_ level: Optional<PartialHandshakeResult>.EncryptionLevelType, file: StaticString = #filePath, line: UInt = #line) {
        Optional(self)?.assertNewEncryptionLevel(level, .write);
        Optional(self)?.assertNewEncryptionLevel(level, .read);
    }

    func assertNewSessionTicket(file: StaticString = #filePath, line: UInt = #line) {
        Optional(self).assertNewSessionTicket(file: file, line: line)
    }
}


enum ByteHexEncodingErrors: Error {
    case incorrectHexValue
    case incorrectString
}

let charA = UInt8(97 /* "a" */)
let char0 = UInt8(48 /* "0" */)

private func itoh(_ value: UInt8) -> UInt8 {
    return (value > 9) ? (charA + value - 10) : (char0 + value)
}

private func htoi(_ value: UInt8) throws -> UInt8 {
    switch value {
    case char0...char0 + 9:
        return value - char0
    case charA...charA + 5:
        return value - charA + 10
    default:
        throw ByteHexEncodingErrors.incorrectHexValue
    }
}

extension Data {
    init(hexString: String) throws {
        self.init()

        if hexString.count % 2 != 0 || hexString.count == 0 {
            throw ByteHexEncodingErrors.incorrectString
        }

        let stringBytes: [UInt8] = Array(hexString.lowercased().data(using: String.Encoding.utf8)!)

        for i in stride(from: stringBytes.startIndex, to: stringBytes.endIndex - 1, by: 2) {
            let char1 = stringBytes[i]
            let char2 = stringBytes[i + 1]

            try self.append(htoi(char1) << 4 + htoi(char2))
        }
    }
}
