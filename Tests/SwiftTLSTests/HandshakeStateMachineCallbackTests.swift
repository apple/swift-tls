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

#if os(Linux)
import Crypto
#else
import CryptoKit
#endif
#if canImport(SwiftTLS) && (os(Linux) || !canImport(CryptoKitPrivate))
// For importing the SwiftTLS package on the public SDK or on Linux
@testable @_spi(SwiftTLSProtocol) import SwiftTLS
#endif

#if canImport(Security)
import Security
#endif

final class ClientCallbackFixtures: Sendable {
    let serverSigningKey: P256.Signing.PrivateKey
    let dummySignatureAlgorithm: UInt16
    let dummyDataCertificates: [Data]
    let dummyDataSignature: Data

    let authenticationCallbackCalled = Mutex<Bool>(false)

    init() {
        self.serverSigningKey = P256.Signing.PrivateKey()
        self.dummySignatureAlgorithm = SignatureScheme.ecdsa_secp256r1_sha256.rawValue

        var rng = SystemRandomNumberGenerator()
        var certs = [Data]()
        for _ in 0..<3 {
            let randomBytes = [UInt8](repeating: 0, count: 2048).map { _ in
                UInt8.random(in: 0..<UInt8.max, using: &rng)
            }
            certs.append(Data(randomBytes))
        }
        self.dummyDataCertificates = certs
        let sigBytes = [UInt8](repeating: 0, count: 512).map { _ in
            UInt8.random(in: 0..<UInt8.max, using: &rng)
        }
        self.dummyDataSignature = Data(sigBytes)
    }

    func resetCallbackFlags() {
        self.authenticationCallbackCalled.withLock { $0 = false }
    }

    // -- callback functions --

    @Sendable func verificationCallbackValid(info: VerificationInfo) -> VerificationResult {
        self.authenticationCallbackCalled.withLock { $0 = true }
        return .valid
    }

    @Sendable func verificationCallbackInvalid(info: VerificationInfo) -> VerificationResult {
        self.authenticationCallbackCalled.withLock { $0 = true }
        return .invalid(reason: "you shall not pass!")
    }

    @Sendable func verificationCallbackRawPublicKey(info: VerificationInfo) -> VerificationResult {
        self.authenticationCallbackCalled.withLock { $0 = true }
        guard info.signatureAlgorithm == SignatureScheme.ecdsa_secp256r1_sha256.rawValue else {
            return .invalid(reason: "unsupported signature algorithm")
        }
        guard info.certificates.type == .rawPublicKey else {
            return .invalid(reason: "unexpected certificate type")
        }
        guard info.certificates.entries.count == 1 else {
            return .invalid(reason: "only expected one key")
        }
        guard let key: P256.Signing.PublicKey = try? P256.Signing.PublicKey(derRepresentation: info.certificates.entries[0]) else {
            return .invalid(reason: "invalid key")
        }
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: info.signature) else {
            return .invalid(reason: "broken signature")
        }
        guard key.isValidSignature(signature, for: info.transcriptHash) else {
            return .invalid(reason: "invalid signature")
        }
        guard key.rawRepresentation == self.serverSigningKey.publicKey.rawRepresentation else {
            return .invalid(reason: "key is not trusted")
        }
        return .valid
    }

    @Sendable func verificationCallbackDummyCertificate(info: VerificationInfo) -> VerificationResult {
        self.authenticationCallbackCalled.withLock { $0 = true }
        guard info.signatureAlgorithm == self.dummySignatureAlgorithm else {
            return .invalid(reason: "unexpected signature algorithm")
        }
        guard info.certificates.type == .x509 else {
            return .invalid(reason: "unexpected certificate type")
        }
        guard info.certificates.entries.count == self.dummyDataCertificates.count else {
            return .invalid(reason: "unexpected number of certificates")
        }
        for (lhs, rhs) in zip(self.dummyDataCertificates, info.certificates.entries) {
            guard lhs == rhs else {
                return .invalid(reason: "certificate mismatch")
            }
        }
        return .valid
    }

    @Sendable func verificationCallbackDummyCertificateAsync(info: VerificationInfo) -> VerificationResult {
        self.authenticationCallbackCalled.withLock { $0 = true }
        info.deliverResult?(.valid)
        return .waiting
    }

    @Sendable func verificationCallbackCapture(info: VerificationInfo) -> VerificationResult {
        self.authenticationCallbackCalled.withLock { $0 = true }
        return .waiting
    }

    @Sendable func verificationCallbackRawPublicKeyExpectBadSignature(info: VerificationInfo) -> VerificationResult {
        self.authenticationCallbackCalled.withLock { $0 = true }
        guard info.signatureAlgorithm == SignatureScheme.ecdsa_secp256r1_sha256.rawValue else {
            return .invalid(reason: "unsupported signature algorithm")
        }
        guard info.certificates.type == .rawPublicKey else {
            return .invalid(reason: "unexpected certificate type")
        }
        guard info.certificates.entries.count == 1 else {
            return .invalid(reason: "only expected one key")
        }
        guard let key: P256.Signing.PublicKey = try? P256.Signing.PublicKey(derRepresentation: info.certificates.entries[0]) else {
            return .invalid(reason: "invalid key")
        }
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: info.signature) else {
            return .invalid(reason: "broken signature")
        }
        if key.isValidSignature(signature, for: info.transcriptHash) {
            return .valid
        }
        return .invalid(reason: "signature failed as expected")
    }
}

class HandshakeStateMachineCallbackTests: XCTestCase {

    var serverPrivateKey = P384EphemeralKey()
    var fixtures: ClientCallbackFixtures!

    // -- set up --

    override func setUp() {
        self.fixtures = ClientCallbackFixtures()
    }

    // -- configuration --

    var configAlwaysValid: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.rawPublicKey], verificationCallback: self.fixtures.verificationCallbackValid(info:))
        )
    }

    var configAlwaysInvalid: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.x509], verificationCallback: self.fixtures.verificationCallbackInvalid(info:))
        )
    }

    var configAuthRawPublicKey: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.rawPublicKey], verificationCallback: self.fixtures.verificationCallbackRawPublicKey(info:))
        )
    }

    var configAuthDummyCertificate: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.x509], verificationCallback: self.fixtures.verificationCallbackDummyCertificate(info:))
        )
    }

    var configAuthDummyCertificateAsync: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.x509], verificationCallback: self.fixtures.verificationCallbackDummyCertificateAsync(info:))
        )
    }

    var configAuthDummyCertificateCapture: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.x509], verificationCallback: self.fixtures.verificationCallbackCapture(info:))
        )
    }

    var configAuthRawPublicKeyExpectBadSignature: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(
                availableCertificateTypes: [.rawPublicKey],
                verificationCallback: self.fixtures.verificationCallbackRawPublicKeyExpectBadSignature(info:)
            )
        )
    }

    // -- utility --

    func processWithAsyncDelivery(_ stateMachine: inout HandshakeStateMachine) throws -> PartialHandshakeResult? {
        let pendingResult = Mutex<PendingAsyncResult?>(nil)
        stateMachine.deliverResultCallback = { result in
            pendingResult.withLock { $0 = result }
        }
        if let result = try stateMachine.processHandshake() {
            return result
        }
        // This will be set during "processHandshake()".
        guard let pending = pendingResult.withLock({ $0 }) else {
            return nil
        }
        stateMachine.applyAsyncResult(pending)
        return try stateMachine.processHandshake()
    }

    // -- messages, etc. --

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

    var stub_serverHelloBuffer: ByteBuffer {
        var buffer = ByteBuffer(data: Data())
        TLSMessageSerializer().writeHandshakeMessage(.serverHello(self.goodServerHello), into: &buffer)
        return buffer
    }

    func makeEncryptedExtensionsBuffer(
        serverCertificateType: CertificateType?,
        quicTransportParameters: ByteBuffer? = nil,
        alpnSelection: ApplicationLayerProtocol? = nil,
        sendEmptySNI: Bool = false,
        additionalExtensions: [Extension]? = nil
    ) -> ByteBuffer {
        var buffer = ByteBuffer(data: Data())
        var extensions: [Extension] = [
            .supportedGroups(.init(groups: [.secp384])),
        ]

        if let serverCertificateType, serverCertificateType != .x509 {
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

    var stub_serverCertificateBufferRawPublicKey: ByteBuffer {
        var buffer = ByteBuffer(data: Data())
        let message = CertificateMessage(
            certificateRequestContext: ByteBuffer(data: Data()),
            certificateList: [
                .init(opaqueCertificateData: ByteBuffer(data: self.fixtures.serverSigningKey.publicKey.derRepresentation), extensions: []),
            ]
        )
        TLSMessageSerializer().writeHandshakeMessage(.certificate(message), into: &buffer)
        return buffer
    }

    var stub_serverCertificateBufferRawPublicKeyEmptyList: ByteBuffer {
        var buffer = ByteBuffer(data: Data())
        let message = CertificateMessage(
            certificateRequestContext: ByteBuffer(data: Data()),
            certificateList: [] // <-- This should not be empty.
        )
        TLSMessageSerializer().writeHandshakeMessage(.certificate(message), into: &buffer)
        return buffer
    }

    var stub_serverCertificateBufferRawPublicKeyTooManyEntries: ByteBuffer {
        var buffer = ByteBuffer(data: Data())
        let message = CertificateMessage(
            certificateRequestContext: ByteBuffer(data: Data()),
            certificateList: [
                .init(opaqueCertificateData: ByteBuffer(data: self.fixtures.serverSigningKey.publicKey.derRepresentation), extensions: []),
                // Add an additional entry:
                .init(opaqueCertificateData: ByteBuffer(data: P256.Signing.PrivateKey().publicKey.derRepresentation), extensions: []),
            ]
        )
        TLSMessageSerializer().writeHandshakeMessage(.certificate(message), into: &buffer)
        return buffer
    }

    var stub_serverCertificateBufferDummyCertificates: ByteBuffer {
        var buffer = ByteBuffer(data: Data())
        let certificates = self.fixtures.dummyDataCertificates.map {
            CertificateMessage.CertificateEntry(
                opaqueCertificateData: ByteBuffer(data: $0),
                extensions: []
            )
        }
        let message = CertificateMessage(
            certificateRequestContext: ByteBuffer(data: Data()),
            certificateList: certificates
        )
        TLSMessageSerializer().writeHandshakeMessage(.certificate(message), into: &buffer)
        return buffer
    }

    func makeServerCertificateVerifyBufferRawPublicKey(
        signingKey: P256.Signing.PrivateKey,
        keyScheduler: ClientSessionKeyManager<SHA384>,
        algorithm: SignatureScheme = .ecdsa_secp256r1_sha256) throws -> ByteBuffer {
        var buffer = ByteBuffer(data: Data())
        let certificateVerify = CertificateVerify(
            algorithm: algorithm,
            signature: ByteBuffer(data: try signingKey.signature(for: keyScheduler.dataToSignInServerCertificateVerify().readableBytesView).derRepresentation)
        )
        TLSMessageSerializer().writeHandshakeMessage(.certificateVerify(certificateVerify), into: &buffer)
        return buffer
    }

    func makeServerCertificateVerifyBufferDummyCertificates(
        signature: Data,
        algorithm: SignatureScheme) throws -> ByteBuffer {
        var buffer = ByteBuffer(data: Data())
        let certificateVerify = CertificateVerify(
            algorithm: algorithm,
            signature: ByteBuffer(data: signature)
        )
        TLSMessageSerializer().writeHandshakeMessage(.certificateVerify(certificateVerify), into: &buffer)
        return buffer
    }

    func makeServerFinished(scheduler: ClientSessionKeyManager<SHA384>) throws -> ByteBuffer {
        var buffer = ByteBuffer(data: Data())
        let finished = Data(try scheduler.serverFinishedPayload())
        TLSMessageSerializer().writeHandshakeMessage(.finished(FinishedMessage.init(verifyData: ByteBuffer(data: finished))), into: &buffer)
        return buffer
    }

    // -- tests --

    // run the happy path (always valid)
    func testReadNetworkDataAcceptAnything() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAlwaysValid)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .rawPublicKey)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBufferRawPublicKey // Using this one here -- could be the other one.
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        XCTAssertFalse(self.fixtures.authenticationCallbackCalled.withLock { $0 }) // The authentication callback was not called yet.
        inputBuffer = try self.makeServerCertificateVerifyBufferRawPublicKey(signingKey: self.fixtures.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
        XCTAssertTrue(self.fixtures.authenticationCallbackCalled.withLock { $0 }) //  The authentication callback was called.

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // check that client finished is returned
        var expectedBuffer = ByteBuffer(data: Data())
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
    }

    // run sad path (verification fails)
    func testReadNetworkDataSadPathVerificationFails() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAlwaysInvalid)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var initialResult = try stateMachine.startHandshake()
        initialResult.assertNewEncryptionLevel(.earlyData, .write)
        parser.appendBytes(&initialResult.handshakeBytesToSend!)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())

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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .x509)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // server certificate
        inputBuffer = stub_serverCertificateBufferDummyCertificates
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))

        // verification will fail
        XCTAssertFalse(self.fixtures.authenticationCallbackCalled.withLock { $0 })
        inputBuffer = try self.makeServerCertificateVerifyBufferDummyCertificates(signature: self.fixtures.dummyDataSignature.subdata(in: 0..<(self.fixtures.dummyDataSignature.count / 2)), algorithm: SignatureScheme(rawValue: self.fixtures.dummySignatureAlgorithm))
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .certificateError)
        }
        XCTAssertTrue(self.fixtures.authenticationCallbackCalled.withLock { $0 })
    }

    // run the happy path (dummy certificates)
    func testReadNetworkDataAcceptDummyCertificates() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthDummyCertificate)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // Per RFC 7250, Section 4.1. the client hello message should not include the certificate
        // types extensions if the only supported type is X509.
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTFail("Unexpectedly encountered server_certificate_type extension for \(types)")
            } else if case .clientCertificateType(.offer(let types)) = ext {
                XCTFail("Unexpectedly encountered client_certificate_type extension for \(types)")
            }
        }

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .x509)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBufferDummyCertificates // Using this one here -- could be the other one.
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        XCTAssertFalse(self.fixtures.authenticationCallbackCalled.withLock { $0 })
        inputBuffer = try self.makeServerCertificateVerifyBufferDummyCertificates(signature: self.fixtures.dummyDataSignature, algorithm: SignatureScheme(rawValue: self.fixtures.dummySignatureAlgorithm))
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
        XCTAssertTrue(self.fixtures.authenticationCallbackCalled.withLock { $0 })

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // check that client finished is returned
        var expectedBuffer = ByteBuffer(data: Data())
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
    }

    // Run happy path (dummy certificates asynchronous)
    func testReadNetworkDataAcceptDummyCertificatesDelayed() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthDummyCertificateAsync)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .x509)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBufferRawPublicKey
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        XCTAssertFalse(self.fixtures.authenticationCallbackCalled.withLock { $0 })
        inputBuffer = try self.makeServerCertificateVerifyBufferRawPublicKey(signingKey: self.fixtures.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        // The async callback delivers via the closure; feed it back via applyAsyncResult.
        XCTAssertNoThrow(XCTAssertNil(try processWithAsyncDelivery(&stateMachine)))
        XCTAssertTrue(self.fixtures.authenticationCallbackCalled.withLock { $0 })
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
        var expectedBuffer = ByteBuffer(data: Data())
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
    }

    // run the happy path (rawPublicKey)
    func testReadNetworkDataAcceptRawPublicKey() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthRawPublicKey)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // Per RFC 7250, Section 4.1. the client hello message should not include the certificate
        // types extensions if the only supported type is X509. This test use raw public keys and
        // thus the server_certificate_types extension must be present.
        var extensionsIncludeServerCertificateType = false
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTAssert(types == [.rawPublicKey])
                extensionsIncludeServerCertificateType = true
            }
        }
        XCTAssertTrue(extensionsIncludeServerCertificateType)

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .rawPublicKey)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBufferRawPublicKey // Using this one here -- could be the other one.
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        XCTAssertFalse(self.fixtures.authenticationCallbackCalled.withLock { $0 })
        inputBuffer = try self.makeServerCertificateVerifyBufferRawPublicKey(signingKey: self.fixtures.serverSigningKey, keyScheduler: scheduler)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
        XCTAssertTrue(self.fixtures.authenticationCallbackCalled.withLock { $0 })

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // check that client finished is returned
        var expectedBuffer = ByteBuffer(data: Data())
        let clientFinishedPayload = Data(try scheduler.clientFinishedPayload())
        TLSMessageSerializer()
            .writeHandshakeMessage(.finished(FinishedMessage(verifyData: ByteBuffer(data: clientFinishedPayload))), into: &expectedBuffer)
        XCTAssertEqual(result?.handshakeBytesToSend, expectedBuffer)
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
    }

    // -- async result of unexpected type is applied  --

    func driveClientToAwaitingVerification() throws -> HandshakeStateMachine {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthDummyCertificateCapture)
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        var parser = HandshakeMessageParser()
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail("failed to parse client hello")
            throw TLSError.handshakeError
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())

        // server hello
        var inputBuffer = stub_serverHelloBuffer
        networkBuffer.writeBuffer(&inputBuffer)
        let (_, keyData) = try self.serverPrivateKey.encap(publicKeyData: hello.clientKeyShare.keyExchange.readableBytesView)
        let ecdheSecret = SymmetricKey(data: keyData)
        try scheduler.postServerHello(ecdheSecret: ecdheSecret, serverHelloBytes: networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        _ = try stateMachine.processHandshake()

        // encrypted extensions
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .x509)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNil(try stateMachine.processHandshake())

        // server certificate
        inputBuffer = stub_serverCertificateBufferDummyCertificates
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNil(try stateMachine.processHandshake())

        // server certificate verify — triggers the verification callback which returns .waiting
        inputBuffer = try self.makeServerCertificateVerifyBufferDummyCertificates(signature: self.fixtures.dummyDataSignature, algorithm: SignatureScheme(rawValue: self.fixtures.dummySignatureAlgorithm))
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        stateMachine.deliverResultCallback = { _ in }
        XCTAssertNil(try stateMachine.processHandshake())
        XCTAssertTrue(stateMachine.awaitingAsyncComputation)

        return stateMachine
    }

    func testHandleAsyncVerificationResultWithoutResult() throws {
        var stateMachine = try driveClientToAwaitingVerification()
        XCTAssertTrue(stateMachine.awaitingAsyncComputation)
        XCTAssertNil(try stateMachine.processHandshake())
        XCTAssertTrue(stateMachine.awaitingAsyncComputation)
    }

    func testHandleAsyncVerificationResultWithWrongResultType() throws {
        var stateMachine = try driveClientToAwaitingVerification()
        XCTAssertTrue(stateMachine.awaitingAsyncComputation)
        // In this state the expected case is `.verification`.
        stateMachine.applyAsyncResult(.certificate(.unavailable(reason: "wrong type")))
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .internalError(reason: "Unexpected async result type in awaitingVerification"))
        }
    }

    // -- EncryptedExtensions certificate type negotiation failures --

    // run sad path (server selects certificate type not offered by client)
    //
    //    Server selects server_certificate_type not in client's offer
    //    - Client configured with availableCertificateTypes: [.rawPublicKey] (only offers RPK)
    //    - Server EncryptedExtensions sends server_certificate_type = .x509
    //    - Expected: TLSError.negotiationFailed at processHandshake() (line 746 of HandshakeState.swift — confirmNegotiated returns nil)
    func testReadNetworkDataServerSelectsUnsupportedTypeX509() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthRawPublicKey)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // Per RFC 7250, Section 4.1. the client hello message should not include the certificate
        // types extensions if the only supported type is X509. This test use raw public keys and
        // thus the server_certificate_types extension must be present.
        var extensionsIncludeServerCertificateType = false
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTAssert(types == [.rawPublicKey])
                extensionsIncludeServerCertificateType = true
            }
        }
        XCTAssertTrue(extensionsIncludeServerCertificateType)

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .x509)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .negotiationFailed)
        }
    }

    // run sad path (server selects certificate type not offered by client)
    //
    //    Server sends server_certificate_type when client didn't send the extension
    //    - Client configured with availableCertificateTypes: [.x509] only (so client omits the extension per RFC 7250 4.1, and
    //    clientHello.serverCertificateTypes defaults to [.x509])
    //    - Server EncryptedExtensions sends server_certificate_type = .rawPublicKey
    //    - Expected: TLSError.negotiationFailed — the client's stored list is [.x509], and confirmNegotiated(.rawPublicKey) returns nil
    func testReadNetworkDataServerSelectsUnsupportedTypeRPK() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthDummyCertificate)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // No server certificate types extension expected.
        var extensionsIncludeServerCertificateType = false
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTAssert(types == [.rawPublicKey])
                extensionsIncludeServerCertificateType = true
            }
        }
        XCTAssertFalse(extensionsIncludeServerCertificateType)

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .rawPublicKey)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .negotiationFailed)
        }
    }

    // sad path (client auth mismatch)
    //
    //    Server selects client_certificate_type not in client's offer
    //    - Client configured with a signingKey (so it sends client_certificate_type = [.rawPublicKey])
    //    - Server EncryptedExtensions sends client_certificate_type = .x509
    //    - Expected: TLSError.negotiationFailed (line 754)
    func testClientAuthMismatchServerSendsX509() throws {
        throw XCTSkip("mTLS not implemented")
    }

    // sad path (client auth mismatch)
    //
    //    Server selects client_certificate_type not in client's offer
    //    - Client configured with a signingKey (so it sends client_certificate_type = [.x509])
    //    - Server EncryptedExtensions sends client_certificate_type = .rawPublicKey
    //    - Expected: TLSError.negotiationFailed (line 754)
    func testClientAuthMismatchServerSendsRPK() throws {
        throw XCTSkip("mTLS not implemented")
    }

    // sad path (client auth mismatch)
    //
    //    Server sends client_certificate_type when client didn't send the extension
    //    - Client configured with no signingKey (so no client_certificate_type extension sent)
    //    - Server EncryptedExtensions sends client_certificate_type = .rawPublicKey
    //    - Expected: TLSError.unsupportedExtension (line 721-722 — the signingKey != nil guard fails)
    func testServerSendsClientCertificateTypeRPKUnexpectedly() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthRawPublicKey)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // Per RFC 7250, Section 4.1. the client hello message should not include the certificate
        // types extensions if the only supported type is X509. This test use raw public keys and
        // thus the server_certificate_types extension must be present.
        var extensionsIncludeServerCertificateType = false
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTAssert(types == [.rawPublicKey])
                extensionsIncludeServerCertificateType = true
            }
        }
        XCTAssertTrue(extensionsIncludeServerCertificateType)

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

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
        inputBuffer = makeEncryptedExtensionsBuffer(
            serverCertificateType: .x509,
            additionalExtensions: [
                .clientCertificateType(.selection(.rawPublicKey))
            ]
        )
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .unsupportedExtension)
        }
    }

    // sad path (server unexpectedly sends server_certificate_type)
    //
    //    Server sends server_certificate_type when using .none verification
    //    - Client configured with verificationMethod: .none
    //    - Server EncryptedExtensions includes server_certificate_type = .rawPublicKey
    //    - Expected: TLSError.unsupportedExtension (line 710-711)
    func testServerUnexpectedlySendsServerCertificateType() throws {
        var clientConfig = self.configAlwaysValid
        // Set verification method to none for this test. The initializer doesn't
        // easily allow this, but its required for this test.
        clientConfig.verificationMethod = .none

        var stateMachine = try HandshakeStateMachine(configuration: clientConfig)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // Expecting the extension to be absent.
        var extensionsIncludeServerCertificateType = false
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTAssert(types == [.rawPublicKey])
                extensionsIncludeServerCertificateType = true
            }
        }
        XCTAssertFalse(extensionsIncludeServerCertificateType)

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

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
        inputBuffer = makeEncryptedExtensionsBuffer(
            serverCertificateType: .x509,
            additionalExtensions: [
                .clientCertificateType(.selection(.rawPublicKey))
            ]
        )
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .unsupportedExtension)
        }
    }

    // sad path (unexpected extension during session resumption)
    //
    //    Server sends server_certificate_type during session resumption
    //    - Client resumes a session (PSK negotiated)
    //    - Server EncryptedExtensions includes server_certificate_type = .rawPublicKey
    //    - Expected: TLSError.negotiationFailed (line 768-770 — "server provided server_certificate_type extension while resuming")
    func testServerSendsServerCertificateTypeDuringSessionResumption() throws {
        throw XCTSkip("Session resumption is currently not supported with callbacks.")
    }

    // -- CertificateVerify / signature algorithm failures --

    // sad path (signature algorithm mismatch)
    //
    //    Server sends CertificateVerify with wrong signature algorithm
    //    - Client offers [.ecdsa_secp256r1_sha256] in signature_algorithms
    //    - Server sends CertificateVerify with a different algorithm (e.g., 0x1337 or .rsa_pss_rsae_sha256)
    //    - Expected: TLSError.illegalParameter -- The state machine itself should reject the mismatch.
    func testSignatureAlgorithmMismatch() throws {
        // We can use the config with the always-failing callback because the state machine will
        // catch the signature algorithm mismatch before invoking the callback.
        var stateMachine = try HandshakeStateMachine(configuration: self.configAlwaysInvalid)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }
        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .x509)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBufferRawPublicKey
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        XCTAssertFalse(self.fixtures.authenticationCallbackCalled.withLock { $0 })
        inputBuffer = try self.makeServerCertificateVerifyBufferRawPublicKey(
            signingKey: self.fixtures.serverSigningKey,
            keyScheduler: scheduler,
            algorithm: .init(rawValue: self.fixtures.dummySignatureAlgorithm + 1) // Mismatch!
        )
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)

        // Expect failure due to signature algorithm mismatch.
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .illegalParameter)
        }
    }

    // sad path (signature verification fails)
    //
    //    Server sends CertificateVerify with valid algorithm but bad signature
    //
    //    - Correct algorithm, but signature bytes are garbage
    //    - Expected: Verification callback returns .invalid, throws TLSError.certificateError
    func testVerificationFailsDueToBadSignature() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthRawPublicKeyExpectBadSignature)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // Per RFC 7250, Section 4.1. the client hello message should not include the certificate
        // types extensions if the only supported type is X509. This test use raw public keys and
        // thus the server_certificate_types extension must be present.
        var extensionsIncludeServerCertificateType = false
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTAssert(types == [.rawPublicKey])
                extensionsIncludeServerCertificateType = true
            }
        }
        XCTAssertTrue(extensionsIncludeServerCertificateType)

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .rawPublicKey)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBufferRawPublicKey // Using this one here -- could be the other one.
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        XCTAssertFalse(self.fixtures.authenticationCallbackCalled.withLock { $0 })
        inputBuffer = try self.makeServerCertificateVerifyBufferRawPublicKey(
            signingKey: P256.Signing.PrivateKey(), // Inject unexpected key for signature.
            keyScheduler: scheduler
        )
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)

        // Expect failure due to bad signature.
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .certificateError)
        }
    }

    // -- Certificate message failures --

    // run sad path (empty certificate list)
    //
    //    Server sends empty certificate list with RPK type negotiated
    //    - RPK negotiated, but Certificate message has 0 entries
    //    - Expected: Error (RPK requires exactly 1 entry)
    func testVerificationFailsDueEmptyCertificateList() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthRawPublicKey)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // Per RFC 7250, Section 4.1. the client hello message should not include the certificate
        // types extensions if the only supported type is X509. This test use raw public keys and
        // thus the server_certificate_types extension must be present.
        var extensionsIncludeServerCertificateType = false
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTAssert(types == [.rawPublicKey])
                extensionsIncludeServerCertificateType = true
            }
        }
        XCTAssertTrue(extensionsIncludeServerCertificateType)

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .rawPublicKey)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBufferRawPublicKeyEmptyList
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)

        // Expect failure because certificate list is empty
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeInvalidMessage)
        }
    }

    // run sad path (too many certificates in certificate message)
    //
    //    Server sends multiple entries with RPK type negotiated
    //    - RPK negotiated, but Certificate message has 2+ entries
    //    - Expected: Error (RPK should have exactly 1 SubjectPublicKeyInfo)
    func testVerificationFailsDueTooManyEntriesInCertificateList() throws {
        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthRawPublicKey)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // Per RFC 7250, Section 4.1. the client hello message should not include the certificate
        // types extensions if the only supported type is X509. This test use raw public keys and
        // thus the server_certificate_types extension must be present.
        var extensionsIncludeServerCertificateType = false
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTAssert(types == [.rawPublicKey])
                extensionsIncludeServerCertificateType = true
            }
        }
        XCTAssertTrue(extensionsIncludeServerCertificateType)

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, nil)
        XCTAssertNil(stateMachine.earlyDataAccepted)

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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .rawPublicKey)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBufferRawPublicKeyTooManyEntries
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)

        // Expect failure because certificate list has too many entries.
        XCTAssertThrowsError(try stateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeInvalidMessage)
        }
    }

    // -- Session resumption with callbacks --

    // This is currently not supported. The client should silently fall back to a full handshake.
    func testSessionResumptionNotSupportedWithCallbacks() throws {
        // Step 1: Perform a successful handshake to acquire a session ticket.

        var stateMachine = try HandshakeStateMachine(configuration: self.configAuthDummyCertificate)
        var parser = HandshakeMessageParser()
        var scheduler = ClientSessionKeyManager<SHA384>()
        var networkBuffer = ByteBuffer(data: Data())

        // client hello
        var clientHelloBytes = try stateMachine.startHandshake().handshakeBytesToSend!
        parser.appendBytes(&clientHelloBytes)
        guard let message = try parser.parseHandshakeMessage(), case .clientHello(var hello) = message.message else {
            XCTFail()
            return
        }

        // Per RFC 7250, Section 4.1. the client hello message should not include the certificate
        // types extensions if the only supported type is X509.
        for ext in hello.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                XCTFail("Unexpectedly encountered server_certificate_type extension for \(types)")
            } else if case .clientCertificateType(.offer(let types)) = ext {
                XCTFail("Unexpectedly encountered client_certificate_type extension for \(types)")
            }
        }

        _ = try scheduler.sendingClientHello(clientHello: &hello, sessionToResume: nil, epsks: [], useRawEPSKs: false, currentTime: Date())
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
        inputBuffer = makeEncryptedExtensionsBuffer(serverCertificateType: .x509)
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate
        inputBuffer = stub_serverCertificateBufferDummyCertificates // Using this one here -- could be the other one.
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // server certificate verify
        XCTAssertFalse(self.fixtures.authenticationCallbackCalled.withLock { $0 })
        inputBuffer = try self.makeServerCertificateVerifyBufferDummyCertificates(signature: self.fixtures.dummyDataSignature, algorithm: SignatureScheme(rawValue: self.fixtures.dummySignatureAlgorithm))
        networkBuffer.writeBuffer(&inputBuffer)
        try scheduler.addPreFinishedMessageToTransportHash(networkBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        XCTAssertNoThrow(XCTAssertNil(try stateMachine.processHandshake()))
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)
        XCTAssertTrue(self.fixtures.authenticationCallbackCalled.withLock { $0 })

        // feed in server finished
        inputBuffer = try self.makeServerFinished(scheduler: scheduler)
        try scheduler.postServerFinished(serverFinishedBytes: inputBuffer)
        networkBuffer.writeBuffer(&inputBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        result = try stateMachine.processHandshake()
        XCTAssertEqual(stateMachine.negotiatedCiphersuite, CipherSuite.TLS_AES_256_GCM_SHA384.rawValue)
        XCTAssertEqual(stateMachine.earlyDataAccepted, false)

        // Feed in a NewSessionTicket and capture the serialized ticket.
        var newSessionTicketBuffer = ByteBuffer()
        let newSessionTicket = NewSessionTicket(
            ticketLifetime: 3600,
            ticketAgeAdd: 0x12345678,
            ticketNonce: ByteBuffer(bytes: "nonce".utf8),
            ticket: ByteBuffer(bytes: "ticket".utf8),
            extensions: []
        )
        TLSMessageSerializer().writeHandshakeMessage(.newSessionTicket(newSessionTicket), into: &newSessionTicketBuffer)
        networkBuffer.writeBuffer(&newSessionTicketBuffer)
        stateMachine.receivedNetworkData(&networkBuffer)
        let ticketResult = try stateMachine.processHandshake()
        guard let serializedTicket = ticketResult?.sessionTicket else {
            XCTFail("expected a session ticket from the handshake")
            return
        }

        // Step 2: Attempt resumption with the ticket. Due to incompatibility,
        // the state machine should fall back to a full handshake.

        let fakeTime = Date()
        var resumingStateMachine = try HandshakeStateMachine(
            sessionTicket: serializedTicket.span.bytes, // <-- Add ticket
            configuration: self.configAuthDummyCertificate,
            clock: FrozenInTimeClock(time: fakeTime)
        )

        var resumingClientHelloBytes = try resumingStateMachine.startHandshake().handshakeBytesToSend!
        var resumingParser = HandshakeMessageParser()
        resumingParser.appendBytes(&resumingClientHelloBytes)
        guard let resumingMessage = try resumingParser.parseHandshakeMessage(), case .clientHello(let resumingHello) = resumingMessage.message else {
            XCTFail("failed to parse resuming client hello")
            return
        }

        // The ClientHello must NOT contain a pre_shared_key extension --> resumption was not attempted.
        XCTAssertNil(resumingHello.preSharedKeyExtension)
    }
}
