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
@testable @_spi(SwiftTLSProtocol) @_spi(SwiftTLSOptions) import SwiftTLS
#endif

#if canImport(Security)
import Security
#endif

final class ServerCallbackFixtures: Sendable {
    let serverSigningKey: P256.Signing.PrivateKey
    let serverSignatureAlgorithm: UInt16
    let clientAuthKey: P256.Signing.PrivateKey
    let dummySignatureAlgorithm: UInt16
    let dummyDataCertificates: [Data]
    let dummyDataSignature: Data

    let authenticationCallbackCalled = Mutex<Bool>(false)
    let certificateCallbackCalled = Mutex<Bool>(false)
    let signingCallbackCalled = Mutex<Bool>(false)

    init() {
        self.serverSigningKey = P256.Signing.PrivateKey()
        self.serverSignatureAlgorithm = SignatureScheme.ecdsa_secp256r1_sha256.rawValue
        self.clientAuthKey = P256.Signing.PrivateKey()
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
        self.certificateCallbackCalled.withLock { $0 = false }
        self.signingCallbackCalled.withLock { $0 = false }
    }

    // -- callback functions: provide certs --

    @Sendable func provideUnavailable(certInfo: CertificateInfo) -> CertificateResult {
        self.certificateCallbackCalled.withLock { $0 = true }
        return .unavailable(reason: "certificate missing")
    }

    @Sendable func provideUnavailableAsync(certInfo: CertificateInfo) -> CertificateResult {
        self.certificateCallbackCalled.withLock { $0 = true }
        certInfo.deliverResult?(.unavailable(reason: "certificate missing"))
        return .waiting
    }

    @Sendable func provideRawPublicKey(certInfo: CertificateInfo) -> CertificateResult {
        self.certificateCallbackCalled.withLock { $0 = true }
        XCTAssertEqual(certInfo.peerOffer.serverName, "test.example.com")
        XCTAssertEqual(certInfo.peerOffer.alpns, ["proto A"])
        guard certInfo.peerOffer.certificateTypes.contains(where: { $0 == .rawPublicKey }) else {
            return .unavailable(reason: "server only supports raw public key")
        }
        let publicKey = self.serverSigningKey.publicKey
        return .available(.init(type: .rawPublicKey, entries: [publicKey.derRepresentation]))
    }

    @Sendable func provideCertificate(certInfo: CertificateInfo) -> CertificateResult {
        self.certificateCallbackCalled.withLock { $0 = true }
        guard certInfo.peerOffer.certificateTypes.isEmpty
                || certInfo.peerOffer.certificateTypes.contains(where: { $0 == .x509 }) else {
            return .unavailable(reason: "server only supports x509")
        }
        return .available(.init(type: .x509, entries: self.dummyDataCertificates))
    }

    @Sendable func provideCertificateAsync(certInfo: CertificateInfo) -> CertificateResult {
        self.certificateCallbackCalled.withLock { $0 = true }
        guard certInfo.peerOffer.certificateTypes.isEmpty
                || certInfo.peerOffer.certificateTypes.contains(where: { $0 == .x509 }) else {
            return .unavailable(reason: "server only supports x509")
        }
        certInfo.deliverResult?(.available(.init(type: .x509, entries: self.dummyDataCertificates)))
        return .waiting
    }

    @Sendable func provideBothAvailable(certInfo: CertificateInfo) -> CertificateResult {
        self.certificateCallbackCalled.withLock { $0 = true }
        let availableTypes = certInfo.peerOffer.certificateTypes
        if availableTypes.isEmpty || availableTypes.contains(.x509) {
            return .available(.init(type: .x509, entries: self.dummyDataCertificates))
        } else if availableTypes.contains(.rawPublicKey) {
            let publicKey = self.serverSigningKey.publicKey
            return .available(.init(type: .rawPublicKey, entries: [publicKey.derRepresentation]))
        } else {
            return .unavailable(reason: "unsupported certificate type")
        }
    }

    // -- callback functions: sign transcript hash --

    @Sendable func signUnavailable(_ signingInfo: SignatureInfo) -> SignatureResult {
        self.signingCallbackCalled.withLock { $0 = true }
        return .unavailable(reason: "I am not signing that")
    }

    @Sendable func signUnavailableAsync(_ signingInfo: SignatureInfo) -> SignatureResult {
        self.signingCallbackCalled.withLock { $0 = true }
        signingInfo.deliverResult?(.unavailable(reason: "I am not signing that"))
        return .waiting
    }

    @Sendable func signRawPublicKey(_ signingInfo: SignatureInfo) -> SignatureResult {
        self.signingCallbackCalled.withLock { $0 = true }
        XCTAssertEqual(signingInfo.peerOffer.serverName, "test.example.com")
        XCTAssertEqual(signingInfo.peerOffer.alpns, ["proto A"])
        if !signingInfo.peerOffer.signatureAlgorithms.contains(self.serverSignatureAlgorithm) {
            return .unavailable(reason: "unsupported signature algorithm")
        }

        if let signature = try? self.serverSigningKey.signature(for: signingInfo.transcriptHash).derRepresentation {
            return .available(signature: signature, algorithm: self.serverSignatureAlgorithm)
        } else {
            return .unavailable(reason: "failed create signature")
        }
    }

    @Sendable func signCertificate(_ signingInfo: SignatureInfo) -> SignatureResult {
        self.signingCallbackCalled.withLock { $0 = true }
        return .available(signature: self.dummyDataSignature, algorithm: self.dummySignatureAlgorithm)
    }

    @Sendable func signCertificateWithWrongSignatureAlgorithm(_ signingInfo: SignatureInfo) -> SignatureResult {
        self.signingCallbackCalled.withLock { $0 = true }
        return .available(
            signature: self.dummyDataSignature,
            algorithm: self.dummySignatureAlgorithm + 1
        )
    }

    @Sendable func signCertificateWithWrongSignatureAlgorithmAsync(_ signingInfo: SignatureInfo) -> SignatureResult {
        self.signingCallbackCalled.withLock { $0 = true }
        signingInfo.deliverResult?(.available(
            signature: self.dummyDataSignature,
            algorithm: self.dummySignatureAlgorithm + 1
        ))
        return .waiting
    }

    @Sendable func signCertificateAsync(_ signingInfo: SignatureInfo) -> SignatureResult {
        self.signingCallbackCalled.withLock { $0 = true }
        signingInfo.deliverResult?(.available(signature: self.dummyDataSignature, algorithm: self.dummySignatureAlgorithm))
        return .waiting
    }

    @Sendable func signBothAvailable(_ signingInfo: SignatureInfo) -> SignatureResult {
        self.signingCallbackCalled.withLock { $0 = true }
        let availableTypes = signingInfo.peerOffer.certificateTypes
        if availableTypes.contains(.x509) {
            return .available(signature: self.dummyDataSignature, algorithm: self.dummySignatureAlgorithm)
        } else if availableTypes.contains(.rawPublicKey) {
            if !signingInfo.peerOffer.signatureAlgorithms.contains(self.serverSignatureAlgorithm) {
                return .unavailable(reason: "unexpected signature algorithm")
            }

            if let signature = try? self.serverSigningKey.signature(for: signingInfo.transcriptHash).derRepresentation {
                return .available(signature: signature, algorithm: self.serverSignatureAlgorithm)
            } else {
                return .unavailable(reason: "failed to create signature")
            }
        } else {
            return .unavailable(reason: "unsupported certificate type")
        }
    }

    // -- callback functions: server auth --

    @Sendable func verificationCallbackRawPublicKey(info: VerificationInfo) -> VerificationResult {
        self.authenticationCallbackCalled.withLock { $0 = true }
        guard info.signatureAlgorithm == SignatureScheme.ecdsa_secp256r1_sha256.rawValue else {
            return .invalid(reason: "unsupported signature algorithm")
        }
        guard info.certificates.type == .rawPublicKey else {
            return .invalid(reason: "unsupported certificate type")
        }
        guard info.certificates.entries.count == 1 else {
            return .invalid(reason: "only expected one key")
        }
        guard let key: P256.Signing.PublicKey = try? P256.Signing.PublicKey(derRepresentation: info.certificates.entries[0]) else {
            return .invalid(reason: "failed to load key")
        }
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: info.signature) else {
            return .invalid(reason: "failed to load signature")
        }
        guard key.isValidSignature(signature, for: info.transcriptHash) else {
            return .invalid(reason: "invalid signature")
        }
        guard key.rawRepresentation == self.serverSigningKey.publicKey.rawRepresentation else {
            return .invalid(reason: "not authorized")
        }
        return .valid
    }

    @Sendable func verificationCallbackCertificate(info: VerificationInfo) -> VerificationResult {
        self.authenticationCallbackCalled.withLock { $0 = true }
        guard info.certificates.type == .x509 else {
            return .invalid(reason: "unsupported certificate type")
        }
        guard info.signatureAlgorithm == self.dummySignatureAlgorithm else {
            return .invalid(reason: "unsupported signature algorithm")
        }
        guard info.certificates.entries.count == self.dummyDataCertificates.count else {
            return .invalid(reason: "unexpected number of certificates")
        }
        for (lhs, rhs) in zip(self.dummyDataCertificates, info.certificates.entries) {
            guard lhs == rhs else {
                return .invalid(reason: "not authorized")
            }
        }
        return .valid
    }

    @Sendable func verificationCallbackBothAvailable(info: VerificationInfo) -> VerificationResult {
        switch info.certificates.type {
        case .rawPublicKey:
            return self.verificationCallbackRawPublicKey(info: info)
        case .x509:
            return self.verificationCallbackCertificate(info: info)
        default:
            self.authenticationCallbackCalled.withLock { $0 = true }
            return .invalid(reason: "unexpected certificate type")
        }
    }
}

class ServerHandshakeStateMachineCallbackTests: XCTestCase {

    var serverPrivateKey = P384EphemeralKey()
    var fixtures: ServerCallbackFixtures!

    // -- set up --

    override func setUp() {
        continueAfterFailure = false
        self.fixtures = ServerCallbackFixtures()
    }

    // -- configuration: server --

    // Fails first callback.
    var serverConfigCertUnavailable: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.rawPublicKey, .x509], getCertificateChain: self.fixtures.provideUnavailable(certInfo:), signTranscriptHash: self.fixtures.signRawPublicKey(_:))
            )
    }

    // Fails first callback.
    var serverConfigCertUnavailableAsync: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.rawPublicKey, .x509], getCertificateChain: self.fixtures.provideUnavailableAsync(certInfo:), signTranscriptHash: self.fixtures.signRawPublicKey(_:))
            )
    }

    // Fails second callback, requires key for signing.
    var serverConfigSignatureUnavailable: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.rawPublicKey], getCertificateChain: self.fixtures.provideRawPublicKey(certInfo:), signTranscriptHash: self.fixtures.signUnavailable(_:))
            )
    }

    // Fails second callback, requires key for signing.
    var serverConfigSignatureUnavailableAsync: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.x509], getCertificateChain: self.fixtures.provideCertificateAsync(certInfo:), signTranscriptHash: self.fixtures.signUnavailableAsync(_:))
            )
    }

    var serverConfigRawPublicKey: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.rawPublicKey], getCertificateChain: self.fixtures.provideRawPublicKey(certInfo:), signTranscriptHash: self.fixtures.signRawPublicKey(_:))
            )
    }

    var serverConfigCertificate: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.x509], getCertificateChain: self.fixtures.provideCertificate(certInfo:), signTranscriptHash: self.fixtures.signCertificate(_:))
            )
    }

    var serverConfigCertificateAsync: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.x509], getCertificateChain: self.fixtures.provideCertificateAsync(certInfo:), signTranscriptHash: self.fixtures.signCertificateAsync(_:))
            )
    }

    var serverConfigCertificateCallbackSelectsWrongAlgorithm: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.x509], getCertificateChain: self.fixtures.provideCertificate(certInfo:), signTranscriptHash: self.fixtures.signCertificateWithWrongSignatureAlgorithm(_:))
            )
    }

    var serverConfigCertificateCallbackSelectsWrongAlgorithmAsync: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.x509], getCertificateChain: self.fixtures.provideCertificateAsync(certInfo:), signTranscriptHash: self.fixtures.signCertificateWithWrongSignatureAlgorithmAsync(_:))
            )
    }

    var serverConfigNoCallback: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                signingKey: SwiftTLSPrivateKey.p256(self.fixtures.serverSigningKey)
            )
    }

    var serverConfigSupportBoth: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.x509, .rawPublicKey], getCertificateChain: self.fixtures.provideBothAvailable(certInfo:), signTranscriptHash: self.fixtures.signBothAvailable(_:))
            )
    }

    var serverConfigRawPublicKeyRequiresRPKClientAuth: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                validPeerPublicKeys: [self.fixtures.clientAuthKey.publicKey],
                clientAuthRequired: true,
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.rawPublicKey], getCertificateChain: self.fixtures.provideRawPublicKey(certInfo:), signTranscriptHash: self.fixtures.signRawPublicKey(_:))
            )
    }

    var serverConfigCertificateRequiresClientAuth: ServerHandshakeStateMachine.Configuration {
        ServerHandshakeStateMachine
            .Configuration(
                quicTransportParameters: ByteBuffer("some opaque bytes"),
                alpn: ["proto A", "proto B"],
                clientAuthRequired: true,
                asyncAuthenticator: AsyncAuthenticator(supportedCertificateTypes: [.x509], getCertificateChain: self.fixtures.provideCertificate(certInfo:), signTranscriptHash: self.fixtures.signCertificate(_:)),
            )
    }

    // -- configuration: client --

    var clientConfigRawPublicKey: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            serverName: "test.example.com",
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A"],
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.rawPublicKey], verificationCallback: self.fixtures.verificationCallbackRawPublicKey(info:))
        )
    }

    var clientConfigRawPublicKeyRPKClientAuth: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            serverName: "test.example.com",
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A"],
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            signingKey: .p256(self.fixtures.clientAuthKey),
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.rawPublicKey], verificationCallback: self.fixtures.verificationCallbackRawPublicKey(info:))
        )
    }

    var clientConfigCertificate: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            serverName: "test.example.com",
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A"],
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.x509], verificationCallback: self.fixtures.verificationCallbackCertificate(info:))
        )
    }

    var clientConfigCertificateEmptyCertificateTypes: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            serverName: "test.example.com",
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A"],
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [], verificationCallback: self.fixtures.verificationCallbackCertificate(info:))
        )
    }

    var clientConfigCertificateUnknownCertificateTypes: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            serverName: "test.example.com",
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A"],
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.init(rawValue: 0xFF)], verificationCallback: self.fixtures.verificationCallbackCertificate(info:))
        )
    }

    var clientConfigCertificateInvalidHostnames: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            serverName: "😈", // non-ascii hostname
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A"],
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.x509], verificationCallback: self.fixtures.verificationCallbackCertificate(info:))
        )
    }

    var clientNoCallback: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            serverName: "test.example.com",
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A"],
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            validPeerPublicKeys: [self.fixtures.serverSigningKey.publicKey],
        )
    }

    var clientBothAvailable: HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            serverName: "test.example.com",
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A"],
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            asyncVerifier: AsyncVerifier(availableCertificateTypes: [.x509, .rawPublicKey], verificationCallback: self.fixtures.verificationCallbackBothAvailable(info:))
        )
    }

    // -- utility --

    func processWithAsyncDelivery(_ stateMachine: inout ServerHandshakeStateMachine) throws -> PartialHandshakeResult? {
        let pendingResult = Mutex<PendingAsyncResult?>(nil)
        stateMachine.deliverResultCallback = { result in
            pendingResult.withLock { mtx in
                mtx = result
            }
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

    @discardableResult
    func checkHandshakeBytes(_ parser: inout HandshakeMessageParser, handshakeBytes: ByteBuffer?, expectedMessage: String) throws -> ByteBuffer? {
        if var handshakeBytesCopy = handshakeBytes {
            parser.appendBytes(&handshakeBytesCopy)
        }
        guard let message = try parser.parseHandshakeMessage() else {
            if (parser.bytesToParse > 0) {
                XCTFail("Couldn't parse handshake message.")
            } else {
                XCTFail("No handshake bytes available to check")
            }
            return nil
        }
        guard message.message.logDescription == expectedMessage else {
            XCTFail("Handshake message did not match expected type: expected \(expectedMessage), got \(message.message.logDescription)")
            return nil
        }
        return message.messageBytes
    }

    func runSuccessfulHandshake(
        clientStateMachine: inout HandshakeStateMachine,
        serverStateMachine: inout ServerHandshakeStateMachine,
        expectCallbacksCalled: Bool = true,
        clientAuthRequired: Bool = false,
    ) throws {

        // Reset callback flags
        self.fixtures.resetCallbackFlags()

        // Initializer handshake parser
        var parser = HandshakeMessageParser()

        // Send Client Hello
        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        var result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        guard var serverHelloBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverHelloBytes, expectedMessage: "serverHello")

        // Read Server Hello
        clientStateMachine.receivedNetworkData(&serverHelloBytes)
        result = try clientStateMachine.processHandshake()!
        XCTAssertNil(result.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // Send Encrypted Extensions
        result = try serverStateMachine.processHandshake()!
        guard var serverEncryptedExtensionsBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverEncryptedExtensionsBytes, expectedMessage: "encryptedExtensions")

        // Read Encrypted Extensions
        clientStateMachine.receivedNetworkData(&serverEncryptedExtensionsBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())

        if clientAuthRequired {
            // Send Ceritificate Request if expecting client auth
            result = try serverStateMachine.processHandshake()!
            guard var serverCertificateRequestBytes = result.handshakeBytesToSend else {
                XCTFail("failed to get Certificate Request bytes")
                return
            }
            try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateRequestBytes, expectedMessage: "certificateRequest")

            // Read Certificate Request
            clientStateMachine.receivedNetworkData(&serverCertificateRequestBytes)
            XCTAssertNil(try clientStateMachine.processHandshake())
        }

        // Send Certificate
        XCTAssertFalse(self.fixtures.certificateCallbackCalled.withLock { $0 })
        guard let certResult = try processWithAsyncDelivery(&serverStateMachine) else {
            XCTFail("processWithAsyncDelivery returned nil for certificate")
            return
        }
        result = certResult
        guard var serverCertificateBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateBytes, expectedMessage: "certificate")
        XCTAssertEqual(self.fixtures.certificateCallbackCalled.withLock { $0 }, expectCallbacksCalled)


        // Read Server Certificate
        clientStateMachine.receivedNetworkData(&serverCertificateBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())

        // Send CertificateVerify
        XCTAssertFalse(self.fixtures.signingCallbackCalled.withLock { $0 })
        guard let sigResult = try processWithAsyncDelivery(&serverStateMachine) else {
            XCTFail("processWithAsyncDelivery returned nil for signature")
            return
        }
        result = sigResult
        guard var serverCertificateVerifyBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateVerifyBytes, expectedMessage: "certificateVerify")
        XCTAssertEqual(self.fixtures.signingCallbackCalled.withLock { $0 }, expectCallbacksCalled)

        // Read Server CertificateVerify
        clientStateMachine.receivedNetworkData(&serverCertificateVerifyBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())

        // Send ServerFinished
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .write)
        guard var serverFinishedBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverFinishedBytes, expectedMessage: "finished")

        // Read ServerFinished and Send ClientFinished
        clientStateMachine.receivedNetworkData(&serverFinishedBytes)
        result = try clientStateMachine.processHandshake()!

        guard var clientSecondFlightBytes = result.handshakeBytesToSend else {
            XCTFail("failed to get Client second flight bytes")
            return
        }
        var clientSecondFlightBytesCopy = clientSecondFlightBytes
        parser.appendBytes(&clientSecondFlightBytesCopy)

        // if client auth required then we need to get the client cert and cert verify also
        if clientAuthRequired {
            try checkHandshakeBytes(&parser, handshakeBytes: nil, expectedMessage: "certificate")
            // already passed in full second flight, so don't add again
            try checkHandshakeBytes(&parser, handshakeBytes: nil, expectedMessage: "certificateVerify")
        }

        try checkHandshakeBytes(&parser, handshakeBytes: nil, expectedMessage: "finished")

        result.assertNewReadAndWriteEncryptionLevel(.application)

        // Read [Client Certificate, Certificate Verify] + ClientFinished
        serverStateMachine.receivedNetworkData(&clientSecondFlightBytes)
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .read)
        XCTAssertEqual(serverStateMachine.stateDescription, "readyForData")

        XCTAssert(!clientStateMachine.negotiatedEPSK)
        XCTAssert(!serverStateMachine.negotiatedEPSK)
    }

    func runFailedHandshake(
        clientStateMachine: inout HandshakeStateMachine,
        serverStateMachine: inout ServerHandshakeStateMachine,
        expectedError: TLSError,
        errorLocation: ErrorLocation,
        extraClientHelloExtensions: [Extension]? = nil
    ) throws {
        // Reset callback flags
        self.fixtures.resetCallbackFlags()

        // Initializer handshake parser
        var parser = HandshakeMessageParser()

        // Send Client Hello
        if case(.sendClientHello) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.startHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!

        // Parse the client hello and inject extensions.
        if let extraClientHelloExtensions {
            var clientHandshakeParser = HandshakeMessageParser()
            var clientHelloBytesCopy = clientHelloBytes
            clientHandshakeParser.appendBytes(&clientHelloBytesCopy)

            guard let message = try clientHandshakeParser.parseHandshakeMessage() else {
                XCTFail("failed to parse client hello")
                return
            }

            guard case .clientHello(var parsedClientHello) = message.message else {
                XCTFail("expected clientHello message")
                return
            }

            for ext in extraClientHelloExtensions {
                parsedClientHello.extensions.append(ext)
            }

            var buffer = ByteBuffer()
            TLSMessageSerializer().writeHandshakeMessage(.clientHello(parsedClientHello), into: &buffer)
            clientHelloBytes = buffer
        }

        // Read Client Hello and Send ServerHello
        XCTAssertEqual(serverStateMachine.stateDescription, "idle")
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        if case(.readClientHello) = errorLocation {
            XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        var result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        guard var serverHelloBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverHelloBytes, expectedMessage: "serverHello")

        // Read Server Hello
        clientStateMachine.receivedNetworkData(&serverHelloBytes)
        if case(.readServerHello) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try clientStateMachine.processHandshake()!
        XCTAssertNil(result.handshakeBytesToSend)
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // Send Encrypted Extensions
        if case(.sendServerEncryptedExtensions) = errorLocation {
            XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try serverStateMachine.processHandshake()!
        guard var serverEncryptedExtensionsBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverEncryptedExtensionsBytes, expectedMessage: "encryptedExtensions")

        // Read Encrypted Extensions
        clientStateMachine.receivedNetworkData(&serverEncryptedExtensionsBytes)
        if case(.readServerEncryptedExtensions) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        XCTAssertNil(try clientStateMachine.processHandshake())

        // Send Certificate
        if case(.sendServerCertificate) = errorLocation {
            XCTAssertThrowsError(try processWithAsyncDelivery(&serverStateMachine)) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try processWithAsyncDelivery(&serverStateMachine)!
        guard var serverCertificateBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateBytes, expectedMessage: "certificate")


        // Read Server Certificate
        clientStateMachine.receivedNetworkData(&serverCertificateBytes)
        if case(.readServerCertificate) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        XCTAssertNil(try clientStateMachine.processHandshake())

        // Send CertificateVerify
        if case(.sendServerCertificateVerify) = errorLocation {
            XCTAssertThrowsError(try processWithAsyncDelivery(&serverStateMachine)) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try processWithAsyncDelivery(&serverStateMachine)!
        guard var serverCertificateVerifyBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverCertificateVerifyBytes, expectedMessage: "certificateVerify")

        // Read Server CertificateVerify
        clientStateMachine.receivedNetworkData(&serverCertificateVerifyBytes)
        if case(.readServerCertificateVerify) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        XCTAssertNil(try clientStateMachine.processHandshake())

        // Send ServerFinished
        if case(.sendServerFinished) = errorLocation {
            XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .write)
        guard var serverFinishedBytes = result.handshakeBytesToSend else {
            XCTFail()
            return
        }
        try checkHandshakeBytes(&parser, handshakeBytes: serverFinishedBytes, expectedMessage: "finished")

        // Read ServerFinished and Send ClientFinished
        clientStateMachine.receivedNetworkData(&serverFinishedBytes)
        if case(.readServerFinished) = errorLocation {
            XCTAssertThrowsError(try clientStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try clientStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.application)
        XCTAssertNotNil(result.handshakeBytesToSend)

        var clientFinishedBytes = result.handshakeBytesToSend!
        var clientFinishedBytesCopy = result.handshakeBytesToSend!
        parser.appendBytes(&clientFinishedBytesCopy)
        guard let message = try parser.parseHandshakeMessage(), case .finished =
                message.message else {
            XCTFail()
            return
        }

        // Read ClientFinished
        serverStateMachine.receivedNetworkData(&clientFinishedBytes)
        if case(.readClientFinished) = errorLocation {
            XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
                XCTAssertEqual(error as? TLSError, expectedError)
            }
            return
        }
        result = try serverStateMachine.processHandshake()!
        result.assertNewEncryptionLevel(.application, .read)
        XCTAssertEqual(serverStateMachine.stateDescription, "readyForData")
        XCTAssertEqual(clientStateMachine.peerALPN, "proto A")
    }

    // -- tests (decoupled async) --

    // Exercises the fully decoupled async path: the getCertificateChain callback captures
    // deliverResult but does NOT call it inline; the closure is called later, outside of
    // processHandshake.
    func testDecoupledAsyncCertificateDelivery() throws {
        let capturedCertClosure = Mutex<(@Sendable (CertificateResult) -> Void)?>(nil)

        let serverConfig = ServerHandshakeStateMachine.Configuration(
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A", "proto B"],
            asyncAuthenticator: AsyncAuthenticator(
                supportedCertificateTypes: [.x509],
                getCertificateChain: { certInfo in
                    capturedCertClosure.withLock { $0 = certInfo.deliverResult }
                    return .waiting
                },
                signTranscriptHash: self.fixtures.signCertificate(_:)
            )
        )

        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        // ClientHello
        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!

        // ServerHello
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        var result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        var serverHelloBytes = result.handshakeBytesToSend!

        // Client reads ServerHello
        clientStateMachine.receivedNetworkData(&serverHelloBytes)
        result = try clientStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)

        // EncryptedExtensions
        result = try serverStateMachine.processHandshake()!
        var serverEEBytes = result.handshakeBytesToSend!

        // Client reads EncryptedExtensions
        clientStateMachine.receivedNetworkData(&serverEEBytes)
        XCTAssertNil(try clientStateMachine.processHandshake())

        // Certificate step: callback captures deliverResult but returns .waiting without calling it.
        let pendingResultMutex = Mutex<PendingAsyncResult?>(nil)
        serverStateMachine.deliverResultCallback = { r in
            pendingResultMutex.withLock { $0 = r }
        }
        XCTAssertNil(try serverStateMachine.processHandshake())
        var pendingResult = pendingResultMutex.withLock({ $0 })
        XCTAssertNil(pendingResult)
        XCTAssertNotNil(capturedCertClosure.withLock { $0 })

        // Simulate async completion happening after processHandshake returned.
        capturedCertClosure.withLock { $0 }?(.available(.init(type: .x509, entries: self.fixtures.dummyDataCertificates)))
        pendingResult = pendingResultMutex.withLock({ $0 })
        XCTAssertNotNil(pendingResult)

        // Feed the result back and resume the handshake.
        serverStateMachine.applyAsyncResult(pendingResult!)
        let certStep = try serverStateMachine.processHandshake()
        XCTAssertNotNil(certStep?.handshakeBytesToSend)
    }

    // -- tests (async result checks) --

    func driveServerToAwaitingCertificate() throws -> ServerHandshakeStateMachine {
        let serverConfig = ServerHandshakeStateMachine.Configuration(
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A", "proto B"],
            asyncAuthenticator: AsyncAuthenticator(
                supportedCertificateTypes: [.x509],
                getCertificateChain: { _ in .waiting },
                signTranscriptHash: self.fixtures.signCertificate(_:)
            )
        )

        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        let result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        var serverHelloBytes = result.handshakeBytesToSend!

        clientStateMachine.receivedNetworkData(&serverHelloBytes)
        _ = try clientStateMachine.processHandshake()!

        _ = try serverStateMachine.processHandshake()!

        // Certificate callback returns .waiting; state machine enters awaitingCertificate.
        serverStateMachine.deliverResultCallback = { _ in }
        XCTAssertNil(try serverStateMachine.processHandshake())
        XCTAssertTrue(serverStateMachine.awaitingAsyncComputation)

        return serverStateMachine
    }

    func testHandleAsyncCertificateResultWithoutResult() throws {
        var serverStateMachine = try driveServerToAwaitingCertificate()
        XCTAssertTrue(serverStateMachine.awaitingAsyncComputation)
        XCTAssertNil(try serverStateMachine.processHandshake())
        XCTAssertTrue(serverStateMachine.awaitingAsyncComputation)
    }

    func testHandleAsyncCertificateResultWithWrongResultType() throws {
        var serverStateMachine = try driveServerToAwaitingCertificate()
        // The expected result would be of case `.certificate` here.
        serverStateMachine.applyAsyncResult(.signature(.unavailable(reason: "wrong type")))
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .internalError(reason: "Unexpected async result type in awaitingCertificate"))
        }
    }

    func driveServerToAwaitingSignature() throws -> ServerHandshakeStateMachine {
        let serverConfig = ServerHandshakeStateMachine.Configuration(
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A", "proto B"],
            asyncAuthenticator: AsyncAuthenticator(
                supportedCertificateTypes: [.x509],
                getCertificateChain: self.fixtures.provideCertificate(certInfo:),
                signTranscriptHash: { _ in .waiting }
            )
        )

        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        let result = try serverStateMachine.processHandshake()!
        result.assertNewReadAndWriteEncryptionLevel(.handshake)
        var serverHelloBytes = result.handshakeBytesToSend!

        clientStateMachine.receivedNetworkData(&serverHelloBytes)
        _ = try clientStateMachine.processHandshake()!

        // EncryptedExtensions
        _ = try serverStateMachine.processHandshake()!

        // The deliverResultCallback must be set before any callback-driven step.
        serverStateMachine.deliverResultCallback = { _ in }

        // Certificate (sync)
        _ = try serverStateMachine.processHandshake()!

        // Signature callback returns .waiting; state machine enters awaitingSignature.
        XCTAssertNil(try serverStateMachine.processHandshake())
        XCTAssertTrue(serverStateMachine.awaitingAsyncComputation)

        return serverStateMachine
    }

    func testHandleAsyncSignatureResultWithoutResult() throws {
        var serverStateMachine = try driveServerToAwaitingSignature()
        XCTAssertTrue(serverStateMachine.awaitingAsyncComputation)
        XCTAssertNil(try serverStateMachine.processHandshake())
        XCTAssertTrue(serverStateMachine.awaitingAsyncComputation)
    }

    func testHandleAsyncSignatureResultWithWrongResultType() throws {
        var serverStateMachine = try driveServerToAwaitingSignature()
        // The expected result would be of case `.signature` here.
        serverStateMachine.applyAsyncResult(.certificate(.unavailable(reason: "wrong type")))
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .internalError(reason: "Unexpected async result type in awaitingSignature"))
        }
    }

    // -- tests --

    func testNetworkDataHappyPathCallbacksRawPublicKey() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigRawPublicKey)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigRawPublicKey)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testNetworkDataHappyPathCallbacksCertificates() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificate)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testNetworkDataHappyPathCallbacksCertificatesClientEmptyCertificateTypes() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificateEmptyCertificateTypes)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificate)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testNetworkDataHappyPathCallbacksCertificatesAsync() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificateAsync)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    // -- callbacks cannot complete --

    func testNetworkDataSadPathCallbacksCertUnavailable() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigRawPublicKey)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertUnavailable)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: .serverMissingCertificate, errorLocation: .sendServerCertificate)
    }

    func testNetworkDataSadPathCallbacksCertUnavailableAsync() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigRawPublicKey)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertUnavailableAsync)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: .serverMissingCertificate, errorLocation: .sendServerCertificate)
    }

    func testNetworkDataSadPathCallbacksSignatureUnavailable() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigRawPublicKey)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigSignatureUnavailable)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: .serverMissingSignature, errorLocation: .sendServerCertificateVerify)
    }

    func testNetworkDataSadPathCallbacksSignatureUnavailableAsync() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigSignatureUnavailableAsync)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: .serverMissingSignature, errorLocation: .sendServerCertificateVerify)
    }

    // The server selects a signature algorithm not offered by the client. The state machine
    // catches this and aborts with a handshake failure.
    func testNetworkDataSadPathCallbacksServerSelectsWrongSignatureAlgorithm() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificateCallbackSelectsWrongAlgorithm)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: .handshakeFailure, errorLocation: .sendServerCertificateVerify)
    }

    // Same, but trigger the async path, which should check the same thing and fails for the same reason.
    func testNetworkDataSadPathCallbacksServerSelectsWrongSignatureAlgorithmAsync() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificateCallbackSelectsWrongAlgorithmAsync)
        try runFailedHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectedError: .handshakeFailure, errorLocation: .sendServerCertificateVerify)
    }

    // -- mixed --

    func testNetworkDataHappyPathInteropServerCallback() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientNoCallback)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigRawPublicKey)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    func testNetworkDataHappyPathInteropClientCallback() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigRawPublicKey)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigNoCallback)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine, expectCallbacksCalled: false)
    }

    // -- agreement --

    // client: rawPublicKey, server: both
    func testNetworkDataHappyPathAgreementClientRawPublicKey() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigRawPublicKey)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigSupportBoth)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    // client: x509, server: both
    func testNetworkDataHappyPathAgreementClientCertificate() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigSupportBoth)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    // client: both, server: rawPublicKey
    func testNetworkDataHappyPathAgreementServerRawPublicKey() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientBothAvailable)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigRawPublicKey)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    // client: both, server: x509
    func testNetworkDataHappyPathAgreementServerCertificate() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientBothAvailable)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificate)
        try runSuccessfulHandshake(clientStateMachine: &clientStateMachine, serverStateMachine: &serverStateMachine)
    }

    // -- certificate negotation failures --

    // client: rawPublicKey, server: x509
    func testNetworkDataFailuresAgreementClientRPKServerCertificate() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigRawPublicKey)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificate)
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.unsupportedCertificate,
            errorLocation: .readClientHello
        )
    }

    // client: x509, server: rawPublicKey
    func testNetworkDataFailuresAgreementClientCertificateServerRPK() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigRawPublicKey)
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            // TODO: This should probably fail in `validateAndDetermineCertificateType`?
            //  But when the client sends an empty certificate list, the server does not
            //  compare types and this will be a failure in the callback that cannot
            //  provide suitable certificates.
            // expectedError: TLSError.unsupportedCertificate,
            // errorLocation: .readClientHello
            expectedError: TLSError.serverMissingCertificate,
            errorLocation: .sendServerCertificate
        )
    }

    // -- server certificate type oddities --

    // client: includes server_certificate_types with empty list, server: certificates
    func testClientIncludesEmptyServerCertificateTypesExtension() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificateEmptyCertificateTypes)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificate)
        // This test manipulates the clientHello received by the server. Since they see different bytes,
        // the handshake will eventually fail when verifying the transcript hashes. However, we pass the
        // remaining parts, which shows that the server can handle a server_certificate_types extension
        // with an empty list (treated as if it was absent).
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.negotiationFailed,
            errorLocation: .readServerFinished,
            extraClientHelloExtensions: [.serverCertificateType(.offer([]))]
        )
    }

    // client: sends unknown certificate type: 0xFF, server callbacks will reject unknown type.
    func testClientSendsServerCertificatesType0xFF() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificateUnknownCertificateTypes)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificate)
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.unsupportedCertificate,
            errorLocation: .readClientHello
        )
    }

    // -- invalid extensions --

    // client: sends host name with non-ascii characters
    // server: parsing the server name extension fails with "illegal parameter".
    func testClientSendsInvalidServerName() throws {
        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificateInvalidHostnames)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: self.serverConfigCertificate)
        try runFailedHandshake(
            clientStateMachine: &clientStateMachine,
            serverStateMachine: &serverStateMachine,
            expectedError: TLSError.illegalParameter,
            errorLocation: .readClientHello
        )
    }

    // -- misconfiguration --

    // Server callback returns .waiting but no deliverResultCallback was configured. —
    // Expectation: The state machine fails with `handshakeError`.
    func testServerWaitingCallbackWithoutDeliverHandlerThrows() throws {
        let serverConfig = ServerHandshakeStateMachine.Configuration(
            quicTransportParameters: ByteBuffer("some opaque bytes"),
            alpn: ["proto A", "proto B"],
            asyncAuthenticator: AsyncAuthenticator(
                supportedCertificateTypes: [.x509],
                getCertificateChain: { _ in .waiting },
                signTranscriptHash: self.fixtures.signCertificate(_:)
            )
        )

        var clientStateMachine = try HandshakeStateMachine(configuration: self.clientConfigCertificate)
        var serverStateMachine = try ServerHandshakeStateMachine(configuration: serverConfig)

        var clientHelloBytes = try clientStateMachine.startHandshake().handshakeBytesToSend!
        serverStateMachine.receivedNetworkData(&clientHelloBytes)
        _ = try serverStateMachine.processHandshake()                // ServerHello
        _ = try serverStateMachine.processHandshake()                // EncryptedExtensions

        // --> Do not set serverStateMachine.deliverResultCallback.
        // The certificate callback returns .waiting and the guard in getCertificateChain
        // should throw because the callback is not set.
        XCTAssertThrowsError(try serverStateMachine.processHandshake()) { error in
            XCTAssertEqual(error as? TLSError, .handshakeError)
        }
    }

    // --  client auth negotiation failures --

    // Configuring clientAuth support on a client with certificate callbacks produce an invalid configuration.
    func testRequiredClientAuthProducesInvalidClientConfig() throws {
        XCTAssertThrowsError(try HandshakeStateMachine(configuration: self.clientConfigRawPublicKeyRPKClientAuth))
    }

    // Configuring clientAuth support on a server with certificate callbacks produce an invalid configuration.
    func testRequiredClientAuthProducesInvalidServerConfig() throws {
        XCTAssertThrowsError(try ServerHandshakeStateMachine(configuration: self.serverConfigCertificateRequiresClientAuth))
    }

    // Positive test first. client: RPK auth, server RPK auth (clientAuthRequired). Callbacks for server auth, SwiftTLS client auth for client auth.
    func testRPKClientAuthWorks() throws {
        throw XCTSkip("This currently produces invalid an configuration as client-auth is not supported.")
    }

    // Server requires client RPK auth, client doesn't send client_certificate_type
    // The server has clientAuthRequired = true and serverSupportedClientCertificateTypes = [.rawPublicKey].
    // negotiateClientCertificateType() returns nil (client didn't offer the extension).
    // Server should throw TLSError.handshakeFailure (line 916-918).
    func testRPKClientAuthNegotiationFailure() throws {
        throw XCTSkip("This currently produces invalid an configuration as client-auth is not supported.")
    }

    // Server requires client RPK auth, client offers only X.509 in client_certificate_type
    // negotiateClientCertificateType() returns nil (no common type). Same failure.
    func testCertificateClientAuthNegotiationFailure() throws {
        throw XCTSkip("This currently produces invalid an configuration as client-auth is not supported.")
    }

    // Server requiring client auth with RPKs (clientAuthRequired = true) and
    // the client sends an empty certificate message and no certificate verify should fail.
    func testClientAuthNegotiationEmptyCertificateMessage() throws {
        throw XCTSkip("This currently produces invalid an configuration as client-auth is not supported.")
    }

}
