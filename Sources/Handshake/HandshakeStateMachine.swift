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

#if canImport(Foundation) && !SWIFTTLS_EMBEDDED
import Foundation
#endif
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif

#if canImport(Darwin) || SWIFTTLS_EXCLAVEKIT
import os.log
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "HandshakeStateMachine")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeStateMachine")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeStateMachine")
#endif

struct HandshakeStateMachine {
    private var parser = HandshakeMessageParser()
    private var serializer = TLSMessageSerializer()
    var state: HandshakeState
    #if SWIFTTLS_EMBEDDED
    private let clock: SwiftTLSDefaultClock
    #else
    private let clock: SwiftTLSClock
    #endif
    private var random: Random
    private var configuration: Configuration
    var deliverResultCallback: (@Sendable (PendingAsyncResult) -> Void)?
    var pendingAsyncResult: PendingAsyncResult?

    mutating func applyAsyncResult(_ result: PendingAsyncResult) {
        self.pendingAsyncResult = result
    }

    init(configuration: Configuration) throws(TLSError) {
        if !configuration.validConfiguration {
            logger.error("Client: unable to start handshake. invalid configuration")
            throw TLSError.invalidConfigurationOptions
        }
        self.clock = SwiftTLSDefaultClock()
        self.random = Random()
        self.configuration = configuration
        self.state = .idle(HandshakeState.IdleState(configuration: configuration, sessionToResume: nil))
        logger.info("client state machine initialized")
    }

    // disable resumption initializers on embedded builds
    #if !hasFeature(Embedded) && !TEST_EMBED && !SWIFTTLS_EXCLAVECORE && !SWIFTTLS_DRIVERKIT
    init(sessionTicket serializedSessionTicket: RawSpan, configuration: Configuration) throws(TLSError) {
        self = try .init(
            sessionTicket: serializedSessionTicket,
            configuration: configuration,
            clock: SwiftTLSDefaultClock()
        )
    }

    internal init(sessionTicket serializedSessionTicket: RawSpan, configuration: Configuration, clock: SwiftTLSClock) throws(TLSError) {
        let sessionToResume = try SessionTicket(serialized: serializedSessionTicket)
        self.clock = clock
        self.random = Random()
        self.configuration = configuration
        self.state = .idle(HandshakeState.IdleState(configuration: configuration, sessionToResume: sessionToResume))
        logger.info("client state machine initialized with session ticket")
    }
    #endif
    

    mutating func startHandshake() throws(TLSError) -> PartialHandshakeResult {

        // Avoiding capture of mutable self.
        let logDescription = self.state.logDescription
        logger.debug("startHandshake in state \(logDescription)")

        let keyExchangeGroup = self.configuration.fixedKeyExchangeGroup
        if keyExchangeGroup == .x25519MLKEM768 {
            logger.info("starting handshake with group \(keyExchangeGroup?.description ?? "none") (PQ-TLS)")
        } else {
            logger.info("starting handshake with group \(keyExchangeGroup?.description ?? "none")")
        }

        guard case .idle(let idleState) = self.state else {
            logger.error("invalid state for startHandshake: \(logDescription)")
            throw TLSError.handshakeError
        }

        var ephemeralKeyShare: GeneratedEphemeralPrivateKey? = nil
        let fixedGroup = self.configuration.fixedKeyExchangeGroup
        switch (fixedGroup) {
        case .secp384:
            ephemeralKeyShare = .p384(P384EphemeralKey())
        case .x25519:
            ephemeralKeyShare = .curve25519(Curve25519EphemeralKey())
        case .x25519MLKEM768:
            ephemeralKeyShare = .X25519MLKEM768(try X25519MLKEM768EphemeralKey())
        case nil:
            break
        default:
            logger.error("unknown fixedGroup: \(fixedGroup?.rawValue ?? 0)")
            throw TLSError.handshakeError
        }

        var helloExtensions: [Extension] = []
        
        if let ephemeralKeyShare {
            helloExtensions.append(.supportedGroups(.init(groups: [
                ephemeralKeyShare.namedGroup,
            ])))
        }
        
        helloExtensions.append(.supportedVersions(.offer([.tlsv13])))
        
        if let ephemeralKeyShare {
            helloExtensions.append(.keyShare(.clientHello([
                .init(group: ephemeralKeyShare.namedGroup, keyExchange: ByteBuffer(data: ephemeralKeyShare.publicKeyData))
            ])))
        }

        let signatureAlgorithms = [
            SignatureScheme.ecdsa_secp256r1_sha256
        ]
        helloExtensions.append(contentsOf: [
            .signatureAlgorithms(.init(schemes: signatureAlgorithms)),
            .preSharedKeyKexModes(.init(modes: [.pskAndDHE])),
        ])

        // We don't send the `server_certificate_type` extension if we are
        // configured to only trust x509 or none. Send it if we are
        // configured to trust only raw public keys or multiple types.
        switch idleState.configuration.verificationMethod {
        case .certificateCallbacks(let asyncVerifier):
            let certificateTypes = asyncVerifier.availableCertificateTypes
            if certificateTypes.count > 1
                || (certificateTypes.count == 1 && certificateTypes.first != .x509) {
                logger.debug("client sending server_certificate_types extension")
                helloExtensions.append(.serverCertificateType(.offer(certificateTypes)))
            }
        case .rawPublicKey:
            logger.debug("client sending server_certificate_types extension")
            helloExtensions.append(.serverCertificateType(PeerCertificateBundle.verificationCertificateTypes))
        case .none:
            break
        }

        // If configured with a signingKey then we can provide a raw public key Certificate Message
        // in response to a CertificateRequest message from the server.
        // This extension must be omitted if we don't actually have an RPK.
        if idleState.configuration.signingKey != nil {
            logger.debug("client sending client_certificate_types extension")
            helloExtensions.append(.clientCertificateType(PeerCertificateBundle.availableCertificateTypes))
        }

        if let serverName = idleState.configuration.serverName {
            helloExtensions.append(.serverName(Extension.ServerName.clientHello(.init(hostName: ByteBuffer(bytes: serverName.utf8)))))
        }

        if let quicTransportParameters = idleState.configuration.quicTransportParameters {
            helloExtensions.append(.quicTransportParameters(Extension.QUICTransportParameters(opaqueOffer: quicTransportParameters)))
        }

        if let alpn = idleState.configuration.alpn {
            helloExtensions.append(.alpn(.offer(alpn)))
        }

        if let ticketRequest = idleState.configuration.ticketRequest {
            helloExtensions.append(.ticketRequest(Extension.TicketRequest.clientHello(ticketRequest)))
        }

        let cipherSuites: [CipherSuite]
        if let supportedCipherSuites = configuration.supportedCipherSuites {
            cipherSuites = supportedCipherSuites
        } else {
            cipherSuites = [.TLS_AES_256_GCM_SHA384]
        }

        var clientHello = ClientHello(
            legacyVersion: .tlsv12,
            random: self.random,
            legacySessionID: .zero,
            cipherSuites: cipherSuites,
            legacyCompressionMethods: [0],
            extensions: helloExtensions
        )
        // For now, enforce that only resumption or epsks are in use.
        guard idleState.sessionToResume == nil || idleState.configuration.epsks == nil else {
            logger.error("both session resumption and imported PSKs are in use, only one is allowed")
            throw TLSError.handshakeError
        }

        // Now we get a bit weird: we may need to perform resumption here.
        #if SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
        let currentTime: Date? = nil
        #else
        let currentTime: Date = self.clock.now()
        #endif
        var sessionToResume: SessionTicket? = nil
        if let session = idleState.sessionToResume {
            #if SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
            logger.debug("session resumption not supported on embedded/driverkit platforms")
            #else
            if session.isCompatibleWith(clientHello, configuration: idleState.configuration, currentTime: currentTime) {
                sessionToResume = session
            } else {
                logger.debug("unable to resume session, incompatible with current handshake")
            }
            #endif
        }

        if configuration.enableEarlyData {
            if let session = sessionToResume, session.maxEarlyDataSize > 0 {
                logger.debug("client requesting early data with session resumption")
                clientHello.extensions.append(.earlyData(.init()))
            } else if let epsks = idleState.configuration.epsks, epsks.count > 0 {
                logger.debug("client requesting early data with external psks")
                clientHello.extensions.append(.earlyData(.init()))
            }
        }

        let result = try self.state.sendingClientHello(&clientHello, sessionToResume: sessionToResume, epsks: idleState.configuration.epsks ?? [], ephemeralKeyShare: ephemeralKeyShare, currentTime: currentTime)

        logger.notice("client beginning TLS handshake")
        logger.info("client sent client hello")
        return result
    }

    mutating func receivedNetworkData(_ data: RawSpan) {
        let byteCount = data.byteCount
        logger.debug("received network data (\(byteCount) bytes)")
        self.parser.appendBytes(data)
    }

    mutating func receivedNetworkData(_ data: inout ByteBuffer) {
        let readableBytes = data.readableBytes

        logger.debug("received network data (\(readableBytes) bytes)")
        self.parser.appendBytes(&data)
    }

    /// Call with an input buffer that we've been parsing from to save any
    /// bytes remaining from the input buffer. These generally correspond to a
    /// partial message.
    mutating func saveUnprocessedIncomingBytes(_ data: inout InputBuffer) {
        let byteCount = data.byteCount
        logger.debug("saving unprocessed network data (\(byteCount) bytes)")
        self.parser.appendBytes(data.readAll())
    }

    mutating func processHandshake() throws(TLSError) -> PartialHandshakeResult? {
        var incomingBytes = InputBuffer(storage: RawSpan())
        return try processHandshake(incomingBytes: &incomingBytes)
    }

    mutating func processHandshake(incomingBytes: inout InputBuffer) throws(TLSError) -> PartialHandshakeResult? {
        // We want to process as many messages as possible.
        while true {
            logger.debug("client attempting process step")

            do throws(TLSError) {
                switch self.state {
                case .idle:
                    logger.error("processHandshake called in idle state")
                    throw TLSError.handshakeUnexpectedRead
                case .clientHello:
                    switch try self.handleReadServerHello(incomingBytes: &incomingBytes) {
                    case .waitingForMoreData:
                        return nil
                    case .complete(let partialResult):
                        return partialResult
                    }
                case .serverHello:
                    switch try self.handleReadServerEncryptedExtensions(incomingBytes: &incomingBytes) {
                    case .waitingForMoreData:
                        return nil
                    case .complete:
                        continue
                    }
                case .serverEncryptedExtensions(let innerState) where (innerState.epskNegotiated || innerState.sessionResumed):
                    // If we're resuming or using an external psk we jump straight to finished.
                    switch try self.handleReadServerFinished(incomingBytes: &incomingBytes) {
                    case .waitingForMoreData:
                        return nil
                    case .complete(let partialResult):
                        logger.notice("client completed TLS handshake")
                        return partialResult
                    }
                case .serverEncryptedExtensions:
                    switch try self.handleReadServerCertificateOrCertificateRequest(incomingBytes: &incomingBytes) {
                    case .waitingForMoreData:
                        return nil
                    case .complete:
                        continue
                    }
                case .serverCertificateRequest:
                    switch try self.handleReadServerCertificate(incomingBytes: &incomingBytes) {
                    case .waitingForMoreData:
                        return nil
                    case .complete:
                        continue
                    }
                case .serverCertificate:
                    // This will transition to an intermediate state when performing asynchronous verification without an immediate result.
                    switch try self.handleReadServerCertificateVerify(incomingBytes: &incomingBytes) {
                    case .waitingForMoreData:
                        return nil
                    case .complete:
                        continue
                    }
                case .awaitingVerification:
                    switch try self.handleAsyncVerificationResult() {
                    case .waitingForMoreData:
                        return nil
                    case .complete:
                        continue
                    }
                case .serverCertificateVerify:
                    switch try self.handleReadServerFinished(incomingBytes: &incomingBytes) {
                    case .waitingForMoreData:
                        return nil
                    case .complete(let partialResult):
                        logger.notice("client completed TLS handshake")
                        return partialResult
                    }
                case .readyForData:
                    switch try self.handleReadNewSessionTicket(incomingBytes: &incomingBytes) {
                    case .waitingForMoreData:
                        return nil
                    case .complete(let partialResult):
                        return partialResult
                    }
                }
            } catch {
                #if SWIFTTLS_EXCLAVEKIT || SWIFTTLS_EXCLAVECORE
                logger.error("processing message failed due to error \(String(describing: error))")
                #else
                logger.error("processing message failed due to error \(error)")
                #endif
                throw error
            }
        }
    }

    /// Obtain the value of the QUIC transport parameters set by the peer, if any.
    ///
    /// Returns `nil` if the peer didn't set any, or if the handshake has not progressed to the point
    /// of having a value yet.
    var peerQUICTransportParameters: ByteBuffer? {
        switch self.state {
        case .idle, .clientHello, .serverHello:
            return nil
        case .serverEncryptedExtensions(let extensions):
            return extensions.serverQUICTransportParameters
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.serverQUICTransportParameters
        case .serverCertificate(let certificate):
            return certificate.serverQUICTransportParameters
        case .awaitingVerification(let waiting):
            return waiting.serverQUICTransportParameters
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.serverQUICTransportParameters
        case .readyForData(let ready):
            return ready.serverQUICTransportParameters
        }
    }

    func generateTLSExporterKey(label: String) -> SymmetricKey? {
        switch self.state {
        case .readyForData(let ready):
            return ready.generateTLSExporterKey(label: label)
        default:
            return nil
        }
    }

    func generateHashForAuthenticator(transcript: ByteBuffer) -> ByteBuffer? {
        switch self.state {
        case .readyForData(let ready):
            return ready.generateHashForAuthenticator(transcript: transcript)
        default:
            return nil
        }
    }

    func generateHMACForAuthenticator(transcript: ByteBuffer, key: SymmetricKey) -> ByteBuffer? {
        switch self.state {
        case .readyForData(let ready):
            return ready.generateHMACForAuthenticator(transcript: transcript, key: key)
        default:
            return nil
        }
    }

    /// Obtain the value of the ALPN sent by the peer, if any.
    ///
    /// Returns `nil` if the peer didn't send any, or if the handshake has not progressed to the point
    /// of having a value yet.
    var peerALPN: ApplicationLayerProtocol? {
        switch self.state {
        case .idle, .clientHello, .serverHello:
            return nil
        case .serverEncryptedExtensions(let extensions):
            return extensions.serverALPN
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.serverALPN
        case .serverCertificate(let certificate):
            return certificate.serverALPN
        case .awaitingVerification(let waiting):
            return waiting.serverALPN
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.serverALPN
        case .readyForData(let ready):
            return ready.serverALPN
        }
    }

    /// Obtain the negotiated ciphersuite, if any.
    ///
    /// Note that this value may change as the handshake progresses if session resumption was
    /// attempted and fails.
    var negotiatedCiphersuite: UInt16? {
        switch self.state {
        case .idle:
            return nil
        case .clientHello(let clientHello):
            if let session = clientHello.sessionToResume {
                return session.cipherSuite.rawValue
            } else if clientHello.epsks.count > 0  && !clientHello.configuration.useRawEPSKs {
                // If using importedPSKs double check that it corresponds to the KDF of the first PSK offered
                // use first ciphersuite in offered list
                let firstCiphersuite = clientHello.allowedCipherSuites[0]
                if clientHello.epsks[0].isImported  {
                    do {
                        let kdfForFirstCipherSuite = try TLSKDFIdentifier.cipherSuiteToKDFIdentifier(cipherSuite: firstCiphersuite)
                        if kdfForFirstCipherSuite.rawValue == clientHello.epsks[0].targetKDF {
                            return firstCiphersuite.rawValue
                        }
                    } catch {
                        logger.debug("first ciphersuite offered does not match KDF of first offered PSK")
                        return nil
                    }
                }
            }
            return nil
        case .serverHello(let serverHello):
            return serverHello.negotiatedCipherSuite?.rawValue
        case .serverEncryptedExtensions(let ee):
            return ee.sessionData?.negotiatedCipherSuite.rawValue
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.negotiatedCipherSuite.rawValue
        case .serverCertificate(let serverCertificate):
            return serverCertificate.negotiatedCipherSuite.rawValue
        case .awaitingVerification(let waiting):
            return waiting.negotiatedCipherSuite.rawValue
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.negotiatedCipherSuite.rawValue
        case .readyForData(let ready):
            return ready.negotiatedCipherSuite?.rawValue
        }
    }

    /// Obtain whether an EPSK was negotiated.
    ///
    /// Returns `false` if the handshake has not progressed to the point of having a value yet.
    var negotiatedEPSK: Bool {
        switch self.state {
        case .idle:
            return false
        case .clientHello:
            return false // need to get to ServerHello to have this value
        case .serverHello(let serverHello):
            return serverHello.epskNegotiated
        case .serverEncryptedExtensions(let ee):
            return ee.epskNegotiated
        case .serverCertificateRequest, .serverCertificate, .serverCertificateVerify, .awaitingVerification:
            return false // can never be in this state if epsk negotiated
        case .readyForData(let ready):
            return ready.epskNegotiated
        }
    }

    /// Obtain whether we offered an EPSK.
    ///
    /// Returns `false` if the handshake has not progressed to the point of having a value yet.
    var epskOffered: Bool {
        switch self.state {
        case .idle:
            return false
        case .clientHello(let clientHello):
            return !clientHello.epsks.isEmpty
        case .serverHello(let serverHello):
            return serverHello.epskNegotiationAttempted
        case .serverEncryptedExtensions(let extensions):
            return extensions.epskNegotiationAttempted
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.epskNegotiationAttempted
        case .serverCertificate(let certificate):
            return certificate.epskNegotiationAttempted
        case .awaitingVerification(let waiting):
            return waiting.epskNegotiationAttempted
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.epskNegotiationAttempted
        case .readyForData(let ready):
            return ready.epskNegotiationAttempted
        }
    }

    /// Obtain the negotiated group, if any.
    ///
    /// Note that this value may change as the handshake progresses if session resumption was
    /// attempted and fails.
    var negotiatedGroup: String? {
        switch self.state {
        case .idle:
            return nil
        case .clientHello(let clientHello):
            return clientHello.sessionToResume?.group.metadataDescription
        case .serverHello(let serverHello):
            return serverHello.negotiatedGroup?.metadataDescription
        case .serverEncryptedExtensions(let ee):
            return ee.sessionData?.negotiatedGroup?.metadataDescription
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.negotiatedGroup.metadataDescription
        case .serverCertificate(let serverCertificate):
            return serverCertificate.negotiatedGroup.metadataDescription
        case .awaitingVerification(let waiting):
            return waiting.negotiatedGroup.metadataDescription
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.negotiatedGroup.metadataDescription
        case .readyForData(let ready):
            return ready.negotiatedGroup?.metadataDescription
        }
    }

    /// Signals whether the peer has accepted early data.
    ///
    /// Will be `nil` if the handshake has not proceeded to the point of receiving the EncryptedExtensions message,
    /// `false` if the ServerHello did not contain an `early_data` extension, or `true` if it did.
    var earlyDataAccepted: Bool? {
        switch self.state {
        case .idle, .clientHello, .serverHello:
            return nil
        case .serverEncryptedExtensions(let ee):
            return ee.earlyDataAccepted
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.earlyDataAccepted
        case .serverCertificate(let serverCertificate):
            return serverCertificate.earlyDataAccepted
        case .awaitingVerification(let waiting):
            return waiting.earlyDataAccepted
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.earlyDataAccepted
        case .readyForData(let ready):
            return ready.earlyDataAccepted
        }
    }

    /// Determine if the state machine is awaiting an asynchronous local computation.
    public var awaitingAsyncComputation: Bool {
        switch self.state {
        case .idle, .clientHello, .serverHello, .serverEncryptedExtensions, .serverCertificateRequest, .serverCertificate, .serverCertificateVerify, .readyForData:
            return false
        case .awaitingVerification:
            return true
        }
    }

    /// Determine if the handshake is fully complete (sent Finished and validated peer's)
    var handshakeComplete: Bool {
        switch self.state {
        case .readyForData:
            return true
        default:
            return false
        }
    }

    var handshakeStarted: Bool {
        switch self.state {
        case .idle:
            return false
        default:
            return true
        }
    }

    var clientRandom: ByteBuffer? {
        var randomBytes = ByteBuffer()
        randomBytes.writeRandom(self.random)
        return randomBytes
    }
}

// MARK: - Parsing
extension HandshakeStateMachine {
    private mutating func handleReadServerHello(incomingBytes: inout InputBuffer) throws(TLSError) -> ProcessStep<PartialHandshakeResult> {
        logger.debug("client expecting server hello")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForMoreData
        }

        let serverHello: ServerHello

        switch message.message {
        case .clientHello, .encryptedExtensions, .certificateRequest, .certificate, .certificateVerify, .finished, .newSessionTicket:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        case .serverHello(let message):
            serverHello = message
        }
        logger.info("client got server hello")

        // Now we can try to construct the server hello state. This does more validation.
        let (newReadKey, newWriteKey) = try self.state.receivedServerHello(serverHello, bytes: message.messageBytes, clock: self.clock)
        return .complete(PartialHandshakeResult(handshakeBytesToSend: nil, newWriteEncryptionLevel: newWriteKey, newReadEncryptionLevel: newReadKey))
    }

    private mutating func handleReadServerEncryptedExtensions(incomingBytes: inout InputBuffer) throws(TLSError) -> ProcessStep<Void> {
        logger.debug("client expecting ee")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForMoreData
        }

        let encryptedExtension: EncryptedExtensions
        switch message.message {
        case .clientHello, .serverHello, .certificateRequest, .certificate, .certificateVerify, .finished, .newSessionTicket:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        case .encryptedExtensions(let message):
            encryptedExtension = message
        }
        logger.info("client got ee")

        return try .complete(self.state.receivedServerEncryptedExtensions(encryptedExtension, extensionBytes: message.messageBytes))
    }

    private mutating func handleReadServerCertificateOrCertificateRequest(incomingBytes: inout InputBuffer) throws(TLSError) -> ProcessStep<Void> {
        logger.debug("client expecting certificate request message or certificate message")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForMoreData
        }

        switch message.message {
        case .certificateRequest(let msg):
            logger.info("client got certificate request message")
            return try .complete(self.state.receivedServerCertificateRequest(msg, certificateRequestBytes: message.messageBytes))
        case .certificate(let msg):
            logger.info("client got certificate message")
            return try .complete(self.state.receivedServerCertificate(msg, certificateBytes: message.messageBytes))
        default:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        }
    }

    private mutating func handleReadServerCertificate(incomingBytes: inout InputBuffer) throws(TLSError) -> ProcessStep<Void> {
        logger.debug("client expecting certificate message")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForMoreData
        }

        let certificate: CertificateMessage
        switch message.message {
        case .certificate(let message):
            certificate = message
        default:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        }

        logger.info("client got certificate message")

        return try .complete(self.state.receivedServerCertificate(certificate, certificateBytes: message.messageBytes))
    }

    private mutating func handleReadServerCertificateVerify(incomingBytes: inout InputBuffer) throws(TLSError) -> ProcessStep<Void> {
        logger.debug("client expecting certificate verify")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForMoreData
        }

        let certificateVerify: CertificateVerify
        switch message.message {
        case .clientHello, .encryptedExtensions, .certificateRequest, .certificate, .serverHello, .finished, .newSessionTicket:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        case .certificateVerify(let message):
            certificateVerify = message
        }

        logger.info("client got certificate verify")

        switch try self.state.receivedServerCertificateVerify(certificateVerify: certificateVerify, certificateVerifyBytes: message.messageBytes, deliverResultCallback: self.deliverResultCallback) {
        case .finished:
            return .complete(())
        case .delayed:
            return .waitingForMoreData
        }
    }

    private mutating func handleAsyncVerificationResult() throws(TLSError) -> ProcessStep<Void> {
        // Make sure we are in the expected state.
        guard case .awaitingVerification(let state) = self.state else {
            logger.error("invalid state for handleAsyncVerificationResult")
            throw TLSError.handshakeError
        }

        // Check if the result is available.
        guard let pending = self.pendingAsyncResult else {
            logger.debug("client handshake continued without setting pending async result")
            return .waitingForMoreData
        }
        self.pendingAsyncResult = nil
        guard case .verification(let verificationResult) = pending.asyncResult else {
            throw TLSError.internalError(reason: "Unexpected async result type in awaitingVerification")
        }

        logger.info("client got async verification result")

        switch verificationResult {
        case .valid:
            self.state = .serverCertificateVerify(
                try HandshakeState.ServerCertificateVerifyState.verifiedPeer(originalState: state, certificateVerifyBytes: state.certificateVerifyBytes)
            )
            return .complete(())
        case .invalid(let reason):
            logger.error("verification failed: \(reason)")
            throw TLSError.certificateError
        case .waiting:
            preconditionFailure("pending result should not be .waiting")
        }
    }

    private mutating func handleReadServerFinished(incomingBytes: inout InputBuffer) throws(TLSError) -> ProcessStep<PartialHandshakeResult> {
        logger.debug("client expecting finished")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForMoreData
        }

        let serverFinished: FinishedMessage
        switch message.message {
        case .clientHello, .encryptedExtensions, .certificateRequest, .certificate, .serverHello, .certificateVerify, .newSessionTicket:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        case .finished(let finished):
            serverFinished = finished
        }
        logger.info("client got server finished")

        let result = try self.state.receivedServerFinished(serverFinished: serverFinished, serverFinishedBytes: message.messageBytes, serializer: &self.serializer)
        return .complete(result)
    }

    private mutating func handleReadNewSessionTicket(incomingBytes: inout InputBuffer) throws(TLSError) -> ProcessStep<PartialHandshakeResult> {
        logger.debug("client expecting newSessionTicket")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForMoreData
        }
        logger.info("client got message expecting new session ticket")

        let newSessionTicket: NewSessionTicket
        switch message.message {
        case .clientHello, .encryptedExtensions, .certificateRequest, .certificate, .serverHello, .certificateVerify, .finished:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        case .newSessionTicket(let ticket):
            newSessionTicket = ticket
        }
        #if hasFeature(Embedded) || TEST_EMBED || SWIFTTLS_DRIVERKIT
        return .complete(PartialHandshakeResult())
        #else
        return .complete(try self.state.receivedNewSessionTicket(newSessionTicket: newSessionTicket, currentTime: self.clock.now()))
        #endif
    }

    private func logUnexpectedMessage(message: HandshakeMessage) {
        let stateLogString = self.state.logDescription
        let messageLogString = message.logDescription

        logger.error("unexpected message \(messageLogString) in state \(stateLogString)")
    }
}

extension HandshakeStateMachine {
    /// This is `Optional<T>` with clearer names.
    fileprivate enum ProcessStep<ResultType> {
        case waitingForMoreData
        case complete(ResultType)
    }
}


extension Collection where Element: Equatable {
    /// Returns `peerChoice` if that was in `self`, otherwise returns `nil`.
    func confirmNegotiated(_ peerChoice: Element) -> Element? {
        self.contains(peerChoice) ? peerChoice: nil
    }
}

enum TLSHandshakeStateMachine {
    case client(HandshakeStateMachine)
#if !SWIFTTLS_CLIENT_ONLY
    case server(ServerHandshakeStateMachine)
#endif
}

extension TLSHandshakeStateMachine {
    var isServer : Bool {
        switch self {
        case .client:
            return false
#if !SWIFTTLS_CLIENT_ONLY
        case .server:
            return true
#endif
        }
    }
}
