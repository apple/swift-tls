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

#if !SWIFTTLS_CLIENT_ONLY

#if canImport(Darwin) || SWIFTTLS_EXCLAVEKIT
import os.log

@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "ServerHandshakeStateMachine")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.ServerHandshakeStateMachine")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.ServerHandshakeStateMachine")
#endif

@available(SwiftTLS 0.1.0, *)
struct SwiftOfferedEPSK {
    let external_identity: Data
    let context: Data?
    init(external_identity: ByteBuffer, context: ByteBuffer?) {
        self.external_identity = external_identity.readableBytesView
        self.context = context?.readableBytesView
    }
}

@available(SwiftTLS 0.1.0, *)
typealias externalPSKCompletionCallback = (Int, EPSK?) -> Void
@available(SwiftTLS 0.1.0, *)
typealias externalPSKSelectionCallback = ([SwiftOfferedEPSK], @escaping externalPSKCompletionCallback) -> Void

@available(SwiftTLS 0.1.0, *)
struct ServerHandshakeStateMachine {
    private var parser = HandshakeMessageParser()
    private var serializer = TLSMessageSerializer()
    var state: ServerHandshakeState
    private let clock: SwiftTLSDefaultClock
    private var random: Random
    private var configuration: Configuration
    var deliverResultCallback: (@Sendable (PendingAsyncResult) -> Void)?
    var pendingAsyncResult: PendingAsyncResult?

    init(configuration: Configuration) throws(TLSError) {
        if !configuration.validConfiguration {
            logger.error("Unable to start server handshake. invalid configuration")
            throw TLSError.invalidConfigurationOptions
        }
        self.clock = SwiftTLSDefaultClock()
        self.random = Random()
        self.configuration = configuration
        self.state = .idle(ServerHandshakeState.IdleState(configuration: configuration))
        logger.info("server state machine initialized")
    }

    mutating func applyAsyncResult(_ result: PendingAsyncResult) {
        self.pendingAsyncResult = result
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

    /// Call with an input buffer that the parser has been reading from to save any
    /// bytes remaining from the input buffer. The saved bytes typically represent a
    /// partial message.
    mutating func saveUnprocessedIncomingBytes(_ data: inout InputBuffer) {
        let byteCount = data.byteCount
        logger.debug("saving unprocessed network data (\(byteCount) bytes)")
        self.parser.appendBytes(data.readAll())
    }

    // should be called for every state transition
    fileprivate mutating func stepHandshake(incomingBytes: inout InputBuffer) throws(TLSError) -> StepResult {
        logger.debug("server attempting step handshake")
        switch self.state {
        case .idle:
            // read client hello
            return try self.handleReadClientHello(incomingBytes: &incomingBytes)
        case .clientHello:
            // send server hello
            return try self.sendServerHello()
        case .serverHello:
            // send EE
            return try self.sendServerEncryptedExtensions()
        case .serverEncryptedExtensions(let innerState) where (innerState.epskNegotiated):
            // send server finished early if psks used.
            return try self.sendServerFinished()
        case .serverEncryptedExtensions(let innerState) where (innerState.configuration.clientAuthRequired):
            // send certificate request if client auth required
            return try self.sendServerCertificateRequest()
        case .serverEncryptedExtensions, .serverCertificateRequest:
            // send server certificate (can go into awaitingCertificate state)
            return try self.sendServerCertificate()
        case .awaitingCertificate:
            return try self.handleAsyncCertificateResult()
        case .serverCertificate:
            // send server certificate verify
            return try self.sendServerCertificateVerify()
        case .awaitingSignature:
            return try self.handleAsyncSignatureResult()
        case .serverCertificateVerify:
            // send server finished
            return try self.sendServerFinished()
        case .serverFinished(let innerState) where (innerState.configuration.clientAuthRequired):
            // read client certificate message
            return try self.handleReadClientCertificate(incomingBytes: &incomingBytes)
        case .serverFinished:
            // read clientFinished
            return try self.handleReadClientFinished(incomingBytes: &incomingBytes)
        case .clientCertificate:
            // read client certificate verify message
            return try self.handleReadClientCertificateVerify(incomingBytes: &incomingBytes)
        case .clientCertificateVerify:
            // read clientFinished
            return try self.handleReadClientFinished(incomingBytes: &incomingBytes)
        case .readyForData:
            // handshake complete
            return .waitingForBytes
        }
    }

    // should only be called when in a state waiting for data
    // returns nil when waiting for more data
    // returns partialResult when key schedule has advanced
    // or a message is ready to be written
    mutating func processHandshake() throws(TLSError) -> PartialHandshakeResult? {
        var incomingBytes = InputBuffer(storage: RawSpan())
        return try processHandshake(incomingBytes: &incomingBytes)
    }

    mutating func processHandshake(incomingBytes: inout InputBuffer) throws(TLSError) -> PartialHandshakeResult? {
        while true {
            logger.debug("server attempting process step")
            do {
                switch try stepHandshake(incomingBytes: &incomingBytes) {
                case .waitingForBytes:
                    return nil
                case .continueOkay:
                    continue
                case .partialResult(let result):
                    return result
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
        case .idle:
            return nil
        case .clientHello(let clientHello):
            return clientHello.clientQUICTransportParameters
        case .serverHello(let serverHello):
            return serverHello.clientQUICTransportParameters
        case .serverEncryptedExtensions(let extensions):
            return extensions.clientQUICTransportParameters
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.clientQUICTransportParameters
        case .awaitingCertificate(let awaitingCertificate):
            return awaitingCertificate.clientQUICTransportParameters
        case .serverCertificate(let certificate):
            return certificate.clientQUICTransportParameters
        case .awaitingSignature(let awaitingSignature):
            return awaitingSignature.clientQUICTransportParameters
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.clientQUICTransportParameters
        case .serverFinished(let finished):
            return finished.clientQUICTransportParameters
        case .clientCertificate(let clientCert):
            return clientCert.clientQUICTransportParameters
        case .clientCertificateVerify(let clientCertVerify):
            return clientCertVerify.clientQUICTransportParameters
        case .readyForData(let ready):
            return ready.clientQUICTransportParameters
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
            return clientHello.negotiatedCipherSuite.rawValue
        case .serverHello(let serverHello):
            return serverHello.negotiatedCiphersuite.rawValue
        case .serverEncryptedExtensions(let extensions):
            return extensions.negotiatedCiphersuite.rawValue
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.negotiatedCiphersuite.rawValue
        case .awaitingCertificate(let awaitingCertificate):
            return awaitingCertificate.negotiatedCiphersuite.rawValue
        case .serverCertificate(let certificate):
            return certificate.negotiatedCiphersuite.rawValue
        case .awaitingSignature(let awaitingSignature):
            return awaitingSignature.negotiatedCiphersuite.rawValue
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.negotiatedCiphersuite.rawValue
        case .serverFinished(let finished):
            return finished.negotiatedCiphersuite.rawValue
        case .clientCertificate(let clientCert):
            return clientCert.negotiatedCiphersuite.rawValue
        case .clientCertificateVerify(let clientCertVerify):
            return clientCertVerify.negotiatedCiphersuite.rawValue
        case .readyForData(let ready):
            return ready.negotiatedCiphersuite.rawValue
        }
    }

    /// Obtain whether EPSK was negotiated
    ///
    /// Returns `false` if the handshake has not progressed to the point of having a value yet.
    var negotiatedEPSK: Bool {
        switch self.state {
        case .idle:
            return false
        case .clientHello(let clientHello):
            return clientHello.selectedPSK != nil
        case .serverHello(let serverHello):
            return serverHello.epskNegotiated
        case .serverEncryptedExtensions(let extensions):
            return extensions.epskNegotiated
        case .serverCertificateRequest:
            return false
        case .awaitingCertificate:
            return false
        case .serverCertificate:
            return false
        case .awaitingSignature:
            return false
        case .serverCertificateVerify:
            return false
        case .serverFinished(let finished):
            return finished.epskNegotiated
        case .clientCertificate(let clientCert):
            return clientCert.epskNegotiated
        case .clientCertificateVerify(let clientCertVerify):
            return clientCertVerify.epskNegotiated
        case .readyForData(let ready):
            return ready.epskNegotiated
        }
    }

    /// Obtain whether EPSK was offered by peer
    ///
    /// Returns `false` if the handshake has not progressed to the point of having a value yet.
    var epskOffered: Bool {
        switch self.state {
        case .idle:
            return false
        case .clientHello(let clientHello):
            return clientHello.pskNegotiationAttempted
        case .serverHello(let serverHello):
            return serverHello.pskNegotiationAttempted
        case .serverEncryptedExtensions(let extensions):
            return extensions.pskNegotiationAttempted
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.pskNegotiationAttempted
        case .awaitingCertificate(let awaitingCertificate):
            return awaitingCertificate.pskNegotiationAttempted
        case .serverCertificate(let certificate):
            return certificate.pskNegotiationAttempted
        case .awaitingSignature(let awaitingSignature):
            return awaitingSignature.pskNegotiationAttempted
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.pskNegotiationAttempted
        case .serverFinished(let finished):
            return finished.pskNegotiationAttempted
        case .clientCertificate(let clientCert):
            return clientCert.pskNegotiationAttempted
        case .clientCertificateVerify(let clientCertVerify):
            return clientCertVerify.pskNegotiationAttempted
        case .readyForData(let ready):
            return ready.pskNegotiationAttempted
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
            return clientHello.negotiatedGroup?.metadataDescription
        case .serverHello(let serverHello):
            return serverHello.negotiatedGroup?.metadataDescription
        case .serverEncryptedExtensions(let extensions):
            return extensions.negotiatedGroup?.metadataDescription
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.negotiatedGroup?.metadataDescription
        case .awaitingCertificate(let awaitingCertificate):
            return awaitingCertificate.negotiatedGroup?.metadataDescription
        case .serverCertificate(let certificate):
            return certificate.negotiatedGroup?.metadataDescription
        case .awaitingSignature(let awaitingSignature):
            return awaitingSignature.negotiatedGroup?.metadataDescription
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.negotiatedGroup?.metadataDescription
        case .serverFinished(let finished):
            return finished.negotiatedGroup?.metadataDescription
        case .clientCertificate(let clientCert):
            return clientCert.negotiatedGroup?.metadataDescription
        case .clientCertificateVerify(let clientCertVerify):
            return clientCertVerify.negotiatedGroup?.metadataDescription
        case .readyForData(let ready):
            return ready.negotiatedGroup?.metadataDescription
        }
    }

    /// Signals whether the server has accepted early data.
    ///
    /// `false` if the server hello did not contain an `early_data` extension, or `true` if it did.
    var earlyDataAccepted: Bool? {

        switch self.state {
        case .idle:
            return nil
        case .clientHello(let clientHello):
            return clientHello.earlyDataPermitted
        case .serverHello(let serverHello):
            return serverHello.earlyDataPermitted
        case .serverEncryptedExtensions(let extensions):
            return extensions.earlyDataPermitted
        case .serverCertificateRequest(let certificateRequest):
            return certificateRequest.earlyDataPermitted
        case .awaitingCertificate(let awaitingCertificate):
            return awaitingCertificate.earlyDataPermitted
        case .serverCertificate(let certificate):
            return certificate.earlyDataPermitted
        case .awaitingSignature(let awaitingSignature):
            return awaitingSignature.earlyDataPermitted
        case .serverCertificateVerify(let certificateVerify):
            return certificateVerify.earlyDataPermitted
        case .serverFinished(let finished):
            return finished.earlyDataPermitted
        case .clientCertificate(let clientCert):
            return clientCert.earlyDataPermitted
        case .clientCertificateVerify(let clientCertVerify):
            return clientCertVerify.earlyDataPermitted
        case .readyForData(let ready):
            return ready.earlyDataPermitted
        }
    }

    var stateDescription: String {
        return self.state.description
    }

    /// Determine if the state machine is awaiting an asynchronous local computation.
    public var awaitingAsyncComputation: Bool {
        switch self.state {
        case .idle:
            return false
        case .clientHello:
            return false
        case .serverHello:
            return false
        case .serverEncryptedExtensions:
            return false
        case .serverCertificateRequest:
            return false
        case .awaitingCertificate:
            return true
        case .serverCertificate:
            return false
        case .awaitingSignature:
            return true
        case .serverCertificateVerify:
            return false
        case .serverFinished:
            return false
        case .clientCertificate:
            return false
        case .clientCertificateVerify:
            return false
        case .readyForData:
            return false
        }
    }


    /// Determine if the handshake is fully complete (sent Finished and validated peer's)
    var handshakeComplete: Bool {
        switch self.state {
        case .idle:
            return false
        case .clientHello:
            return false
        case .serverHello:
            return false
        case .serverEncryptedExtensions:
            return false
        case .serverCertificateRequest:
            return false
        case .awaitingCertificate:
            return false
        case .serverCertificate:
            return false
        case .awaitingSignature:
            return false
        case .serverCertificateVerify:
            return false
        case .serverFinished:
            return false
        case .clientCertificate:
            return false
        case .clientCertificateVerify:
            return false
        case .readyForData:
            return true
        }
    }

    var handshakeStarted: Bool {
        switch self.state {
        case .idle:
            // Counting this as handshake having started
            // even if the Client Hello was too long or if
            // we failed to negotiated initial parameters.
            // This way the server will send an alert even
            // though it does not move to the .clientHello state.
            return self.parser.readClientHello
        default:
            return true
        }
    }

}

@available(SwiftTLS 0.1.0, *)
extension ServerHandshakeStateMachine {
    private mutating func handleReadClientHello(incomingBytes: inout InputBuffer) throws(TLSError) -> StepResult {
        logger.debug("server expecting client hello")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForBytes
        }

        let clientHello: ClientHello
        switch message.message {
        case .clientHello(let message):
            clientHello = message
        default:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        }
        logger.info("server got client hello")

        // transition to clientHello state
        if let partialResult = try self.state.receivedClientHello(clientHello, bytes: message.messageBytes) {
            return .partialResult(partialResult)
        } else {
            return .continueOkay
        }
    }

    private mutating func sendServerHello() throws(TLSError) -> StepResult {
        logger.info("sending server hello")
        guard case .clientHello(let clientHelloState) = self.state else {
            // TODO: check for hello retry stuff
            let logDescription = self.stateDescription
            logger.error("invalid state for handleReadClientHello: \(logDescription)")
            throw TLSError.handshakeError
        }

        var helloExtensions: [Extension] = [
            .supportedVersions(.selection(.tlsv13))
        ]

        if let ephemeralKey = clientHelloState.ephemeralKey, let publicKeyShare = clientHelloState.publicKeyShare {
            helloExtensions.append(.keyShare(.serverHello(.init(group: ephemeralKey.namedGroup, keyExchange: ByteBuffer(data: publicKeyShare)))))
        }

        if clientHelloState.selectedPSK != nil {
            helloExtensions.append(.preSharedKey(.serverHello(clientHelloState.selectedPSKIndex)))
        }

        // using negotiated parameters construct and send ServerHello
        var serverHello = ServerHello(
            legacyVersion: .tlsv12,
            random: self.random,
            legacySessionIDEcho: clientHelloState.legacySessionIDEcho,
            cipherSuite: clientHelloState.negotiatedCipherSuite,
            legacyCompressionMethod: 0,
            extensions: helloExtensions
        )

        // send Server Hello
        let result = try self.state.sendingServerHello(&serverHello)
        return .partialResult(result)
    }

    private mutating func sendServerEncryptedExtensions() throws(TLSError) -> StepResult {
        // send EE msg
        logger.info("sending server EE")
        guard case .serverHello(let serverHelloState) = self.state else {
            let logDescription = self.stateDescription
            logger.error("invalid state for sendServerEncryptedExtensions: \(logDescription)")
            throw TLSError.handshakeError
        }

        var serverEncryptedExtensionsArray: [Extension] = []

        serverEncryptedExtensionsArray.append(.supportedGroups(.init(groups: [.x25519MLKEM768, .secp384, .x25519])))
        if let certType = serverHelloState.negotiatedServerCertificateType {
            serverEncryptedExtensionsArray.append(.serverCertificateType(.selection(certType)))
        }
        if let certType = serverHelloState.negotiatedClientCertificateType {
            serverEncryptedExtensionsArray.append(.clientCertificateType(.selection(certType)))
        }

        if let selectedALPN = serverHelloState.selectedALPN {
            serverEncryptedExtensionsArray.append(.alpn(.selection(selectedALPN)))
        }

        if let quicTransportParameters = self.configuration.quicTransportParameters {
            serverEncryptedExtensionsArray.append(.quicTransportParameters(Extension.QUICTransportParameters(opaqueOffer: quicTransportParameters)))
        }

        if serverHelloState.earlyDataPermitted {
            serverEncryptedExtensionsArray.append(.earlyData(.init()))
        }

        let serverEncryptedExtensions = EncryptedExtensions(extensions: serverEncryptedExtensionsArray)
        let result = try self.state.sendingServerEncryptedExtensions(serverEncryptedExtensions)
        return .partialResult(result)
    }

    private mutating func sendServerCertificateRequest() throws(TLSError) -> StepResult {
        // send Server Certificate Request msg
        logger.info("sending server certificate request")
        let result = try self.state.sendingServerCertificateRequest()
        return .partialResult(result)
    }

    private mutating func getCertificateChain(asyncAuthenticator: AsyncAuthenticator, certInfo: CertificateInfo) throws(TLSError) -> StepResult {
        var certInfo = certInfo
        if let deliverCallback = self.deliverResultCallback {
            certInfo.deliverResult = { result in
                deliverCallback(.certificate(result))
            }
        }
        switch asyncAuthenticator.getCertificateChain(certInfo) {
        case .available(let certificateList):
            switch certificateList.type {
            case .rawPublicKey:
                guard certificateList.entries.count == 1, let rawPublicKey = certificateList.entries.first else {
                    logger.error("unexpected number of certificates")
                    throw TLSError.serverMissingCertificate
                }
                // send Server Certificate msg
                logger.info("sending server certificate")
                let result = try self.state.sendingServerCertificate(withRawPublicKey: rawPublicKey, authDetails: .callbacks(asyncAuthenticator))
                return .partialResult(result)
            case .x509:
                // send Server Certificate msg
                logger.info("sending server certificate")
                let result = try self.state.sendingServerCertificate(withCertificates: certificateList.entries, authDetails: .callbacks(asyncAuthenticator))
                return .partialResult(result)
            default:
                logger.error("unexpected certificate type")
                throw TLSError.serverMissingCertificate
            }
        case .unavailable(let reason):
            logger.error("certificate provider failed to provide a certificate chain: '\(reason)'")
            throw TLSError.serverMissingCertificate
        case .waiting:
            guard certInfo.deliverResult != nil else {
                logger.error("certificate callback returned .waiting but no deliverResultCallback is set")
                throw TLSError.handshakeError
            }
            return .waitingForBytes
        }
    }

    // Implementation for cases in `sendServerCertificate()` below.
    private mutating func sendServerCertificate(with authMethod: AuthenticationMethod, clientOffer: PeerOffer, negotiatedSignatureAlgorithm: SignatureScheme?) throws(TLSError) -> StepResult? {
        switch authMethod {
        case .certificateAuthCallbacks(let authProvider):
            let certInfo = CertificateInfo(peerOffer: clientOffer)
            switch try getCertificateChain(asyncAuthenticator: authProvider, certInfo: certInfo) {
            case .waitingForBytes:
                // Switch into waiting state.
                try self.state.awaitCertificate(asyncAuthenticator: authProvider, certInfo: certInfo)
                return .waitingForBytes
            case .partialResult(let result):
                return .partialResult(result)
            case .continueOkay:
                return .continueOkay
            }
        case .rawPublicKeyAuth(let serverKey):
            // send Server Certificate msg
            guard let signatureAlgorithms = negotiatedSignatureAlgorithm else {
                logger.error("server failed to agree on a signature algorithm.")
                throw TLSError.negotiationFailed
            }
            logger.info("sending server certificate")
            let result = try self.state.sendingServerCertificate(withRawPublicKey: serverKey.publicKey.derRepresentation, authDetails: .rawPublicKey(serverKey, signatureAlgorithms))
            return .partialResult(result)
        default:
            // The error handling case differs depending on the current state.
            return nil
        }
    }

    private mutating func sendServerCertificate() throws(TLSError) -> StepResult {
        switch self.state {
        case .serverEncryptedExtensions(let state):
            guard let result = try sendServerCertificate(
                with: state.configuration.authenticationMethod,
                clientOffer: state.clientOffer,
                negotiatedSignatureAlgorithm: state.negotiatedSignatureAlgorithm
            ) else {
                throw TLSError.serverMissingSigningKey
            }
            return result

        case .serverCertificateRequest(let state):
            guard let result = try sendServerCertificate(
                with: state.configuration.authenticationMethod,
                clientOffer: state.clientOffer,
                negotiatedSignatureAlgorithm: state.negotiatedSignatureAlgorithm
            ) else {
                preconditionFailure("This state should not be reachable when not using either callbacks or rawPublicKeyAuth")
            }
            return result

        default:
            let logDescription = self.stateDescription
            logger.error("invalid state for sendServerCertificate: \(logDescription)")
            throw TLSError.handshakeError
        }
    }


    private mutating func handleAsyncCertificateResult() throws(TLSError) -> StepResult {
        // Make sure this is called from the correct state.
        guard case .awaitingCertificate(let state) = self.state else {
            let logDescription = self.stateDescription
            logger.error("invalid state for handleAsyncCertificateResult: \(logDescription)")
            throw TLSError.handshakeError
        }

        // Collect async result to continue handshake.
        guard let pending = self.pendingAsyncResult else {
            logger.debug("server called continue handshake without setting async result")
            return .waitingForBytes
        }
        self.pendingAsyncResult = nil
        guard case .certificate(let certResult) = pending.asyncResult else {
            throw TLSError.internalError(reason: "Unexpected async result type in awaitingCertificate")
        }

        // Continue handshake
        switch certResult {
        case .available(let certificateList):
            switch certificateList.type {
            case .rawPublicKey:
                guard certificateList.entries.count == 1, let rawPublicKey = certificateList.entries.first else {
                    logger.error("unexpected number of certificates")
                    throw TLSError.serverMissingCertificate
                }
                logger.info("sending server certificate (from async result)")
                let partialResult = try self.state.sendingServerCertificate(withRawPublicKey: rawPublicKey, authDetails: .callbacks(state.asyncAuthenticator))
                return .partialResult(partialResult)
            case .x509:
                logger.info("sending server certificate (from async result)")
                let partialResult = try self.state.sendingServerCertificate(withCertificates: certificateList.entries, authDetails: .callbacks(state.asyncAuthenticator))
                return .partialResult(partialResult)
            default:
                logger.error("unexpected certificate type")
                throw TLSError.serverMissingCertificate
            }
        case .unavailable(let reason):
            logger.error("certificate provider failed to provide a certificate chain: '\(reason)'")
            throw TLSError.serverMissingCertificate
        case .waiting:
            preconditionFailure("pending result should not be .waiting")
        }
    }

    private mutating func sendServerCertificateVerify() throws(TLSError) -> StepResult {
        guard case .serverCertificate(let state) = self.state else {
            let logDescription = self.stateDescription
            logger.error("invalid state for sendServerCertificateVerify: \(logDescription)")
            throw TLSError.handshakeError
        }
        switch state.authenticationDetails {
        case .callbacks(let authProvider):
            let keyScheduler = state.keyScheduler
            let data = try keyScheduler.dataToSignInServerCertificateVerify().readableBytesView
            var info = SignatureInfo(transcriptHash: data, peerOffer: state.clientOffer)

            if let deliverCallback = self.deliverResultCallback {
                info.deliverResult = { result in
                    deliverCallback(.signature(result))
                }
            }

            switch authProvider.signTranscriptHash(info) {
            case .available(let signature, let signatureAlgorithm):
                guard info.peerOffer.signatureAlgorithms.contains(signatureAlgorithm) else {
                    logger.error("callback selected signature algorithm not offered by peer")
                    throw TLSError.handshakeFailure
                }
                // send CertificateVerify message
                logger.info("sending server certificate verify")
                let result = try self.state.sendingServerCertificateVerify(keyScheduler: keyScheduler, signatureAlgorithm: SignatureScheme(rawValue: signatureAlgorithm), signatureData: signature)
                return .partialResult(result)
            case .unavailable(let reason):
                logger.error("authenticator failed to provide signature: '\(reason)'")
                throw TLSError.serverMissingSignature
            case .waiting:
                guard info.deliverResult != nil else {
                    logger.error("signature callback returned .waiting but no deliverResultCallback is set")
                    throw TLSError.handshakeError
                }
                try self.state.awaitSignature(signatureInfo: info, keyScheduler: keyScheduler, authProvider: authProvider)
                return .waitingForBytes
            }
        case .rawPublicKey(let serverKey, let negotiatedSignatureAlgorithm):
            let keyScheduler = state.keyScheduler
            let data = try keyScheduler.dataToSignInServerCertificateVerify().readableBytesView

            let signature = try serverKey.sign(bytes: data, signatureScheme: SignatureScheme.ecdsa_secp256r1_sha256.rawValue)

            // send CertificateVerify message
            logger.info("sending server certificate verify")
            let result = try self.state.sendingServerCertificateVerify(keyScheduler: keyScheduler, signatureAlgorithm: negotiatedSignatureAlgorithm, signatureData: signature)
            return .partialResult(result)
        }
    }

    private mutating func handleAsyncSignatureResult() throws(TLSError) -> StepResult {
        // Make sure this is called from the correct state.
        guard case .awaitingSignature(let state) = self.state else {
            let logDescription = self.stateDescription
            logger.error("invalid state for handleAsyncSignatureResult: \(logDescription)")
            throw TLSError.handshakeError
        }

        // Collect async result to continue handshake.
        guard let pending = self.pendingAsyncResult else {
            logger.debug("server called continue handshake without setting async result")
            return .waitingForBytes
        }
        self.pendingAsyncResult = nil
        guard case .signature(let sigResult) = pending.asyncResult else {
            throw TLSError.internalError(reason: "Unexpected async result type in awaitingSignature")
        }

        // Continue handshake.
        switch sigResult {
        case .available(let signature, let signatureAlgorithm):
            guard state.signatureInfo.peerOffer.signatureAlgorithms.contains(signatureAlgorithm) else {
                logger.error("callback selected signature algorithm not offered by peer")
                throw TLSError.handshakeFailure
            }
            logger.info("sending server certificate verify (from async result)")
            let partialResult = try self.state.sendingServerCertificateVerify(keyScheduler: state.keyScheduler, signatureAlgorithm: SignatureScheme(rawValue: signatureAlgorithm), signatureData: signature)
            return .partialResult(partialResult)
        case .unavailable(let reason):
            logger.error("authenticator failed to provide signature: '\(reason)'")
            throw TLSError.serverMissingSignature
        case .waiting:
            preconditionFailure("pending result should not be .waiting")
        }
    }

    private mutating func sendServerFinished() throws(TLSError) -> StepResult {
        // send Finished msg
        logger.info("sending server finished")
        let result = try self.state.sendingServerFinished()
        return .partialResult(result)
    }

    private mutating func handleReadClientCertificate(incomingBytes: inout InputBuffer) throws(TLSError) -> StepResult {
        logger.debug("server expecting client certificate")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForBytes
        }

        let clientCertificate: CertificateMessage
        switch message.message {
        case .certificate(let message):
            clientCertificate = message
        default:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        }
        logger.info("server got client certificate")

        // transition to clientCertificate state
        try self.state.receivedClientCertificate(clientCertificate, bytes: message.messageBytes)
        return .continueOkay
    }

    private mutating func handleReadClientCertificateVerify(incomingBytes: inout InputBuffer) throws(TLSError) -> StepResult {
        logger.debug("server expecting client certificate verify")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForBytes
        }

        let clientCertificateVerify: CertificateVerify
        switch message.message {
        case .certificateVerify(let message):
            clientCertificateVerify = message
        default:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        }
        logger.info("server got client certificate verify")

        // transition to clientCertificateVerify state
        try self.state.receivedClientCertificateVerify(clientCertificateVerify, bytes: message.messageBytes)
        return .continueOkay
    }

    private mutating func handleReadClientFinished(incomingBytes: inout InputBuffer) throws(TLSError) -> StepResult {
        logger.debug("server expecting client finished")
        guard let message = try self.parser.parseHandshakeMessage(incomingBytes: &incomingBytes) else {
            logger.debug("incomplete message, waiting for more data")
            return .waitingForBytes
        }

        let clientFinished: FinishedMessage

        switch message.message {
        case .finished(let message):
            clientFinished = message
        default:
            self.logUnexpectedMessage(message: message.message)
            throw TLSError.handshakeUnexpectedMessage
        }
        logger.info("server got message expecting finished")

        // transition to readyForData state
        let result = try self.state.receivedClientFinished(clientFinished, bytes: message.messageBytes)
        logger.notice("server completed TLS handshake")
        return .partialResult(result)
    }

    private func logUnexpectedMessage(message: HandshakeMessage) {
        let stateLogString = self.state.description
        let messageLogString = message.logDescription
        logger.error("unexpected message \(messageLogString) in state \(stateLogString)")
    }
}

@available(SwiftTLS 0.1.0, *)
extension ServerHandshakeStateMachine {
    fileprivate enum StepResult {
        case partialResult(PartialHandshakeResult)
        case continueOkay
        case waitingForBytes
    }
}

#endif
