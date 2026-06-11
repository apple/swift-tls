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
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "HandshakeState")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeState")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeState")
#endif

@available(SwiftTLS 0.1.0, *)
enum HandshakeState {

    /// Ready, but the handshake has not yet started
    case idle(IdleState)

    /// The client hello has been sent to the server
    case clientHello(ClientHelloState)

    /// The client has received the server hello
    case serverHello(ServerHelloState)

    /// The client has received the server's encrypted extensions
    case serverEncryptedExtensions(EncryptedExtensionsState)

    /// The client has received a certificate request from the server
    case serverCertificateRequest(ServerCertificateRequestState)

    /// The client has received the server's certificate.
    ///
    /// When using callbacks for verification, the verification result might not be directly available.
    /// The state machine transitions to `awaitingVerification` in case it needs to wait,
    /// and to `serverCertificateVerify` if the result is directly available.
    case serverCertificate(ServerCertificateState)

    /// The client received the server's certificate verification, but is awaiting the verification result.
    ///
    /// This is an intermediate state between `serverCertificate` and `serverCertificateVerify`
    /// when verification is performed by a callback that did not return a result directly. Once the result is
    /// available, transition to `serverCertificateVerify`.
    case awaitingVerification(AwaitingVerificationState)

    /// The client has received the server's certificate verification
    case serverCertificateVerify(ServerCertificateVerifyState)

    /// The client has received `ServerFinished`, verified the server, and sent
    /// the client's second flight, which includes:
    /// - `ClientCertificate` (if a certificate request was received; empty if no real cert/rpk was available).
    /// - `ClientCertificateVerify` (if a certificate or rpk was available).
    /// - `ClientFinished`.
    ///
    /// The handshake is now complete in the client's view.
    case readyForData(ReadyState)

    mutating func sendingClientHello(
        _ clientHello: inout ClientHello,
        sessionToResume: SessionTicket?,
        epsks: [GeneralEPSK],
        ephemeralKeyShare: GeneratedEphemeralPrivateKey?,
        currentTime: Date?
    ) throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .idle(let state):
            let (newState, clientHelloBytes) = try ClientHelloState.sendingClientHello(
                originalState: state,
                clientHello: &clientHello,
                sessionToResume: sessionToResume,
                epsks: epsks,
                useRawEPSKs: state.configuration.useRawEPSKs,
                ephemeralKeyShare: ephemeralKeyShare,
                currentTime: currentTime
            )
            let clientEarlySecret = newState.keyScheduler.clientEarlyTrafficSecret!
            self = .clientHello(newState)
            return PartialHandshakeResult(handshakeBytesToSend: clientHelloBytes, newWriteEncryptionLevel: .earlyData(secret: clientEarlySecret))
        default:
            preconditionFailure()
        }
    }

    mutating func receivedServerHello(_ serverHello: ServerHello, bytes: ByteBuffer, clock: some SwiftTLSClock) throws(TLSError) -> (newReadKey: EncryptionLevel, newWriteKey: EncryptionLevel) {
        switch self {
        case .clientHello(let clientHelloState):
            let newState = try ServerHelloState(originalState: clientHelloState, serverHello: serverHello, serverHelloBytes: bytes, clock: clock)
            guard let clientTrafficSecret = newState.keyScheduler.clientHandshakeTrafficSecret,
                  let serverTrafficSecret = newState.keyScheduler.serverHandshakeTrafficSecret else {
                preconditionFailure()
            }
            self = .serverHello(newState)
            return (.handshake(secret: serverTrafficSecret), .handshake(secret: clientTrafficSecret))
        default:
            preconditionFailure()
        }
    }

    mutating func receivedServerEncryptedExtensions(_ encryptedExtensions: EncryptedExtensions, extensionBytes: ByteBuffer) throws(TLSError) {
        switch self {
        case .serverHello(let serverHelloState):
            self = .serverEncryptedExtensions(
                try EncryptedExtensionsState(originalState: serverHelloState, encryptedExtensions: encryptedExtensions, extensionBytes: extensionBytes)
            )
        default:
            preconditionFailure()
        }
    }

    mutating func receivedServerCertificateRequest(_ serverCertificateRequest: CertificateRequest, certificateRequestBytes: ByteBuffer) throws(TLSError) {
        switch self {
        case .serverEncryptedExtensions(let encryptedExtensionsState):
            guard !encryptedExtensionsState.epskNegotiated,
                  !encryptedExtensionsState.sessionResumed
            else {
                // this should be handled in `processHandshake`, but we double check here
                logger.error("invalid state transition. Processing certificate request when EPSK negotiated.")
                throw TLSError.internalError(reason: "invalid transition to process cert request")
            }

            self = .serverCertificateRequest(
                try ServerCertificateRequestState(originalState: encryptedExtensionsState, serverCertificateRequest: serverCertificateRequest, certificateRequestBytes: certificateRequestBytes)
            )
        default:
            preconditionFailure()
        }
    }

    mutating func receivedServerCertificate(_ serverCertificateMessage: CertificateMessage, certificateBytes: ByteBuffer) throws(TLSError) {
        switch self {
        case .serverEncryptedExtensions(let encryptedExtensionState):
            self = .serverCertificate(
                try ServerCertificateState(originalState: encryptedExtensionState, serverCertificate: serverCertificateMessage, certificateBytes: certificateBytes)
            )
        case .serverCertificateRequest(let serverCertificateRequestState):
            self = .serverCertificate(
                try ServerCertificateState(originalState: serverCertificateRequestState, serverCertificate: serverCertificateMessage, certificateBytes: certificateBytes)
            )
        default:
            preconditionFailure()
        }
    }

    mutating func receivedServerCertificateVerify(certificateVerify: CertificateVerify, certificateVerifyBytes: ByteBuffer, deliverResultCallback: (@Sendable (PendingAsyncResult) -> Void)?) throws(TLSError) -> AuthenticationResult {
        switch self {
        case .serverCertificate(let certificateState):

            // Verify that the signature algorithm matches the client's offer.
            if !certificateState.sessionData.signatureAlgorithmOffer.contains(certificateVerify.algorithm) {
                logger.error("server used unexpected signature algorithm: \(certificateVerify.algorithm.rawValue)")
                throw TLSError.illegalParameter
            }

            switch certificateState.configuration.verificationMethod {
            case .certificateCallbacks(let asyncVerifier):
                guard let certificates = try? certificateState.certificates.exportList() else {
                    logger.error("exporting certificates failed")
                    throw TLSError.certificateError
                }
                // Transcription Hash
                let transcriptHash = try certificateState.keyScheduler.dataToSignInServerCertificateVerify().readableBytesView
                // Bundle authentication data.
                var verificationInfo = VerificationInfo(
                    certificates: certificates,
                    signatureAlgorithm: certificateVerify.algorithm.rawValue,
                    signature: certificateVerify.signature.readableBytesView,
                    transcriptHash: transcriptHash
                )
                if let deliverCallback = deliverResultCallback {
                    verificationInfo.deliverResult = { result in
                        deliverCallback(.verification(result))
                    }
                }
                // Pass it to our authentication callback.
                switch asyncVerifier.verifyHandshake(verificationInfo) {
                case .valid:
                    self = .serverCertificateVerify(
                        try ServerCertificateVerifyState.verifiedPeer(originalState: certificateState, certificateVerifyBytes: certificateVerifyBytes)
                    )
                    return .finished
                case .invalid(let reason):
                    logger.error("verification failed: \(reason)")
                    throw TLSError.certificateError
                case .waiting:
                    guard verificationInfo.deliverResult != nil else {
                        logger.error("verification callback returned .waiting but no deliverResultCallback is set")
                        throw TLSError.handshakeError
                    }
                    // We need to ask again later.
                    self = .awaitingVerification(
                        try .init(originalState: certificateState, asyncVerifier: asyncVerifier, verificationInfo: verificationInfo, certificateVerifyBytes: certificateVerifyBytes)
                    )
                    // --> Go into asynchronous verification state.
                    return .delayed
                }
            case .rawPublicKey(let validPublicKeys):
                guard try certificateState.certificates.verifyServerCertificateVerifySignature(
                    message: certificateVerify,
                    validKeys: validPublicKeys,
                    keyScheduler: certificateState.keyScheduler
                ) else {
                    logger.error("verification failed")
                    throw TLSError.certificateError
                }
                self = .serverCertificateVerify(
                    try ServerCertificateVerifyState.verifiedPeer(originalState: certificateState, certificateVerifyBytes: certificateVerifyBytes)
                )
                return .finished
            default:
                guard try certificateState.certificates.verifyServerCertificateVerifySignature(
                    message: certificateVerify,
                    validKeys: [],
                    keyScheduler: certificateState.keyScheduler
                ) else {
                    logger.error("verification failed")
                    throw TLSError.certificateError
                }
                self = .serverCertificateVerify(
                    try ServerCertificateVerifyState.verifiedPeer(originalState: certificateState, certificateVerifyBytes: certificateVerifyBytes)
                )
                return .finished
            }
        default:
            preconditionFailure()
        }
    }

    /// Returns bytes for `ClientFinished`, or bytes for
    /// `Client Certificate | [Client Certificate Verify] | Client Finished`
    /// if client authentication with a certificate or RPK is requested.
    mutating func receivedServerFinished(serverFinished: FinishedMessage, serverFinishedBytes: ByteBuffer, serializer: inout TLSMessageSerializer) throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .serverCertificateVerify(var state) where state.sendClientCertificateMessage:
            // process Server finished:
            guard try state.keyScheduler.serverFinishedPayload() == serverFinished.verifyData.readableBytesView else {
                logger.error("invalid server finished payload")
                throw TLSError.negotiationFailed
            }
            try state.keyScheduler.postServerFinished(serverFinishedBytes: serverFinishedBytes)
            var clientSecondFlightBuffer = ByteBuffer()
            // send client certificate (empty or with cert)
            var (newState, clientCertificate) = try ClientCertificateState.sendingClientCertificate(originalState: state)
            clientSecondFlightBuffer.writeBuffer(&clientCertificate)
            // if certificate msg non empty also send certificate verify
            var (newerState, clientCertificateVerify) = try ClientCertificateVerifyState.sendingClientCertificateVerify(originalState: newState)
            clientSecondFlightBuffer.writeBuffer(&clientCertificateVerify)
            // send finished
            var clientFinishedBuffer = ByteBuffer()
            let clientFinished = try newerState.keyScheduler.clientFinishedPayload()
            serializer.writeHandshakeMessage(.finished(.init(verifyData: ByteBuffer(bytes: clientFinished))), into: &clientFinishedBuffer)
            try newerState.keyScheduler.postClientFinished(clientFinishedBytes: clientFinishedBuffer)

            clientSecondFlightBuffer.writeBuffer(&clientFinishedBuffer)

            let state = ReadyState(configuration: state.configuration,
                             negotiatedCipherSuite: state.negotiatedCipherSuite,
                             negotiatedGroup: state.negotiatedGroup,
                             certificates: state.certificates,
                             serverALPN: state.serverALPN,
                             serverQUICTransportParameters: state.serverQUICTransportParameters,
                             earlyDataAccepted: state.earlyDataAccepted,
                             keyScheduler: newerState.keyScheduler,
                             epskNegotiated: false,
                             epskNegotiationAttempted: state.epskNegotiationAttempted)
            guard let clientTrafficSecret = state.keyScheduler.clientApplicationTrafficSecret,
                  let serverTrafficSecret = state.keyScheduler.serverApplicationTrafficSecret else {
                preconditionFailure()
            }
            self = .readyForData(state)
            logger.info("client sending client certificate, certificate verify, and client finished")
            return .init(handshakeBytesToSend: clientSecondFlightBuffer, newWriteEncryptionLevel: .application(secret: clientTrafficSecret), newReadEncryptionLevel: .application(secret: serverTrafficSecret))
        case .serverCertificateVerify(let state):
            let (newState, clientFinished) =
                try ReadyState.receivingServerFinished(
                    originalState: state, serverFinished: serverFinished,
                    serverFinishedBytes: serverFinishedBytes,
                    serializer: &serializer)
            guard let clientTrafficSecret = newState.keyScheduler.clientApplicationTrafficSecret,
                  let serverTrafficSecret = newState.keyScheduler.serverApplicationTrafficSecret else {
                preconditionFailure()
            }

            self = .readyForData(newState)
            return .init(handshakeBytesToSend: clientFinished, newWriteEncryptionLevel: .application(secret: clientTrafficSecret), newReadEncryptionLevel: .application(secret: serverTrafficSecret))
        case .serverEncryptedExtensions(let state) where state.epskNegotiated || state.sessionResumed:
            let (newState, clientFinished) =
                try ReadyState.receivingServerFinished(
                    originalState: state, serverFinished: serverFinished,
                    serverFinishedBytes: serverFinishedBytes,
                    serializer: &serializer)
            guard let clientTrafficSecret = newState.keyScheduler.clientApplicationTrafficSecret,
                  let serverTrafficSecret = newState.keyScheduler.serverApplicationTrafficSecret else {
                preconditionFailure()
            }

            self = .readyForData(newState)
            return .init(handshakeBytesToSend: clientFinished, newWriteEncryptionLevel: .application(secret: clientTrafficSecret), newReadEncryptionLevel: .application(secret: serverTrafficSecret))

        default:
            preconditionFailure()
        }
    }

    mutating func receivedNewSessionTicket(newSessionTicket: NewSessionTicket, currentTime: Date) throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .readyForData(let state):
            // newSessionTicket is valid in the ready for data state, but at no other time.
            let ticket = try state.prepareSessionTicket(message: newSessionTicket, currentTime: currentTime)
            logger.notice("generated new session ticket")
            return .init(handshakeBytesToSend: nil, newWriteEncryptionLevel: nil, sessionTicket: ticket.serialize())
        default:
            preconditionFailure()
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension HandshakeState {
    struct IdleState {
        var configuration: HandshakeStateMachine.Configuration

        var sessionToResume: SessionTicket?

        var keyScheduler: ClientSessionKeyManager<SHA384>

        init(
            configuration: HandshakeStateMachine.Configuration,
            sessionToResume: SessionTicket?,
        ) {
            self.configuration = configuration
            self.sessionToResume = sessionToResume
            self.keyScheduler = ClientSessionKeyManager()
        }
    }

    struct ClientHelloState {
        var configuration: HandshakeStateMachine.Configuration
        var expectedLegacySessionID: LegacySessionID
        var allowedCipherSuites: [CipherSuite]
        var serverCertificateTypes: [CertificateType]
        var clientCertificateTypes: [CertificateType]
        var signatureAlgorithmOffer: [SignatureScheme]
        var ephemeralKeyShare: GeneratedEphemeralPrivateKey?
        var keyScheduler: ClientSessionKeyManager<SHA384>
        var sessionToResume: SessionTicket?
        var epsks: [GeneralEPSK]

        init(
            configuration: HandshakeStateMachine.Configuration,
            expectedLegacySessionID: LegacySessionID,
            allowedCipherSuites: [CipherSuite],
            serverCertificateTypes: [CertificateType],
            clientCertificateTypes: [CertificateType],
            signatureAlgorithmOffer: [SignatureScheme],
            ephemeralKeyShare: GeneratedEphemeralPrivateKey?,
            keyScheduler: ClientSessionKeyManager<SHA384>,
            sessionToResume: SessionTicket?,
            epsks: [GeneralEPSK]
        ) {
            self.configuration = configuration
            self.expectedLegacySessionID = expectedLegacySessionID
            self.allowedCipherSuites = allowedCipherSuites
            self.serverCertificateTypes = serverCertificateTypes
            self.clientCertificateTypes = clientCertificateTypes
            self.signatureAlgorithmOffer = signatureAlgorithmOffer
            self.ephemeralKeyShare = ephemeralKeyShare
            self.keyScheduler = keyScheduler
            self.sessionToResume = sessionToResume
            self.epsks = epsks
        }

        static func sendingClientHello(
            originalState: IdleState,
            clientHello: inout ClientHello,
            sessionToResume: SessionTicket?,
            epsks: [GeneralEPSK],
            useRawEPSKs: Bool,
            ephemeralKeyShare: GeneratedEphemeralPrivateKey?,
            currentTime: Date?
        ) throws(TLSError) -> (state: ClientHelloState, clientHelloBytes: ByteBuffer) {
            var keyScheduler = originalState.keyScheduler
            let clientHelloBytes = try keyScheduler.sendingClientHello(clientHello: &clientHello, sessionToResume: sessionToResume, epsks: epsks, useRawEPSKs: useRawEPSKs, currentTime: currentTime)
            let newState = Self(
                configuration: originalState.configuration,
                expectedLegacySessionID: clientHello.legacySessionID,
                allowedCipherSuites: clientHello.cipherSuites,
                serverCertificateTypes: clientHello.serverCertificateTypes,
                clientCertificateTypes: clientHello.clientCertificateTypes,
                signatureAlgorithmOffer: clientHello.signatureAlgorithms.map { SignatureScheme(rawValue: $0) },
                ephemeralKeyShare: ephemeralKeyShare,
                keyScheduler: keyScheduler,
                sessionToResume: sessionToResume,
                epsks: epsks)
            return (state: newState, clientHelloBytes: clientHelloBytes)
        }
    }

    struct ServerHelloState {
        var configuration: HandshakeStateMachine.Configuration
        var sessionData: SessionData
        var keyScheduler: ClientSessionKeyManager<SHA384>
        var negotiatedCipherSuite: CipherSuite?
        var negotiatedGroup: NamedGroup?
        var signatureAlgorithmOffer: [SignatureScheme]
        var epskNegotiated: Bool = false
        var sessionResumed: Bool = false
        var pskNegotiatedIndex: UInt16?
        let epskNegotiationAttempted: Bool

        init(originalState clientHelloState: ClientHelloState, serverHello: ServerHello, serverHelloBytes: ByteBuffer, clock: some SwiftTLSClock) throws(TLSError) {
            logger.debug("validating server hello")

            // Let's validate this ServerHello. As we have no configuration at the moment, this validation is manual.
            // The rules:
            //
            // - helloRetryRequest is forbidden
            // - the server must have echoed our legacy session ID
            // - the legacy version number must be TLSv1.2
            // - the chosen compression option must be zero
            // - the supported version must be TLSV1.3

            guard !serverHello.isHelloRetryRequest,
                  serverHello.legacySessionIDEcho == clientHelloState.expectedLegacySessionID,
                  serverHello.legacyVersion == .tlsv12,
                  serverHello.legacyCompressionMethod == 0,
                  serverHello.supportedVersion == .tlsv13 else {
                logger.error("server hello invalid for QUIC")
                throw TLSError.handshakeInvalidMessage
            }

            guard let negotiatedCipherSuite = clientHelloState.allowedCipherSuites.confirmNegotiated(serverHello.cipherSuite) else {
                #if SWIFTTLS_EXCLAVECORE
                logger.error("server hello chose a cipher suite we didn't offer (\(String(describing:serverHello.cipherSuite))")
                #else
                logger.error("server hello chose a cipher suite we didn't offer (\(serverHello.cipherSuite))")
                #endif
                throw TLSError.negotiationFailed
            }
            self.negotiatedCipherSuite = negotiatedCipherSuite
            self.signatureAlgorithmOffer = clientHelloState.signatureAlgorithmOffer

            var serverKeyShare: Extension.KeyShare.KeyShareEntry?
            var sessionToResume: SessionTicket?
            var EPSKSelected: GeneralEPSK?

            var observedExtensionTypes = Set<ExtensionType>()

            for ext in serverHello.extensions {
                let (inserted, _) = observedExtensionTypes.insert(ext.type)

                if !inserted {
                    #if SWIFTTLS_EXCLAVECORE
                    logger.error("server offered duplicate extension of type \(String(describing: ext.type)) on server hello")
                    #else
                    logger.error("server offered duplicate extension of type \(ext.type) on server hello")
                    #endif
                    throw TLSError.handshakeInvalidMessage
                }


                switch ext {
                case .keyShare(.serverHello(let offeredKeyShare)):
                    serverKeyShare = offeredKeyShare
                    break

                case .preSharedKey(.serverHello(let acceptedIndex)):
                    if let session = clientHelloState.sessionToResume {
                        guard acceptedIndex == 0 else {
                            logger.error("server hello is trying to resume a session we didn't offer")
                            throw TLSError.negotiationFailed
                        }

                        guard negotiatedCipherSuite == session.cipherSuite else {
                            #if SWIFTTLS_EXCLAVECORE
                            logger.error("server negotiated cipher suite \(String(describing: negotiatedCipherSuite)), expected \(String(describing: session.cipherSuite))")
                            #else
                            logger.error("server negotiated cipher suite \(negotiatedCipherSuite), expected \(session.cipherSuite)")
                            #endif
                            throw TLSError.negotiationFailed
                        }
                        logger.debug("resuming session")
                        sessionToResume = session
                        self.sessionResumed = true
                        self.pskNegotiatedIndex = acceptedIndex
                    } else if !clientHelloState.epsks.isEmpty {
                        guard acceptedIndex == 0 else {
                            logger.error("server hello is trying to use a psk at an index we didn't offer")
                            throw TLSError.negotiationFailed
                        }

                        logger.debug("external psk accepted by server")
                        EPSKSelected = clientHelloState.epsks[0]
                        self.epskNegotiated = true
                        self.pskNegotiatedIndex = acceptedIndex
                    } else {
                        logger.error("server hello sent a pre_shared_key extension when we didn't offer psks")
                        throw TLSError.negotiationFailed
                    }

                default:
                    // We ignore other extensions here
                    ()
                }
            }

            let sharedSecret: SymmetricKey
            let expectedGroup = clientHelloState.configuration.fixedKeyExchangeGroup
            guard let keyShare = serverKeyShare,
                (keyShare.group == expectedGroup) else {
                logger.error("unsupported server key share, expected secp384 or x25519 or x25519-MLKEM768 got \(serverKeyShare?.description ?? "nil")")
                throw TLSError.negotiationFailed
            }

            guard let ephemeralKeyShare = clientHelloState.ephemeralKeyShare else {
                logger.error("missing key share")
                throw TLSError.negotiationFailed
            }

            logger.debug("valid TLS1.3 server hello, constructing shared secret.")
            sharedSecret = try ephemeralKeyShare.decap(ciphertextData: keyShare.keyExchange.readableBytesView)

            self.negotiatedGroup = keyShare.group

            // We need these to validate against EncryptedExtensions later.
            if let sessionToResume = sessionToResume {
                self.sessionData = .resumingSession(sessionToResume)
            } else {
                self.sessionData = .newSession(.init(negotiatedCipherSuite: negotiatedCipherSuite,
                                                     negotiatedGroup: self.negotiatedGroup!,
                                                     serverCertificateTypes: clientHelloState.serverCertificateTypes,
                                                     clientCertificateTypes: clientHelloState.clientCertificateTypes,
                                                     signatureAlgorithmOffer: clientHelloState.signatureAlgorithmOffer))
            }

            let resumptionFailed = sessionToResume == nil && clientHelloState.sessionToResume != nil
            self.epskNegotiationAttempted = !clientHelloState.epsks.isEmpty
            let epskFailed = EPSKSelected == nil && !clientHelloState.epsks.isEmpty

            self.configuration = clientHelloState.configuration
            self.keyScheduler = clientHelloState.keyScheduler
            try self.keyScheduler.postServerHello(ecdheSecret: .init(data: sharedSecret),
                                                  serverHelloBytes: serverHelloBytes,
                                                  pskFailed: resumptionFailed || epskFailed)
            logger.debug("server hello valid")
        }

        enum SessionData {
            case newSession(NewSession)
            case resumingSession(SessionTicket)

            struct NewSession {
                var negotiatedCipherSuite: CipherSuite
                var negotiatedGroup: NamedGroup
                var serverCertificateTypes: [CertificateType]
                var clientCertificateTypes: [CertificateType]
                var signatureAlgorithmOffer: [SignatureScheme]
            }
        }
    }

    struct EncryptedExtensionsState {
        var configuration: HandshakeStateMachine.Configuration
        var sessionData: SessionData?
        var serverALPN: ApplicationLayerProtocol?
        var serverQUICTransportParameters: ByteBuffer?
        var earlyDataAccepted: Bool = false
        var keyScheduler: ClientSessionKeyManager<SHA384>
        var epskNegotiated: Bool
        var sessionResumed: Bool
        let epskNegotiationAttempted: Bool

        init(originalState serverHelloState: ServerHelloState, encryptedExtensions: EncryptedExtensions, extensionBytes: ByteBuffer) throws(TLSError) {
            logger.debug("validating encrypted extensions")

            var serverCertificateType: CertificateType?

            var clientCertificateType: CertificateType?

            var observedExtensionTypes = Set<ExtensionType>()

            for ext in encryptedExtensions.extensions {
                let (inserted, _) = observedExtensionTypes.insert(ext.type)

                if !inserted {
                    #if SWIFTTLS_EXCLAVECORE
                    logger.error("server offered duplicate extension of type \(String(describing: ext.type)) on encrypted extensions")
                    #else
                    logger.error("server offered duplicate extension of type \(ext.type) on encrypted extensions")
                    #endif
                    throw TLSError.handshakeInvalidMessage
                }

                switch ext {
                case .alpn(.selection(let serverALPN)):
                    guard serverHelloState.configuration.alpn != nil else {
                        // We didn't send ALPN, invalid.
                        logger.error("server unexpectedly offered alpn")
                        throw TLSError.unsupportedExtension
                    }

                    self.serverALPN = serverALPN
                case .quicTransportParameters(let serverTransportParameters):
                    guard serverHelloState.configuration.quicTransportParameters != nil else {
                        // We didn't send transport parameters, invalid.
                        logger.error("server unexpectedly offered transport parameters")
                        throw TLSError.unsupportedExtension
                    }

                    self.serverQUICTransportParameters = serverTransportParameters.opaqueOffer
                case .serverCertificateType(.selection(let selectedType)):
                    switch serverHelloState.configuration.verificationMethod {
                    case .none:
                        logger.error("server unexpectedly sent server_certificate_type extension")
                        throw TLSError.unsupportedExtension
                    case .rawPublicKey:
#if SWIFTTLS_SUPPORT_UNVERIFIED_X509
                        // The unverified X509 path runs with this configuration and must be able to pass here.
                        guard selectedType == .rawPublicKey || selectedType == .x509 else {
                            logger.error("server reported unsupported certificate type")
                            throw TLSError.negotiationFailed
                        }
#else
                        guard selectedType == .rawPublicKey else {
                            logger.error("server reported unsupported certificate type")
                            throw TLSError.negotiationFailed
                        }
#endif
                    case .certificateCallbacks(let asyncVerifier):
                        let ourSupportedTypes = asyncVerifier.availableCertificateTypes

                        // Check that the selected type is supported.
                        guard ourSupportedTypes.contains(selectedType) else {
                            logger.error("server reported unsupported certificate type")
                            throw TLSError.negotiationFailed
                        }

                        // If the only supported type is x509 these extensions should be omitted.
                        if ourSupportedTypes.count == 1 && ourSupportedTypes.first == .x509 {
                            logger.error("server unexpectedly sent server_certificate_type extension")
                            throw TLSError.negotiationFailed
                        }
                    }
                    serverCertificateType = selectedType
                case .clientCertificateType(.selection(let selectedType)):
                    logger.info("got client cert type ext")
                    guard serverHelloState.configuration.signingKey != nil else {
                        logger.error("server unexpectedly sent client_certificate_type extension")
                        throw TLSError.unsupportedExtension
                    }
                    clientCertificateType = selectedType
                case .earlyData:
                    // this checks if either resumed or external PSK
                    if (serverHelloState.epskNegotiated || serverHelloState.sessionResumed), let index = serverHelloState.pskNegotiatedIndex, index == 0 {
                        if case .resumingSession(let session) = serverHelloState.sessionData, session.maxEarlyDataSize == 0 {
                            logger.error("server unexpectedly offered early data for session with max early data size 0")
                            throw TLSError.negotiationFailed
                        }
                        logger.info("server accepted early data")
                        self.earlyDataAccepted = true
                    } else {
                        logger.error("server unexpectedly offered early data")
                        throw TLSError.negotiationFailed
                    }
                default:
                    // Ignore unknown extensions
                    ()
                }
            }

            switch serverHelloState.sessionData {
            case .newSession(let newSession):
                guard let negotiatedType = newSession.serverCertificateTypes.confirmNegotiated(serverCertificateType ?? .x509) else {
#if SWIFTTLS_EXCLAVECORE
                    logger.error("server chose non-offered certificate type \(String(describing: serverCertificateType ?? .x509))")
#else
                    logger.error("server chose non-offered certificate type \(serverCertificateType ?? .x509)")
#endif
                    throw TLSError.negotiationFailed
                }
                guard let negotiatedClientCertType = newSession.clientCertificateTypes.confirmNegotiated(clientCertificateType ?? .x509) else {
#if SWIFTTLS_EXCLAVECORE
                    logger.error("server chose non-offered client certificate type \(String(describing: clientCertificateType ?? .x509))")
#else
                    logger.error("server chose non-offered client certificate type \(clientCertificateType ?? .x509)")
#endif
                    throw TLSError.negotiationFailed
                }

                self.sessionData = .newSession(.init(negotiatedCipherSuite: newSession.negotiatedCipherSuite,
                                                     negotiatedGroup: newSession.negotiatedGroup,
                                                     serverCertificateType: negotiatedType,
                                                     clientCertificateType: negotiatedClientCertType,
                                                     signatureAlgorithmOffer: newSession.signatureAlgorithmOffer))
            case .resumingSession(let resumedSession):
                guard serverCertificateType == nil else {
                    logger.error("server provided server_certificate_type extension while resuming")
                    throw TLSError.negotiationFailed
                }
                self.sessionData = .resumingSession(resumedSession)
            }
            self.configuration = serverHelloState.configuration
            self.keyScheduler = serverHelloState.keyScheduler
            self.epskNegotiated = serverHelloState.epskNegotiated
            self.sessionResumed = serverHelloState.sessionResumed
            self.epskNegotiationAttempted = serverHelloState.epskNegotiationAttempted
            try self.keyScheduler.addPreFinishedMessageToTransportHash(extensionBytes)

            logger.debug("encrypted extensions valid")
        }

        enum SessionData {
            case newSession(NewSession)
            case resumingSession(SessionTicket)

            // We should have another session type for epsks
            struct NewSession {
                var negotiatedCipherSuite: CipherSuite
                var negotiatedGroup: NamedGroup
                var serverCertificateType: CertificateType
                var clientCertificateType: CertificateType
                var signatureAlgorithmOffer: [SignatureScheme]
                var serverName: String?
            }

            var negotiatedCipherSuite: CipherSuite {
                switch self {
                case .newSession(let newSession):
                    return newSession.negotiatedCipherSuite
                case .resumingSession(let resumingSession):
                    return resumingSession.cipherSuite
                }
            }

            var negotiatedGroup: NamedGroup? {
                switch self {
                case .newSession(let newSession):
                    return newSession.negotiatedGroup
                case .resumingSession(let resumingSession):
                    return resumingSession.group
                }
            }
        }

        var isResumption: Bool {
            switch self.sessionData {
            case .newSession:
                return false
            case .resumingSession:
                return true
            case nil:
                return false
            }
        }
    }

    struct ServerCertificateRequestState {
        var configuration: HandshakeStateMachine.Configuration
        var sessionData: EncryptedExtensionsState.SessionData?
        var negotiatedCipherSuite: CipherSuite
        var negotiatedGroup: NamedGroup
        var serverALPN: ApplicationLayerProtocol?
        var serverQUICTransportParameters: ByteBuffer?
        var earlyDataAccepted: Bool
        var keyScheduler: ClientSessionKeyManager<SHA384>
        let epskNegotiationAttempted: Bool
        let sendClientCertificateMessage: Bool
        let clientCertificateSignatureAlgorithms: [SignatureScheme]?

        init(originalState encryptedExtensionsState: EncryptedExtensionsState, serverCertificateRequest: CertificateRequest, certificateRequestBytes: ByteBuffer) throws(TLSError) {
            logger.debug("processing certificate request")
            // Check that the context string is empty since:
            // RFC 8446
            // This field SHALL be zero
            // length unless used for the post-handshake authentication exchanges
            // described in Section 4.6.2.
            guard serverCertificateRequest.certificateRequestContext.readableBytes == 0 else {
                logger.error("received unexpected context: \(serverCertificateRequest.certificateRequestContext.readableBytes)")
                throw TLSError.handshakeInvalidMessage
            }

            // A set of extensions describing the parameters of the
            // certificate being requested.  The "signature_algorithms" extension
            // MUST be specified, and other extensions may optionally be included
            // if defined for this message.  Clients MUST ignore unrecognized
            // extensions.
            guard serverCertificateRequest.extensions.count > 0 else {
                logger.error("received certificate request with no extensions")
                throw TLSError.handshakeInvalidMessage
            }

            let serverSupportedSignatureAlgorithms = serverCertificateRequest.extensions.first(where: { ext in ext.type == .signatureAlgorithms})
            switch serverSupportedSignatureAlgorithms! {
                case .signatureAlgorithms(let sigAlgs):
                    self.clientCertificateSignatureAlgorithms = sigAlgs.schemes
                default:
                    self.clientCertificateSignatureAlgorithms = nil
            }
            // TODO: Should do more to check for duplicate extensions on all messages
            guard serverCertificateRequest.extensions.count(where: { ext in ext.type == .signatureAlgorithms}) == 1 else {
                logger.error("received certificate request without exactly one 'signature_algorithms' extension.")
                throw TLSError.handshakeInvalidMessage
            }

            guard case .newSession(let newSessionData) = encryptedExtensionsState.sessionData else {
                logger.error("received server certificate request message while resuming session")
                throw TLSError.handshakeUnexpectedMessage
            }
            self.sessionData = encryptedExtensionsState.sessionData

            // If the server requests client authentication but no cert is available.
            // According to RFC 8446:
            //   If the server requests client authentication but no
            //   suitable certificate is available, the client MUST send a Certificate
            //   message containing no certificates (i.e., with the "certificate_list"
            //   field having length 0).
            self.sendClientCertificateMessage = true

            self.configuration = encryptedExtensionsState.configuration
            self.negotiatedCipherSuite = newSessionData.negotiatedCipherSuite
            self.negotiatedGroup = newSessionData.negotiatedGroup
            self.serverALPN = encryptedExtensionsState.serverALPN
            self.serverQUICTransportParameters = encryptedExtensionsState.serverQUICTransportParameters
            self.earlyDataAccepted = encryptedExtensionsState.earlyDataAccepted
            self.keyScheduler = encryptedExtensionsState.keyScheduler
            self.epskNegotiationAttempted = encryptedExtensionsState.epskNegotiationAttempted
            try self.keyScheduler.addPreFinishedMessageToTransportHash(certificateRequestBytes)
        }
    }

    struct ServerCertificateState {
        var configuration: HandshakeStateMachine.Configuration
        var sessionData: EncryptedExtensionsState.SessionData.NewSession
        var negotiatedCipherSuite: CipherSuite
        var negotiatedGroup: NamedGroup
        var serverALPN: ApplicationLayerProtocol?
        var serverQUICTransportParameters: ByteBuffer?
        var earlyDataAccepted: Bool
        var certificates: PeerCertificateBundle
        var keyScheduler: ClientSessionKeyManager<SHA384>
        let epskNegotiationAttempted: Bool
        let sendClientCertificateMessage: Bool
        let clientCertificateSignatureAlgorithms: [SignatureScheme]?

        init(originalState: ServerCertificateRequestState, serverCertificate: CertificateMessage, certificateBytes: ByteBuffer) throws(TLSError) {
            logger.debug("validating certificate")

            // Quickly check that the context string is empty.
            guard serverCertificate.certificateRequestContext.readableBytes == 0 else {
                logger.error("received unexpected context: \(serverCertificate.certificateRequestContext.readableBytes)")
                throw TLSError.handshakeInvalidMessage
            }

            guard case .newSession(let newSessionData) = originalState.sessionData else {
                logger.error("received server certificate message while resuming session")
                throw TLSError.handshakeUnexpectedMessage
            }

            // This is mostly a straight copy, but we unpack the certificates too.
            self.configuration = originalState.configuration
            self.sessionData = newSessionData
            self.negotiatedCipherSuite = originalState.negotiatedCipherSuite
            self.negotiatedGroup = originalState.negotiatedGroup
            self.serverALPN = originalState.serverALPN
            self.serverQUICTransportParameters = originalState.serverQUICTransportParameters
            self.earlyDataAccepted = originalState.earlyDataAccepted
            self.certificates = try PeerCertificateBundle(expectedCertificateType: newSessionData.serverCertificateType,
                                                          peerCertificateMessage: serverCertificate, fromClient: false)
            self.keyScheduler = originalState.keyScheduler
            self.epskNegotiationAttempted = originalState.epskNegotiationAttempted
            self.sendClientCertificateMessage = originalState.sendClientCertificateMessage
            self.clientCertificateSignatureAlgorithms = originalState.clientCertificateSignatureAlgorithms
            try self.keyScheduler.addPreFinishedMessageToTransportHash(certificateBytes)

            logger.debug("certificate valid")
        }

        init(originalState encryptedExtensionsState: EncryptedExtensionsState, serverCertificate: CertificateMessage, certificateBytes: ByteBuffer) throws(TLSError) {
            logger.debug("validating certificate")

            // Quickly check that the context string is empty.
            guard serverCertificate.certificateRequestContext.readableBytes == 0 else {
                logger.error("received unexpected context: \(serverCertificate.certificateRequestContext.readableBytes)")
                throw TLSError.handshakeInvalidMessage
            }

            guard case .newSession(let newSessionData) = encryptedExtensionsState.sessionData else {
                logger.error("received server certificate message while resuming session")
                throw TLSError.handshakeUnexpectedMessage
            }
            self.sessionData = newSessionData

            // This is mostly a straight copy, but we unpack the certificates too.
            self.configuration = encryptedExtensionsState.configuration
            self.negotiatedCipherSuite = newSessionData.negotiatedCipherSuite
            self.negotiatedGroup = newSessionData.negotiatedGroup
            self.serverALPN = encryptedExtensionsState.serverALPN
            self.serverQUICTransportParameters = encryptedExtensionsState.serverQUICTransportParameters
            self.earlyDataAccepted = encryptedExtensionsState.earlyDataAccepted
            self.certificates = try PeerCertificateBundle(expectedCertificateType: newSessionData.serverCertificateType,
                                                          peerCertificateMessage: serverCertificate, fromClient: false)
            self.keyScheduler = encryptedExtensionsState.keyScheduler
            self.epskNegotiationAttempted = encryptedExtensionsState.epskNegotiationAttempted
            self.sendClientCertificateMessage = false
            self.clientCertificateSignatureAlgorithms = nil
            try self.keyScheduler.addPreFinishedMessageToTransportHash(certificateBytes)

            logger.debug("certificate valid")
        }
    }

    struct AwaitingVerificationState {
        var configuration: HandshakeStateMachine.Configuration
        var sessionData: EncryptedExtensionsState.SessionData.NewSession
        var negotiatedCipherSuite: CipherSuite
        var negotiatedGroup: NamedGroup
        var certificates: PeerCertificateBundle
        var serverALPN: ApplicationLayerProtocol?
        var serverQUICTransportParameters: ByteBuffer?
        var earlyDataAccepted: Bool
        var keyScheduler: ClientSessionKeyManager<SHA384>
        let epskNegotiationAttempted: Bool
        let sendClientCertificateMessage: Bool
        let clientCertificateSignatureAlgorithms: [SignatureScheme]?
        var verificationInfo: VerificationInfo
        var certificateVerifyBytes: ByteBuffer
        var asyncVerifier: AsyncVerifier

        init(originalState state: ServerCertificateState, asyncVerifier: AsyncVerifier, verificationInfo: VerificationInfo, certificateVerifyBytes: ByteBuffer) throws(TLSError) {
            self.configuration = state.configuration
            self.sessionData = state.sessionData
            self.negotiatedCipherSuite = state.negotiatedCipherSuite
            self.negotiatedGroup = state.negotiatedGroup
            self.certificates = state.certificates
            self.serverALPN = state.serverALPN
            self.serverQUICTransportParameters = state.serverQUICTransportParameters
            self.earlyDataAccepted = state.earlyDataAccepted
            self.keyScheduler = state.keyScheduler
            self.epskNegotiationAttempted = state.epskNegotiationAttempted
            self.sendClientCertificateMessage = state.sendClientCertificateMessage
            self.clientCertificateSignatureAlgorithms = state.clientCertificateSignatureAlgorithms
            self.asyncVerifier = asyncVerifier
            self.verificationInfo = verificationInfo
            self.certificateVerifyBytes = certificateVerifyBytes
        }
    }

    struct ServerCertificateVerifyState {
        var configuration: HandshakeStateMachine.Configuration
        var sessionData: EncryptedExtensionsState.SessionData.NewSession
        var negotiatedCipherSuite: CipherSuite
        var negotiatedGroup: NamedGroup
        var certificates: PeerCertificateBundle
        var serverALPN: ApplicationLayerProtocol?
        var serverQUICTransportParameters: ByteBuffer?
        var earlyDataAccepted: Bool
        var keyScheduler: ClientSessionKeyManager<SHA384>
        let epskNegotiationAttempted: Bool
        let sendClientCertificateMessage: Bool
        let clientCertificateSignatureAlgorithms: [SignatureScheme]?

        init(originalState state: ServerCertificateState, certificateVerifyBytes: ByteBuffer) throws(TLSError) {
            self.configuration = state.configuration
            self.sessionData = state.sessionData
            self.negotiatedCipherSuite = state.negotiatedCipherSuite
            self.negotiatedGroup = state.negotiatedGroup
            self.certificates = state.certificates
            self.serverALPN = state.serverALPN
            self.serverQUICTransportParameters = state.serverQUICTransportParameters
            self.earlyDataAccepted = state.earlyDataAccepted
            self.keyScheduler = state.keyScheduler
            self.epskNegotiationAttempted = state.epskNegotiationAttempted
            self.sendClientCertificateMessage = state.sendClientCertificateMessage
            self.clientCertificateSignatureAlgorithms = state.clientCertificateSignatureAlgorithms
            try self.keyScheduler.addPreFinishedMessageToTransportHash(certificateVerifyBytes)
        }

        init(originalState state: AwaitingVerificationState, certificateVerifyBytes: ByteBuffer) throws(TLSError) {
            self.configuration = state.configuration
            self.sessionData = state.sessionData
            self.negotiatedCipherSuite = state.negotiatedCipherSuite
            self.negotiatedGroup = state.negotiatedGroup
            self.certificates = state.certificates
            self.serverALPN = state.serverALPN
            self.serverQUICTransportParameters = state.serverQUICTransportParameters
            self.earlyDataAccepted = state.earlyDataAccepted
            self.keyScheduler = state.keyScheduler
            self.epskNegotiationAttempted = state.epskNegotiationAttempted
            self.sendClientCertificateMessage = state.sendClientCertificateMessage
            self.clientCertificateSignatureAlgorithms = state.clientCertificateSignatureAlgorithms
            try self.keyScheduler.addPreFinishedMessageToTransportHash(certificateVerifyBytes)
        }

        static func verifiedPeer(originalState state: ServerCertificateState, certificateVerifyBytes: ByteBuffer) throws(TLSError) -> ServerCertificateVerifyState {
            return try .init(originalState: state, certificateVerifyBytes: certificateVerifyBytes)
        }

        static func verifiedPeer(originalState state: AwaitingVerificationState, certificateVerifyBytes: ByteBuffer) throws(TLSError) -> ServerCertificateVerifyState {
            return try .init(originalState: state, certificateVerifyBytes: certificateVerifyBytes)
        }
    }

    struct ClientCertificateState {
        // only valid transition is ServerCertificateVerifyState -> ClientCertificateState
        var configuration: HandshakeStateMachine.Configuration
        var sessionData: EncryptedExtensionsState.SessionData.NewSession
        var negotiatedCipherSuite: CipherSuite
        var negotiatedGroup: NamedGroup
        var certificates: PeerCertificateBundle
        var serverALPN: ApplicationLayerProtocol?
        var serverQUICTransportParameters: ByteBuffer?
        var earlyDataAccepted: Bool
        var keyScheduler: ClientSessionKeyManager<SHA384>
        let epskNegotiationAttempted: Bool
        let sendClientCertificateMessage: Bool
        let clientCertificateSignatureAlgorithms: [SignatureScheme]?

        init(originalState state: ServerCertificateVerifyState, keyScheduler: ClientSessionKeyManager<SHA384>) throws(TLSError) {
            self.configuration = state.configuration
            self.sessionData = state.sessionData
            self.negotiatedCipherSuite = state.negotiatedCipherSuite
            self.negotiatedGroup = state.negotiatedGroup
            self.certificates = state.certificates
            self.serverALPN = state.serverALPN
            self.serverQUICTransportParameters = state.serverQUICTransportParameters
            self.earlyDataAccepted = state.earlyDataAccepted
            self.keyScheduler = keyScheduler
            self.epskNegotiationAttempted = state.epskNegotiationAttempted
            self.sendClientCertificateMessage = state.sendClientCertificateMessage
            self.clientCertificateSignatureAlgorithms = state.clientCertificateSignatureAlgorithms
        }

        static func sendingClientCertificate(originalState serverCertificateVerifyState: ServerCertificateVerifyState) throws(TLSError) -> (state: ClientCertificateState, clientCertificateBytes: ByteBuffer) {
            let clientCertificateMessage: CertificateMessage

            // if we have a signing key (currently only support P256)
            // and we negotiated P256 as a signing algorithm
            // and we negotiated Raw Public Keys as the certificate type
            // then send a Certificate message
            if serverCertificateVerifyState.sessionData.clientCertificateType == .rawPublicKey,
                let clientKey = serverCertificateVerifyState.configuration.signingKey,
                serverCertificateVerifyState.clientCertificateSignatureAlgorithms?.contains(where: { $0 == .ecdsa_secp256r1_sha256 }) ?? false {
                // we have a key configured can make a real Certificate message
                clientCertificateMessage = CertificateMessage(
                    certificateRequestContext: ByteBuffer(),
                    certificateList: [
                        .init(opaqueCertificateData: ByteBuffer(data:clientKey.publicKey.derRepresentation), extensions: [])
                    ]
                )
            } else {
                logger.info("client not configured with a signing key for server, sending empty certificate message")
                // send empty Certificate message if we don't
                // have a key or don't support the negotiated signature algorithm
                clientCertificateMessage = CertificateMessage(
                    certificateRequestContext: ByteBuffer(),
                    certificateList:[]
                )
            }

            var keyScheduler = serverCertificateVerifyState.keyScheduler
            var clientCertificateBytes = ByteBuffer()
            clientCertificateBytes.writeHandshakeMessage(clientCertificateMessage)
            try keyScheduler.addPostFinishedMessageToTransportHash(clientCertificateBytes)
            let newState = try Self(originalState: serverCertificateVerifyState, keyScheduler: keyScheduler)
            return (newState, clientCertificateBytes)
        }
    }

    struct ClientCertificateVerifyState {
        var configuration: HandshakeStateMachine.Configuration
        var negotiatedCipherSuite: CipherSuite
        var negotiatedGroup: NamedGroup
        var certificates: PeerCertificateBundle
        var serverALPN: ApplicationLayerProtocol?
        var serverQUICTransportParameters: ByteBuffer?
        var earlyDataAccepted: Bool
        var keyScheduler: ClientSessionKeyManager<SHA384>
        let epskNegotiationAttempted: Bool
        let sendClientCertificateMessage: Bool
        let clientCertificateSignatureAlgorithms: [SignatureScheme]?

        init(originalState state: ClientCertificateState, keyScheduler: ClientSessionKeyManager<SHA384>) throws(TLSError) {
            self.configuration = state.configuration
            self.negotiatedCipherSuite = state.negotiatedCipherSuite
            self.negotiatedGroup = state.negotiatedGroup
            self.certificates = state.certificates
            self.serverALPN = state.serverALPN
            self.serverQUICTransportParameters = state.serverQUICTransportParameters
            self.earlyDataAccepted = state.earlyDataAccepted
            self.keyScheduler = keyScheduler
            self.epskNegotiationAttempted = state.epskNegotiationAttempted
            self.sendClientCertificateMessage = state.sendClientCertificateMessage
            self.clientCertificateSignatureAlgorithms = state.clientCertificateSignatureAlgorithms
        }

        // only valid transition is ClientCertificateState -> ClientCertificateVerifyState
        static func sendingClientCertificateVerify(originalState clientCertificateState: ClientCertificateState) throws(TLSError) -> (state: ClientCertificateVerifyState, clientCertificateVerifyBytes: ByteBuffer) {
            guard let clientKey = clientCertificateState.configuration.signingKey else {
                // skip
                let newState = try Self.init(originalState: clientCertificateState, keyScheduler: clientCertificateState.keyScheduler)
                return (newState, ByteBuffer())
            }
            // if we have a signing key actually send this message
            var keyScheduler = clientCertificateState.keyScheduler
            let negotiatedSigAlg = SignatureScheme.ecdsa_secp256r1_sha256
            let data = try keyScheduler.dataToSignInClientCertificateVerify().readableBytesView

            let signature = try clientKey.sign(bytes: data, signatureScheme: SignatureScheme.ecdsa_secp256r1_sha256.rawValue)

            let clientCertificateVerifyMessage = CertificateVerify(
                algorithm: negotiatedSigAlg,
                signature: ByteBuffer(data: signature)
                )
            var clientCertificateVerifyBytes = ByteBuffer()
            clientCertificateVerifyBytes.writeHandshakeMessage(clientCertificateVerifyMessage)
            try keyScheduler.addPostFinishedMessageToTransportHash(clientCertificateVerifyBytes)
            let newState = try Self(originalState: clientCertificateState, keyScheduler: keyScheduler)

            return (newState, clientCertificateVerifyBytes)
        }
    }

    // could get here from EE, ServerCertificateVerifyState, or ClientCertificateVerifyState
    struct ReadyState {

        var configuration: HandshakeStateMachine.Configuration

        var negotiatedCipherSuite: CipherSuite?

        var negotiatedGroup: NamedGroup?

        var certificates: PeerCertificateBundle?

        var serverALPN: ApplicationLayerProtocol?

        var serverQUICTransportParameters: ByteBuffer?

        var earlyDataAccepted: Bool

        var keyScheduler: ClientSessionKeyManager<SHA384>

        var epskNegotiated: Bool

        let epskNegotiationAttempted: Bool

        init(
            configuration: HandshakeStateMachine.Configuration,
            negotiatedCipherSuite: CipherSuite?,
            negotiatedGroup: NamedGroup?,
            certificates: PeerCertificateBundle?,
            serverALPN: ApplicationLayerProtocol?,
            serverQUICTransportParameters: ByteBuffer?,
            earlyDataAccepted: Bool,
            keyScheduler: ClientSessionKeyManager<SHA384>,
            epskNegotiated: Bool,
            epskNegotiationAttempted: Bool
        ) {
            self.configuration = configuration
            self.negotiatedCipherSuite = negotiatedCipherSuite
            self.negotiatedGroup = negotiatedGroup
            self.certificates = certificates
            self.serverALPN = serverALPN
            self.serverQUICTransportParameters = serverQUICTransportParameters
            self.earlyDataAccepted = earlyDataAccepted
            self.keyScheduler = keyScheduler
            self.epskNegotiated = epskNegotiated
            self.epskNegotiationAttempted = epskNegotiationAttempted
        }

        func prepareSessionTicket(message: NewSessionTicket, currentTime: Date) throws(TLSError) -> SessionTicket {
            let ticketPSK = try self.keyScheduler.generateSessionTicketPSK(ticketNonce: message.ticketNonce)
            guard let peerCertificates = self.certificates else {
                throw TLSError.sessionMissingPeerCertificates
            }
            guard let negotiatedCipherSuite, let negotiatedGroup else {
                throw TLSError.sessionMissingNegotiatedCipherSuiteOrGroup
            }
            return try SessionTicket(message: message,
                                     psk: ticketPSK,
                                     cipherSuite: negotiatedCipherSuite,
                                     group: negotiatedGroup,
                                     alpn: self.serverALPN,
                                     certificateBundle: peerCertificates,
                                     currentTime: currentTime)
        }

        /// Creates a `ReadyState` and returns `ClientFinished` bytes
        static func receivingServerFinished(originalState state: ServerCertificateVerifyState,
                                            serverFinished: FinishedMessage,
                                            serverFinishedBytes: ByteBuffer,
                                            serializer: inout TLSMessageSerializer) throws(TLSError) -> (ReadyState, ByteBuffer) {

            var keyScheduler = state.keyScheduler
            guard try keyScheduler.serverFinishedPayload() == serverFinished.verifyData.readableBytesView else {
                logger.error("invalid server finished payload")
                throw TLSError.negotiationFailed
            }
            try keyScheduler.postServerFinished(serverFinishedBytes: serverFinishedBytes)

            let clientFinished = try keyScheduler.clientFinishedPayload()
            var clientFinishedBuffer = ByteBuffer()
            serializer.writeHandshakeMessage(.finished(.init(verifyData: ByteBuffer(bytes: clientFinished))), into: &clientFinishedBuffer)
            try keyScheduler.postClientFinished(clientFinishedBytes: clientFinishedBuffer)

            let state = Self(configuration: state.configuration,
                             negotiatedCipherSuite: state.negotiatedCipherSuite,
                             negotiatedGroup: state.negotiatedGroup,
                             certificates: state.certificates,
                             serverALPN: state.serverALPN,
                             serverQUICTransportParameters: state.serverQUICTransportParameters,
                             earlyDataAccepted: state.earlyDataAccepted,
                             keyScheduler: keyScheduler,
                             epskNegotiated: false,
                             epskNegotiationAttempted: state.epskNegotiationAttempted
                            )

            return (state, clientFinishedBuffer)
        }

        /// Creates a `ReadyState` and returns `ClientFinished` bytes.
        ///
        /// Called when client authentication with a certificate or RPK is in progress.
        static func receivingServerFinished(originalState state: ClientCertificateVerifyState,
                                            serverFinished: FinishedMessage,
                                            serverFinishedBytes: ByteBuffer,
                                            serializer: inout TLSMessageSerializer) throws(TLSError) -> (ReadyState, ByteBuffer) {

            var keyScheduler = state.keyScheduler
            guard try keyScheduler.serverFinishedPayload() == serverFinished.verifyData.readableBytesView else {
                logger.error("invalid server finished payload")
                throw TLSError.negotiationFailed
            }
            try keyScheduler.postServerFinished(serverFinishedBytes: serverFinishedBytes)

            let clientFinished = try keyScheduler.clientFinishedPayload()
            var clientFinishedBuffer = ByteBuffer()
            serializer.writeHandshakeMessage(.finished(.init(verifyData: ByteBuffer(bytes: clientFinished))), into: &clientFinishedBuffer)
            try keyScheduler.postClientFinished(clientFinishedBytes: clientFinishedBuffer)

            let state = Self(configuration: state.configuration,
                             negotiatedCipherSuite: state.negotiatedCipherSuite,
                             negotiatedGroup: state.negotiatedGroup,
                             certificates: state.certificates,
                             serverALPN: state.serverALPN,
                             serverQUICTransportParameters: state.serverQUICTransportParameters,
                             earlyDataAccepted: state.earlyDataAccepted,
                             keyScheduler: keyScheduler,
                             epskNegotiated: false,
                             epskNegotiationAttempted: state.epskNegotiationAttempted
                             )

            return (state, clientFinishedBuffer)
        }

        /// Creates a `ReadyState` and returns `ClientFinished` bytes.
        ///
        /// Called during resumption or using an external psk
        static func receivingServerFinished(originalState state: EncryptedExtensionsState,
                                            serverFinished: FinishedMessage,
                                            serverFinishedBytes: ByteBuffer,
                                            serializer: inout TLSMessageSerializer) throws(TLSError) -> (ReadyState, ByteBuffer) {

            guard state.sessionResumed || state.epskNegotiated else {
                logger.error("received server finished message while not resuming session or using an external pre shared key")
                throw TLSError.handshakeUnexpectedMessage
            }

            var negotiatedCipherSuite: CipherSuite?
            var negotiatedGroup: NamedGroup?
            var peerCertificates: PeerCertificateBundle?
            if case .resumingSession(let ticket) = state.sessionData {
                negotiatedCipherSuite = ticket.cipherSuite
                negotiatedGroup = ticket.group
                peerCertificates = ticket.certificateBundle
            } else if let sessionData = state.sessionData {
                // external psk used
                negotiatedCipherSuite = sessionData.negotiatedCipherSuite
                negotiatedGroup = sessionData.negotiatedGroup
                peerCertificates = nil
            }

            var keyScheduler = state.keyScheduler
            guard try keyScheduler.serverFinishedPayload() == serverFinished.verifyData.readableBytesView else {
                logger.error("invalid server finished payload")
                throw TLSError.negotiationFailed
            }
            try keyScheduler.postServerFinished(serverFinishedBytes: serverFinishedBytes)

            let clientFinished = try keyScheduler.clientFinishedPayload()
            var clientFinishedBuffer = ByteBuffer()
            serializer.writeHandshakeMessage(.finished(.init(verifyData: ByteBuffer(bytes: clientFinished))), into: &clientFinishedBuffer)
            try keyScheduler.postClientFinished(clientFinishedBytes: clientFinishedBuffer)

            let state = Self(configuration: state.configuration,
                             negotiatedCipherSuite: negotiatedCipherSuite,
                             negotiatedGroup: negotiatedGroup,
                             certificates: peerCertificates,
                             serverALPN: state.serverALPN,
                             serverQUICTransportParameters: state.serverQUICTransportParameters,
                             earlyDataAccepted: state.earlyDataAccepted,
                             keyScheduler: keyScheduler,
                             epskNegotiated: state.epskNegotiated,
                             epskNegotiationAttempted: state.epskNegotiationAttempted
                             )

            return (state, clientFinishedBuffer)
        }

        func generateTLSExporterKey(label: String) -> SymmetricKey? {
            return self.keyScheduler.generateTLSExporterKey(label: label)
        }

        func generateHashForAuthenticator(transcript: ByteBuffer) -> ByteBuffer {
            return self.keyScheduler.generateHashForAuthenticator(transcript: transcript)
        }

        func generateHMACForAuthenticator(transcript: ByteBuffer, key: SymmetricKey) -> ByteBuffer {
            return self.keyScheduler.generateHMACForAuthenticator(transcript: transcript, key:key)
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension HandshakeState {
    var logDescription: String {
        switch self {
        case .idle:
            return "idle"
        case .clientHello:
            return "clientHello"
        case .serverHello:
            return "serverHello"
        case .serverEncryptedExtensions:
            return "serverEncryptedExtensions"
        case .serverCertificateRequest:
            return "serverCertificateRequest"
        case .awaitingVerification:
            return "awaitingVerification"
        case .serverCertificate:
            return "serverCertificate"
        case .serverCertificateVerify:
            return "serverCertificateVerify"
        case .readyForData:
            return "readyForData"
        }
    }
}
