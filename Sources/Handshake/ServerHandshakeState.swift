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
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "ServerHandshakeState")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.ServerHandshakeState")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.ServerHandshakeState")
#endif

@available(SwiftTLS 0.1.0, *)
enum ServerHandshakeState {
    /// Ready, but the handshake has not yet started
    case idle(IdleState)

    /// The server has received the client hello and negotiated parameters
    case clientHello(ClientHelloState)

    /// The server hello has been sent to the client.
    case serverHello(ServerHelloState)

    /// The `ServerEncryptedExtensions` has been sent to the client.
    case serverEncryptedExtensions(ServerEncryptedExtensionsState)

    /// The `ServerCertificateRequest` has been sent to the client
    case serverCertificateRequest(ServerCertificateRequestState)

    /// The server is awaiting the certificate data to include in the `ServerCertificate` message.
    case awaitingCertificate(AwaitingCertificateState)

    /// The `ServerCertificate` has been sent to the client.
    case serverCertificate(ServerCertificateState)

    /// The server is awaiting the signature to include in the `ServerCertificateVerify` message.
    case awaitingSignature(AwaitingSignatureState)

    /// The `ServerCertificateVerify` has been sent to the client.
    case serverCertificateVerify(ServerCertificateVerifyState)

    /// The `ServerFinished` has been sent to the client.
    case serverFinished(ServerFinishedState)

    /// The `Certificate` message has been read from the client.
    case clientCertificate(ClientCertificateState)

    /// The `CertificateVerify` message has been read from the client.
    case clientCertificateVerify(ClientCertificateVerifyState)

    /// The server has received `ClientFinished`, and the handshake is now complete
    case readyForData(ReadyState)

    mutating func receivedClientHello(_ clientHello: ClientHello, bytes: ByteBuffer) throws(TLSError) -> PartialHandshakeResult? {
        switch self {
        case .idle(let state):
            let newState = try ClientHelloState.readingClientHello(originalState: state, clientHello: clientHello, clientHelloBytes: bytes, externalPSKSelectionCallback: state.externalPSKSelectionCallback, transportIsQUIC: state.transportIsQUIC)
            self = .clientHello(newState)
            if newState.earlyDataPermitted {
                let earlyClientTrafficSecret = newState.keyScheduler.clientEarlyTrafficSecret!
                return PartialHandshakeResult(newReadEncryptionLevel: .earlyData(secret: earlyClientTrafficSecret))
            }
            return nil
        default:
            preconditionFailure()
        }
    }

    mutating func sendingServerHello(_ serverHello: inout ServerHello) throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .clientHello(let state):
            let (newState, serverHelloBytes) = try ServerHelloState.sendingServerHello(originalState: state, serverHello: serverHello)
            let clientTrafficSecret = newState.keyScheduler.clientHandshakeTrafficSecret!
            let serverTrafficSecret = newState.keyScheduler.serverHandshakeTrafficSecret!
            self = .serverHello(newState)
            return PartialHandshakeResult(
                    handshakeBytesToSend: serverHelloBytes,
                    newWriteEncryptionLevel: .handshake(secret: serverTrafficSecret),
                    newReadEncryptionLevel: .handshake(secret: clientTrafficSecret))
        default:
            preconditionFailure()
        }
    }

    mutating func sendingServerEncryptedExtensions(_ serverEncryptedExtensions: EncryptedExtensions) throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .serverHello(let state):
            let (newState, serverEncryptedExtensionsBytes) = try ServerEncryptedExtensionsState.sendingServerEncryptedExtensions(
                originalState: state,
                serverEncryptedExtensions: serverEncryptedExtensions
            )
            self = .serverEncryptedExtensions(newState)

            return PartialHandshakeResult(handshakeBytesToSend: serverEncryptedExtensionsBytes)
        default:
            preconditionFailure()
        }
    }

    mutating func sendingServerCertificateRequest() throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .serverEncryptedExtensions(let state):
            let (newState, serverCertificateRequestBytes) = try ServerCertificateRequestState.sendingServerCertificateRequest(originalState: state)
            self = .serverCertificateRequest(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverCertificateRequestBytes)
        default:
            preconditionFailure()
        }
    }

    enum AuthenticationDetails {
        case callbacks(AsyncAuthenticator)
        case rawPublicKey(PrivateKey, SignatureScheme)
    }

    mutating func sendingServerCertificate(withRawPublicKey publicKey: Data, authDetails: AuthenticationDetails) throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .serverEncryptedExtensions(let state):
            let (newState, serverCertificateBytes) = try ServerCertificateState.sendingServerCertificate(originalState: state, withRawPublicKey: publicKey, authDetails: authDetails)
            self = .serverCertificate(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverCertificateBytes)
        case .serverCertificateRequest(let state):
            let (newState, serverCertificateBytes) = try ServerCertificateState.sendingServerCertificate(originalState: state, withRawPublicKey: publicKey, authDetails: authDetails)
            self = .serverCertificate(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverCertificateBytes)
        case .awaitingCertificate(let state):
            let (newState, serverCertificateBytes) = try ServerCertificateState.sendingServerCertificate(originalState: state, withRawPublicKey: publicKey, authDetails: authDetails)
            self = .serverCertificate(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverCertificateBytes)
        default:
            preconditionFailure()
        }
    }

    mutating func awaitCertificate(asyncAuthenticator: AsyncAuthenticator, certInfo: CertificateInfo) throws(TLSError) {
        switch self {
        case .serverEncryptedExtensions(let state):
            self = .awaitingCertificate(AwaitingCertificateState(originalState: state, asyncAuthenticator: asyncAuthenticator, certInfo: certInfo))
        default:
            preconditionFailure()
        }
    }

    mutating func sendingServerCertificate(withCertificates certificates: [Data], authDetails: AuthenticationDetails) throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .serverEncryptedExtensions(let state):
            let (newState, serverCertificateBytes) = try ServerCertificateState.sendingServerCertificate(originalState: state, withCertificates: certificates, authDetails: authDetails)
            self = .serverCertificate(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverCertificateBytes)
        case .awaitingCertificate(let state):
            let (newState, serverCertificateBytes) = try ServerCertificateState.sendingServerCertificate(originalState: state, withCertificates: certificates, authDetails: authDetails)
            self = .serverCertificate(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverCertificateBytes)
        default:
            preconditionFailure()
        }
    }

    mutating func awaitSignature(signatureInfo: SignatureInfo, keyScheduler: ServerSessionKeyManager<SHA384>, authProvider: AsyncAuthenticator) throws(TLSError) {
        switch self {
        case .serverCertificate(let state):
            self = .awaitingSignature(AwaitingSignatureState(originalState: state, signatureInfo: signatureInfo, keyScheduler: keyScheduler, asyncAuthenticator: authProvider))
        default:
            preconditionFailure()
        }
    }

    mutating func sendingServerCertificateVerify(keyScheduler: ServerSessionKeyManager<SHA384>, signatureAlgorithm: SignatureScheme, signatureData: Data) throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .serverCertificate(let state):
            let (newState, serverCertificateBytes) = try ServerCertificateVerifyState.sendingServerCertificateVerify(originalState: state, keyScheduler: keyScheduler, signatureAlgorithm: signatureAlgorithm, signatureData: signatureData)
            self = .serverCertificateVerify(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverCertificateBytes)
        case .awaitingSignature(let state):
            let (newState, serverCertificateBytes) = try ServerCertificateVerifyState.sendingServerCertificateVerify(originalState: state, keyScheduler: keyScheduler, signatureAlgorithm: signatureAlgorithm, signatureData: signatureData)
            self = .serverCertificateVerify(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverCertificateBytes)
        default:
            preconditionFailure()
        }
    }

    mutating func sendingServerFinished() throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .serverCertificateVerify(let state):
            let (newState, serverFinishedBytes) = try ServerFinishedState.sendingServerFinished(serverCertificateVerifyState: state)
            let serverSecret = newState.keyScheduler.serverApplicationTrafficSecret!
            self = .serverFinished(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverFinishedBytes, newWriteEncryptionLevel: .application(secret: serverSecret))
        case .serverEncryptedExtensions(let state):
            guard state.epskNegotiated else {
                preconditionFailure()
            }
            let (newState, serverFinishedBytes) = try ServerFinishedState.sendingServerFinished(serverEncryptedExtensionsState: state)
            let serverSecret = newState.keyScheduler.serverApplicationTrafficSecret!
            self = .serverFinished(newState)
            return PartialHandshakeResult(handshakeBytesToSend: serverFinishedBytes, newWriteEncryptionLevel: .application(secret: serverSecret))
        default:
            preconditionFailure()
        }
    }

    mutating func receivedClientFinished(_ clientFinished: FinishedMessage, bytes: ByteBuffer) throws(TLSError) -> PartialHandshakeResult {
        switch self {
        case .serverFinished(let state):
            let newState = try ReadyState.receivingClientFinished(originalState: state, clientFinished: clientFinished, clientFinishedBytes: bytes)
            self = .readyForData(newState)
            let clientSecret = newState.keyScheduler.clientApplicationTrafficSecret!
            return PartialHandshakeResult(newReadEncryptionLevel: .application(secret: clientSecret))
        case .clientCertificateVerify(let state):
            let newState = try ReadyState.receivingClientFinished(originalState: state, clientFinished: clientFinished, clientFinishedBytes: bytes)
            self = .readyForData(newState)
            let clientSecret = newState.keyScheduler.clientApplicationTrafficSecret!
            return PartialHandshakeResult(newReadEncryptionLevel: .application(secret: clientSecret))
        default:
            preconditionFailure()
        }
    }

    mutating func receivedClientCertificate(_ clientCertificate: CertificateMessage, bytes: ByteBuffer) throws(TLSError) {
        switch self {
        case .serverFinished(let state):
            let newState = try ClientCertificateState.init(originalState: state, clientCertificate: clientCertificate, clientCertificateBytes: bytes)
            self = .clientCertificate(newState)
        default:
            preconditionFailure()
        }
    }

    mutating func receivedClientCertificateVerify(_ clientCertificateVerify: CertificateVerify, bytes: ByteBuffer) throws(TLSError) {
        switch self {
        case .clientCertificate(let state):
            let newState = try ClientCertificateVerifyState.init(originalState: state, clientCertificateVerify: clientCertificateVerify, clientCertificateVerifyBytes: bytes)
            self = .clientCertificateVerify(newState)
        default:
            preconditionFailure()
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ServerHandshakeState {
    struct IdleState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let epsks: [GeneralEPSK]?
        let externalPSKSelectionCallback: externalPSKSelectionCallback?
        let transportIsQUIC: Bool

        init(
            configuration: ServerHandshakeStateMachine.Configuration
        ) {
            self.configuration = configuration
            self.keyScheduler = ServerSessionKeyManager()
            self.epsks = configuration.epsks
            self.externalPSKSelectionCallback = configuration.epskSelectionCallback
            self.transportIsQUIC = configuration.transportIsQUIC
        }

    }

    struct NegotiatedParams {
        let negotiatedGroup: NamedGroup
        let negotiatedSignatureAlgorithm: SignatureScheme
        let negotiatedCertificateType: CertificateType
    }

    struct ClientHelloVerifier {
        var observedExtensionTypes = Set<ExtensionType>()
        var clientKeyShares: [Extension.KeyShare.KeyShareEntry]? = nil
        var clientOfferedGroups: Extension.SupportedGroups? = nil
        var clientOfferedSupportedVersions: [ProtocolVersion]? = nil
        var clientOfferedSignatureAlgs: Extension.SignatureAlgorithms? = nil
        var clientRequestedServerCertificateTypes: [CertificateType]? = nil
        var clientRequestedClientCertificateTypes: [CertificateType]? = nil
        var clientRequestPSKKexModes: Extension.PreSharedKeyKexModes? = nil
        var clientQUICTransportParameters: ByteBuffer? = nil
        var clientALPN: [ApplicationLayerProtocol]? = nil
        var clientOfferedPSKs: Extension.PreSharedKey.OfferedPSKs? = nil
        var clientIndicatedEarlyData: Bool = false
        let serverSupportedGroups: [NamedGroup]
        let serverSupportedSignatureAlgs: [SignatureScheme] /* must include at least one element */
        let serverSupportedCertificateTypes: [CertificateType] /* must include at least one element */
        let serverSupportedClientCertificateTypes: [CertificateType] /* must include at least one element */
        let serverSupportedPSKKexModes: [Extension.PreSharedKeyKexModes.Mode]
        let serverSupportedPSKs: [GeneralEPSK]
        let useRawEPSKs: Bool
        let externalPSKSelectionCallback: externalPSKSelectionCallback?
        let transportIsQuic: Bool
        mutating func processExtension(_ ext: Extension) throws(TLSError) {
            let (inserted, _) = observedExtensionTypes.insert(ext.type)
            if !inserted {
                #if SWIFTTLS_EXCLAVECORE
                logger.error("client offered duplicate extension of type \(String(describing: ext.type)) on server hello")
                #else
                logger.error("client offered duplicate extension of type \(ext.type) on server hello")
                #endif
                throw TLSError.handshakeInvalidMessage
            }

            switch ext {
            case .supportedGroups(let offeredGroups):
                clientOfferedGroups = offeredGroups
            case .keyShare(.clientHello(let offeredKeyShares)):
                clientKeyShares = offeredKeyShares
            case .supportedVersions(.offer(let offeredVersions)):
                clientOfferedSupportedVersions = offeredVersions
            case .signatureAlgorithms(let offeredSignatureAlgs):
                clientOfferedSignatureAlgs = offeredSignatureAlgs
            case .serverCertificateType(.offer(let requestedCertificateTypes)):
                clientRequestedServerCertificateTypes = requestedCertificateTypes
            case .clientCertificateType(.offer(let requestedCertificateTypes)):
                clientRequestedClientCertificateTypes = requestedCertificateTypes
            case .preSharedKeyKexModes(let pskKexModes):
                clientRequestPSKKexModes = pskKexModes
            case .serverName(_):
                // pass. Currently never used by server so we don't bother storing it.
                // TODO: Flesh out when supporting session resumption/certificate selection.
                break
            case .quicTransportParameters(let transportParams):
                clientQUICTransportParameters = transportParams.opaqueOffer
            case .alpn(.offer(let alpnExt)):
                clientALPN = alpnExt
            case .ticketRequest(_):
                // TODO: handle ticket_request extension (RFC 9149)
                logger.warning("skipped processing ticket_request in CH")
            case .preSharedKey(.clientHello(let offeredPSKs)):
                clientOfferedPSKs = offeredPSKs
            case .earlyData(_):
                clientIndicatedEarlyData = true
            default:
                // skip unknown extensions
                #if SWIFTTLS_EXCLAVECORE
                logger.warning("skipped unknown/unsupported client extension with raw value \(String(describing: ext.type))")
                #else
                logger.warning("skipped unknown/unsupported client extension with raw value \(ext.type)")
                #endif
            }
        }

        struct negotiatedEPSKResult {
            let negotiatedPSK: GeneralEPSK
            let pskIndex: UInt16
            let binderValue: ByteBuffer
            let bindersArrayLength: Int
        }

        func negotiatePSK(externalPSKKDF: TLSKDFIdentifier) throws(TLSError) -> negotiatedEPSKResult? {
            if let clientOfferedPSKs {
                logger.debug("client offered psks, attempting to negotiate")
                guard let clientRequestPSKKexModes else {
                    // abort handshake if client sent
                    // pre_shared_key extension without also sending
                    // psk_key_exchange_modes extension
                    logger.error("client sent psk extension without psk_key_exchange_modes")
                    throw TLSError.missingPSKKeyExchangeModesExtension
                }
                guard clientRequestPSKKexModes.modes.contains(.pskAndDHE) else {
                    // ignore pre shared keys if client did not offer psk_dhe
                    logger.debug("server ignoring offered pre shared keys because it did not offer psk_dhe mode")
                    return nil
                }

                var offeredEPSKs: [SwiftOfferedEPSK] = [] // psks matching KDF that are possibilities for the selection block to choose
                var offeredEPSKIndices: [UInt16] = [] // their corresponding indices in the client offered list of psks

                guard clientOfferedPSKs.identities.count == clientOfferedPSKs.binders.count else {
                    logger.error("offered psk identities doesn't match number of binders")
                    throw TLSError.illegalParameter
                }

                var bindersArrayLength: Int = 0
                for binder in clientOfferedPSKs.binders {
                    bindersArrayLength += binder.serializedBinder.readableBytes + 1 // +1 for per-entry length prefix byte
                }

                for (i, pskIdentity) in clientOfferedPSKs.identities.enumerated() {
                    if pskIdentity.obfuscatedTicketAge != 0 {
                        // When we add resumption that should be tried first
                        logger.debug("psk has non 0 obfuscated ticket age. still attempting to treat as an epsk.")
                    }

                    // server only supports one or the other: raw or imported EPSKs. No mix and match.
                    if !useRawEPSKs {
                        // check if offered psk is an imported psk
                        if let importedIdentity = ImportedIdentity.getImportedIdentity(serialized: pskIdentity.identity.readableBytesSpan) {
                            for supportedPSK in serverSupportedPSKs {
                                // this checks the full serialized identity including KDF, context, and external identity
                                if supportedPSK.identity == pskIdentity.identity {
                                    // validation of binder value occurs later in Key Scheduler, serverCreate function
                                    return negotiatedEPSKResult(negotiatedPSK: supportedPSK,
                                                                pskIndex: UInt16(i),
                                                                binderValue: clientOfferedPSKs.binders[i].serializedBinder,
                                                                bindersArrayLength: bindersArrayLength)
                                }
                            }
                            // if it didn't match a pre-imported psk, store it to later pass to the external psk selection callback (if set)
                            offeredEPSKs.append(SwiftOfferedEPSK(external_identity: importedIdentity.externalIdentity, context: importedIdentity.context))
                            offeredEPSKIndices.append(UInt16(i))
                        }
                    } else {
                        // check if offered psk is a raw psk
                        for supportedPSK in serverSupportedPSKs {
                            if pskIdentity.identity == supportedPSK.identity {
                                return negotiatedEPSKResult(negotiatedPSK: supportedPSK,
                                                            pskIndex: UInt16(i),
                                                            binderValue: clientOfferedPSKs.binders[i].serializedBinder,
                                                            bindersArrayLength: bindersArrayLength)
                            }
                        }
                        // if it didn't match a pre-imported psk, store it to later pass to the external psk selection callback (if set)
                        offeredEPSKs.append(SwiftOfferedEPSK(external_identity: pskIdentity.identity, context: nil))
                        offeredEPSKIndices.append(UInt16(i))
                    }
                }

                var selectedPSK: GeneralEPSK? = nil // psk selected by the callback
                var selectedPSKIndex: UInt16? = nil // index of selected psk in client offered psks.
                if let externalPSKSelectionCallback = self.externalPSKSelectionCallback {
                    externalPSKSelectionCallback(offeredEPSKs, { i, epsk in
                        logger.debug("in server handshake state machine completion block... epsk == nil? \(epsk == nil) usingRawEPSKs: \(useRawEPSKs)")
                        guard let epsk else {
                            return
                        }
                        do throws(TLSError) {
                            selectedPSKIndex = offeredEPSKIndices[i];
                            if useRawEPSKs {
                                selectedPSK = GeneralEPSK(RawEPSK(identity: epsk.externalIdentity, epsk: epsk.epsk))
                            } else {
                                selectedPSK = GeneralEPSK(try epsk.deriveImportedPSKs(for: [externalPSKKDF])[0]);
                            }
                        } catch {
                            return
                        }
                    })
                }
                if let selectedPSK, let selectedPSKIndex {
                    logger.debug("epsk selected")
                    return negotiatedEPSKResult(negotiatedPSK: selectedPSK,
                            pskIndex: UInt16(selectedPSKIndex),
                            binderValue: clientOfferedPSKs.binders[Int(selectedPSKIndex)].serializedBinder,
                            bindersArrayLength: bindersArrayLength)
                }
            }
            return nil
        }

        private func validateSupportedVersions() throws(TLSError) {
            // supported_versions is required to indicate TLS 1.3
            guard let clientOfferedSupportedVersions else {
                logger.error("Client Hello without supported_versions extension received")
                throw TLSError.protocolVersion
            }

            guard clientOfferedSupportedVersions.contains(.tlsv13) else {
                logger.error("TLS 1.3 Client Hello missing TLS 1.3 version in supported_versions extension")
                throw TLSError.handshakeInvalidMessage
            }
        }

        private func validateSupportedGroups() throws(TLSError) {
            if clientOfferedGroups == nil {
                // required extension if using DHE or ECDHE key exchange
                logger.error("client hello missing required supported_groups extension")
                throw TLSError.missingExtension
            }
        }

        private func validateAndDetermineCertificateType() throws(TLSError) -> CertificateType {
            // Process server_certificate_type extension
            if let clientRequestedServerCertificateTypes, clientRequestedServerCertificateTypes.count > 0 {
                var commonServerCertType: CertificateType? = nil
                for certType in clientRequestedServerCertificateTypes {
                    if serverSupportedCertificateTypes.contains(certType) {
                        commonServerCertType = certType
                        break
                    }
                }

                // if server does not have any certificate type in common with the client,
                // server terminates the session with a fatal alert of type "unsupported_certificate"
                if commonServerCertType == nil {
                    logger.error("client requested unsupported server certificate type")
                    throw TLSError.unsupportedCertificate
                }
                return commonServerCertType!
            }
            return serverSupportedCertificateTypes[0]
        }

        private func validateSignatureAlgorithms(serverCertificateType: CertificateType) throws(TLSError) {
            if clientOfferedGroups == nil && serverCertificateType == .x509 {
                // if using certificate authentication signature_algorithms extension is required
                logger.error("client hello missing required signature_algorithms extension")
                throw TLSError.missingExtension
            }
        }

        private func validateKeyShares() throws(TLSError) {
            // key_shares extension required if using DHE or ECDHE key exchange
            guard let clientKeyShares else {
                logger.error("client hello missing required key_shares extension")
                throw TLSError.missingExtension
            }
            if clientKeyShares.isEmpty {
                logger.error("no client key shares")
                // TODO: send Hello Retry Request instead of failing
                throw TLSError.helloRetryRequestPlaceholder
            }
        }

        private func validatePSKKexModes() throws(TLSError) {
            // Process psk_key_exchange_modes extension
            // this determines the modes of psks the client supports
            // server must respect these when supplying a NewSessionTicket
            // currently only two options: psk_ke and psk_dhe_ke
            // psk_ke: server MUST NOT supply a "key_share" value
            // psk_dhe_ke: client and server MUST supply "key_share" values
            if let clientRequestPSKKexModes {
                for mode in clientRequestPSKKexModes.modes {
                    if serverSupportedPSKKexModes.contains(mode) {
                        // TODO: store for use when the server supports issuing session tickets
                        // (psk_dhe_ke is only supported value, enforced in `negotiatePSK`)
                    }
                }
            }
        }

        func negotiateSignatureAlgorithm() throws(TLSError) -> SignatureScheme? {
            // negotiate signature algorithm
            if let clientOfferedSignatureAlgs {
                var negotiatedSignatureAlgorithm: SignatureScheme? = nil
                for alg in clientOfferedSignatureAlgs.schemes {
                    if serverSupportedSignatureAlgs.contains(alg) {
                        negotiatedSignatureAlgorithm = alg
                        break
                    }
                }
                guard let negotiatedSignatureAlgorithm else {
                    logger.error("signature algorithm negotiation failed")
                    throw TLSError.negotiationFailed
                }
                return negotiatedSignatureAlgorithm
            } else {
                // default to server preferred signature algorithm if client did not send signature_algorithm extension
                return serverSupportedSignatureAlgs[0]
            }
        }

        func negotiateServerCertificateType() throws(TLSError) -> CertificateType? {
            var commonServerCertType: CertificateType? = nil
            // Process server_certificate_type extension
            if let clientRequestedServerCertificateTypes {
                for certType in clientRequestedServerCertificateTypes {
                    if serverSupportedCertificateTypes.contains(certType) {
                        commonServerCertType = certType
                        break
                    }
                }
            }
            return commonServerCertType
        }

        func negotiateClientCertificateType() throws(TLSError) -> CertificateType? {
            var commonClientCertType: CertificateType? = nil
            // Process client_certificate_type extension
            if let clientRequestedClientCertificateTypes {
                for certType in clientRequestedClientCertificateTypes {
                    if serverSupportedClientCertificateTypes.contains(certType) {
                        commonClientCertType = certType
                        break
                    }
                }
            }
            return commonClientCertType
        }

        func negotiateGroup() throws(TLSError) -> NamedGroup? {
            // negotiate key exchange "group"
            var negotiatedGroup: NamedGroup? = nil
            for grp in clientOfferedGroups!.groups {
                if serverSupportedGroups.contains(grp) {
                    negotiatedGroup = grp
                    break
                }
            }

            // fail if client sent supported_groups extension
            // but none of the offered groups are supported
            // by the client
            guard let negotiatedGroup else {
                logger.error("key exchange group negotiation failed")
                throw TLSError.negotiationFailed
            }
            return negotiatedGroup
        }

        func getClientKeyShare(_ negotiatedGroup: NamedGroup) throws(TLSError) -> Extension.KeyShare.KeyShareEntry {
            var clientKeyShare: Extension.KeyShare.KeyShareEntry?
            for keyShare in clientKeyShares! {
                if keyShare.group == negotiatedGroup {
                    clientKeyShare = keyShare
                }
            }

            guard let clientKeyShare else {
                logger.error("no client key share matching group received")
                // TODO: send Hello Retry Request instead of failing
                throw TLSError.helloRetryRequestPlaceholder
            }
            return clientKeyShare
        }

        func validateExtensions() throws(TLSError) {
            try validateSupportedVersions()
            try validateSupportedGroups()
            let serverCertificateType = try validateAndDetermineCertificateType()
            try validateSignatureAlgorithms(serverCertificateType: serverCertificateType)
            try validateKeyShares()
            try validatePSKKexModes()
        }

        func getALPNSelection(selfALPN: [ApplicationLayerProtocol]?) throws(TLSError) -> (ApplicationLayerProtocol, Int)? {
            logger.debug("server selecting ALPN protocol")
            guard let peerALPN = self.clientALPN, let selfALPN else {
                if self.transportIsQuic {
                    logger.error("quic requires alpn")
                    throw TLSError.noApplicationProtocol
                }
                return nil
            }
            for (i, peerProto) in peerALPN.enumerated() {
                for selfProto in selfALPN {
                    if selfProto.utf8.elementsEqual(peerProto.utf8) {
                        return (peerProto, i)
                    }
                }
            }
            // if the client and server have no application protocols in common
            // server should respond with a fatal "no_application_protocol"
            // alert.
            logger.error("alpn negotiation failed")
            throw TLSError.noApplicationProtocol
        }
    }

    struct ClientHelloState {
        let configuration: ServerHandshakeStateMachine.Configuration
        let keyScheduler: ServerSessionKeyManager<SHA384>
        let negotiatedCipherSuite: CipherSuite
        let negotiatedGroup: NamedGroup?
        let negotiatedSignatureAlgorithm: SignatureScheme?
        let negotiatedServerCertificateType: CertificateType?
        let negotiatedClientCertificateType: CertificateType?
        let clientKeyShare: Extension.KeyShare.KeyShareEntry?
        let ephemeralKey: GeneratedEphemeralPrivateKey?
        let sharedSecret: SymmetricKey
        let publicKeyShare: Data?
        let legacySessionIDEcho: LegacySessionID
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let pskNegotiationAttempted: Bool
        let selectedPSK: GeneralEPSK?
        let selectedPSKIndex: UInt16
        let earlyDataPermitted: Bool
        let transportIsQUIC: Bool
        let clientHello: ClientHello

        init(
            originalState idleState: IdleState,
            _ keyScheduler: ServerSessionKeyManager<SHA384>,
            _ negotiatedCipherSuite: CipherSuite,
            _ negotiatedGroup: NamedGroup?,
            _ negotiatedSignatureAlgorithm: SignatureScheme?,
            _ negotiatedServerCertificateType: CertificateType?,
            _ negotiatedClientCertificateType: CertificateType?,
            _ clientKeyShare: Extension.KeyShare.KeyShareEntry?,
            _ legacySessionIDEcho: LegacySessionID,
            _ ephemeralKey: GeneratedEphemeralPrivateKey?,
            _ sharedSecret: SymmetricKey,
            _ publicKeyShare: Data?,
            _ clientQUICTransportParameters: ByteBuffer?,
            _ selectedALPN: ApplicationLayerProtocol?,
            _ pskNegotiationAttempted: Bool,
            _ selectedPSK: GeneralEPSK?,
            _ selectedPSKIndex: UInt16,
            _ earlyDataPermitted: Bool,
            _ transportIsQUIC: Bool,
            _ clientHello: ClientHello
        ) {
            self.configuration = idleState.configuration
            self.keyScheduler = keyScheduler
            self.negotiatedCipherSuite = negotiatedCipherSuite
            self.negotiatedGroup = negotiatedGroup
            self.negotiatedSignatureAlgorithm = negotiatedSignatureAlgorithm
            self.negotiatedServerCertificateType = negotiatedServerCertificateType
            self.negotiatedClientCertificateType = negotiatedClientCertificateType
            self.clientKeyShare = clientKeyShare
            self.legacySessionIDEcho = legacySessionIDEcho
            self.ephemeralKey = ephemeralKey
            self.sharedSecret = sharedSecret
            self.publicKeyShare = publicKeyShare
            self.clientQUICTransportParameters = clientQUICTransportParameters
            self.selectedALPN = selectedALPN
            self.pskNegotiationAttempted = pskNegotiationAttempted
            self.selectedPSK = selectedPSK
            self.selectedPSKIndex = selectedPSKIndex
            self.earlyDataPermitted = earlyDataPermitted
            self.transportIsQUIC = transportIsQUIC
            self.clientHello = clientHello
        }

        private static func negotiateCipherSuite(_ clientCipherSuites: Array<CipherSuite>, _ serverSupportedCipherSuites: [CipherSuite]) throws(TLSError) -> CipherSuite {
            // negotiate ciphersuite
            var negotiatedCipherSuite: CipherSuite? = nil
            for cipherSuite in clientCipherSuites {
                if serverSupportedCipherSuites.contains(cipherSuite) {
                    negotiatedCipherSuite = cipherSuite
                    break
                }
            }

            // fail if client sent supported_groups extension
            // but none of the offered groups are supported
            // by the client
            guard let negotiatedCipherSuite else {
                logger.error("no common ciphersuites")
                throw TLSError.negotiationFailed
            }
            return negotiatedCipherSuite
        }

        static func readingClientHello(originalState idleState: IdleState, clientHello: ClientHello, clientHelloBytes: ByteBuffer, externalPSKSelectionCallback: externalPSKSelectionCallback?, transportIsQUIC: Bool) throws(TLSError) -> ClientHelloState {
            // ClientHello validation
            // Properties enforced:
            //
            // - legacy_version MUST be set to 0x0303 (TLSv1.2)
            // - supported_versions extension is present
            // - supported_versions extension includes 0x0304 (TLSv1.3)
            // - cipherSuites contains supported values
            // - legacy_compression_methods must contain one byte set to zero
            // - key_shares extension present (required for ECDHE or DHE key exchange)
            // - supported_groups extension present (required for ECDHE or DHE key exchange)
            // - supported_groups contains either secp384 or x25519 or x25519MLKEM768
            // - signature_algorithms extension is present if certificates are being used
            // - signature_algorithms contains .ecdsa_secp256r1_sha256
            // - if server_certificate_type extension present it contains a server supported type
            // - key_shares contains a key share for negotiated group
            // - quic_transport_params is required since SwiftTLS is currently only used with QUIC
            // - does not require server_name extension, but checks it is properly formatted if present
            // - TODO: HRR Support
            guard clientHello.legacyVersion == .tlsv12,
                  clientHello.legacyCompressionMethods == [0] else {
                #if SWIFTTLS_EXCLAVECORE
                logger.error("client hello legacy version and/or legacy compression methods incorrect. version expected \(String(describing: ProtocolVersion.tlsv12)), got \(String(describing:clientHello.legacyVersion)), legacy compression methods expected [0], got array of length \(clientHello.legacyCompressionMethods.count) with first value == 0? \(clientHello.legacyCompressionMethods.count > 0 ? clientHello.legacyCompressionMethods[0] == 0 : false).")
                #else
                logger.error("client hello legacy version and/or legacy compression methods incorrect. version expected \(ProtocolVersion.tlsv12), got \(clientHello.legacyVersion), legacy compression methods expected [0], got array of length \(clientHello.legacyCompressionMethods.count) with first value == 0? \(clientHello.legacyCompressionMethods.count > 0 ? clientHello.legacyCompressionMethods[0] == 0 : false).")
                #endif
                throw TLSError.handshakeInvalidMessage
            }

            var serverSupportedCertificateTypes: [CertificateType] = []
            if let authenticator = idleState.configuration.asyncAuthenticator {
                serverSupportedCertificateTypes = authenticator.supportedCertificateTypes
            } else if case .offer(let availableCertTypes) = PeerCertificateBundle.availableCertificateTypes {
                serverSupportedCertificateTypes = availableCertTypes
            }

            var serverSupportedClientCertificateTypes: [CertificateType] = []
            if case .offer(let verifyCertTypes) = PeerCertificateBundle.verificationCertificateTypes {
                serverSupportedClientCertificateTypes = verifyCertTypes
            }

            // TODO: add server config for signature algorithms, certificate types
            var clientHelloVerifier = ClientHelloVerifier(
                serverSupportedGroups: [.x25519MLKEM768, .secp384, .x25519],
                serverSupportedSignatureAlgs: [.ecdsa_secp256r1_sha256],
                serverSupportedCertificateTypes: serverSupportedCertificateTypes,
                serverSupportedClientCertificateTypes: serverSupportedClientCertificateTypes,
                serverSupportedPSKKexModes: [.pskAndDHE],
                serverSupportedPSKs: idleState.epsks ?? [],
                useRawEPSKs: idleState.configuration.useRawEPSKs,
                externalPSKSelectionCallback: externalPSKSelectionCallback,
                transportIsQuic: transportIsQUIC
            )

            for ext in clientHello.extensions {
                try clientHelloVerifier.processExtension(ext)
            }

            try clientHelloVerifier.validateExtensions()

            let serverSupportedCipherSuites: [CipherSuite]
            if let configuredCipherSuites = idleState.configuration.supportedCipherSuites {
                serverSupportedCipherSuites = configuredCipherSuites
            } else {
                serverSupportedCipherSuites = [.TLS_AES_256_GCM_SHA384]
            }

            // Negotiate ciphersuite - this always happens
            let negotiatedCipherSuite = try negotiateCipherSuite(clientHello.cipherSuites, serverSupportedCipherSuites)

            // Non-nil ONLY if the client sent a server certificate type extension and the server negotiated a common one
            let negotiatedServerCertificateType = try clientHelloVerifier.negotiateServerCertificateType()

            // Non-nil ONLY if the client sent a client_certificate_type extension and the server negotiated a common one
            let negotiatedClientCertificateType = try clientHelloVerifier.negotiateClientCertificateType()
            // if the server requires client auth and needs a raw public key then it needs this to be negotiated to raw public key
            if idleState.configuration.clientAuthRequired &&
                clientHelloVerifier.serverSupportedClientCertificateTypes == [.rawPublicKey] {
                guard let negotiatedClientCertificateType, negotiatedClientCertificateType == .rawPublicKey else {
                    logger.error("server requires the client to authenticate with raw public keys, but client did not indicate support. Failing.")
                    throw TLSError.handshakeFailure
                }
            }

            // Negotiate group, signature algorithm
            let negotiatedGroup = try clientHelloVerifier.negotiateGroup()
            var negotiatedSignatureAlgorithm: SignatureScheme? = nil
            // If configured, the auth provider is responsible to choose the signature algorithms.
            if idleState.configuration.asyncAuthenticator == nil {
                negotiatedSignatureAlgorithm = try clientHelloVerifier.negotiateSignatureAlgorithm()
            }
            var clientKeyShare: Extension.KeyShare.KeyShareEntry?
            if let negotiatedGroup {
                clientKeyShare = try clientHelloVerifier.getClientKeyShare(negotiatedGroup)
            }

            // Try to negotiate PSKs
            let pskNegotiationAttempted = clientHelloVerifier.clientOfferedPSKs != nil

            // negotiatedCipherSuite uniquely identifies KDF of an imported psk
            let externalPSKKDF = try TLSKDFIdentifier.cipherSuiteToKDFIdentifier(cipherSuite: negotiatedCipherSuite)
            let negotiatedPSKResult = try clientHelloVerifier.negotiatePSK(externalPSKKDF: externalPSKKDF)

            let alpnSelectionResult = try clientHelloVerifier.getALPNSelection(selfALPN: idleState.configuration.alpn)

            // Check conditions for early data:
            // if the server is configured to allow early data,
            // negotiatedPSK != nil, pskIndex == 0, clientIndicatedEarlyData (sent early data extension), and
            // if ALPN selection is the first protocol offered by client then then server should accept early data.
            var earlyDataPermitted: Bool = false
            if clientHelloVerifier.clientIndicatedEarlyData && idleState.configuration.enableEarlyData {
                logger.debug("Client requested early data and server configured to allow early data. Checking conditions...")
                if  let negotiatedPSKResult, negotiatedPSKResult.pskIndex == 0 {
                    logger.debug("A PSK compatible with early data was negotiated. Continuing checks...")
                    if clientHelloVerifier.clientALPN != nil {
                        // client attempted to negotiate ALPN so early data corresponds to app protocol at index 0
                        if alpnSelectionResult?.1 == 0 {
                            logger.debug("Server supports ALPN protocol associated with early data. Accepting early data.")
                            earlyDataPermitted = true
                        } else {
                            logger.debug("Server does not support the ALPN protocol associated with early data. Rejecting early data.")
                        }
                    }
                    // Currently if no ALPN negotiated, early data not allowed. ALPN is always used with QUIC and we only support
                    // early data with QUIC right now, but this is a gap.
                } else {
                    logger.debug("Early data not authorized: \(negotiatedPSKResult == nil ? "psk not negotiated" : "negotiated psk at index != 0")")
                }
            }

            // Values set during normal key-exchange
            var ephemeralKeyShare: GeneratedEphemeralPrivateKey?
            var publicKeyShare: Data?

            // Shared secret, set by either method
            let sharedSecret: SymmetricKey
            
            // Decide how we will establish a shared secret (normal key exchange currently)
            if let negotiatedGroup, let clientKeyShare {
                // Normal key-exchange
                guard let generatedKey = generateEphemeralKeyForNamedGroup(negotiatedGroup) else {
                    logger.error("Failed to generate ephemeral key for negotiated group: \(String(describing: negotiatedGroup))")
                    throw TLSError.handshakeError
                }
                ephemeralKeyShare = generatedKey
                (publicKeyShare, sharedSecret) = try ephemeralKeyShare!.encap(publicKeyData: clientKeyShare.keyExchange.readableBytesView)
            } else {
                logger.error("no group negotiated")
                throw TLSError.handshakeError
            }

            var keyScheduler = idleState.keyScheduler

            try keyScheduler.postClientHello(clientHelloBytes: clientHelloBytes, negotiatedPSK: negotiatedPSKResult?.negotiatedPSK, binderValue: negotiatedPSKResult?.binderValue, bindersArrayLength: negotiatedPSKResult?.bindersArrayLength, useRawEPSKs: idleState.configuration.useRawEPSKs)

            let newState = Self(
                originalState: idleState,
                keyScheduler,
                negotiatedCipherSuite,
                negotiatedGroup,
                negotiatedSignatureAlgorithm,
                negotiatedServerCertificateType,
                negotiatedClientCertificateType,
                clientKeyShare,
                clientHello.legacySessionID,
                ephemeralKeyShare,
                sharedSecret,
                publicKeyShare,
                clientHelloVerifier.clientQUICTransportParameters,
                alpnSelectionResult?.0,
                pskNegotiationAttempted,
                negotiatedPSKResult?.negotiatedPSK,
                negotiatedPSKResult?.pskIndex ?? 0,
                earlyDataPermitted,
                transportIsQUIC,
                clientHello
            )

            return newState
        }
    }

    struct ServerHelloState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        var negotiatedSignatureAlgorithm: SignatureScheme?
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let epskNegotiated: Bool
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let negotiatedServerCertificateType: CertificateType?
        let negotiatedClientCertificateType: CertificateType?
        let pskNegotiationAttempted: Bool
        let clientOffer: PeerOffer

        init(originalState clientHelloState: ClientHelloState, keyScheduler: ServerSessionKeyManager<SHA384>) {
            self.configuration = clientHelloState.configuration
            self.keyScheduler = keyScheduler
            self.negotiatedSignatureAlgorithm = clientHelloState.negotiatedSignatureAlgorithm
            self.clientQUICTransportParameters = clientHelloState.clientQUICTransportParameters
            self.selectedALPN = clientHelloState.selectedALPN
            self.negotiatedCiphersuite = clientHelloState.negotiatedCipherSuite
            self.epskNegotiated = clientHelloState.selectedPSK != nil
            self.earlyDataPermitted = clientHelloState.earlyDataPermitted
            self.negotiatedGroup = clientHelloState.negotiatedGroup
            self.pskNegotiationAttempted = clientHelloState.pskNegotiationAttempted
            self.negotiatedServerCertificateType = clientHelloState.negotiatedServerCertificateType
            self.negotiatedClientCertificateType = clientHelloState.negotiatedClientCertificateType
            self.clientOffer = PeerOffer(clientHello: clientHelloState.clientHello)
        }

        static func sendingServerHello(originalState clientHelloState: ClientHelloState, serverHello: ServerHello) throws(TLSError) -> (state: ServerHelloState, serverHelloBytes: ByteBuffer) {
            var keyScheduler = clientHelloState.keyScheduler
            let pskFailed = clientHelloState.selectedPSK == nil && clientHelloState.pskNegotiationAttempted
            logger.debug("selectedPSK? = \(clientHelloState.selectedPSK != nil), pskNegotiationAttempted? = \(clientHelloState.pskNegotiationAttempted), useRawEPSKs? = \(clientHelloState.configuration.useRawEPSKs)")

            let serverHelloBytes = try keyScheduler.sendingServerHello(serverHello: serverHello, ecdheSecret: .init(data: clientHelloState.sharedSecret), pskFailed: pskFailed)
            let newState = Self(originalState: clientHelloState, keyScheduler: keyScheduler)

            return (newState, serverHelloBytes)
        }
    }

    struct ServerEncryptedExtensionsState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let negotiatedSignatureAlgorithm: SignatureScheme?
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let epskNegotiated: Bool
        let earlyDataPermitted: Bool
        let negotiatedClientCertificateType: CertificateType?
        let negotiatedGroup: NamedGroup?
        let pskNegotiationAttempted: Bool
        let clientOffer: PeerOffer

        init(originalState serverHelloState: ServerHelloState, keyScheduler: ServerSessionKeyManager<SHA384>) {
            self.configuration = serverHelloState.configuration
            self.keyScheduler = keyScheduler
            self.negotiatedSignatureAlgorithm = serverHelloState.negotiatedSignatureAlgorithm
            self.clientQUICTransportParameters = serverHelloState.clientQUICTransportParameters
            self.selectedALPN = serverHelloState.selectedALPN
            self.negotiatedCiphersuite = serverHelloState.negotiatedCiphersuite
            self.epskNegotiated = serverHelloState.epskNegotiated
            self.earlyDataPermitted = serverHelloState.earlyDataPermitted
            self.negotiatedGroup = serverHelloState.negotiatedGroup
            self.pskNegotiationAttempted = serverHelloState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = serverHelloState.negotiatedClientCertificateType
            self.clientOffer = serverHelloState.clientOffer
        }

        static func sendingServerEncryptedExtensions(originalState serverHelloState: ServerHelloState, serverEncryptedExtensions: EncryptedExtensions)
            throws(TLSError) -> (state: ServerEncryptedExtensionsState, serverEncryptedExtensionsBytes: ByteBuffer) {
            var keyScheduler = serverHelloState.keyScheduler
            var serverEncryptedExtensionsBytes = ByteBuffer()
            serverEncryptedExtensionsBytes.writeHandshakeMessage(serverEncryptedExtensions)
            try keyScheduler.addPreFinishedMessageToTransportHash(serverEncryptedExtensionsBytes)
            let newState = Self(originalState: serverHelloState, keyScheduler: keyScheduler)
            return (newState, serverEncryptedExtensionsBytes)

        }
    }

    struct ServerCertificateRequestState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let negotiatedSignatureAlgorithm: SignatureScheme?
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let pskNegotiationAttempted: Bool
        let negotiatedClientCertificateType: CertificateType?
        let clientOffer: PeerOffer

        init(originalState serverEncryptedExtensionsState: ServerEncryptedExtensionsState, keyScheduler: ServerSessionKeyManager<SHA384>) {
            self.configuration = serverEncryptedExtensionsState.configuration
            self.keyScheduler = keyScheduler
            self.negotiatedSignatureAlgorithm = serverEncryptedExtensionsState.negotiatedSignatureAlgorithm
            self.clientQUICTransportParameters = serverEncryptedExtensionsState.clientQUICTransportParameters
            self.selectedALPN = serverEncryptedExtensionsState.selectedALPN
            self.negotiatedCiphersuite = serverEncryptedExtensionsState.negotiatedCiphersuite
            self.earlyDataPermitted = serverEncryptedExtensionsState.earlyDataPermitted
            self.negotiatedGroup = serverEncryptedExtensionsState.negotiatedGroup
            self.pskNegotiationAttempted = serverEncryptedExtensionsState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = serverEncryptedExtensionsState.negotiatedClientCertificateType
            self.clientOffer = serverEncryptedExtensionsState.clientOffer
        }

        static func sendingServerCertificateRequest(originalState serverEncryptedExtensionsState: ServerEncryptedExtensionsState)
            throws(TLSError) -> (state: ServerCertificateRequestState, serverCertificateRequestBytes: ByteBuffer) {
            guard serverEncryptedExtensionsState.configuration.clientAuthRequired else {
                logger.error("sendingServerCertificateRequest called when not configured to ask for client auth.")
                throw TLSError.internalError(reason: "sendingServerCertificateRequest called unexpectedly")
            }
            // TODO: when server resumption support added, also check for resumption not just epsks
            guard serverEncryptedExtensionsState.epskNegotiated == false else {
                logger.error("sendingServerCertificateRequest called when psk negotiated.")
                throw TLSError.internalError(reason: "sendingServerCertificateRequest called unexpectedly when psk negotiated")
            }
            var keyScheduler = serverEncryptedExtensionsState.keyScheduler
            let signatureAlgorithmsExt = Extension.SignatureAlgorithms(schemes: [.ecdsa_secp256r1_sha256])
            let serverCertificateRequestMessage = CertificateRequest(certificateRequestContext: ByteBuffer(),
                                                                     extensions: [
                                                                        .signatureAlgorithms(signatureAlgorithmsExt),
                                                                     ])
            var serverCertificateRequestBytes = ByteBuffer()
            serverCertificateRequestBytes.writeHandshakeMessage(serverCertificateRequestMessage)
            try keyScheduler.addPreFinishedMessageToTransportHash(serverCertificateRequestBytes)
            let newState = Self(originalState: serverEncryptedExtensionsState, keyScheduler: keyScheduler)
            return (newState, serverCertificateRequestBytes)
        }
    }

    struct AwaitingCertificateState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let negotiatedSignatureAlgorithm: SignatureScheme?
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let pskNegotiationAttempted: Bool
        let negotiatedClientCertificateType: CertificateType?
        let certInfo: CertificateInfo
        let asyncAuthenticator: AsyncAuthenticator

        init(originalState serverEncryptedExtensionsState: ServerEncryptedExtensionsState, asyncAuthenticator: AsyncAuthenticator, certInfo: CertificateInfo) {
            self.configuration = serverEncryptedExtensionsState.configuration
            self.keyScheduler = serverEncryptedExtensionsState.keyScheduler
            self.negotiatedSignatureAlgorithm = serverEncryptedExtensionsState.negotiatedSignatureAlgorithm
            self.clientQUICTransportParameters = serverEncryptedExtensionsState.clientQUICTransportParameters
            self.selectedALPN = serverEncryptedExtensionsState.selectedALPN
            self.negotiatedCiphersuite = serverEncryptedExtensionsState.negotiatedCiphersuite
            self.earlyDataPermitted = serverEncryptedExtensionsState.earlyDataPermitted
            self.negotiatedGroup = serverEncryptedExtensionsState.negotiatedGroup
            self.pskNegotiationAttempted = serverEncryptedExtensionsState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = serverEncryptedExtensionsState.negotiatedClientCertificateType
            self.certInfo = certInfo
            self.asyncAuthenticator = asyncAuthenticator
        }

        init(originalState serverCertificateRequestState: ServerCertificateRequestState, asyncAuthenticator: AsyncAuthenticator, certInfo: CertificateInfo) {
            self.configuration = serverCertificateRequestState.configuration
            self.keyScheduler = serverCertificateRequestState.keyScheduler
            self.negotiatedSignatureAlgorithm = serverCertificateRequestState.negotiatedSignatureAlgorithm
            self.clientQUICTransportParameters = serverCertificateRequestState.clientQUICTransportParameters
            self.selectedALPN = serverCertificateRequestState.selectedALPN
            self.negotiatedCiphersuite = serverCertificateRequestState.negotiatedCiphersuite
            self.earlyDataPermitted = serverCertificateRequestState.earlyDataPermitted
            self.negotiatedGroup = serverCertificateRequestState.negotiatedGroup
            self.pskNegotiationAttempted = serverCertificateRequestState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = serverCertificateRequestState.negotiatedClientCertificateType
            self.certInfo = certInfo
            self.asyncAuthenticator = asyncAuthenticator
        }
    }

    struct ServerCertificateState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let negotiatedSignatureAlgorithm: SignatureScheme?
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let pskNegotiationAttempted: Bool
        let negotiatedClientCertificateType: CertificateType?
        let clientOffer: PeerOffer
        let authenticationDetails: AuthenticationDetails

        init(originalState serverEncryptedExtensionsState: ServerEncryptedExtensionsState, keyScheduler: ServerSessionKeyManager<SHA384>, authenticationDetails: AuthenticationDetails) {
            self.configuration = serverEncryptedExtensionsState.configuration
            self.keyScheduler = keyScheduler
            self.negotiatedSignatureAlgorithm = serverEncryptedExtensionsState.negotiatedSignatureAlgorithm
            self.clientQUICTransportParameters = serverEncryptedExtensionsState.clientQUICTransportParameters
            self.selectedALPN = serverEncryptedExtensionsState.selectedALPN
            self.negotiatedCiphersuite = serverEncryptedExtensionsState.negotiatedCiphersuite
            self.earlyDataPermitted = serverEncryptedExtensionsState.earlyDataPermitted
            self.negotiatedGroup = serverEncryptedExtensionsState.negotiatedGroup
            self.pskNegotiationAttempted = serverEncryptedExtensionsState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = serverEncryptedExtensionsState.negotiatedClientCertificateType
            self.clientOffer = serverEncryptedExtensionsState.clientOffer
            self.authenticationDetails = authenticationDetails
        }

        init(originalState serverCertificateRequestState: ServerCertificateRequestState, keyScheduler: ServerSessionKeyManager<SHA384>, authenticationDetails: AuthenticationDetails) {
            self.configuration = serverCertificateRequestState.configuration
            self.keyScheduler = keyScheduler
            self.negotiatedSignatureAlgorithm = serverCertificateRequestState.negotiatedSignatureAlgorithm
            self.clientQUICTransportParameters = serverCertificateRequestState.clientQUICTransportParameters
            self.selectedALPN = serverCertificateRequestState.selectedALPN
            self.negotiatedCiphersuite = serverCertificateRequestState.negotiatedCiphersuite
            self.earlyDataPermitted = serverCertificateRequestState.earlyDataPermitted
            self.negotiatedGroup = serverCertificateRequestState.negotiatedGroup
            self.pskNegotiationAttempted = serverCertificateRequestState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = serverCertificateRequestState.negotiatedClientCertificateType
            self.clientOffer = serverCertificateRequestState.clientOffer
            self.authenticationDetails = authenticationDetails
        }

        init(originalState awaitingCertificateState: AwaitingCertificateState, keyScheduler: ServerSessionKeyManager<SHA384>, authenticationDetails: AuthenticationDetails) {
            self.configuration = awaitingCertificateState.configuration
            self.keyScheduler = keyScheduler
            self.negotiatedSignatureAlgorithm = awaitingCertificateState.negotiatedSignatureAlgorithm
            self.clientQUICTransportParameters = awaitingCertificateState.clientQUICTransportParameters
            self.selectedALPN = awaitingCertificateState.selectedALPN
            self.negotiatedCiphersuite = awaitingCertificateState.negotiatedCiphersuite
            self.earlyDataPermitted = awaitingCertificateState.earlyDataPermitted
            self.negotiatedGroup = awaitingCertificateState.negotiatedGroup
            self.pskNegotiationAttempted = awaitingCertificateState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = awaitingCertificateState.negotiatedClientCertificateType
            self.clientOffer = awaitingCertificateState.certInfo.peerOffer
            self.authenticationDetails = authenticationDetails
        }

        // Build the CertificateMessage
        static func buildCertificateMessage(configuration: ServerHandshakeStateMachine.Configuration, keyScheduler: inout ServerSessionKeyManager<SHA384>, certificateList: [CertificateMessage.CertificateEntry]) throws(TLSError) -> ByteBuffer {
            let serverCertificateMessage = CertificateMessage(
                certificateRequestContext: ByteBuffer(),
                certificateList: certificateList
            )
            var serverCertificateBytes = ByteBuffer()
            serverCertificateBytes.writeHandshakeMessage(serverCertificateMessage)
            try keyScheduler.addPreFinishedMessageToTransportHash(serverCertificateBytes)
            return serverCertificateBytes
        }

        // can get to this state from ServerCertificateRequestState
        static func sendingServerCertificate(originalState serverCertificateRequestState: ServerCertificateRequestState, withCertificates certificates: [Data], authDetails: AuthenticationDetails)
            throws(TLSError) -> (state: ServerCertificateState, serverCertificateBytes: ByteBuffer) {
            var keyScheduler = serverCertificateRequestState.keyScheduler
            let serverCertificateBytes = try self.buildCertificateMessage(
                configuration: serverCertificateRequestState.configuration,
                keyScheduler: &keyScheduler,
                certificateList: certificates.map {
                    CertificateMessage.CertificateEntry(opaqueCertificateData: ByteBuffer(data: $0), extensions: [])
                }
            )
            let newState = Self(originalState: serverCertificateRequestState, keyScheduler: keyScheduler, authenticationDetails: authDetails)
            return (newState, serverCertificateBytes)
        }

        static func sendingServerCertificate(originalState serverCertificateRequestState: ServerCertificateRequestState, withRawPublicKey serverKey: Data, authDetails: AuthenticationDetails)
            throws(TLSError) -> (state: ServerCertificateState, serverCertificateBytes: ByteBuffer) {
            var keyScheduler = serverCertificateRequestState.keyScheduler
            let serverCertificateBytes = try self.buildCertificateMessage(
                configuration: serverCertificateRequestState.configuration,
                keyScheduler: &keyScheduler,
                certificateList: [.init(opaqueCertificateData: ByteBuffer(data: serverKey), extensions: [])]
            )
            let newState = Self(originalState: serverCertificateRequestState, keyScheduler: keyScheduler, authenticationDetails: authDetails)
            return (newState, serverCertificateBytes)
        }

        // or directly from ServerEncryptedExtensionsState if not doing client auth
        static func sendingServerCertificate(originalState serverEncryptedExtensionsState: ServerEncryptedExtensionsState, withCertificates certificates: [Data], authDetails: AuthenticationDetails)
            throws(TLSError) -> (state: ServerCertificateState, serverCertificateBytes: ByteBuffer) {
            var keyScheduler = serverEncryptedExtensionsState.keyScheduler
            let serverCertificateBytes = try self.buildCertificateMessage(
                configuration: serverEncryptedExtensionsState.configuration,
                keyScheduler: &keyScheduler,
                certificateList: certificates.map {
                    CertificateMessage.CertificateEntry(opaqueCertificateData: ByteBuffer(data: $0), extensions: [])
                }
            )
            let newState = Self(originalState: serverEncryptedExtensionsState, keyScheduler: keyScheduler, authenticationDetails: authDetails)
            return (newState, serverCertificateBytes)
        }

        static func sendingServerCertificate(originalState serverEncryptedExtensionsState: ServerEncryptedExtensionsState, withRawPublicKey serverKey: Data, authDetails: AuthenticationDetails) throws(TLSError) -> (state: ServerCertificateState, serverCertificateBytes: ByteBuffer) {
            var keyScheduler = serverEncryptedExtensionsState.keyScheduler
            let serverCertificateBytes = try self.buildCertificateMessage(
                configuration: serverEncryptedExtensionsState.configuration,
                keyScheduler: &keyScheduler,
                certificateList: [.init(opaqueCertificateData: ByteBuffer(data: serverKey), extensions: [])]
            )
            let newState = Self(originalState: serverEncryptedExtensionsState, keyScheduler: keyScheduler, authenticationDetails: authDetails)
            return (newState, serverCertificateBytes)
        }

        // ... or after waiting for certificates when waiting for callback
        static func sendingServerCertificate(originalState awaitingCertificateState: AwaitingCertificateState, withCertificates certificates: [Data], authDetails: AuthenticationDetails)
            throws(TLSError) -> (state: ServerCertificateState, serverCertificateBytes: ByteBuffer) {
            var keyScheduler = awaitingCertificateState.keyScheduler
            let serverCertificateBytes = try self.buildCertificateMessage(
                configuration: awaitingCertificateState.configuration,
                keyScheduler: &keyScheduler,
                certificateList: certificates.map {
                    CertificateMessage.CertificateEntry(opaqueCertificateData: ByteBuffer(data: $0), extensions: [])
                }
            )
            let newState = Self(originalState: awaitingCertificateState, keyScheduler: keyScheduler, authenticationDetails: authDetails)
            return (newState, serverCertificateBytes)
        }

        static func sendingServerCertificate(originalState awaitingCertificateState: AwaitingCertificateState, withRawPublicKey serverKey: Data, authDetails: AuthenticationDetails)
            throws(TLSError) -> (state: ServerCertificateState, serverCertificateBytes: ByteBuffer) {
            var keyScheduler = awaitingCertificateState.keyScheduler
            let serverCertificateBytes = try self.buildCertificateMessage(
                configuration: awaitingCertificateState.configuration,
                keyScheduler: &keyScheduler,
                certificateList: [.init(opaqueCertificateData: ByteBuffer(data: serverKey), extensions: [])]
            )
            let newState = Self(originalState: awaitingCertificateState, keyScheduler: keyScheduler, authenticationDetails: authDetails)
            return (newState, serverCertificateBytes)
        }
    }

    struct AwaitingSignatureState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let negotiatedSignatureAlgorithm: SignatureScheme?
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let pskNegotiationAttempted: Bool
        let signatureInfo: SignatureInfo
        let asyncAuthenticator: AsyncAuthenticator
        let negotiatedClientCertificateType: CertificateType?

        init(originalState serverCertificateState: ServerCertificateState, signatureInfo: SignatureInfo, keyScheduler: ServerSessionKeyManager<SHA384>, asyncAuthenticator: AsyncAuthenticator) {
            self.configuration = serverCertificateState.configuration
            self.keyScheduler = keyScheduler
            self.negotiatedSignatureAlgorithm = serverCertificateState.negotiatedSignatureAlgorithm
            self.clientQUICTransportParameters = serverCertificateState.clientQUICTransportParameters
            self.selectedALPN = serverCertificateState.selectedALPN
            self.negotiatedCiphersuite = serverCertificateState.negotiatedCiphersuite
            self.earlyDataPermitted = serverCertificateState.earlyDataPermitted
            self.negotiatedGroup = serverCertificateState.negotiatedGroup
            self.pskNegotiationAttempted = serverCertificateState.pskNegotiationAttempted
            self.asyncAuthenticator = asyncAuthenticator
            self.signatureInfo = signatureInfo
            self.negotiatedClientCertificateType = serverCertificateState.negotiatedClientCertificateType
        }
    }


    struct ServerCertificateVerifyState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let clientQUICTransportParameters: ByteBuffer?
        var selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let pskNegotiationAttempted: Bool
        let negotiatedClientCertificateType: CertificateType?

        init(originalState serverCertificateState: ServerCertificateState, keyScheduler: ServerSessionKeyManager<SHA384>) {
            self.configuration = serverCertificateState.configuration
            self.keyScheduler = keyScheduler
            self.clientQUICTransportParameters = serverCertificateState.clientQUICTransportParameters
            self.selectedALPN = serverCertificateState.selectedALPN
            self.negotiatedCiphersuite = serverCertificateState.negotiatedCiphersuite
            self.earlyDataPermitted = serverCertificateState.earlyDataPermitted
            self.negotiatedGroup = serverCertificateState.negotiatedGroup
            self.pskNegotiationAttempted = serverCertificateState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = serverCertificateState.negotiatedClientCertificateType
        }

        init(originalState awaitingSignatureState: AwaitingSignatureState, keyScheduler: ServerSessionKeyManager<SHA384>) {
            self.configuration = awaitingSignatureState.configuration
            self.keyScheduler = keyScheduler
            self.clientQUICTransportParameters = awaitingSignatureState.clientQUICTransportParameters
            self.selectedALPN = awaitingSignatureState.selectedALPN
            self.negotiatedCiphersuite = awaitingSignatureState.negotiatedCiphersuite
            self.earlyDataPermitted = awaitingSignatureState.earlyDataPermitted
            self.negotiatedGroup = awaitingSignatureState.negotiatedGroup
            self.pskNegotiationAttempted = awaitingSignatureState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = awaitingSignatureState.negotiatedClientCertificateType
        }

        static func sendingServerCertificateVerify(originalState serverCertificateState: ServerCertificateState, keyScheduler: ServerSessionKeyManager<SHA384>, signatureAlgorithm negotiatedSignatureAlgorithm: SignatureScheme, signatureData signature: Data)
            throws(TLSError) -> (state: ServerCertificateVerifyState, serverCertificateVerifyBytes: ByteBuffer)
        {
            let serverCertificateVerifyMessage = CertificateVerify(
                algorithm: negotiatedSignatureAlgorithm,
                signature: ByteBuffer(data: signature)
            )
            var serverCertificateVerifyBytes = ByteBuffer()
            serverCertificateVerifyBytes.writeHandshakeMessage(serverCertificateVerifyMessage)
            var keyScheduler = keyScheduler
            try keyScheduler.addPreFinishedMessageToTransportHash(serverCertificateVerifyBytes)
            let newState = Self(originalState: serverCertificateState, keyScheduler: keyScheduler)
            return (newState, serverCertificateVerifyBytes)
        }

        static func sendingServerCertificateVerify(originalState awaitingSignatureState: AwaitingSignatureState, keyScheduler: ServerSessionKeyManager<SHA384>, signatureAlgorithm negotiatedSignatureAlgorithm: SignatureScheme, signatureData signature: Data)
            throws(TLSError) -> (state: ServerCertificateVerifyState, serverCertificateVerifyBytes: ByteBuffer)
        {
            let serverCertificateVerifyMessage = CertificateVerify(
                algorithm: negotiatedSignatureAlgorithm,
                signature: ByteBuffer(data: signature)
            )

            var serverCertificateVerifyBytes = ByteBuffer()
            serverCertificateVerifyBytes.writeHandshakeMessage(serverCertificateVerifyMessage)
            var keyScheduler = keyScheduler
            try keyScheduler.addPreFinishedMessageToTransportHash(serverCertificateVerifyBytes)
            let newState = Self(originalState: awaitingSignatureState, keyScheduler: keyScheduler)
            return (newState, serverCertificateVerifyBytes)
        }
    }

    struct ServerFinishedState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let epskNegotiated: Bool
        let pskNegotiationAttempted: Bool
        let negotiatedClientCertificateType: CertificateType?

        init(originalState serverCertificateVerifyState: ServerCertificateVerifyState, keyScheduler: ServerSessionKeyManager<SHA384>) {
            self.configuration = serverCertificateVerifyState.configuration
            self.keyScheduler = keyScheduler
            self.clientQUICTransportParameters = serverCertificateVerifyState.clientQUICTransportParameters
            self.selectedALPN = serverCertificateVerifyState.selectedALPN
            self.negotiatedCiphersuite = serverCertificateVerifyState.negotiatedCiphersuite
            self.earlyDataPermitted = serverCertificateVerifyState.earlyDataPermitted
            self.negotiatedGroup = serverCertificateVerifyState.negotiatedGroup
            self.epskNegotiated = false
            self.pskNegotiationAttempted = serverCertificateVerifyState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = serverCertificateVerifyState.negotiatedClientCertificateType
        }

        init(originalState serverEncryptedExtensionsState: ServerEncryptedExtensionsState, keyScheduler: ServerSessionKeyManager<SHA384>) {
            // PSKs directly jump from EncryptedExtensions -> Finished
            guard serverEncryptedExtensionsState.epskNegotiated else {
                preconditionFailure()
            }
            self.configuration = serverEncryptedExtensionsState.configuration
            self.keyScheduler = keyScheduler
            self.clientQUICTransportParameters = serverEncryptedExtensionsState.clientQUICTransportParameters
            self.selectedALPN = serverEncryptedExtensionsState.selectedALPN
            self.negotiatedCiphersuite = serverEncryptedExtensionsState.negotiatedCiphersuite
            self.earlyDataPermitted = serverEncryptedExtensionsState.earlyDataPermitted
            self.negotiatedGroup = serverEncryptedExtensionsState.negotiatedGroup
            self.epskNegotiated = serverEncryptedExtensionsState.epskNegotiated
            self.pskNegotiationAttempted = serverEncryptedExtensionsState.pskNegotiationAttempted
            self.negotiatedClientCertificateType = nil
        }

        static func sendingServerFinished(serverCertificateVerifyState: ServerCertificateVerifyState) throws(TLSError) -> (state: ServerFinishedState, serverFinishedBytes: ByteBuffer) {
                var keyScheduler = serverCertificateVerifyState.keyScheduler
                let serverFinishedMessage = FinishedMessage(
                    verifyData: ByteBuffer(bytes: try keyScheduler.serverFinishedPayload())
                )
                let serverFinishedBytes = try keyScheduler.sendingServerFinished(serverFinishedMessage: serverFinishedMessage)
                let newState = Self(originalState: serverCertificateVerifyState, keyScheduler: keyScheduler)
                return (newState, serverFinishedBytes)
        }

        static func sendingServerFinished(serverEncryptedExtensionsState: ServerEncryptedExtensionsState) throws(TLSError) -> (state: ServerFinishedState, serverFinishedBytes: ByteBuffer) {
            guard serverEncryptedExtensionsState.epskNegotiated else {
                preconditionFailure()
            }
            var keyScheduler = serverEncryptedExtensionsState.keyScheduler
            let serverFinishedMessage = FinishedMessage(
                verifyData: ByteBuffer(bytes: try keyScheduler.serverFinishedPayload())
            )
            let serverFinishedBytes = try keyScheduler.sendingServerFinished(serverFinishedMessage: serverFinishedMessage)
            let newState = Self(originalState: serverEncryptedExtensionsState, keyScheduler: keyScheduler)
            return (newState, serverFinishedBytes)
        }
    }

    struct ClientCertificateState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let epskNegotiated: Bool
        let clientCertificates: PeerCertificateBundle
        let negotiatedClientCertificateType: CertificateType?
        let pskNegotiationAttempted: Bool

        init(originalState serverFinishedState: ServerFinishedState, clientCertificate: CertificateMessage, clientCertificateBytes: ByteBuffer) throws(TLSError) {
            logger.info("validating client certificate")
            // Quickly check that the context string is empty.
            guard clientCertificate.certificateRequestContext.readableBytes == 0 else {
                logger.error("received unexpected context: \(clientCertificate.certificateRequestContext.readableBytes)")
                throw TLSError.handshakeInvalidMessage
            }

            self.configuration = serverFinishedState.configuration
            self.clientQUICTransportParameters = serverFinishedState.clientQUICTransportParameters
            self.selectedALPN = serverFinishedState.selectedALPN
            self.negotiatedCiphersuite = serverFinishedState.negotiatedCiphersuite
            self.earlyDataPermitted = serverFinishedState.earlyDataPermitted
            self.negotiatedGroup = serverFinishedState.negotiatedGroup
            self.epskNegotiated = serverFinishedState.epskNegotiated
            self.negotiatedClientCertificateType = serverFinishedState.negotiatedClientCertificateType
            self.clientCertificates = try PeerCertificateBundle(expectedCertificateType: serverFinishedState.negotiatedClientCertificateType ?? .x509, peerCertificateMessage: clientCertificate, fromClient: true)
            self.pskNegotiationAttempted = serverFinishedState.pskNegotiationAttempted

            keyScheduler = serverFinishedState.keyScheduler
            try keyScheduler.addPostFinishedMessageToTransportHash(clientCertificateBytes)

            logger.debug("certificate valid")
        }
    }

    struct ClientCertificateVerifyState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let epskNegotiated: Bool
        let pskNegotiationAttempted: Bool

        init(originalState clientCertificateState: ClientCertificateState, clientCertificateVerify: CertificateVerify, clientCertificateVerifyBytes: ByteBuffer) throws(TLSError) {
            guard try clientCertificateState.clientCertificates.verifyClientCertificateVerifySignature(
                message: clientCertificateVerify,
                validKeys: clientCertificateState.configuration.validPeerPublicKeys ?? [],
                keyScheduler: clientCertificateState.keyScheduler)
            else {
                logger.error("certificate verification failed")
                throw TLSError.certificateError
            }
            logger.info("client certificate trusted")
            self.configuration = clientCertificateState.configuration
            self.keyScheduler = clientCertificateState.keyScheduler
            self.clientQUICTransportParameters = clientCertificateState.clientQUICTransportParameters
            self.selectedALPN = clientCertificateState.selectedALPN
            self.negotiatedCiphersuite = clientCertificateState.negotiatedCiphersuite
            self.earlyDataPermitted = clientCertificateState.earlyDataPermitted
            self.negotiatedGroup = clientCertificateState.negotiatedGroup
            self.epskNegotiated = clientCertificateState.epskNegotiated
            self.pskNegotiationAttempted = clientCertificateState.pskNegotiationAttempted
            try keyScheduler.addPostFinishedMessageToTransportHash(clientCertificateVerifyBytes)
        }
    }

    struct ReadyState {
        var configuration: ServerHandshakeStateMachine.Configuration
        var keyScheduler: ServerSessionKeyManager<SHA384>
        let clientQUICTransportParameters: ByteBuffer?
        let selectedALPN: ApplicationLayerProtocol?
        let negotiatedCiphersuite: CipherSuite
        let earlyDataPermitted: Bool
        let negotiatedGroup: NamedGroup?
        let epskNegotiated: Bool
        let pskNegotiationAttempted: Bool

        private init(originalState serverFinishedState: ServerFinishedState,
            configuration: ServerHandshakeStateMachine.Configuration,
            keyScheduler: ServerSessionKeyManager<SHA384>
        ) {
            self.configuration = configuration
            self.keyScheduler = keyScheduler
            self.clientQUICTransportParameters = serverFinishedState.clientQUICTransportParameters
            self.selectedALPN = serverFinishedState.selectedALPN
            self.negotiatedCiphersuite = serverFinishedState.negotiatedCiphersuite
            self.earlyDataPermitted = serverFinishedState.earlyDataPermitted
            self.negotiatedGroup = serverFinishedState.negotiatedGroup
            self.epskNegotiated = serverFinishedState.epskNegotiated
            self.pskNegotiationAttempted = serverFinishedState.pskNegotiationAttempted
        }

        private init(originalState clientCertificateVerifyState: ClientCertificateVerifyState,
            configuration: ServerHandshakeStateMachine.Configuration,
            keyScheduler: ServerSessionKeyManager<SHA384>
        ) {
            self.configuration = configuration
            self.keyScheduler = keyScheduler
            self.clientQUICTransportParameters = clientCertificateVerifyState.clientQUICTransportParameters
            self.selectedALPN = clientCertificateVerifyState.selectedALPN
            self.negotiatedCiphersuite = clientCertificateVerifyState.negotiatedCiphersuite
            self.earlyDataPermitted = clientCertificateVerifyState.earlyDataPermitted
            self.negotiatedGroup = clientCertificateVerifyState.negotiatedGroup
            self.epskNegotiated = clientCertificateVerifyState.epskNegotiated
            self.pskNegotiationAttempted = clientCertificateVerifyState.pskNegotiationAttempted
        }

        static func receivingClientFinished(originalState state: ServerFinishedState, clientFinished: FinishedMessage, clientFinishedBytes: ByteBuffer) throws(TLSError) -> ReadyState {
            var keyScheduler = state.keyScheduler
            let expectedClientFinishedPayload = try keyScheduler.clientFinishedPayload()
            let actualPayload = clientFinished.verifyData.readableBytesView
            guard expectedClientFinishedPayload == actualPayload else {
                logger.error("invalid client finished payload")
                throw TLSError.negotiationFailed
            }
            try keyScheduler.postClientFinished(clientFinishedBytes: clientFinishedBytes)
            let newState = Self(originalState: state, configuration: state.configuration,
                             keyScheduler:  keyScheduler)
            return newState
        }

        static func receivingClientFinished(originalState state: ClientCertificateVerifyState, clientFinished: FinishedMessage, clientFinishedBytes: ByteBuffer) throws(TLSError) -> ReadyState {
            var keyScheduler = state.keyScheduler
            let expectedClientFinishedPayload = try keyScheduler.clientFinishedPayload()
            let actualPayload = clientFinished.verifyData.readableBytesView
            guard expectedClientFinishedPayload == actualPayload else {
                logger.error("invalid client finished payload")
                throw TLSError.negotiationFailed
            }
            try keyScheduler.postClientFinished(clientFinishedBytes: clientFinishedBytes)
            let newState = Self(originalState: state, configuration: state.configuration,
                             keyScheduler:  keyScheduler)
            return newState
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ServerHandshakeState: CustomStringConvertible {
    var description: String {
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
        case .awaitingCertificate:
            return "awaitingCertificate"
        case .serverCertificate:
            return "serverCertificate"
        case .serverCertificateVerify:
            return "serverCertificateVerify"
        case .serverFinished:
            return "serverFinished"
        case .clientCertificate:
            return "clientCertificate"
        case .awaitingSignature:
            return "awaitingSignature"
        case .clientCertificateVerify:
            return "clientCertificateVerify"
        case .readyForData:
            return "readyForData"
        }
    }
}

#endif
