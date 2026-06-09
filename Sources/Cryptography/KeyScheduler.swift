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
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "SessionKeyManager")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.SessionKeyManager")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.SessionKeyManager")
#endif

// Wrapper around SessionKeyManager that only exposes functions a client should
// need to call to help avoid invalid transitions.
struct ClientSessionKeyManager<HF: HashFunction> {
    private var sessionKeyManager: SessionKeyManager<HF>

    init() {
        self.sessionKeyManager = SessionKeyManager()
    }

    // Common with server wrappers
    var clientEarlyTrafficSecret: SymmetricKey? {
        return sessionKeyManager.clientEarlyTrafficSecret
    }

    var clientHandshakeTrafficSecret: SymmetricKey? {
        return sessionKeyManager.clientHandshakeTrafficSecret
    }

    var serverHandshakeTrafficSecret: SymmetricKey? {
        return sessionKeyManager.serverHandshakeTrafficSecret
    }

    var clientApplicationTrafficSecret: SymmetricKey? {
        return sessionKeyManager.clientApplicationTrafficSecret
    }

    var serverApplicationTrafficSecret: SymmetricKey? {
        return sessionKeyManager.serverApplicationTrafficSecret
    }

    var exporterMasterSecret: SymmetricKey? {
        return sessionKeyManager.exporterMasterSecret
    }

    var resumptionMasterSecret: SymmetricKey?  {
        return sessionKeyManager.resumptionMasterSecret
    }

    mutating func addPreFinishedMessageToTransportHash(_ messageBytes: ByteBuffer) throws(TLSError) {
        try sessionKeyManager.addPreFinishedMessageToTransportHash(messageBytes)
    }

    mutating func addPostFinishedMessageToTransportHash(_ messageBytes: ByteBuffer) throws(TLSError) {
        try sessionKeyManager.addPostFinishedMessageToTransportHash(messageBytes)
    }

    func dataToSignInServerCertificateVerify() throws(TLSError) -> ByteBuffer {
        return try sessionKeyManager.dataToSignInServerCertificateVerify()
    }

    func dataToSignInClientCertificateVerify() throws(TLSError) -> ByteBuffer {
        return try sessionKeyManager.dataToSignInClientCertificateVerify()
    }

    func serverFinishedPayload() throws(TLSError) -> HashedAuthenticationCode<HF> {
        return try sessionKeyManager.serverFinishedPayload()
    }

    func clientFinishedPayload() throws(TLSError) -> HashedAuthenticationCode<HF> {
        return try sessionKeyManager.clientFinishedPayload()
    }

    mutating func postClientFinished(clientFinishedBytes: ByteBuffer) throws(TLSError) {
        try sessionKeyManager.postClientFinished(clientFinishedBytes)
    }

    // Client specific functions
     mutating func sendingClientHello(clientHello: inout ClientHello, sessionToResume: SessionTicket?, epsks: [GeneralEPSK], useRawEPSKs: Bool, currentTime: Date?) throws(TLSError) -> ByteBuffer {
         return try sessionKeyManager.sendingClientHello(&clientHello, sessionToResume, epsks, useRawEPSKs, currentTime)
    }

    mutating func postServerHello(ecdheSecret: SymmetricKey, serverHelloBytes: ByteBuffer, pskFailed: Bool = false) throws(TLSError) {
        try sessionKeyManager.postServerHello(ecdheSecret, serverHelloBytes, pskFailed: pskFailed)
    }

    mutating func postServerFinished(serverFinishedBytes: ByteBuffer) throws(TLSError) {
        return try sessionKeyManager.postServerFinished(serverFinishedBytes)
    }

    func generateSessionTicketPSK(ticketNonce: ByteBuffer) throws(TLSError) -> SymmetricKey {
        return try sessionKeyManager.generateSessionTicketPSK(ticketNonce)
    }

    func generateTLSExporterKey(label: String) -> SymmetricKey? {
        return sessionKeyManager.generateTLSExporterKey(label)
    }

    func generateHashForAuthenticator(transcript: ByteBuffer) -> ByteBuffer {
        return sessionKeyManager.generateHashForAuthenticator(transcript)
    }

    func generateHMACForAuthenticator(transcript: ByteBuffer, key: SymmetricKey) -> ByteBuffer {
        return sessionKeyManager.generateHMACForAuthenticator(transcript, key)
    }

    mutating func addPreClientFinishedMessageToTransportHash(_ messageBytes: ByteBuffer) throws(TLSError) {
        try sessionKeyManager.addPreClientFinishedMessageToTransportHash(messageBytes)
    }
}

// Wrapper around SessionKeyManager that only exposes functions a server should
// need to call to help avoid invalid transitions.
struct ServerSessionKeyManager<HF: HashFunction> {
    private var sessionKeyManager: SessionKeyManager<HF>

    init() {
        self.sessionKeyManager = SessionKeyManager()
    }

    // Common with client wrappers
    var clientEarlyTrafficSecret: SymmetricKey? {
        return sessionKeyManager.clientEarlyTrafficSecret
    }

    var clientHandshakeTrafficSecret: SymmetricKey? {
        return sessionKeyManager.clientHandshakeTrafficSecret
    }

    var serverHandshakeTrafficSecret: SymmetricKey? {
        return sessionKeyManager.serverHandshakeTrafficSecret
    }

    var clientApplicationTrafficSecret: SymmetricKey? {
        return sessionKeyManager.clientApplicationTrafficSecret
    }

    var serverApplicationTrafficSecret: SymmetricKey? {
        return sessionKeyManager.serverApplicationTrafficSecret
    }

    var exporterMasterSecret: SymmetricKey? {
        return sessionKeyManager.exporterMasterSecret
    }

    var resumptionMasterSecret: SymmetricKey?  {
        return sessionKeyManager.resumptionMasterSecret
    }

    mutating func addPreFinishedMessageToTransportHash(_ messageBytes: ByteBuffer) throws(TLSError) {
        try sessionKeyManager.addPreFinishedMessageToTransportHash(messageBytes)
    }

    mutating func addPostFinishedMessageToTransportHash(_ messageBytes: ByteBuffer) throws(TLSError) {
        try sessionKeyManager.addPostFinishedMessageToTransportHash(messageBytes)
    }

    func dataToSignInServerCertificateVerify() throws(TLSError) -> ByteBuffer {
        return try sessionKeyManager.dataToSignInServerCertificateVerify()
    }

    func dataToSignInClientCertificateVerify() throws(TLSError) -> ByteBuffer {
        return try sessionKeyManager.dataToSignInClientCertificateVerify()
    }

    func serverFinishedPayload() throws(TLSError) -> HashedAuthenticationCode<HF> {
        return try sessionKeyManager.serverFinishedPayload()
    }

    func clientFinishedPayload() throws(TLSError) -> HashedAuthenticationCode<HF> {
        return try sessionKeyManager.clientFinishedPayload()
    }

    mutating func postClientFinished(clientFinishedBytes: ByteBuffer) throws(TLSError) {
        try sessionKeyManager.postClientFinished(clientFinishedBytes)
    }

    // Server specific functions
    mutating func postClientHello(clientHelloBytes: ByteBuffer, negotiatedPSK: GeneralEPSK?, binderValue: ByteBuffer?, bindersArrayLength: Int?, useRawEPSKs: Bool) throws(TLSError) {
        try sessionKeyManager.postClientHello(clientHelloBytes, negotiatedPSK, binderValue, bindersArrayLength, useRawEPSKs)
    }

    mutating func sendingServerHello(serverHello: ServerHello, ecdheSecret: SymmetricKey, pskFailed: Bool) throws(TLSError) -> ByteBuffer {
        try sessionKeyManager.sendingServerHello(serverHello, ecdheSecret, pskFailed: pskFailed)
     }

    mutating func sendingServerFinished(serverFinishedMessage: FinishedMessage) throws(TLSError) -> ByteBuffer {
        return try sessionKeyManager.sendingServerFinished(serverFinishedMessage)
    }
}


/// Manages the TLS 1.3 session key schedule and exposes the derived secrets to the rest of the handshake.
///
/// The TLS 1.3 key schedule builds out a ratchet of keys and secrets for various purposes.
/// This object encapsulates the current state in the key schedule and provides access to the
/// various secrets for the rest of the code to use.
fileprivate struct SessionKeyManager<HF: HashFunction> {

    /// The running state of the key manager.
    private var state: State

    /// This is the binder key secret.
    var binderKey: SymmetricKey? {
        switch self.state {
        case .idle, .handshakeSecret, .masterSecret, .allSecrets:
            return nil
        case .earlySecret(let earlySecret):
            return earlySecret.binderKey
        }
    }

    /// This is the client early traffic secret.
    var clientEarlyTrafficSecret: SymmetricKey? {
        switch self.state {
        case .idle, .handshakeSecret, .masterSecret, .allSecrets:
            return nil
        case .earlySecret(let earlySecret):
            return earlySecret.clientEarlyTrafficSecret
        }
    }

    /// This is the early exporter master secret.
    var earlyExporterMasterSecret: SymmetricKey? {
        switch self.state {
        case .idle, .handshakeSecret, .masterSecret, .allSecrets:
            return nil
        case .earlySecret(let earlySecret):
            return earlySecret.earlyExporterMasterSecret
        }
    }

    /// This is the client handshake traffic secret.
    var clientHandshakeTrafficSecret: SymmetricKey? {
        switch self.state {
        case .idle, .earlySecret, .allSecrets:
            return nil
        case .handshakeSecret(let handshakeSecret):
            return handshakeSecret.clientHandshakeTrafficSecret
        case .masterSecret(let masterSecret):
            return masterSecret.clientHandshakeTrafficSecret
        }
    }

    /// This is the server handshake traffic secret.
    var serverHandshakeTrafficSecret: SymmetricKey? {
        switch self.state {
        case .idle, .earlySecret, .allSecrets:
            return nil
        case .handshakeSecret(let handshakeSecret):
            return handshakeSecret.serverHandshakeTrafficSecret
        case .masterSecret(let masterSecret):
            return masterSecret.serverHandshakeTrafficSecret
        }
    }

    /// This is the client application traffic secret.
    var clientApplicationTrafficSecret: SymmetricKey? {
        switch self.state {
        case .idle, .earlySecret, .handshakeSecret:
            return nil
        case .masterSecret(let masterSecret):
            return masterSecret.clientApplicationTrafficSecret
        case .allSecrets(let allSecrets):
            return allSecrets.clientApplicationTrafficSecret
        }
    }

    /// This is the server application traffic secret.
    var serverApplicationTrafficSecret: SymmetricKey? {
        switch self.state {
        case .idle, .earlySecret, .handshakeSecret:
            return nil
        case .masterSecret(let masterSecret):
            return masterSecret.serverApplicationTrafficSecret
        case .allSecrets(let allSecrets):
            return allSecrets.serverApplicationTrafficSecret
        }
    }

    /// This is the exporter master secret.
    var exporterMasterSecret: SymmetricKey? {
        switch self.state {
        case .idle, .earlySecret, .handshakeSecret:
            return nil
        case .masterSecret(let masterSecret):
            return masterSecret.exporterMasterSecret
        case .allSecrets(let allSecrets):
            return allSecrets.exporterMasterSecret
        }
    }

    /// The resumption master secret.
    var resumptionMasterSecret: SymmetricKey?  {
        switch self.state {
        case .idle, .earlySecret, .handshakeSecret, .masterSecret:
            return nil
        case .allSecrets(let allSecrets):
            return allSecrets.resumptionMasterSecret
        }
    }

    init() {
        self.state = .idle
    }

    mutating func sendingClientHello(_ clientHello: inout ClientHello, _ sessionToResume: SessionTicket?, _ epsks: [GeneralEPSK], _ useRawEPSKs: Bool, _ currentTime: Date?) throws(TLSError) -> ByteBuffer {
        switch self.state {
        case .idle:
            let (state, clientHelloBytes) = State.EarlySecret.create(clientHello: &clientHello, sessionToResume: sessionToResume, epsks: epsks, useRawEPSKs: useRawEPSKs, currentTime: currentTime)
            self.state = .earlySecret(state)
            return clientHelloBytes
        case .earlySecret, .handshakeSecret, .masterSecret, .allSecrets:
            throw TLSError.handshakeError
        }
    }

    mutating func postClientHello(_ clientHelloBytes: ByteBuffer, _ negotiatedPSK: GeneralEPSK?, _ binderValue: ByteBuffer?, _ bindersArrayLength: Int?, _ useRawEPSKs: Bool) throws(TLSError) {
        switch self.state {
        case .idle:
            let state = try State.EarlySecret.serverCreate(clientHelloBytes: clientHelloBytes, negotiatedPSK: negotiatedPSK, useRawEPSKs: useRawEPSKs, binderValue: binderValue, bindersArrayLength: bindersArrayLength)
            self.state = .earlySecret(state)
        case .earlySecret, .handshakeSecret, .masterSecret, .allSecrets:
            throw TLSError.handshakeError
        }
    }

    mutating func sendingServerHello(_ serverHello: ServerHello, _ ecdheSecret: SymmetricKey, pskFailed: Bool) throws(TLSError) -> ByteBuffer {
        switch self.state {
        case .earlySecret(let earlySecret):
            var serverHelloBytes = ByteBuffer()
            serverHelloBytes.writeHandshakeMessage(serverHello)
            let secret = State.HandshakeSecret(earlySecret: earlySecret, ecdheSecret: ecdheSecret, serverHelloBytes: serverHelloBytes, pskFailed: pskFailed)
            let handshakeSecret: State = .handshakeSecret(secret)
            self.state = handshakeSecret
            return serverHelloBytes
        case .idle, .handshakeSecret, .masterSecret, .allSecrets:
            throw TLSError.handshakeError
        }
    }

    mutating func postServerHello(_ ecdheSecret: SymmetricKey, _ serverHelloBytes: ByteBuffer, pskFailed: Bool = false) throws(TLSError) {
        switch self.state {
        case .earlySecret(let earlySecret):
            self.state = .handshakeSecret(State.HandshakeSecret(earlySecret: earlySecret,
                                                                ecdheSecret: ecdheSecret,
                                                                serverHelloBytes: serverHelloBytes,
                                                                pskFailed: pskFailed))
        case .idle, .handshakeSecret, .masterSecret, .allSecrets:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "postServerHello")
            throw TLSError.handshakeError
        }
    }

    mutating func sendingServerFinished(_ serverFinishedMessage: FinishedMessage) throws(TLSError) -> ByteBuffer {
        switch self.state {
        case .handshakeSecret(let handshakeSecret):
            var serverFinishBytes = ByteBuffer()
            serverFinishBytes.writeHandshakeMessage(serverFinishedMessage)
            self.state = .masterSecret(State.MasterSecret(handshakeSecret: handshakeSecret, serverFinishedBytes: serverFinishBytes))
            return serverFinishBytes
        case .idle, .earlySecret, .masterSecret, .allSecrets:
            throw TLSError.handshakeError
        }
    }

    mutating func postServerFinished(_ serverFinishedBytes: ByteBuffer) throws(TLSError) {
        switch self.state {
        case .handshakeSecret(let handshakeSecret):
            self.state = .masterSecret(State.MasterSecret(handshakeSecret: handshakeSecret, serverFinishedBytes: serverFinishedBytes))
        case .idle, .earlySecret, .masterSecret, .allSecrets:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "postServerFinished")
            throw TLSError.handshakeError
        }
    }

    // pre-server finished
    mutating func addPreFinishedMessageToTransportHash(_ messageBytes: ByteBuffer) throws(TLSError) {
        switch self.state {
        case .handshakeSecret(var handshakeSecret):
            handshakeSecret.addMessageToTranscriptHash(messageBytes)
            self.state = .handshakeSecret(handshakeSecret)
        case .idle, .earlySecret, .masterSecret, .allSecrets:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "preFinishedMessage")
            throw TLSError.handshakeError
        }
    }

    // post server finished, pre client finished
    mutating func addPostFinishedMessageToTransportHash(_ messageBytes: ByteBuffer) throws(TLSError) {
        switch self.state {
        case .masterSecret(var masterSecret):
            masterSecret.addMessageToTranscriptHash(messageBytes)
            self.state = .masterSecret(masterSecret)
        case .idle, .earlySecret, .handshakeSecret, .allSecrets:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "postFinishedMessage")
            throw TLSError.handshakeError
        }
    }

    mutating func postClientFinished(_ clientFinishedBytes: ByteBuffer) throws(TLSError) {
        switch self.state {
        case .masterSecret(let masterSecret):
            self.state = .allSecrets(State.AllSecrets(masterSecret: masterSecret, clientFinishedBytes: clientFinishedBytes))
        case .idle, .earlySecret, .handshakeSecret, .allSecrets:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "clientFinishedBytes")
            throw TLSError.handshakeError
        }
    }

    /// The data that the server certificate verify should be signed over. This should be called only when
    /// generating the server CertificateVerify message _or_ when validating it, as this property will change with
    /// further messages. All prior handshake messages must have been operated upon.
    func dataToSignInServerCertificateVerify() throws(TLSError) -> ByteBuffer {
        switch self.state {
        case .handshakeSecret(let handshakeSecret):
            return handshakeSecret.dataToSignInServerCertificateVerify
        case .idle, .earlySecret, .masterSecret, .allSecrets:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "dataToSignInCertificateVerify")
            throw TLSError.handshakeError
        }
    }

    func dataToSignInClientCertificateVerify() throws(TLSError) -> ByteBuffer {
        switch self.state {
            case .masterSecret(let masterSecret):
                return masterSecret.dataToSignInClientCertificateVerify
            case .idle, .earlySecret, .handshakeSecret, .allSecrets:
                logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "dataToSignInClientCertificateVerify")
            throw TLSError.handshakeError
        }
    }

    /// The expected payload of server Finished. This should be called only when generating the server Finished _or_ when
    /// validating it, as the output of this property will change with further messages.
    func serverFinishedPayload() throws(TLSError) -> HashedAuthenticationCode<HF> {
        switch self.state {
        case .handshakeSecret(let handshakeSecret):
            return handshakeSecret.serverFinishedPayload
        case .idle, .earlySecret, .masterSecret, .allSecrets:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "serverFinishedPayload")
            throw TLSError.handshakeError
        }
    }

    mutating func addPreClientFinishedMessageToTransportHash(_ messageBytes: ByteBuffer) throws(TLSError) {
        switch self.state {
        case .masterSecret(var masterSecret):
            masterSecret.addMessageToTranscriptHash(messageBytes)
            self.state = .masterSecret(masterSecret)
        case .idle, .earlySecret, .handshakeSecret, .allSecrets:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "preFinishedMessage")
            throw TLSError.handshakeError
        }
    }

    /// The expected payload of client Finished. This should be called only when generating the client Finished _or_ when
    /// validating it, as the output of this property will change with further messages.
    func clientFinishedPayload() throws(TLSError) -> HashedAuthenticationCode<HF> {
        switch self.state {
        case .masterSecret(let masterSecret):
            return masterSecret.clientFinishedPayload
        case .idle, .earlySecret, .handshakeSecret, .allSecrets:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "clientFinishedPayload")
            throw TLSError.handshakeError
        }
    }

    func generateSessionTicketPSK(_ ticketNonce: ByteBuffer) throws(TLSError) -> SymmetricKey {
        switch self.state {
        case .allSecrets(let allSecrets):
            return allSecrets.generateSessionTicketPSK(ticketNonce: ticketNonce)
        case .idle, .earlySecret, .handshakeSecret, .masterSecret:
            logger.logInvalidStateTransition(stateName: self.state.logDescription, event: "generateSessionTicketPSK")
            throw TLSError.handshakeError
        }
    }

    func generateTLSExporterKey(_ label: String) -> SymmetricKey? {
        guard let exporterMasterSecret = self.exporterMasterSecret else {
            return nil
        }
        return HKDF<HF>.tlsExporter(secret: exporterMasterSecret, label: label, context: HF.zeroHash)
    }

    func generateHashForAuthenticator(_ transcript: ByteBuffer) -> ByteBuffer {
        var buffer = ByteBuffer()
        var transcriptHasher = HF()
        transcriptHasher.update(data: transcript.readableBytesView)
        let hash = transcriptHasher.finalize()
        hash.withUnsafeBytes { _ = buffer.writeBytes($0) }
        return buffer
    }

    func generateHMACForAuthenticator(_ transcript: ByteBuffer, _ key: SymmetricKey) -> ByteBuffer {
        return ByteBuffer(bytes: HMAC<HF>.authenticationCode(bytes: transcript.readableBytesView, using: key))
    }
}

extension SessionKeyManager {
    fileprivate enum State {
        /// The dialog has not yet begun; no keying material is available.
        case idle

        /// The `ClientHello` was sent or received. The early secret and the derived early
        /// secrets are available.
        case earlySecret(SessionKeyManager.State.EarlySecret)

        /// The `ServerHello` was sent or received. The handshake secret and the derived
        /// handshake secrets are available.
        case handshakeSecret(SessionKeyManager.State.HandshakeSecret)

        /// The server `Finished` was sent or received. The master secret and the derived
        /// master secrets are available, but not the resumption secret.
        case masterSecret(SessionKeyManager.State.MasterSecret)

        /// The client `Finished` was sent or received. All the secrets are available.
        case allSecrets(SessionKeyManager.State.AllSecrets)

        var logDescription: String {
            switch self {
            case .idle:
                return "idle"
            case .earlySecret:
                return "earlySecret"
            case .handshakeSecret:
                return "handshakeSecret"
            case .masterSecret:
                return "masterSecret"
            case .allSecrets:
                return "allSecrets"
            }
        }
    }
}

extension SessionKeyManager.State {
    fileprivate struct EarlySecret {
        /// The transcript hasher, advanced through the `ClientHello`.
        fileprivate var transcriptHasher: HF

        /// This is the tail derived secret.
        fileprivate var derivedSecret: SymmetricKey

        /// This is the binder key secret.
        fileprivate var binderKey: SymmetricKey

        /// This is the client early traffic secret.
        fileprivate var clientEarlyTrafficSecret: SymmetricKey

        /// This is the early exporter master secret.
        fileprivate var earlyExporterMasterSecret: SymmetricKey

        private init(
            transcriptHasher: HF,
            derivedSecret: SymmetricKey,
            binderKey: SymmetricKey,
            clientEarlyTrafficSecret: SymmetricKey,
            earlyExporterMasterSecret: SymmetricKey
        ) {
            self.transcriptHasher = transcriptHasher
            self.derivedSecret = derivedSecret
            self.binderKey = binderKey
            self.clientEarlyTrafficSecret = clientEarlyTrafficSecret
            self.earlyExporterMasterSecret = earlyExporterMasterSecret
        }

        fileprivate static func serverCreate(
            clientHelloBytes:  ByteBuffer,
            negotiatedPSK: GeneralEPSK?,
            useRawEPSKs: Bool,
            binderValue: ByteBuffer?,
            bindersArrayLength: Int?
        ) throws(TLSError) -> EarlySecret {
            var transcriptHasher = HF()
            transcriptHasher.update(data: clientHelloBytes.readableBytesView)

            let zeros = Array(repeating: UInt8(0), count: HF.Digest.byteCount)

            let preSharedKey = negotiatedPSK?.key ?? SymmetricKey(data: zeros)
            let earlySecret = HKDF<HF>.extract(inputKeyMaterial: preSharedKey, salt: zeros)

            let label = useRawEPSKs ? PSKSource.external.secretLabel : PSKSource.imported.secretLabel
            let binderSecret = HKDF<HF>.deriveSecret(secret: earlySecret,
                                                  label: label,
                                                  transcriptHash: HF.zeroHash)

            if negotiatedPSK != nil {
                guard let binderValue, let bindersArrayLength else {
                    throw TLSError.internalError(reason: "Missing binder value or binders array length")
                }
                logger.debug("bindersArrayLength: \(bindersArrayLength)")
                // add 2 for the outer binders list length field (per-entry length prefix bytes are already in bindersArrayLength)
                let truncatedClientHello = clientHelloBytes.readableBytesView.dropLast(bindersArrayLength &+ 2)
                let helloDigest = HF.hash(data: truncatedClientHello)
                let binderKey = HKDF<HF>.expandLabel(secret: binderSecret, label: "finished", context: [], length: HF.Digest.byteCount)
                let calculatedBinderValue = HMAC<HF>.authenticationCode(bytes: helloDigest, using: binderKey)
                if !(calculatedBinderValue == binderValue.readableBytesView) {
                    if calculatedBinderValue.byteCount != binderValue.readableBytes {
                        logger.error("psk binder value not of expected length. Likely epsk hash algorithm mismatch.")
                    }
                    logger.error("client binder value incorrect. Aborting handshake.")
                    throw TLSError.decryptError
                }
            }


            let currentTranscriptHash = transcriptHasher.finalize()

            let clientEarlyTrafficSecret = HKDF<HF>.deriveSecret(secret: earlySecret,
                                                                 label: "c e traffic",
                                                                 transcriptHash: currentTranscriptHash)
            let earlyExporterMasterSecret = HKDF<HF>.deriveSecret(secret: earlySecret,
                                                                  label: "e exp master",
                                                                  transcriptHash: currentTranscriptHash)

            let derivedSecret = HKDF<HF>.deriveSecret(secret: earlySecret,
                                                      label: "derived",
                                                      transcriptHash: HF.zeroHash)

            let earlySecretState = Self(
                transcriptHasher: transcriptHasher,
                derivedSecret: derivedSecret,
                binderKey: binderSecret,
                clientEarlyTrafficSecret: clientEarlyTrafficSecret,
                earlyExporterMasterSecret: earlyExporterMasterSecret
            )

            return earlySecretState
        }

        fileprivate static func create(
            clientHello: inout ClientHello,
            sessionToResume: SessionTicket?,
            epsks: [GeneralEPSK],
            useRawEPSKs: Bool,
            currentTime: Date?
        ) -> (earlySecretState: EarlySecret, clientHelloBytes: ByteBuffer) {
            let zeros = Array(repeating: UInt8(0), count: HF.Digest.byteCount)

            // Client uses the resumption psk or first imported psk as psk input to key schedule if available. Otherwise it uses all zeros.
            // If server does not select one of the psks the key schedule will be recomputed with all zeros.
            var preSharedKey: SymmetricKey
            var label = PSKSource.resumption.secretLabel
            if epsks.isEmpty && sessionToResume == nil {
                preSharedKey = SymmetricKey(data: zeros)
            } else if sessionToResume != nil {
                preSharedKey = sessionToResume!.psk
            } else {
                // epsk
                preSharedKey = epsks[0].key
                if useRawEPSKs {
                    label = PSKSource.external.secretLabel
                } else {
                    label = PSKSource.imported.secretLabel
                }
            }

            let earlySecret = HKDF<HF>.extract(inputKeyMaterial: preSharedKey, salt: zeros)
            let binderKey = HKDF<HF>.deriveSecret(secret: earlySecret,
                                                  label: label,
                                                  transcriptHash: HF.zeroHash)

            // Now we need to resume the session, in the event one is being provided.
            var clientHelloBytes: ByteBuffer
            if let sessionToResume = sessionToResume {
                guard let currentTime else {
                    fatalError("Cannot resume session without current time")
                }
                clientHelloBytes = Self.tryToResume(session: sessionToResume, binderSecret: binderKey, clientHello: &clientHello, currentTime: currentTime)

            }  else if !epsks.isEmpty {
                guard epsks.count > 0 else { fatalError("No PSKs provided") }
                clientHelloBytes = Self.useEPSK(epsk: epsks[0], binderSecret: binderKey, clientHello: &clientHello)
            } else {
                clientHelloBytes = ByteBuffer()
                clientHelloBytes.writeHandshakeMessage(clientHello)
            }

            var transcriptHasher = HF()
            transcriptHasher.update(data: clientHelloBytes.readableBytesView)
            let currentTranscriptHash = transcriptHasher.finalize()

            let clientEarlyTrafficSecret = HKDF<HF>.deriveSecret(secret: earlySecret,
                                                                 label: "c e traffic",
                                                                 transcriptHash: currentTranscriptHash)
            let earlyExporterMasterSecret = HKDF<HF>.deriveSecret(secret: earlySecret,
                                                                  label: "e exp master",
                                                                  transcriptHash: currentTranscriptHash)

            let derivedSecret = HKDF<HF>.deriveSecret(secret: earlySecret,
                                                      label: "derived",
                                                      transcriptHash: HF.zeroHash)

            let earlySecretState = Self(
                transcriptHasher: transcriptHasher,
                derivedSecret: derivedSecret,
                binderKey: binderKey,
                clientEarlyTrafficSecret: clientEarlyTrafficSecret,
                earlyExporterMasterSecret: earlyExporterMasterSecret
            )

            return (earlySecretState: earlySecretState, clientHelloBytes: clientHelloBytes)
        }

        private static func calculateFinalClientHello(binderSecret: SymmetricKey, clientHello: inout ClientHello, obfuscatedTicketAge: UInt32, identity: Extension.PreSharedKey.OfferedPSKs.PSKIdentity) -> ByteBuffer {
            var binder = Extension.PreSharedKey.OfferedPSKs.PSKBinderEntry(
                serializedBinder: ByteBuffer(data: Data(repeating: 0, count: HF.Digest.byteCount))
            )
            let fakeExtensionValue = Extension.preSharedKey(
                .clientHello(
                    .init(identities: [identity], binders: [binder])
                )
            )
            clientHello.extensions.append(fakeExtensionValue)

            var buffer = ByteBuffer()
            buffer.writeHandshakeMessage(clientHello)

            // We now need to strip trailing data. We know the binder list contains only one binder,
            // which is HF.Digest.byteCount in length, plus the 1 byte length of the binder length and the
            // 2 byte length of the binder entry field it's a part of. Drop those.
            logger.debug("bindersarray length should be \(HF.Digest.byteCount &+ 1 &+ 2)")
            let truncatedClientHello = buffer.readableBytesView.dropLast(HF.Digest.byteCount &+ 1 &+ 2)

            // Now we can generate the new binder and replace the zero binder with it.
            let helloDigest = HF.hash(data: truncatedClientHello)
            let binderKey = HKDF<HF>.expandLabel(secret: binderSecret,
                                                 label: "finished",
                                                 context: [],
                                                 length: HF.Digest.byteCount)

            // Now we can replace the lousy fake binder with the real one. We also write it onto the end of the
            // client hello bytes.
            binder.serializedBinder = ByteBuffer(bytes: HMAC<HF>.authenticationCode(bytes: helloDigest, using: binderKey))
            buffer.setImmutableBuffer(binder.serializedBinder, at: buffer.writerIndex &- binder.serializedBinder.readableBytes)

            let lastElementIndex = clientHello.extensions.index(before: clientHello.extensions.endIndex)
            clientHello.extensions[lastElementIndex] = .preSharedKey(
                .clientHello(
                    .init(identities: [identity], binders: [binder])
                )
            )

            // Ok, nice, we're done!
            return buffer
        }

        /// Attempts to resume a TLS session.
        ///
        /// - parameters:
        ///     - session: The session to try to resume
        ///     - binderSecret: The binder secret to use to calculate a HMAC
        ///     - clientHello: The client hello message to attach resumption to. This message will be mutated to contain the full
        ///         set of extensions.
        /// - returns: The serialized bytes of the `ClientHello` containing the session ticket. We return this to avoid needing to serialize the
        ///     `ClientHello` more than once.
        private static func tryToResume(session: SessionTicket, binderSecret: SymmetricKey, clientHello: inout ClientHello, currentTime: Date) -> ByteBuffer {
            // Step 1: compute the PSK binder. To do this we write a fake binder value that is all zeros, and then
            // serialize the client hello.
            let obfuscatedTicketAge = session.obfuscatedTicketAge(currentTime: currentTime)
            let identity = Extension.PreSharedKey.OfferedPSKs.PSKIdentity(
                identity: session.ticket, obfuscatedTicketAge: obfuscatedTicketAge
            )
            return calculateFinalClientHello(binderSecret: binderSecret, clientHello: &clientHello, obfuscatedTicketAge: obfuscatedTicketAge, identity: identity)
        }

        /// Attempts to use an imported PSK.
        ///
        /// - parameters:
        ///     - epsk: The imported or raw ePSK being offered.
        ///     - binderSecret: The binder secret to use to calculate a HMAC
        ///     - clientHello: The client hello message to attach the psk to. This message will be mutated to contain the full
        ///         set of extensions.
        /// - returns: The serialized bytes of the `ClientHello` containing the offered psk. We return this to avoid needing to serialize the
        ///     `ClientHello` more than once.
        private static func useEPSK (epsk: GeneralEPSK, binderSecret: SymmetricKey, clientHello: inout ClientHello) -> ByteBuffer {
            // Step 1: compute the PSK binder. To do this we write a fake binder value that is all zeros, and then
            // serialize the client hello.
            let obfuscatedTicketAge: UInt32 = 0 // for external PSKs should be set to 0

            let identity = Extension.PreSharedKey.OfferedPSKs.PSKIdentity(
                identity: epsk.identity, obfuscatedTicketAge: obfuscatedTicketAge
            )
            return calculateFinalClientHello(binderSecret: binderSecret, clientHello: &clientHello, obfuscatedTicketAge: obfuscatedTicketAge, identity: identity)
        }
    }

    fileprivate struct HandshakeSecret {
        /// This is the current state of the transcript hash. For this state, this contains the
        /// transcript hash through the server hello at construction, and then potentially up to
        /// but not including the server Finished.
        fileprivate var transcriptHasher: HF

        /// This is the tail derived secret.
        fileprivate var derivedSecret: SymmetricKey

        /// This is the client handshake traffic secret.
        fileprivate var clientHandshakeTrafficSecret: SymmetricKey

        /// This is the server handshake traffic secret.
        fileprivate var serverHandshakeTrafficSecret: SymmetricKey

        init(earlySecret: EarlySecret, ecdheSecret: SymmetricKey, serverHelloBytes: ByteBuffer, pskFailed: Bool) {
            var salt = earlySecret.derivedSecret
            if pskFailed {
                logger.debug("authenticating with a psk failed (resumption or external psk)")
                // If authenticating with a psk failed, we need to re-derive the secret with an all-zero PSK
                // Currently resumption and external psks are mutually exclusive: a client can only configure one or the other.
                // Only one external psk is allowed and SwiftTLS will only get one imported psk from that
                // because it only supports TLS 1.3 and one KDF.
                // If this changes in the future (i.e. there may be more than one psk offered by the client)
                // then the client will need to handle the server picking a psk at index != 0 and using that
                // psk to re-derive the Early Secret.
                let zeros = Array(repeating: UInt8(0), count: HF.Digest.byteCount)
                let zeroPreSharedKey = SymmetricKey(data: zeros)
                let fallbackEarlySecret = HKDF<HF>.extract(inputKeyMaterial: zeroPreSharedKey, salt: zeros)
                salt = HKDF<HF>.deriveSecret(secret: fallbackEarlySecret,
                                             label: "derived",
                                             transcriptHash: HF.zeroHash)
            }
            let handshakeSecret = HKDF<HF>.extract(inputKeyMaterial: ecdheSecret, salt: salt)
            self.transcriptHasher = earlySecret.transcriptHasher
            self.transcriptHasher.update(data: serverHelloBytes.readableBytesView)
            let transcriptHash = self.transcriptHasher.finalize()

            self.clientHandshakeTrafficSecret = HKDF<HF>.deriveSecret(secret: handshakeSecret,
                                                                      label: "c hs traffic",
                                                                      transcriptHash: transcriptHash)
            self.serverHandshakeTrafficSecret = HKDF<HF>.deriveSecret(secret: handshakeSecret,
                                                                      label: "s hs traffic",
                                                                      transcriptHash: transcriptHash)
            self.derivedSecret = HKDF<HF>.deriveSecret(secret: handshakeSecret,
                                                       label: "derived",
                                                       transcriptHash: HF.zeroHash)
        }

        /// Adds a message to the transcript hash.
        ///
        /// This method does not enforce message ordering of any kind: the state machine is required to do that.
        mutating func addMessageToTranscriptHash(_ messageBytes: ByteBuffer) {
            self.transcriptHasher.update(data: messageBytes.readableBytesView)
        }

        var serverFinishedPayload: HashedAuthenticationCode<HF> {
            let finishedKey = HKDF<HF>.expandLabel(secret: self.serverHandshakeTrafficSecret,
                                                                     label: "finished",
                                                                     context: [],
                                                                     length: HF.Digest.byteCount)
            return HMAC<HF>.authenticationCode(bytes: self.transcriptHasher.finalize(), using: finishedKey)
        }

        var dataToSignInServerCertificateVerify: ByteBuffer {
            var buffer = ByteBuffer()
            buffer.writeBytes(repeatElement(0x20, count: 64))
            buffer.writeBytes("TLS 1.3, server CertificateVerify".utf8)
            buffer.writeInteger(UInt8(0))

            let hash = self.transcriptHasher.finalize()
            hash.withUnsafeBytes { _ = buffer.writeBytes($0) }
            return buffer
        }
    }

    fileprivate struct MasterSecret {
        /// This is the current state of the transcript hash. For this state, this contains the
        /// transcript hash through the server Finished.
        fileprivate var transcriptHasher: HF

        /// This is the master secret.
        fileprivate var masterSecret: SymmetricKey

        /// This is the client handshake traffic secret. We save this from the previous state.
        fileprivate var clientHandshakeTrafficSecret: SymmetricKey

        /// This is the server handshake traffic secret. We save this from the previous state.
        fileprivate var serverHandshakeTrafficSecret: SymmetricKey

        /// This is the client application traffic secret.
        fileprivate var clientApplicationTrafficSecret: SymmetricKey

        /// This is the server application traffic secret.
        fileprivate var serverApplicationTrafficSecret: SymmetricKey

        /// This is the exporter master secret.
        fileprivate var exporterMasterSecret: SymmetricKey

        init(handshakeSecret: HandshakeSecret, serverFinishedBytes: ByteBuffer) {
            let zeros = SymmetricKey(data: Array(repeating: 0, count: HF.Digest.byteCount))
            self.masterSecret = SymmetricKey(data: HKDF<HF>.extract(inputKeyMaterial: zeros, salt: handshakeSecret.derivedSecret))

            self.transcriptHasher = handshakeSecret.transcriptHasher
            self.transcriptHasher.update(data: serverFinishedBytes.readableBytesView)
            let transcriptHash = self.transcriptHasher.finalize()

            self.clientHandshakeTrafficSecret = handshakeSecret.clientHandshakeTrafficSecret
            self.serverHandshakeTrafficSecret = handshakeSecret.serverHandshakeTrafficSecret
            self.clientApplicationTrafficSecret = HKDF<HF>.deriveSecret(secret: self.masterSecret,
                                                                        label: "c ap traffic",
                                                                        transcriptHash: transcriptHash)
            self.serverApplicationTrafficSecret = HKDF<HF>.deriveSecret(secret: self.masterSecret,
                                                                        label: "s ap traffic",
                                                                        transcriptHash: transcriptHash)
            self.exporterMasterSecret = HKDF<HF>.deriveSecret(secret: self.masterSecret,
                                                              label: "exp master",
                                                              transcriptHash: transcriptHash)
        }

        /// Adds a message to the transcript hash.
        ///
        /// This method does not enforce message ordering of any kind: the state machine is required to do that.
        mutating func addMessageToTranscriptHash(_ messageBytes: ByteBuffer) {
            self.transcriptHasher.update(data: messageBytes.readableBytesView)
        }

        var dataToSignInClientCertificateVerify: ByteBuffer {
            var buffer = ByteBuffer()
            buffer.writeBytes(repeatElement(0x20, count: 64))
            buffer.writeBytes("TLS 1.3, client CertificateVerify".utf8)
            buffer.writeInteger(UInt8(0))

            let hash = self.transcriptHasher.finalize()
            hash.withUnsafeBytes { _ = buffer.writeBytes($0) }
            return buffer
        }


        var clientFinishedPayload: HashedAuthenticationCode<HF> {
            let finishedKey = HKDF<HF>.expandLabel(secret: self.clientHandshakeTrafficSecret,
                                                   label: "finished",
                                                   context: [],
                                                   length: HF.Digest.byteCount)
            return HMAC<HF>.authenticationCode(bytes: self.transcriptHasher.finalize(), using: finishedKey)
        }
    }

    fileprivate struct AllSecrets {
        /// This is the client application traffic secret. We save this from the previous state.
        fileprivate var clientApplicationTrafficSecret: SymmetricKey

        /// This is the server application traffic secret. We save this from the previous state.
        fileprivate var serverApplicationTrafficSecret: SymmetricKey

        /// This is the exporter master secret. We save this from the previous state.
        fileprivate var exporterMasterSecret: SymmetricKey

        /// The resumption master secret.
        fileprivate var resumptionMasterSecret: SymmetricKey

        init(masterSecret: MasterSecret, clientFinishedBytes: ByteBuffer) {
            self.clientApplicationTrafficSecret = masterSecret.clientApplicationTrafficSecret
            self.serverApplicationTrafficSecret = masterSecret.serverApplicationTrafficSecret
            self.exporterMasterSecret = masterSecret.exporterMasterSecret

            var transcriptHasher = masterSecret.transcriptHasher
            transcriptHasher.update(data: clientFinishedBytes.readableBytesView)
            let transcriptHash = transcriptHasher.finalize()

            self.resumptionMasterSecret = HKDF<HF>.deriveSecret(secret: masterSecret.masterSecret,
                                                                label: "res master",
                                                                transcriptHash: transcriptHash)
        }

        func generateSessionTicketPSK(ticketNonce: ByteBuffer) -> SymmetricKey {
            return HKDF<HF>.expandLabel(secret: self.resumptionMasterSecret,
                                        label: "resumption",
                                        context: ticketNonce.readableBytesView,
                                        length: HF.Digest.byteCount)
        }
    }
}

fileprivate extension Logger {
    func logInvalidStateTransition(stateName: String, event: String) {
        self.error("invalid state transition for session key manager: state \(stateName) event: \(event)")
    }
}
