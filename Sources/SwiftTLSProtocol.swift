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
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "SwiftTLSProtocol")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.SwiftTLSProtocol")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.SwiftTLSProtocol")
#endif

@_spi(SwiftTLSProtocol)
@available(anyAppleOS 26, *)
public enum SwiftTLSError: Error, Equatable {
    case unsupportedOptions
    case invalidServerPrivateKey
    case cryptoError
    case tlsError
}

@_spi(SwiftTLSOptions)
@available(anyAppleOS 26, *)
public struct SwiftTLSOptions {
    @frozen public enum EncryptionLevel: CustomDebugStringConvertible {
        case initial
        case earlyData
        case handshake
        case application

        public var debugDescription: String {
            switch self {
            case .initial: return "initial"
            case .earlyData: return "early data"
            case .handshake: return "handshake"
            case .application: return "application"
            }
        }
    }

    // options used for clients and servers
    public var serverName: String?
    public var quicTransportParameters: [UInt8]?
    public var applicationProtocols: [String]?

    // options used for setting up clients or servers
    // with the raw public keys they are willing to
    // trust from their peer.
    public var trustedRawPublicKeyCertificates: [[UInt8]]? // DER format
    public var trustedRawPublicKeyP256PublicKeys: [P256.Signing.PublicKey]?

    // Server or client private key for use with Raw Public Keys
    // Preferred method for setting the private key
    public var privateKey: SwiftTLSPrivateKey?

    // Option for setting private key that is currently
    // used in Network Framework which has a hard
    // time using CryptoKit types.
    //
    // Still hardcoded to always be interpreted
    // as the DER encoding of a P256.Signing.PrivateKey.
    public var rawPrivateKey: [UInt8]?

    public var enableEarlyData: Bool = false
    public var sessionState: [UInt8]?
    public var newSessionTicketRequestCount: UInt8 = 0
    public var resumedSessionTicketRequestCount: UInt8 = 0
    public enum KeyExchangeGroup: UInt16 {
        case secp256 = 0x0017
        case secp384 = 0x0018
        case x25519 = 0x001D
        case x25519MLKEM768 = 0x11EC
    }
    public var keyExchangeGroup: KeyExchangeGroup = .secp384

    public enum CipherSuite: UInt16 {
        case AES128GCM_SHA256 = 0x1301
        case AES256GCM_SHA384 = 0x1302
        case chacha20Poly1305_SHA256 = 0x1303
    }
    public var supportedCipherSuites: [SwiftTLSOptions.CipherSuite] = [ .AES256GCM_SHA384 ]

    // Whether the server requires the client to authenticate.
    // If set with raw public keys will send a "Certificate Request" message.
    public var clientAuthRequired: Bool = false

    public struct ExternalPSK {
        let externalIdentity: [UInt8]
        let epsk: SymmetricKey
        let context: [UInt8]?
        #if canImport(CryptoKit)
        public init(externalIdentity: [UInt8], epsk: CryptoKit.SymmetricKey, context: [UInt8]? = nil) {
            self.externalIdentity = externalIdentity
            self.epsk = epsk
            self.context = context
        }
        #elseif canImport(Crypto)
        public init(externalIdentity: [UInt8], epsk: Crypto.SymmetricKey, context: [UInt8]? = nil) {
            self.externalIdentity = externalIdentity
            self.epsk = epsk
            self.context = context
        }
        #endif
    }
    public var externalPSK: ExternalPSK?

    // Configure callback-based verification of peer certificates. This can
    // be used to implement certificate-based authentication.
    //
    // The verification callbacks of the `AsyncVerifier` may return `.waiting`
    // to indicate that the result is not yet available. A `deliverResultCallback`
    // must be configured on the handshaker before starting the handshake so that
    // async results can be delivered, see `setAsyncContinuationHandler`.
    public var asyncVerifier: AsyncVerifier?

    // Implement callbacks to provide certificate data and signatures
    // to authenticate this peer. This can be used to implement
    // certificate-based authentication.
    //
    // The callbacks of an `AsyncAuthenticator` may return `.waiting`
    // to indicate that the result is not yet available. A `deliverResultCallback`
    // must be configured on the handshaker before starting the handshake so that
    // async results can be delivered, see `setAsyncContinuationHandler`.
    public var asyncAuthenticator: AsyncAuthenticator?

    public init() { }
}

// MARK: Common helper functions

@available(anyAppleOS 26, *)
fileprivate extension CipherSuite {
    static func convertArray(_ input: [SwiftTLSOptions.CipherSuite]?) -> [CipherSuite]? {
        guard let input else { return nil }
        let output: [CipherSuite] = input.map {
            switch $0 {
            case .AES128GCM_SHA256: return .TLS_AES_128_GCM_SHA256
            case .AES256GCM_SHA384: return .TLS_AES_256_GCM_SHA384
            case .chacha20Poly1305_SHA256: return .TLS_CHACHA20_POLY1305_SHA256
            }
        }
        return output
    }
}

@available(anyAppleOS 26, *)
fileprivate func epskFromSwiftTLSOptions(_ options: SwiftTLSOptions) throws(SwiftTLSError) -> EPSK? {
    var epsk: EPSK? = nil
    if let externalPSK = options.externalPSK {
        do {
            let context: ByteBuffer?
            if let providedContext = externalPSK.context {
                context = ByteBuffer(bytes: providedContext)
            } else {
                context = nil
            }
            epsk = try EPSK(externalIdentity: ByteBuffer(bytes: externalPSK.externalIdentity), epsk: externalPSK.epsk, context: context)
        } catch {
            throw SwiftTLSError.unsupportedOptions
        }
    }
    return epsk
}

@available(anyAppleOS 26, *)
fileprivate func clientStateMachineFromTLSOptions(options: SwiftTLSOptions, forQUIC: Bool = true, latestError: inout LatestError?) throws(SwiftTLSError) -> HandshakeStateMachine {
    guard let applicationProtocols = options.applicationProtocols else {
        logger.error("Cannot start the handshake, missing application protocol")
        throw SwiftTLSError.unsupportedOptions
    }

    var quicTransportParameters: ByteBuffer? = nil
    if forQUIC {
        guard let params = options.quicTransportParameters else {
            logger.error("Cannot start the handshake, missing QUIC transport parameters")
            throw SwiftTLSError.unsupportedOptions
        }
        quicTransportParameters = ByteBuffer(bytes: params)
    } else {
        guard options.quicTransportParameters == nil else {
            logger.error("Unexpectedly have quicTransportParameters for non-quic conn")
            throw SwiftTLSError.unsupportedOptions
        }
    }

    var keys = [P256.Signing.PublicKey]()
    if let p256Keys = options.trustedRawPublicKeyP256PublicKeys {
        keys = p256Keys
    } else {
        var trustedRawPublicKeyCertificates: [[UInt8]]? = nil
        if let certs = options.trustedRawPublicKeyCertificates {
            trustedRawPublicKeyCertificates = certs
        }
        if let trustedRawPublicKeyCertificates {
            do {
                for spki in trustedRawPublicKeyCertificates {
                    keys.append(try P256.Signing.PublicKey(derRepresentation: spki))
                }
            } catch {
                latestError = .cryptoKitMetaError(error)
                // CryptoKitMetaError is not Equatable, so it can't be included in SwiftTLSError
                throw SwiftTLSError.cryptoError
            }
        }
    }

    // Client is not required to have a private key.
    // It will need one for mutual authentication
    // (i.e. if the server is configured to require clientAuth)
    var privateKey: SwiftTLSPrivateKey? = options.privateKey
    if privateKey == nil, let rawPrivateKey = options.rawPrivateKey {
        do {
            let p256key = try P256.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
            privateKey = SwiftTLSPrivateKey.p256(p256key)
        } catch {
            logger.error("Could not initialize server private key")
            throw SwiftTLSError.invalidServerPrivateKey
        }
    }

    var clientTicketRequest: ClientTicketRequest? = nil
    if options.newSessionTicketRequestCount > 0 || options.resumedSessionTicketRequestCount > 0 {
        clientTicketRequest = ClientTicketRequest(newSessionCount: UInt8(options.newSessionTicketRequestCount),
                                                  resumptionCount: UInt8(options.resumedSessionTicketRequestCount))
    }

    let epsk = try epskFromSwiftTLSOptions(options)
    
    do {
        let configuration = HandshakeStateMachine.Configuration(
            serverName: options.serverName,
            quicTransportParameters: quicTransportParameters,
            alpn: applicationProtocols,
            fixedKeyExchangeGroup: options.keyExchangeGroup.rawValue,
            supportedCipherSuites: CipherSuite.convertArray(options.supportedCipherSuites),
            signingKey: privateKey,
            validPeerPublicKeys: keys,
            ticketRequest: clientTicketRequest,
            epsk: epsk,
            useRawEPSKs: false,
            enableEarlyData: options.enableEarlyData,
            asyncVerifier: options.asyncVerifier
        )

        var stateMachine: HandshakeStateMachine
        // disable resumption initializers on embedded builds
        #if !hasFeature(Embedded) && !SWIFTTLS_EXCLAVECORE && !SWIFTTLS_DRIVERKIT
        if let sessionState = options.sessionState {
            do {
                try stateMachine = HandshakeStateMachine(sessionTicket: sessionState.span.bytes, configuration: configuration)
            } catch {
                logger.error("Failed to use provided session state")
                stateMachine = try HandshakeStateMachine(configuration: configuration)
            }
        } else {
            stateMachine = try HandshakeStateMachine(configuration: configuration)
        }
        #else
        stateMachine = try HandshakeStateMachine(configuration: configuration)
        #endif
        return stateMachine
    } catch {
        logger.error("Invalid configuration")
        throw SwiftTLSError.unsupportedOptions
    }
}

#if !SWIFTTLS_CLIENT_ONLY

@available(anyAppleOS 26, *)
fileprivate func serverStateMachineFromTLSOptions(options: SwiftTLSOptions, forQUIC: Bool = true) throws(SwiftTLSError) -> ServerHandshakeStateMachine {
    var keys: [P256.Signing.PublicKey]? = nil
    if let p256Keys = options.trustedRawPublicKeyP256PublicKeys {
        keys = p256Keys
    } else if let trustedRawPublicKeyCertificates = options.trustedRawPublicKeyCertificates {
        var trustedKeys = [P256.Signing.PublicKey]()
        do {
            for spki in trustedRawPublicKeyCertificates {
                trustedKeys.append(try P256.Signing.PublicKey(derRepresentation: spki))
            }
            keys = trustedKeys
        } catch {
            throw SwiftTLSError.cryptoError
        }
    }

    var privateKey: SwiftTLSPrivateKey? = options.privateKey
    if privateKey == nil {
        var rawPrivateKey: [UInt8]? = nil
        if let key = options.rawPrivateKey {
            rawPrivateKey = key
        }

        if let rawPrivateKey {
            do {
                let p256Key = try P256.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
                privateKey = SwiftTLSPrivateKey.p256(p256Key)
            } catch {
                logger.error("Could not initialize server private key")
                throw SwiftTLSError.invalidServerPrivateKey
            }
        }
    }

    var quicTransportParameters: ByteBuffer? = nil
    if let params = options.quicTransportParameters {
        quicTransportParameters = ByteBuffer(bytes: params)
    }

    var epsks: [EPSK]? = nil
    if let epsk = try epskFromSwiftTLSOptions(options) {
        epsks = [epsk]
    }
    
    do {
        let configuration = ServerHandshakeStateMachine
            .Configuration(
                serverName: options.serverName,
                quicTransportParameters: quicTransportParameters,
                alpn: options.applicationProtocols,
                transportIsQUIC: forQUIC,
                signingKey: privateKey,
                validPeerPublicKeys: keys,
                supportedCipherSuites: CipherSuite.convertArray(options.supportedCipherSuites),
                epsks: epsks,
                clientAuthRequired: options.clientAuthRequired,
                enableEarlyData: options.enableEarlyData,
                asyncAuthenticator: options.asyncAuthenticator
            )
        return try ServerHandshakeStateMachine(configuration: configuration)
    } catch {
        logger.error("could not create server configuration")
        throw SwiftTLSError.unsupportedOptions
    }
}

#endif

@available(anyAppleOS 26, *)
fileprivate enum LatestError {
    case tlsError(TLSError)
    case cryptoKitMetaError(CryptoKitMetaError)
}

@available(anyAppleOS 26, *)
fileprivate func errorCodeFromLatestError(_ latestError: LatestError?) -> Int32 {
    guard let latestError = latestError else {
        #if canImport(CryptoKit) && !SWIFTTLS_EMBEDDED && !SWIFTTLS_EXCLAVEKIT && !SWIFTTLS_DRIVERKIT
        return errSecSuccess
        #else
        return TLSErrorCode.errSecSuccess.rawValue
        #endif
    }
    switch latestError {
    case .tlsError(let tlsError):
        switch tlsError {
        case TLSError.certificateError:
            #if canImport(CryptoKit) && !SWIFTTLS_EMBEDDED && !SWIFTTLS_EXCLAVEKIT && !SWIFTTLS_DRIVERKIT
            return errSSLBadCert
            #else
            return TLSErrorCode.errSSLBadCert.rawValue
            #endif
        case TLSError.negotiationFailed:
            #if canImport(CryptoKit) && !SWIFTTLS_EMBEDDED && !SWIFTTLS_EXCLAVEKIT && !SWIFTTLS_DRIVERKIT
            return errSSLHandshakeFail
            #else
            return TLSErrorCode.errSSLHandshakeFail.rawValue
            #endif
        case TLSError.handshakeUnexpectedRead, TLSError.handshakeUnexpectedMessage:
            #if canImport(CryptoKit) && !SWIFTTLS_EMBEDDED && !SWIFTTLS_EXCLAVEKIT && !SWIFTTLS_DRIVERKIT
            return errSSLUnexpectedMessage
            #else
            return TLSErrorCode.errSSLUnexpectedMessage.rawValue
            #endif
        case TLSError.invalidSerializedSession:
            #if canImport(CryptoKit) && !SWIFTTLS_EMBEDDED && !SWIFTTLS_EXCLAVEKIT && !SWIFTTLS_DRIVERKIT
            return errSSLIllegalParam
            #else
            return TLSErrorCode.errSSLIllegalParam.rawValue
            #endif
        default:
            #if canImport(CryptoKit) && !SWIFTTLS_EMBEDDED && !SWIFTTLS_EXCLAVEKIT && !SWIFTTLS_DRIVERKIT
            return errSSLHandshakeFail
            #else
            return TLSErrorCode.errSSLHandshakeFail.rawValue
            #endif
        }
    case .cryptoKitMetaError(_):
        #if canImport(CryptoKit) && !SWIFTTLS_EMBEDDED && !SWIFTTLS_EXCLAVEKIT && !SWIFTTLS_DRIVERKIT
        return errSSLHandshakeFail
        #else
        return TLSErrorCode.errSSLHandshakeFail.rawValue
        #endif
    }
}

// WARNING:
// The following type (SwiftTLSHandshaker) is referenced in SwiftNetwork.
// Changing this interface may cause build failures for SwiftNetwork.

// MARK: QUIC Handshakers

@_spi(SwiftTLSProtocol)
@available(anyAppleOS 26, *)
public class SwiftTLSHandshaker {
    public var receivedSessionTickets = [[UInt8]]()

    public var negotiatedCiphersuite: Int { 0 }

    public var peerQUICTransportParameters: [UInt8]? { nil }

    public var earlyDataAccepted: Bool { false }

    public func setupHandshake(options: SwiftTLSOptions) throws(SwiftTLSError) -> [UInt8]? { nil }
    public func continueHandshake(with message: RawSpan? = nil) throws(SwiftTLSError) -> [UInt8]? { nil }

    public final func continueHandshake(with message: [UInt8]?) throws(SwiftTLSError) -> [UInt8]? {
        try continueHandshake(with: message?.span.bytes)
    }

    fileprivate var asyncContinuationHandler: (@Sendable (PendingAsyncResult) -> Void)?

    /// Handles asynchronous results yielded by certificate callbacks.
    ///
    /// Certificate callbacks may yield results asynchronously, in which case they call this handler with the pending result.
    /// The handler is expected to do the following:
    /// - Apply the result to the handshake via `setAsyncResult`.
    /// - Call `continueHandshake` to drive the TLS handshake forward.
    ///
    /// Note: This must be called from the same execution context as all handshaker mutations.
    public func setAsyncContinuationHandler(_ handler: (@Sendable (PendingAsyncResult) -> Void)?) {
        self.asyncContinuationHandler = handler
    }

    fileprivate var asyncResult: PendingAsyncResult?

    /// Sets the result of an async callback. The result resets to `nil` after the handshake consumes it.
    /// The pending result will be supplied by the `asyncContinuationHandler`.
    public func setAsyncResult(_ result: PendingAsyncResult) {
        asyncResult = result
    }

    fileprivate var latestError: LatestError? = nil

    public var errorCode: Int32 {
        errorCodeFromLatestError(latestError)
    }

    static func encryptionLevel(_ level: EncryptionLevel?) -> SwiftTLSOptions.EncryptionLevel {
        guard let level else {
            return .initial
        }
        switch level {
        case .earlyData: return .earlyData
        case .handshake: return .handshake
        case .application: return .application
        }
    }

    var currentReadEncryptionLevel: EncryptionLevel?
    var currentWriteEncryptionLevel: EncryptionLevel?

    public var readEncryptionLevel : SwiftTLSOptions.EncryptionLevel {
        return SwiftTLSHandshaker.encryptionLevel(currentReadEncryptionLevel)
    }

    public var writeEncryptionLevel : SwiftTLSOptions.EncryptionLevel {
        return SwiftTLSHandshaker.encryptionLevel(currentWriteEncryptionLevel)
    }

    static func encryptionSecret(_ level: EncryptionLevel?) -> [UInt8]? {
        guard let level else {
            return nil
        }
        var secretKey: SymmetricKey
        switch level {
        case .earlyData(let secret),
                .handshake(let secret),
                .application(let secret):
            secretKey = secret
        }

        let secretBytes = secretKey.withUnsafeBytes {
            return [UInt8]($0)
        }
        return secretBytes
    }

    public var readEncryptionSecret: [UInt8]? {
        return SwiftTLSHandshaker.encryptionSecret(currentReadEncryptionLevel)
    }

    public var writeEncryptionSecret: [UInt8]? {
        return SwiftTLSHandshaker.encryptionSecret(currentWriteEncryptionLevel)
    }

    public static func createClientHandshake() -> SwiftTLSHandshaker {
        return SwiftTLSClientHandshaker()
    }

    public static func createServerHandshake() -> SwiftTLSHandshaker {
#if !SWIFTTLS_CLIENT_ONLY
        return SwiftTLSServerHandshaker()
#else
        // TODO: Throw instead
        return SwiftTLSClientHandshaker()
#endif
    }
}

@available(anyAppleOS 26, *)
class SwiftTLSClientHandshaker: SwiftTLSHandshaker {
    var stateMachine: HandshakeStateMachine?

    override var negotiatedCiphersuite: Int {
        let ciphersuite = self.stateMachine!.negotiatedCiphersuite ?? 0
        guard ciphersuite <= Int32.max else {
            return 0
        }
        return Int(ciphersuite)
    }

    override var peerQUICTransportParameters: [UInt8]? {
        guard let transportParameters = self.stateMachine!.peerQUICTransportParameters else {
            return nil
        }
        return [UInt8](transportParameters.readableBytesView)
    }

    override var earlyDataAccepted: Bool {
        return self.stateMachine?.earlyDataAccepted ?? false
    }

    override func setupHandshake(options: SwiftTLSOptions) throws(SwiftTLSError) -> [UInt8]? {
        self.stateMachine = try clientStateMachineFromTLSOptions(options: options, latestError: &latestError)

        let hs: PartialHandshakeResult
        do {
            hs = try self.stateMachine!.startHandshake()
        } catch {
            latestError = .tlsError(error)
            throw SwiftTLSError.tlsError
        }

        if let writeEncryptionLevel = hs.newWriteEncryptionLevel {
            self.currentWriteEncryptionLevel = writeEncryptionLevel
        }
        if let readEncryptionLevel = hs.newReadEncryptionLevel {
            self.currentReadEncryptionLevel = readEncryptionLevel
        }
        guard let handshakeBytesToSend = hs.handshakeBytesToSend?.readableBytesView else {
            return nil
        }

        return [UInt8](handshakeBytesToSend)
    }

    override func continueHandshake(with message: RawSpan? = nil) throws(SwiftTLSError) -> [UInt8]? {
        if let onCont = self.asyncContinuationHandler {
            self.stateMachine!.deliverResultCallback = { result in
                onCont(result)
            }
        }

        if let pending = self.asyncResult {
            self.asyncResult = nil
            self.stateMachine!.applyAsyncResult(pending)
        }

        // Form an input buffer from the incoming message.
        var incomingBytes: InputBuffer
        if let message {
            incomingBytes = InputBuffer(storage: message)
        } else {
            incomingBytes = InputBuffer(storage: RawSpan())
        }

        let numIncomingBytes = incomingBytes.byteCount
        logger.debug("handshake processing (\(numIncomingBytes) bytes)")

        defer {
            // Any bytes not consumed by the parse will be saved in the state
            // machine.
            self.stateMachine!.saveUnprocessedIncomingBytes(&incomingBytes)
        }

        var partialHandshakeResult: PartialHandshakeResult?
        var dataOut: Data?
        do {
            while true {
                partialHandshakeResult = try self.stateMachine!
                    .processHandshake(incomingBytes: &incomingBytes)
                if let writeEncryptionLevel = partialHandshakeResult?.newWriteEncryptionLevel {
                    self.currentWriteEncryptionLevel = writeEncryptionLevel
                }
                if let readEncryptionLevel = partialHandshakeResult?.newReadEncryptionLevel {
                    self.currentReadEncryptionLevel = readEncryptionLevel
                }
                let sessionTicket = partialHandshakeResult?.sessionTicket
                if let sessionTicket = sessionTicket {
                    self.receivedSessionTickets.append([UInt8](sessionTicket))
                }

                guard let bytesToSend = partialHandshakeResult?.handshakeBytesToSend?.readableBytesView else {
                    if sessionTicket != nil {
                        // If there wasn't any data, but we read a session ticket, there may be more session
                        // tickets available. Keep looping to read more into receivedSessionTickets.
                        continue
                    }
                    dataOut = nil
                    break
                }
                dataOut = bytesToSend
                break
            }
        } catch {
            #if SWIFTTLS_EXCLAVEKIT || SWIFTTLS_EXCLAVECORE
            logger.error("Internal error when processing the handshake: \(String(describing: error))")
            #else
            logger.error("Internal error when processing the handshake: \(error)")
            #endif
            latestError = .tlsError(error)
            throw SwiftTLSError.tlsError
        }

        guard let dataOut else {
            return nil
        }
        return [UInt8](dataOut)
    }
}

#if !SWIFTTLS_CLIENT_ONLY

@available(anyAppleOS 26, *)
class SwiftTLSServerHandshaker: SwiftTLSHandshaker {
    var stateMachine: ServerHandshakeStateMachine?
    var clientAppSecret: SymmetricKey? = nil

    override func setupHandshake(options: SwiftTLSOptions) throws(SwiftTLSError) -> [UInt8]? {
        self.stateMachine = try serverStateMachineFromTLSOptions(options: options)

        return nil
    }

    override func continueHandshake(with message: RawSpan? = nil) throws(SwiftTLSError) -> [UInt8]? {
        if let onCont = self.asyncContinuationHandler {
            self.stateMachine!.deliverResultCallback = { result in
                onCont(result)
            }
        }

        if let pending = self.asyncResult {
            self.asyncResult = nil
            self.stateMachine!.applyAsyncResult(pending)
        }

        // Form an input buffer from the incoming message.
        var incomingBytes: InputBuffer
        if let message {
            incomingBytes = InputBuffer(storage: message)
        } else {
            incomingBytes = InputBuffer(storage: RawSpan())
        }

        let numIncomingBytes = incomingBytes.byteCount
        logger.debug("handshake processing (\(numIncomingBytes) bytes)")

        defer {
            // Any bytes not consumed by the parse will be saved in the state
            // machine.
            self.stateMachine!.saveUnprocessedIncomingBytes(&incomingBytes)
        }

        var partialHandshakeResult: PartialHandshakeResult?
        let dataOut: Data?
        do {
            while true {
                partialHandshakeResult = try self.stateMachine!.processHandshake(incomingBytes: &incomingBytes)
                if let writeEncryptionLevel = partialHandshakeResult?.newWriteEncryptionLevel {
                    self.currentWriteEncryptionLevel = writeEncryptionLevel
                }
                if let readEncryptionLevel = partialHandshakeResult?.newReadEncryptionLevel {
                    self.currentReadEncryptionLevel = readEncryptionLevel
                }
                guard let bytesToSend = partialHandshakeResult?.handshakeBytesToSend?.readableBytesView else {
                    dataOut = nil
                    break
                }
                dataOut = bytesToSend
                break
            }
        } catch {
            #if SWIFTTLS_EXCLAVEKIT || SWIFTTLS_EXCLAVECORE
            logger.error("Internal error when processing the handshake: \(String(describing: error))")
            #else
            logger.error("Internal error when processing the handshake: \(error)")
            #endif
            latestError = .tlsError(error)
            throw SwiftTLSError.tlsError
        }

        guard let dataOut else {
            return nil
        }
        return [UInt8](dataOut)
    }

    override var negotiatedCiphersuite: Int {
        let ciphersuite = self.stateMachine!.negotiatedCiphersuite ?? 0
        guard ciphersuite <= Int32.max else {
            return 0
        }
        return Int(ciphersuite)
    }

    override var peerQUICTransportParameters: [UInt8]? {
        guard let transportParameters = self.stateMachine!.peerQUICTransportParameters else {
            return nil
        }
        return [UInt8](transportParameters.readableBytesView)
    }
}

#endif
