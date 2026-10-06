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
// Availability due to `os.log`'s `Logger`
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "HandshakeStateMachineConfiguration")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeStateMachineConfiguration")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeStateMachineConfiguration")
#endif

@_spi(SwiftTLSOptions)
// Availability due to `CryptoKit`'s `P256.Signing.PublicKey`
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
public enum SwiftTLSPrivateKey {
    case p256(P256.Signing.PrivateKey)
#if !SWIFTTLS_EMBEDDED && canImport(Darwin)
    case p256SEPBacked(SecureEnclave.P256.Signing.PrivateKey)
#endif
    case opaqueReference(SwiftTLSOpaqueReferenceKey)
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension HandshakeStateMachine {
    enum AuthenticationMethod {
        case noAuthAvailable

        /// The client's signing key.
        case rawPublicKeyAuth(PrivateKey)

        /// Certificate data and signatures supplied by the embedder.
        case certificateAuthCallbacks(AsyncAuthenticator)

        /// External pre shared key
        case externalPreSharedKeyAuth([GeneralEPSK])
    }

    enum VerificationMethod {
        case none

        case rawPublicKey([P256.Signing.PublicKey])

        case certificateCallbacks(AsyncVerifier)
    }

    /// Configuration for the Handshake State Machine.
    struct Configuration {
        var validConfiguration: Bool

        /// The server name for the purposes of the SNI extension.
        let serverName: String?

        /// The QUIC transport parameters, if any are set.
        let quicTransportParameters: ByteBuffer?

        /// The value of the ALPN extension to send to the peer.
        let alpn: [ApplicationLayerProtocol]?

        /// The fixed key exchange group to use for the handshake.
        let fixedKeyExchangeGroup: NamedGroup?

        /// The list of cipher suites to use for the handshake.
        let supportedCipherSuites: [CipherSuite]?

        /// An optional client ticket request.
        var ticketRequest: ClientTicketRequest? = nil

        var authenticationMethod: AuthenticationMethod

        var verificationMethod: VerificationMethod

        /// The public keys this client accepts for the configured server name.
        private var _validPeerPublicKeys: [P256.Signing.PublicKey]? {
            get {
                if case .rawPublicKey(let publicKeys) = self.verificationMethod {
                    return publicKeys
                }
                return nil
            }
        }

        /// Whether external PSKs should be treated as imported or raw
        var useRawEPSKs: Bool = false

        /// Enable Early data.
        var enableEarlyData: Bool = false

        /// The public keys that will be accepted for this server name.
        var validPeerPublicKeys: [P256.Signing.PublicKey]? {
            return _validPeerPublicKeys
        }

        var signingKey: PrivateKey? {
            if case .rawPublicKeyAuth(let privateKey) = authenticationMethod {
                return privateKey
            }
            return nil
        }

        var publicKey: PublicKey? {
            if case .rawPublicKeyAuth(let privateKey) = authenticationMethod {
                return privateKey.publicKey
            }
            return nil
        }

        var epsks: [GeneralEPSK]? {
            if case .externalPreSharedKeyAuth(let array) = authenticationMethod {
                return array
            }
            return nil
        }


        var asyncVerifier: AsyncVerifier? {
            if case .certificateCallbacks(let asyncVerifier) = verificationMethod {
                return asyncVerifier
            }
            return nil
        }

        var asyncAuthenticator: AsyncAuthenticator? {
            if case .certificateAuthCallbacks(let asyncAuthenticator) = authenticationMethod {
                return asyncAuthenticator
            }
            return nil
        }

        /// The certificate types this client can verify from the server, offered in
        /// `server_certificate_type`. Empty when the client verifies nothing.
        var verifiableServerCertificateTypes: [CertificateType] {
            switch verificationMethod {
            case .certificateCallbacks(let asyncVerifier):
                return asyncVerifier.verifiableCertificateTypes
            case .rawPublicKey:
                guard case .offer(let types) = PeerCertificateBundle.verificationCertificateTypes else {
                    return []
                }
                return types
            case .none:
                return []
            }
        }

        /// The certificate types this client can present, offered in `client_certificate_type`.
        /// Empty when the client cannot authenticate itself.
        var providableClientCertificateTypes: [CertificateType] {
            switch authenticationMethod {
            case .rawPublicKeyAuth:
                guard case .offer(let types) = PeerCertificateBundle.availableCertificateTypes else {
                    return []
                }
                return types
            case .certificateAuthCallbacks(let asyncAuthenticator):
                return asyncAuthenticator.providableCertificateTypes
            case .noAuthAvailable, .externalPreSharedKeyAuth:
                return []
            }
        }

        /// Turns the supplied options into one answer per job.
        ///
        /// Precedence among mutually exclusive inputs is unchanged: trusted raw public keys
        /// win over an EPSK, which wins over the callbacks.
        static func resolve(
            signingKey: SwiftTLSPrivateKey?,
            validPeerPublicKeys: [P256.Signing.PublicKey]?,
            epsk: EPSK?,
            useRawEPSKs: Bool,
            supportedCipherSuites: [CipherSuite]?,
            asyncVerifier: AsyncVerifier?,
            asyncAuthenticator: AsyncAuthenticator?
        ) throws(TLSError) -> (authentication: AuthenticationMethod, verification: VerificationMethod) {
            let verification: VerificationMethod
            if let validPeerPublicKeys, !validPeerPublicKeys.isEmpty {
                verification = .rawPublicKey(validPeerPublicKeys)
                if epsk != nil {
                    logger.error("CONFIGURATION: client epsk set but not used as we have raw public keys set")
                }
                if asyncVerifier != nil {
                    logger.error("CONFIGURATION: async verifier config set but not used as we have raw public keys set")
                }
            } else if epsk != nil {
                // An EPSK replaces the certificate exchange, so there is nothing to verify.
                verification = .none
                if asyncVerifier != nil {
                    logger.error("CONFIGURATION: async verifier config set but not used as we have epsk set")
                }
            } else if let asyncVerifier {
                verification = .certificateCallbacks(asyncVerifier)
            } else {
                verification = .none
            }

            let authentication: AuthenticationMethod
            if case .none = verification, let epsk {
                // EPSKs are only supported for TLS_AES_256_GCM_SHA384
                guard supportedCipherSuites == nil || supportedCipherSuites == [.TLS_AES_256_GCM_SHA384] else {
                    throw TLSError.unknownCiphersuite
                }
                if useRawEPSKs {
                    authentication = .externalPreSharedKeyAuth(
                        [GeneralEPSK(RawEPSK(identity: epsk.externalIdentity, epsk: epsk.epsk))]
                    )
                } else {
                    let psks = try epsk.deriveImportedPSKs(for: [TLSKDFIdentifier.HKDF_SHA384])
                    authentication = .externalPreSharedKeyAuth(psks.map { GeneralEPSK($0) })
                }
            } else if let signingKey {
                authentication = .rawPublicKeyAuth(PrivateKey.init(signingKey))
                if asyncAuthenticator != nil {
                    logger.error("CONFIGURATION: async authenticator set but not used as we have a signing key set")
                }
            } else if let asyncAuthenticator {
                authentication = .certificateAuthCallbacks(asyncAuthenticator)
            } else {
                authentication = .noAuthAvailable
            }

            return (authentication, verification)
        }

        static func validate(_ authentication: AuthenticationMethod, _ verification: VerificationMethod) -> Bool {
            switch (authentication, verification) {
            // An EPSK authenticates both peers by itself; no certificates are exchanged.
            case (.externalPreSharedKeyAuth, .none):
                return true
            case (.externalPreSharedKeyAuth, .rawPublicKey),
                 (.externalPreSharedKeyAuth, .certificateCallbacks):
                return false

            // A client has no way to authenticate an anonymous server.
            case (.noAuthAvailable, .none),
                 (.rawPublicKeyAuth, .none),
                 (.certificateAuthCallbacks, .none):
                return false

            case (.noAuthAvailable, _),
                 (.rawPublicKeyAuth, _),
                 (.certificateAuthCallbacks, _):
                return true
            }
        }

        init(
            serverName: String? = nil,
            quicTransportParameters: ByteBuffer? = nil,
            alpn: [ApplicationLayerProtocol]? = nil,
            fixedKeyExchangeGroup: UInt16? = nil,
            supportedCipherSuites: [CipherSuite]? = nil,
            signingKey: SwiftTLSPrivateKey? = nil,
            validPeerPublicKeys: [P256.Signing.PublicKey]? = nil,
            ticketRequest: ClientTicketRequest? = nil,
            epsk: EPSK? = nil,
            useRawEPSKs: Bool = false,
            enableEarlyData: Bool = false,
            asyncVerifier: AsyncVerifier? = nil,
            asyncAuthenticator: AsyncAuthenticator? = nil
        ) {
            self.serverName = serverName
            self.quicTransportParameters = quicTransportParameters
            self.alpn = alpn
            self.fixedKeyExchangeGroup = fixedKeyExchangeGroup.map { NamedGroup(rawValue: $0) }
            self.supportedCipherSuites = supportedCipherSuites

            do throws(TLSError) {
                let (authentication, verification) = try Self.resolve(
                    signingKey: signingKey,
                    validPeerPublicKeys: validPeerPublicKeys,
                    epsk: epsk,
                    useRawEPSKs: useRawEPSKs,
                    supportedCipherSuites: supportedCipherSuites,
                    asyncVerifier: asyncVerifier,
                    asyncAuthenticator: asyncAuthenticator
                )
                self.authenticationMethod = authentication
                self.verificationMethod = verification

                guard Self.validate(authentication, verification) else {
                    self.validConfiguration = false
                    return
                }

                if case .externalPreSharedKeyAuth = authentication {
                    self.useRawEPSKs = useRawEPSKs
                }
                self.ticketRequest = ticketRequest
                self.enableEarlyData = enableEarlyData
                self.validConfiguration = true
            } catch {
                self.authenticationMethod = .noAuthAvailable
                self.verificationMethod = .none
                self.validConfiguration = false
            }
        }
    }
}
