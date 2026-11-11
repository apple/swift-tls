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

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif

#if canImport(Foundation) && !SWIFTTLS_EMBEDDED
import Foundation
#endif

#if !SWIFTTLS_CLIENT_ONLY

#if canImport(Darwin) || SWIFTTLS_EXCLAVEKIT
import os.log
// Availability due to `os.log`'s `Logger`
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "ServerHandshakeStateMachineConfiguration")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.ServerHandshakeStateMachineConfiguration")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.ServerHandshakeStateMachineConfiguration")
#endif

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension ServerHandshakeStateMachine {
    enum AuthenticationMethod {
        case noAuthAvailable

        /// The server's signing key.
        case rawPublicKeyAuth(PrivateKey)

        /// External pre shared key
        case externalPreSharedKeyAuth([GeneralEPSK])

        /// EPSK callback
        case externalPreSharedKeyAuthCallback(externalPSKSelectionCallback)

        case certificateAuthCallbacks(AsyncAuthenticator)

        /// Whether a handshake using this method exchanges certificates at all.
        ///
        /// An EPSK authenticates both peers by itself and sends no
        /// `CertificateRequest`, so client authentication has nothing to attach to.
        var exchangesCertificates: Bool {
            switch self {
            case .noAuthAvailable, .rawPublicKeyAuth, .certificateAuthCallbacks:
                return true
            case .externalPreSharedKeyAuth, .externalPreSharedKeyAuthCallback:
                return false
            }
        }
    }

    enum VerificationMethod {
        case none

        case rawPublicKey([P256.Signing.PublicKey])

        case certificateCallbacks(AsyncVerifier)
    }

    /// Configuration for the Handshake State Machine.
    struct Configuration {
        let validConfiguration: Bool

        /// The server name for the purposes of the SNI extension.
        let serverName: String?

        /// The QUIC transport parameters, if any are set.
        let quicTransportParameters: ByteBuffer?

        /// The value of the server supported ALPN extensions
        let alpn: [ApplicationLayerProtocol]?

        /// The authentication method for this configuration.
        internal let authenticationMethod: AuthenticationMethod

        /// How this server verifies the client, when it requires client authentication.
        internal let verificationMethod: VerificationMethod

        /// List of cipher suites to use for the handshake
        let supportedCipherSuites: [CipherSuite]?

        /// Whether to treat external PSKs as imported or raw.
        var useRawEPSKs: Bool = false

        /// Whether the server is willing to accept early data.
        var enableEarlyData: Bool = false

        /// `true` when used within QUIC; `false` otherwise.
        var transportIsQUIC: Bool

        /// `true` when the client is required to authenticate with RPK or a certificate.
        var clientAuthRequired: Bool {
            if case .none = verificationMethod {
                return false
            }
            return true
        }

        /// Public keys for trusted clients.
        var validPeerPublicKeys: [P256.Signing.PublicKey]? {
            if case .rawPublicKey(let publicKeys) = verificationMethod {
                return publicKeys
            }
            return nil
        }

        var publicKey: PublicKey? {
            if case .rawPublicKeyAuth(let swiftTLSRefKey) = authenticationMethod {
                return swiftTLSRefKey.publicKey
            }
            return nil
        }

        var signingKey: PrivateKey? {
            if case .rawPublicKeyAuth(let privateKey) = authenticationMethod {
                return privateKey
            }
            return nil
        }

        var epsks: [GeneralEPSK]? {
            if case .externalPreSharedKeyAuth(let array) = authenticationMethod {
                return array
            }
            return nil
        }

        var epskSelectionCallback: externalPSKSelectionCallback? {
            if case .externalPreSharedKeyAuthCallback(let externalPSKSelectionCallback) = authenticationMethod {
                return externalPSKSelectionCallback
            }
            return nil
        }

        var asyncAuthenticator: AsyncAuthenticator? {
            if case .certificateAuthCallbacks(let serverAuthProvider) = authenticationMethod {
                return serverAuthProvider
            }
            return nil
        }

        var asyncVerifier: AsyncVerifier? {
            if case .certificateCallbacks(let asyncVerifier) = verificationMethod {
                return asyncVerifier
            }
            return nil
        }

        /// The certificate types this server can present, negotiated via `server_certificate_type`.
        ///
        /// Empty when this server presents no certificate at all, which is the case for an EPSK.
        /// There is then nothing to negotiate and the extension is omitted.
        var providableServerCertificateTypes: [CertificateType] {
            guard authenticationMethod.exchangesCertificates else {
                return []
            }
            if let asyncAuthenticator {
                return asyncAuthenticator.providableCertificateTypes
            }
            // Without an authenticator the server can only present a raw public key.
            return [.rawPublicKey]
        }

        /// The certificate types this server can verify from the client, negotiated via
        /// `client_certificate_type`.
        ///
        /// Deliberately independent of `providableServerCertificateTypes`: what this server can
        /// present says nothing about what it can verify.
        var verifiableClientCertificateTypes: [CertificateType] {
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

        /// Turns the supplied options into one answer per job.
        ///
        /// Returns `nil` when the options contradict each other. Precedence among mutually
        /// exclusive authentication inputs is unchanged: a signing key wins over EPSKs, which
        /// win over an EPSK callback, which wins over the certificate callbacks.
        static func resolve(
            signingKey: SwiftTLSPrivateKey?,
            validPeerPublicKeys: [P256.Signing.PublicKey]?,
            epsks: [EPSK]?,
            epskSelectionCallback: externalPSKSelectionCallback?,
            useRawEPSKs: Bool,
            clientAuthentication: ClientAuthenticationPolicy,
            supportedCipherSuites: [CipherSuite]?,
            asyncAuthenticator: AsyncAuthenticator?,
            asyncVerifier: AsyncVerifier?,
            fallbackAuthentication: AuthenticationMethod? = nil
        ) throws(TLSError) -> (authentication: AuthenticationMethod, verification: VerificationMethod)? {
            var verification: VerificationMethod = .none
            if clientAuthentication == .required {
                if let validPeerPublicKeys, !validPeerPublicKeys.isEmpty {
                    verification = .rawPublicKey(validPeerPublicKeys)
                } else if let asyncVerifier {
                    verification = .certificateCallbacks(asyncVerifier)
                }
                // Having nothing to verify with is resolved below, once the authentication
                // method is known: whether it is an error depends on that method.
            }

            let authentication: AuthenticationMethod
            if let signingKey {
                authentication = .rawPublicKeyAuth(PrivateKey.init(signingKey))
                if epsks != nil {
                    logger.error("CONFIGURATION: server epsk set but not used as we have raw public keys set")
                }
                if epskSelectionCallback != nil {
                    logger.error("CONFIGURATION: epskSelectionCallback set but not used. we have raw public keys set")
                }
                if asyncAuthenticator != nil {
                    logger.error("CONFIGURATION: asyncAuthenticator set but not used. we have raw public keys set")
                }
            } else if let epsks {
                // EPSKs are only supported for TLS_AES_256_GCM_SHA384
                guard supportedCipherSuites == nil || supportedCipherSuites == [.TLS_AES_256_GCM_SHA384] else {
                    throw TLSError.unknownCiphersuite
                }

                var PSKs: [GeneralEPSK] = []
                for epsk in epsks {
                    if useRawEPSKs {
                        PSKs.append(GeneralEPSK(RawEPSK(identity: epsk.externalIdentity, epsk: epsk.epsk)))
                    } else {
                        let psks = try epsk.deriveImportedPSKs(for: [TLSKDFIdentifier.HKDF_SHA384])
                        PSKs.append(contentsOf: psks.map { GeneralEPSK($0) })
                    }
                }
                authentication = .externalPreSharedKeyAuth(PSKs)
                if epskSelectionCallback != nil {
                    logger.error("CONFIGURATION: epskSelectionCallback set but not used. we have epsks set")
                }
                if asyncAuthenticator != nil {
                    logger.error("CONFIGURATION: asyncAuthenticator set but not used. we have epsks set")
                }
            } else if let epskSelectionCallback {
                authentication = .externalPreSharedKeyAuthCallback(epskSelectionCallback)
                if asyncAuthenticator != nil {
                    logger.error("CONFIGURATION: asyncAuthenticator set but not used. we have epskSelectionCallback set")
                }
            } else if let asyncAuthenticator {
                authentication = .certificateAuthCallbacks(asyncAuthenticator)
            } else if let fallbackAuthentication, case .none = verification {
                // Only applies when nothing else is configured and there is nothing to
                // verify, so it cannot mask a failure found above.
                authentication = fallbackAuthentication
            } else {
                authentication = .noAuthAvailable
            }

            if clientAuthentication == .required, case .none = verification {
                // Never silently downgrade a server that was asked to require client auth.
                guard !authentication.exchangesCertificates else {
                    logger.error("CONFIGURATION: client authentication required with no way to verify the client")
                    return nil
                }
                logger.info("CONFIGURATION: client authentication required but the configured authentication method already authenticates the client; ignoring")
            }

            return (authentication, verification)
        }

        static func validate(_ authentication: AuthenticationMethod, _ verification: VerificationMethod) -> Bool {
            switch (authentication, verification) {
            // A server must always be able to authenticate itself.
            case (.noAuthAvailable, _):
                return false

            // An EPSK authenticates both peers by itself; no certificates are exchanged.
            case (.externalPreSharedKeyAuth, .none),
                 (.externalPreSharedKeyAuthCallback, .none):
                return true
            case (.externalPreSharedKeyAuth, _),
                 (.externalPreSharedKeyAuthCallback, _):
                return false

            case (.rawPublicKeyAuth, _),
                 (.certificateAuthCallbacks, _):
                return true
            }
        }

        init(
            serverName: String? = nil,
            quicTransportParameters: ByteBuffer? = nil,
            alpn: [ApplicationLayerProtocol]? = nil,
            transportIsQUIC: Bool = false,
            signingKey: SwiftTLSPrivateKey? = nil,
            validPeerPublicKeys: [P256.Signing.PublicKey]? = nil,
            supportedCipherSuites: [CipherSuite]? = nil,
            epsks: [EPSK]? = nil,
            epskSelectionCallback: externalPSKSelectionCallback? = nil,
            useRawEPSKs: Bool = false,
            clientAuthentication: ClientAuthenticationPolicy = .disabled,
            enableEarlyData: Bool = false,
            asyncAuthenticator: AsyncAuthenticator? = nil,
            asyncVerifier: AsyncVerifier? = nil,
            fallbackAuthentication: AuthenticationMethod? = nil
        ) {
            self.serverName = serverName
            self.quicTransportParameters = quicTransportParameters
            self.alpn = alpn
            self.transportIsQUIC = transportIsQUIC
            self.enableEarlyData = enableEarlyData
            self.supportedCipherSuites = supportedCipherSuites

            do throws(TLSError) {
                if transportIsQUIC {
                    guard quicTransportParameters != nil else {
                        self.authenticationMethod = .noAuthAvailable
                        self.verificationMethod = .none
                        self.validConfiguration = false
                        return
                    }
                }

                guard let (authentication, verification) = try Self.resolve(
                    signingKey: signingKey,
                    validPeerPublicKeys: validPeerPublicKeys,
                    epsks: epsks,
                    epskSelectionCallback: epskSelectionCallback,
                    useRawEPSKs: useRawEPSKs,
                    clientAuthentication: clientAuthentication,
                    supportedCipherSuites: supportedCipherSuites,
                    asyncAuthenticator: asyncAuthenticator,
                    asyncVerifier: asyncVerifier,
                    fallbackAuthentication: fallbackAuthentication
                ) else {
                    self.authenticationMethod = .noAuthAvailable
                    self.verificationMethod = .none
                    self.validConfiguration = false
                    return
                }
                self.authenticationMethod = authentication
                self.verificationMethod = verification

                guard Self.validate(authentication, verification) else {
                    self.validConfiguration = false
                    return
                }

                switch authentication {
                case .externalPreSharedKeyAuth, .externalPreSharedKeyAuthCallback:
                    self.useRawEPSKs = useRawEPSKs
                default:
                    break
                }
                self.validConfiguration = true
            } catch {
                self.authenticationMethod = .noAuthAvailable
                self.verificationMethod = .none
                self.validConfiguration = false
            }
        }
    }
}

#endif
