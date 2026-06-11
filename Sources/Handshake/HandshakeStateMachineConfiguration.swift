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
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "HandshakeStateMachineConfiguration")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeStateMachineConfiguration")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeStateMachineConfiguration")
#endif

@_spi(SwiftTLSOptions)
@available(anyAppleOS 26, *)
public enum SwiftTLSPrivateKey {
    case p256(P256.Signing.PrivateKey)
#if !SWIFTTLS_EMBEDDED && canImport(Darwin)
    case p256SEPBacked(SecureEnclave.P256.Signing.PrivateKey)
#endif
    case opaqueReference(SwiftTLSOpaqueReferenceKey)
}

@available(anyAppleOS 26, *)
extension HandshakeStateMachine {
    enum AuthenticationMethod {
        case noAuthAvailable

        /// The client's signing key.
        case rawPublicKeyAuth(PrivateKey)

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
            asyncVerifier: AsyncVerifier? = nil
        ) {
            do throws(TLSError) {
                self.serverName = serverName
                self.quicTransportParameters = quicTransportParameters
                self.alpn = alpn
                self.fixedKeyExchangeGroup = fixedKeyExchangeGroup.map { NamedGroup(rawValue: $0) }
                self.supportedCipherSuites = supportedCipherSuites
                self.verificationMethod = .none // Update when RawPublicKeys or AsyncVerifier is set

                // Figure out which authentication method we are doing
                // We silently ignore options that are not compatible with
                // The one chosen.
                //
                // Preference order is:
                // If configured with trusted Public Key array (can be empty):
                // NoAuthAvailable (server auth only) if no signing key set
                // RPK if signing key set.
                // Signing key with no nil validPeerPublicKeys is ignored.
                //
                // If configured with an EPSK:
                // ExternalPreSharedKeyAuth
                //

                // It is possible to do server auth with regular certificates
                // and client auth with raw public keys.
                // But we do not have certificate support yet, so for
                // now we assume that client auth with raw public keys
                // is only possible if we are also configured to
                // trust raw public keys from the server.
                if let validPeerPublicKeys, !validPeerPublicKeys.isEmpty {
                    self.verificationMethod = .rawPublicKey(validPeerPublicKeys)
                    // Server RPK Auth available
                    if let signingKey {
                        // Mutual RPK Auth available
                        self.authenticationMethod = .rawPublicKeyAuth(PrivateKey.init(signingKey))
                    } else {
                        self.authenticationMethod = .noAuthAvailable
                    }

                    // With RPKs these options are also valid since resumption
                    // can also be attempted:
                    self.ticketRequest = ticketRequest
                    self.enableEarlyData = enableEarlyData

                    if epsk != nil {
                        logger.error("CONFIGURATION: client epsk set but not used as we have raw public keys set")
                    }
                    if asyncVerifier != nil {
                        logger.error("CONFIGURATION: async verifier config set but not used as we have raw public keys set")
                    }
                } else if let epsk {
                    // EPSKs are only supported for TLS_AES_256_GCM_SHA384
                    guard supportedCipherSuites == nil || supportedCipherSuites == [.TLS_AES_256_GCM_SHA384] else {
                        throw TLSError.unknownCiphersuite
                    }

                    self.useRawEPSKs = useRawEPSKs
                    var PSKs: [GeneralEPSK] = []
                    if useRawEPSKs {
                        PSKs.append(GeneralEPSK(RawEPSK(identity: epsk.externalIdentity, epsk: epsk.epsk)))
                    } else {
                        let psks = try epsk.deriveImportedPSKs(for: [TLSKDFIdentifier.HKDF_SHA384])
                        PSKs.append(contentsOf: psks.map { GeneralEPSK($0) })
                    }
                    self.authenticationMethod = .externalPreSharedKeyAuth(PSKs)

                    // With EPSKs these options are also valid:
                    self.enableEarlyData = enableEarlyData
                    self.ticketRequest = ticketRequest

                    if asyncVerifier != nil {
                        logger.error("CONFIGURATION: async verifier config set but not used as we have epsk set")
                    }
                } else if let asyncVerifier {
                    self.verificationMethod = .certificateCallbacks(asyncVerifier)
                    // mTLS is currently not supported via certificate callbacks.
                    self.authenticationMethod = .noAuthAvailable
                    guard signingKey == nil else {
                        logger.error("CONFIGURATION: mTLS is not supported with certificate callbacks")
                        self.validConfiguration = false
                        return
                    }
                } else {
                    self.validConfiguration = false
                    self.authenticationMethod = .noAuthAvailable
                    return
                }
                self.validConfiguration = true
            } catch {
                self.validConfiguration = false
                self.authenticationMethod = .noAuthAvailable
            }
        }
    }
}
