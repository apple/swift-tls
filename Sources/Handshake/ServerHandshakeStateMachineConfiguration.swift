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
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "ServerHandshakeStateMachineConfiguration")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.ServerHandshakeStateMachineConfiguration")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.ServerHandshakeStateMachineConfiguration")
#endif

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

        /// Public keys for trusted clients
        var _validPeerPublicKeys: [P256.Signing.PublicKey]? = nil

        /// List of cipher suites to use for the handshake
        let supportedCipherSuites: [CipherSuite]?

        /// Whether external PSKs should be treated as imported or raw
        var useRawEPSKs: Bool = false

        /// Whether the server is willing to accept early data
        var enableEarlyData: Bool = false

        /// True if used within QUIC, false otherwise
        var transportIsQUIC: Bool

        /// True if client required to authenticate with RPK/Cert
        var clientAuthRequired: Bool

        /// Public keys for trusted clients
        var validPeerPublicKeys: [P256.Signing.PublicKey]? {
            return _validPeerPublicKeys
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
            clientAuthRequired: Bool = false,
            enableEarlyData: Bool = false,
            asyncAuthenticator: AsyncAuthenticator? = nil
        ) {
            do throws(TLSError) {
                self.serverName = serverName
                self.quicTransportParameters = quicTransportParameters
                self.alpn = alpn
                self.transportIsQUIC = transportIsQUIC
                self.enableEarlyData = enableEarlyData
                self.clientAuthRequired = clientAuthRequired
                self.supportedCipherSuites = supportedCipherSuites
                if transportIsQUIC {
                    guard quicTransportParameters != nil else {
                        self.validConfiguration = false
                        self.authenticationMethod = .noAuthAvailable
                        return
                    }
                }

                // RPKs
                if let signingKey {
                    // Mutual RPK Auth available
                    self.authenticationMethod = .rawPublicKeyAuth(PrivateKey.init(signingKey))
                    if clientAuthRequired {
                        guard let validPeerPublicKeys else {
                            self.validConfiguration = false
                            return
                        }
                        _validPeerPublicKeys = validPeerPublicKeys
                    }
                    self.enableEarlyData = enableEarlyData

                    if epsks != nil {
                        logger.error("CONFIGURATION: server epsk set but not used as we have raw public keys set")
                    }
                    if epskSelectionCallback != nil {
                        logger.error("CONFIGURATION: epskSelectionCallback set but not used. we have raw public keys set")
                    }
                    if asyncAuthenticator != nil {
                        logger.error("CONFIGURATION: asyncAuthenticator set but not used. we have raw public keys set")
                    }
                // EPSKs
                } else if let epsks {
                    // EPSKs are only supported for TLS_AES_256_GCM_SHA384
                    guard supportedCipherSuites == nil || supportedCipherSuites == [.TLS_AES_256_GCM_SHA384] else {
                        throw TLSError.unknownCiphersuite
                    }

                    self.useRawEPSKs = useRawEPSKs
                    var PSKs: [GeneralEPSK] = []
                    for epsk in epsks {
                        if useRawEPSKs {
                            PSKs.append(GeneralEPSK(RawEPSK(identity: epsk.externalIdentity, epsk: epsk.epsk)))
                        } else {
                            let psks = try epsk.deriveImportedPSKs(for: [TLSKDFIdentifier.HKDF_SHA384])
                            PSKs.append(contentsOf: psks.map { GeneralEPSK($0) })
                        }
                    }
                    authenticationMethod = .externalPreSharedKeyAuth(PSKs)
                    if epskSelectionCallback != nil {
                        logger.error("CONFIGURATION: epskSelectionCallback set but not used. we have epsks set")
                    }
                    if asyncAuthenticator != nil {
                        logger.error("CONFIGURATION: asyncAuthenticator set but not used. we have epsks set")
                    }
                } else if let epskSelectionCallback {
                    self.useRawEPSKs = useRawEPSKs
                    self.authenticationMethod = .externalPreSharedKeyAuthCallback(epskSelectionCallback)
                    if asyncAuthenticator != nil {
                        logger.error("CONFIGURATION: asyncAuthenticator set but not used. we have epskSelectionCallback set")
                    }
                } else if let asyncAuthenticator {
                    self.authenticationMethod = .certificateAuthCallbacks(asyncAuthenticator)
                    // mTLS is currently not supported with certificate callbacks.
                    if clientAuthRequired {
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

#endif
