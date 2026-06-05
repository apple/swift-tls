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

#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@_spi(SwiftTLSOptions) @testable import SwiftTLS
#endif
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif

#if canImport(Foundation) && !SWIFTTLS_EMBEDDED
import Foundation
#endif

var goodClientHello: ClientHello {
  let ephemeralKey = P384EphemeralKey()
  return ClientHello(
      legacyVersion: .tlsv12,
      random: Random(),
      legacySessionID: .zero,
      cipherSuites: [.TLS_AES_256_GCM_SHA384],
      legacyCompressionMethods: [0],
      extensions: [
          .supportedVersions(.offer([.tlsv13])),
          .supportedGroups(.init(groups: [
          ephemeralKey.namedGroup,
          ])),
          .keyShare(.clientHello([.init(group: ephemeralKey.namedGroup, keyExchange: ByteBuffer(data: ephemeralKey.publicKeyData))])),
          .signatureAlgorithms(.init(schemes: [
              .ecdsa_secp256r1_sha256
          ])),
          .serverCertificateType(PeerCertificateBundle.verificationCertificateTypes),
          .preSharedKeyKexModes(.init(modes: [.pskAndDHE])),
          .quicTransportParameters(.init(opaqueOffer: ByteBuffer("some opaque bytes"))),
          .alpn(.offer(["proto A"]))
      ]
  )
}

class TestConfigurationGenerator {
    let serverSigningKey = P256.Signing.PrivateKey()
    let clientSigningKey =  P256.Signing.PrivateKey()
    #if !SWIFTTLS_EMBEDDED && canImport(Darwin)
    var serverSEPSigningKey: SecureEnclave.P256.Signing.PrivateKey? = nil
    var clientSEPSigningKey: SecureEnclave.P256.Signing.PrivateKey? = nil
    #endif

    let externalIdentity = ByteBuffer("test psk identity")
    let epsk = SymmetricKey(size: SymmetricKeySize.bits128)
    let context = ByteBuffer("test context")

    let sampleEPSK: EPSK
    let EPSKMismatchIdentity: EPSK
    let EPSKMismatchContext: EPSK
    let EPSKMismatchKey: EPSK
    let EPSKNilContext: EPSK

    let EPSK2: EPSK
    let EPSK3: EPSK

    init() throws {
        sampleEPSK = try EPSK(externalIdentity: externalIdentity, epsk: epsk, context: context)
        EPSKMismatchIdentity = try EPSK(externalIdentity: ByteBuffer("other identity"), epsk: epsk, context: context)
        EPSKMismatchContext = try EPSK(externalIdentity: externalIdentity, epsk: epsk, context: ByteBuffer("other context"))
        EPSKMismatchKey = try EPSK(externalIdentity: externalIdentity, epsk: SymmetricKey(size: SymmetricKeySize.bits128), context: context)
        EPSKNilContext = try EPSK(externalIdentity: externalIdentity, epsk: epsk, context: nil)

        EPSK2 = try EPSK(externalIdentity: ByteBuffer("test psk identity 2"), epsk: SymmetricKey(size: SymmetricKeySize.bits128), context: ByteBuffer("test context"))
        EPSK3 = try EPSK(externalIdentity: ByteBuffer("test psk identity 3"), epsk: SymmetricKey(size: SymmetricKeySize.bits128), context: ByteBuffer("test context"))
        #if !SWIFTTLS_EMBEDDED && canImport(Darwin)
        if SecureEnclave.isAvailable {
            serverSEPSigningKey = try? SecureEnclave.P256.Signing.PrivateKey()
            clientSEPSigningKey = try? SecureEnclave.P256.Signing.PrivateKey()
        }
        #endif
    }

    func getValidEPSK() -> EPSK {
        return sampleEPSK
    }

    func getValidEPSKNilContext() -> EPSK {
        return EPSKNilContext
    }

    func getClientEPSKConfiguration(raw: Bool = false, earlyData: Bool = false, nilContext: Bool = false, alpn: [String]? = ["proto a"]) -> HandshakeStateMachine.Configuration {
        HandshakeStateMachine.Configuration(
            serverName: nil,
            quicTransportParameters: nil,
            alpn: alpn,
            fixedKeyExchangeGroup: NamedGroup.secp384.rawValue,
            signingKey: nil,
            validPeerPublicKeys: nil,
            ticketRequest: nil,
            epsk: nilContext ? EPSKNilContext : sampleEPSK,
            useRawEPSKs: raw,
            enableEarlyData: earlyData)
    }

    func getServerEPSKConfiguration(
        raw: Bool = false,
        earlyData: Bool = false,
        nilContext: Bool = false,
        alpn: [String]? = ["proto a"],
        multiple: Bool = false,
        mismatchIdentity: Bool = false,
        mismatchBaseKey: Bool = false,
        mismatchContext: Bool = false
    ) -> ServerHandshakeStateMachine.Configuration {

        var epsks = nilContext ? [EPSKNilContext] : [sampleEPSK]
        if multiple {
            epsks = [EPSK2, nilContext ? EPSKNilContext : sampleEPSK, EPSK3]
        } else if mismatchIdentity {
            epsks = [EPSKMismatchIdentity]
        } else if mismatchContext {
            epsks = [EPSKMismatchContext]
        } else if mismatchBaseKey {
            epsks = [EPSKMismatchKey]
        }
        return ServerHandshakeStateMachine.Configuration(
            serverName: nil,
            quicTransportParameters: nil,
            alpn: alpn,
            signingKey: nil,
            validPeerPublicKeys: nil,
            epsks: epsks,
            useRawEPSKs: raw,
            clientAuthRequired: false,
            enableEarlyData: earlyData
        )
    }

    func getClientConfigWithOptions(
        serverName: String? = nil,
        quicTransportParams: ByteBuffer? = nil,
        alpn: [String]? = nil,
        fixedKeyExchangeGroup: NamedGroup? = nil,
        supportedCipherSuites: [CipherSuite]? = nil,
        signingKey: Bool = false,
        mismatchSigningKey: Bool = false,
        enableEarlyData: Bool = false,
        refKey: Bool = false,
        sepKey: Bool = false
    ) -> HandshakeStateMachine.Configuration {
        var clientKey: SwiftTLSPrivateKey? = nil
        var trustedPubKeys: [P256.Signing.PublicKey] = [serverSigningKey.publicKey]
        if signingKey || mismatchSigningKey {
            clientKey = signingKey ? .p256(clientSigningKey) : (mismatchSigningKey ? .p256(P256.Signing.PrivateKey()) : nil)
        }

        if refKey {
            let signCallback: SwiftTLSRefKeySignCallback = { (data: Data, sigAlg: UInt16) -> Data? in
                do {
                    return try self.clientSigningKey.signature(for: data).derRepresentation as Data
                } catch {
                    return nil
                }
            }
            clientKey = .opaqueReference(SwiftTLSOpaqueReferenceKey(clientSigningKey.publicKey, signCallback))
        }
        if sepKey {
            #if !SWIFTTLS_EMBEDDED && canImport(Darwin)
            if let clientSEPSigningKey, let serverSEPSigningKey {
                clientKey = .p256SEPBacked(clientSEPSigningKey)
                trustedPubKeys = [serverSEPSigningKey.publicKey]
            }
            #endif
        }

        return HandshakeStateMachine.Configuration(
            serverName: serverName,
            quicTransportParameters: quicTransportParams,
            alpn: alpn,
            fixedKeyExchangeGroup: fixedKeyExchangeGroup?.rawValue ?? NamedGroup.secp384.rawValue,
            supportedCipherSuites: supportedCipherSuites,
            signingKey: clientKey,
            validPeerPublicKeys: trustedPubKeys,
            ticketRequest: nil,
            enableEarlyData: enableEarlyData)
    }

    func getServerConfigWithOptions(
        serverName: String? = nil,
        quicTransportParams: ByteBuffer? = nil,
        supportedCipherSuites: [CipherSuite]? = nil,
        alpn: [String]? = nil,
        signingKey: Bool = true,
        mismatchSigningKey: Bool = false,
        enableEarlyData: Bool = false,
        transportIsQUIC: Bool = false,
        clientAuthReq: Bool = false,
        refKey: Bool = false,
        sepKey: Bool = false
    ) -> ServerHandshakeStateMachine.Configuration {

        var serverKey: SwiftTLSPrivateKey? = nil
        var trustedPubKeys: [P256.Signing.PublicKey]? = clientAuthReq ? [clientSigningKey.publicKey] : nil
        if signingKey {
            serverKey = signingKey ? .p256(serverSigningKey) : (mismatchSigningKey ? .p256(P256.Signing.PrivateKey()) : nil)
        }

        if refKey {
            let signCallback: SwiftTLSRefKeySignCallback = { (data: Data, sigAlg: UInt16) -> Data? in
                do {
                    return try self.serverSigningKey.signature(for: data).derRepresentation as Data
                } catch {
                    return nil
                }
            }
            serverKey = .opaqueReference(SwiftTLSOpaqueReferenceKey(serverSigningKey.publicKey, signCallback))
        }
        if sepKey {
            #if !SWIFTTLS_EMBEDDED && canImport(Darwin)
            if let serverSEPSigningKey {
                serverKey = .p256SEPBacked(serverSEPSigningKey)
                if clientAuthReq, let clientSEPSigningKey {
                    trustedPubKeys = [clientSEPSigningKey.publicKey]
                }
            }
            #endif
        }

        return ServerHandshakeStateMachine.Configuration(
            serverName: serverName,
            quicTransportParameters: quicTransportParams,
            alpn: alpn,
            transportIsQUIC: transportIsQUIC,
            signingKey: serverKey,
            validPeerPublicKeys: trustedPubKeys,
            supportedCipherSuites: supportedCipherSuites,
            clientAuthRequired: clientAuthReq,
            enableEarlyData: enableEarlyData)
    }
}
