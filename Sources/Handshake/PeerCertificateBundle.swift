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
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "PeerCertificateBundle")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.PeerCertificateBundle")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.PeerCertificateBundle")
#endif


/// `PeerCertificateBundle` represents the bundle of certificates sent by the peer.
///
/// Depending on negotiated extensions, the bundle holds either X.509 certificates or raw
/// public keys; a single bundle uses exactly one of these representations.
@available(anyAppleOS 26, *)
struct PeerCertificateBundle {
    fileprivate var bundle: Bundle

    init(expectedCertificateType: CertificateType, peerCertificateMessage: CertificateMessage, fromClient: Bool) throws(TLSError) {
        if fromClient {
            // certificate_required:  Sent by servers when a client certificate is
            // desired but none was provided by the client.
            // According to RFC 8446 it is valid for servers to do optional
            // client authentication (e.g. request a certificate, but still
            // succeed even if none is provided). We do not support this
            // at present.
            guard peerCertificateMessage.certificateList.count > 0 else {
                logger.error("client sent empty certificate list")
                throw TLSError.certificateRequired
            }
        }
        switch expectedCertificateType {
        case .rawPublicKey:
            // Raw public keys only allow a single key.
            guard peerCertificateMessage.certificateList.count == 1,
                  let certificate = peerCertificateMessage.certificateList.first else {
                logger.error("invalid number of public key entries: \(peerCertificateMessage.certificateList.count)")
                throw TLSError.handshakeInvalidMessage
            }

            // We don't send any extensions, for now, so we forbid getting any back.
            guard certificate.extensions.count == 0 else {
                logger.error("invalid number of extensions: \(certificate.extensions.count)")
                throw TLSError.handshakeInvalidMessage
            }

            // For now we assume this must be P256. This will fail if we're wrong.
            logger.debug("constructing public key from peer bytes")
            self.bundle = try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try .rawPublicKey(P256.Signing.PublicKey(derRepresentation: certificate.opaqueCertificateData.readableBytesView)) }
        case .x509:
            guard peerCertificateMessage.certificateList.count >= 1 else {
                logger.error("invalid number of public key entries: \(peerCertificateMessage.certificateList.count)")
                throw TLSError.handshakeInvalidMessage
            }

            logger.notice("negotiating x.509 authentication")
            self.bundle = .x509(peerCertificateMessage.certificateList)
        default:
#if SWIFTTLS_EXCLAVECORE
            logger.error("unsupported certificate type from peer: \(String(describing: expectedCertificateType))")
#else
            logger.error("unsupported certificate type from peer: \(expectedCertificateType)")
#endif
            throw TLSError.handshakeUnexpectedMessage
        }
    }

    fileprivate init(bundle: Bundle) {
        self.bundle = bundle
    }

    func verifyClientCertificateVerifySignature(
        message: CertificateVerify, validKeys: [P256.Signing.PublicKey], keyScheduler: ServerSessionKeyManager<SHA384>
    ) throws(TLSError) -> Bool {
        switch self.bundle {
        case .rawPublicKey(let key):
            guard message.algorithm == .ecdsa_secp256r1_sha256 else {
#if SWIFTTLS_EXCLAVECORE
                logger.error("unsupported algorithm from peer: \(String(describing: message.algorithm))")
#else
                logger.error("unsupported algorithm from peer: \(message.algorithm)")
#endif
                throw TLSError.negotiationFailed
            }

            logger.debug("validating signature from peer client")
            let data = try keyScheduler.dataToSignInClientCertificateVerify()
            let signature = try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try P256.Signing.ECDSASignature(derRepresentation: message.signature.readableBytesView) }
            guard key.isValidSignature(signature, for: data.readableBytesView) else {
                logger.error("signature validation failed")
                return false
            }

            logger.debug("validation succeeded")
            return self.wouldBeTrusted(forKeys: validKeys)

        case .x509:
            // We don't do proper verification of X.509 because we don't want to bring in that dependency stack into
            // this path. We use X.509 for testing purposes only.
            if !Self.supportsUnverifiedX509 {
                fatalError("Self.supportsUnverifiedX509 MUST be true for this path")
            }
            logger.notice("skipping validation of x.509")
            return true
        }
    }

    func verifyServerCertificateVerifySignature(
        message: CertificateVerify, validKeys: [P256.Signing.PublicKey], keyScheduler: ClientSessionKeyManager<SHA384>
    ) throws(TLSError) -> Bool {
        switch self.bundle {
        case .rawPublicKey(let key):
            guard message.algorithm == .ecdsa_secp256r1_sha256 else {
#if SWIFTTLS_EXCLAVECORE
                logger.error("unsupported algorithm from peer: \(String(describing: message.algorithm))")
#else
                logger.error("unsupported algorithm from peer: \(message.algorithm)")
#endif
                throw TLSError.negotiationFailed
            }

            logger.debug("validating signature from peer server")
            let data = try keyScheduler.dataToSignInServerCertificateVerify()
            let signature = try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try P256.Signing.ECDSASignature(derRepresentation: message.signature.readableBytesView) }
            guard key.isValidSignature(signature, for: data.readableBytesView) else {
                logger.error("signature validation failed")
                return false
            }

            logger.debug("validation succeeded")
            return self.wouldBeTrusted(forKeys: validKeys)

        case .x509:
            // We don't do proper verification of X.509 because we don't want to bring in that dependency stack into
            // this path. We use X.509 for testing purposes only. Use the callback-based API to implement X509
            // verification.
            if !Self.supportsUnverifiedX509 {
                fatalError("Self.supportsUnverifiedX509 MUST be true for this path")
            }
            logger.warning("skipping validation of x.509, you should use the callback-based API for this")
            return true
        }
    }

    func wouldBeTrusted(forKeys validKeys: [P256.Signing.PublicKey]) -> Bool {
        switch self.bundle {
        case .rawPublicKey(let key):
            let result = validKeys.contains(where: { $0.rawRepresentation == key.rawRepresentation })
            if (!result) {
#if !SWIFTTLS_EMBEDDED && !SWIFTTLS_DRIVERKIT
                logger.error("couldn't find \(key.rawRepresentation) in trusted keys");
                logger.error("Trusted keys include: \(validKeys.count) keys")
                validKeys.forEach( { logger.error("key: \($0.rawRepresentation) ") } )
#else
                logger.error("the public key is not in the set of \(validKeys.count) trusted public keys")
#endif
            }
            return result
        case .x509:
            // We don't do proper verification of X.509 because we don't want to bring in that dependency stack into
            // this path. We use X.509 for testing purposes only.
            if !Self.supportsUnverifiedX509 {
                fatalError("Self.supportsUnverifiedX509 MUST be true for this path")
            }
            logger.notice("X.509 would always be trusted")
            return true
        }
    }

    func exportList() throws -> CertificateList {
        switch bundle {
        case .rawPublicKey(let publicKey):
            return CertificateList(type: .rawPublicKey, entries: [publicKey.derRepresentation])
        case .x509(let array):
            return CertificateList(type: .x509, entries: array.map { $0.opaqueCertificateData.readableBytesView })
        }
    }
}

@available(anyAppleOS 26, *)
extension PeerCertificateBundle {
    /// The kinds of certificate bundle this package supports.
    fileprivate enum Bundle {
        case rawPublicKey(P256.Signing.PublicKey)
        case x509([CertificateMessage.CertificateEntry])
    }
}

@available(anyAppleOS 26, *)
extension PeerCertificateBundle {
    /// Whether this package supports unverified X.509.
    ///
    /// This is `true` only when the `SWIFTTLS_SUPPORT_UNVERIFIED_X509` compile flag is passed.
    #if SWIFTTLS_SUPPORT_UNVERIFIED_X509
        fileprivate static let supportsUnverifiedX509 = true
    #else
        fileprivate static let supportsUnverifiedX509 = false
    #endif

    /// The certificate types this peer is willing to verify.
    ///
    /// The client offers these in the client hello under `server_certificate_types` when it is
    /// configured to expect a server raw public key. The server uses this same list to determine
    /// whether it supports any of the offered certificate types in `client_certificate_types`.
    static let verificationCertificateTypes: Extension.CertificateTypeExt = {
        if Self.supportsUnverifiedX509 {
            // This is a bit weird. When we really support x509 we will want to
            // differentiate between when we require our peer to have an RPK
            // and when we are okay with RPK or x509
            return Extension.CertificateTypeExt.offer([.rawPublicKey, .x509])
        } else {
            return Extension.CertificateTypeExt.offer([.rawPublicKey])
        }
    }()

    /// The certificate types this peer can provide to its peer.
    ///
    /// The client offers this in the client hello under `client_certificate_types` when it is
    /// configured with a raw public key. The server uses this list to determine whether it
    /// supports any of the offered certificate types in `client_certificate_types`.
    static let availableCertificateTypes: Extension.CertificateTypeExt = {
            // we don't offer .x509 even when we support
            // unverified x509 because that only involves whether
            // we have insecure verification enabled, we don't
            // have support to configure an x509 certificate
            // at all.
            return Extension.CertificateTypeExt.offer([.rawPublicKey])
    }()
}

@available(anyAppleOS 26, *)
extension PeerCertificateBundle: Equatable { }

@available(anyAppleOS 26, *)
extension PeerCertificateBundle.Bundle: Equatable {
    static func ==(lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.rawPublicKey(let lhsKey), .rawPublicKey(let rhsKey)):
            return lhsKey.rawRepresentation == rhsKey.rawRepresentation
        case (.x509, .x509):
            return true
        case (.rawPublicKey, .x509), (.x509, .rawPublicKey):
            return false
        }
    }
}

@available(anyAppleOS 26, *)
extension ByteBuffer {
    mutating func writePeerCertificateBundle(_ bundle: PeerCertificateBundle) {
        switch bundle.bundle {
        case .rawPublicKey(let key):
            self.writeInteger(UInt8(0))
            self.writeLengthPrefixedBytes(key.rawRepresentation)
        case .x509(let entries):
            self.writeInteger(UInt8(1))
            self.writeVariableLengthVectorUInt24 { buffer in
                return entries.reduce(into: 0) { count, certificateEntry in
                    count += buffer.writeCertificateEntry(certificateEntry)
                }
            }
        }
    }
}

@available(anyAppleOS 26, *)
extension InputBuffer {
    mutating func readPeerCertificateBundle() throws(TLSError) -> PeerCertificateBundle? {
        guard let discriminator = self.readInteger(as: UInt8.self) else {
            return nil
        }

        switch discriminator {
        case 0:
            let key = try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try self.readLengthPrefixed { buffer throws(CryptoKitMetaError) in
                try buffer.bytes.withUnsafeBytes { (bytes) throws(CryptoKitMetaError) in
                    try P256.Signing.PublicKey(rawRepresentation: bytes)
                }
            } }
            guard let key = key else {
                return nil
            }
            return PeerCertificateBundle(bundle: .rawPublicKey(key))
        case 1:
            guard let certificateEntries = try self.readVariableLengthVectorUInt24({ buffer throws(TLSError) in
                var certificates = [CertificateMessage.CertificateEntry]()

                while let cert = try buffer.readCertificateEntry() {
                    certificates.append(cert)
                }

                return certificates
            }) else {
                return nil
            }

            return PeerCertificateBundle(bundle: .x509(certificateEntries))
        default:
            logger.error("invalid serialized session")
            throw TLSError.invalidSerializedSession
        }
    }
}
