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

/// A generic wrapper over the supported private-key types.
///
/// Loosely based on the implementation in Swift Certificates.
struct PrivateKey {
    var backing: BackingPrivateKey

    internal init(backing: BackingPrivateKey) {
        self.backing = backing
    }

    /// Construct a `PrivateKey` wrapping the provided key
    init(_ privateKey: SwiftTLSPrivateKey) {
        switch privateKey {
        case .p256(let key):
            self.backing = .p256(key)
#if !SWIFTTLS_EMBEDDED && canImport(Darwin)
        case .p256SEPBacked(let key):
            self.backing = .secureEnclaveP256(key)
#endif
        case .opaqueReference(let key):
            self.backing = .opaqueReference(key)
        }
    }

    /// Use the private key to sign the provided bytes with a given signature algorithm.
    ///
    /// - Parameters:
    ///   - bytes: The data to create the signature for.
    ///   - signatureScheme: The raw value of the TLS signature scheme to use.
    /// - Returns: The signature.
    func sign(
        bytes: Data,
        signatureScheme: UInt16
    ) throws(TLSError) -> Data {
        switch self.backing {
        case .p256(let p256):
            guard signatureScheme == SignatureScheme.ecdsa_secp256r1_sha256.rawValue else {
                throw TLSError.internalError(reason: "asked to sign using \(SignatureScheme(rawValue: signatureScheme).description) with a \(self.description)")
            }
            return try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try p256.signature(for: bytes).derRepresentation }
#if !SWIFTTLS_EMBEDDED && canImport(Darwin)
        case .secureEnclaveP256(let secureEnclaveP256):
            guard signatureScheme == SignatureScheme.ecdsa_secp256r1_sha256.rawValue else {
                throw TLSError.internalError(reason: "asked to sign using \(SignatureScheme(rawValue: signatureScheme).description) with a \(self.description)")
            }
            return try TLSError.wrappingCryptoError { () throws (CryptoKitMetaError) in try secureEnclaveP256.signature(for: bytes).derRepresentation }
#endif
        case .opaqueReference(let refKey):
            guard refKey.supportsSignatureScheme(SignatureScheme(rawValue: signatureScheme)) else {
                throw TLSError.internalError(reason: "asked to sign using \(SignatureScheme(rawValue: signatureScheme).description) with a \(self.description)")
            }
            guard let signature = refKey.sign(bytes, signatureScheme) else {
                throw TLSError.refKeySigningFailure
            }
            return signature
        }
    }

    var publicKey: PublicKey {
        switch self.backing {
        case .p256(let p256):
            return PublicKey(p256.publicKey)
#if !SWIFTTLS_EMBEDDED && canImport(Darwin)
        case .secureEnclaveP256(let secureEnclaveP256):
            return PublicKey(secureEnclaveP256.publicKey)
#endif
        case .opaqueReference(let refKey):
            return refKey.publicKey
        }
    }
}

extension PrivateKey: Hashable {}

extension PrivateKey: CustomStringConvertible {
    var description: String {
        switch self.backing {
        case .p256:
            return "P256.PrivateKey"
#if !SWIFTTLS_EMBEDDED && canImport(Darwin)
        case .secureEnclaveP256:
            return "SecureEnclave.P256.PrivateKey"
#endif
        case .opaqueReference(let refKey):
            return refKey.description
        }
    }
}


@_spi(SwiftTLSOptions)
@available(SwiftTLS 0.1.0, *)
public typealias SwiftTLSSignatureScheme = UInt16

/// A callback that accepts the bytes to sign and the negotiated TLS signature scheme,
/// and returns the signature, or `nil` when signing fails.
@_spi(SwiftTLSOptions)
@available(SwiftTLS 0.1.0, *)
public typealias SwiftTLSRefKeySignCallback = (Data, SwiftTLSSignatureScheme) -> Data?

/// The underlying key types supported by `SwiftTLSOpaqueReferenceKey`.
enum SwiftTLSOpaqueReferenceKeyType: Sendable {
    case p256
}

/// A generic private-key type that lets a caller produce signatures over data using any key
/// the caller can access.
@_spi(SwiftTLSOptions)
@available(SwiftTLS 0.1.0, *)
public struct SwiftTLSOpaqueReferenceKey {
    let publicKey: PublicKey
    let sign: SwiftTLSRefKeySignCallback
    let keyType: SwiftTLSOpaqueReferenceKeyType

    var description: String {
        switch self.keyType {
        case .p256:
            "Opaque P256 Reference Key"
        }
    }

    /// Construct a private key handle for a P256 key that the caller does not directly hold.
    /// - Parameter p256: The P256 public key corresponding to the underlying private key.
    /// - Parameter signCallback: `SwiftTLSRefKeySignCallback` callback that signs data using the underlying private key.
    public init(_ p256: P256.Signing.PublicKey, _ signCallback: @escaping SwiftTLSRefKeySignCallback) {
        publicKey = PublicKey(p256)
        sign = signCallback
        keyType = .p256
    }

    /// Returns whether this `SwiftTLSOpaqueReferenceKey` has a key type
    /// compatible with the negotiated TLS signature scheme.
    func supportsSignatureScheme(_ sigScheme: SignatureScheme) -> Bool {
        switch self.keyType {
        case .p256:
            if sigScheme == .ecdsa_secp256r1_sha256 {
                return true
            }
        }
        return false
    }
}

extension PrivateKey {
    enum BackingPrivateKey: Hashable {
        case p256(P256.Signing.PrivateKey)
#if !SWIFTTLS_EMBEDDED && canImport(Darwin)
        case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)
#endif
        case opaqueReference(SwiftTLSOpaqueReferenceKey)

        static func == (lhs: BackingPrivateKey, rhs: BackingPrivateKey) -> Bool {
            switch (lhs, rhs) {
            case (.p256(let l), .p256(let r)):
                return l.rawRepresentation == r.rawRepresentation
#if !SWIFTTLS_EMBEDDED && canImport(Darwin)
            case (.secureEnclaveP256(let l), .secureEnclaveP256(let r)):
                return l.dataRepresentation == r.dataRepresentation
#endif
            case (.opaqueReference(let l), .opaqueReference(let r)):
                // compare public keys since we don't have access to the real private
                // keys
                return l.publicKey == r.publicKey && l.keyType == r.keyType
            default:
                return false
            }
        }

        func hash(into hasher: inout Hasher) {
            switch self {
            case .p256(let digest):
                hasher.combine(0)
                hasher.combine(digest.rawRepresentation)
#if !SWIFTTLS_EMBEDDED && canImport(Darwin)
            case .secureEnclaveP256(let digest):
                hasher.combine(1)
                hasher.combine(digest.dataRepresentation)
#endif
            case .opaqueReference(let digest):
                hasher.combine(2)
                hasher.combine(digest.publicKey)
                hasher.combine(digest.keyType)
            }
        }
    }
}
