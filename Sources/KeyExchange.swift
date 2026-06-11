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
@available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
typealias SymmetricKey = CryptoKit.SymmetricKey
#elseif canImport(Crypto)
@preconcurrency import Crypto
@available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
typealias SymmetricKey = Crypto.SymmetricKey
#endif

@available(anyAppleOS 26, *)
protocol EphemeralPrivateKey {
    var namedGroup: NamedGroup { get }
    var publicKeyData: Data { get }
    func encap(publicKeyData: Data) throws(TLSError) -> (Data, SymmetricKey)
    func decap(ciphertextData: Data) throws(TLSError) -> SymmetricKey
}

@available(anyAppleOS 26, *)
enum GeneratedEphemeralPrivateKey: EphemeralPrivateKey {
    var namedGroup: NamedGroup {
        get {
            switch self {
            case .curve25519(let key):
                return key.namedGroup
            case .p384(let key):
                return key.namedGroup
            case .X25519MLKEM768(let key):
                return key.namedGroup
            }
        }
    }

    var publicKeyData: Data {
        get {
            switch self {
            case .curve25519(let key):
                return key.publicKeyData
            case .p384(let key):
                return key.publicKeyData
            case .X25519MLKEM768(let key):
                return key.publicKeyData
            }
        }
    }

    func encap(publicKeyData: Data) throws(TLSError) -> (Data, SymmetricKey) {
        switch self {
        case .curve25519(let key):
            return try key.encap(publicKeyData: publicKeyData)
        case .p384(let key):
            return try key.encap(publicKeyData: publicKeyData)
        case .X25519MLKEM768(let key):
            return try key.encap(publicKeyData: publicKeyData)
        }
    }

    func decap(ciphertextData: Data) throws(TLSError) -> SymmetricKey {
        switch self {
            case .curve25519(let key):
            return try key.decap(ciphertextData: ciphertextData)
        case .p384(let key):
            return try key.decap(ciphertextData: ciphertextData)
        case .X25519MLKEM768(let key):
            return try key.decap(ciphertextData: ciphertextData)
        }
    }

    case curve25519(Curve25519EphemeralKey)
    case p384(P384EphemeralKey)
    case X25519MLKEM768(X25519MLKEM768EphemeralKey)
}

@available(anyAppleOS 26, *)
struct Curve25519EphemeralKey: EphemeralPrivateKey {
    var privateKey: Curve25519.KeyAgreement.PrivateKey

    init() {
        self.privateKey = Curve25519.KeyAgreement.PrivateKey()
    }

    var namedGroup: NamedGroup {
        get {
            return .x25519
        }
    }

    var publicKeyData: Data {
        get {
            return self.privateKey.publicKey.rawRepresentation
        }
    }

    func encap(publicKeyData: Data) throws(TLSError) -> (Data, SymmetricKey) {
        let key = try decap(ciphertextData: publicKeyData)
        return (self.publicKeyData, key)
    }

    func decap(ciphertextData: Data) throws(TLSError) -> SymmetricKey {
        let peerPublicKey = try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ciphertextData) }
        let secret = try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try self.privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey) }
        return SymmetricKey.init(data: secret)
    }
}

@available(anyAppleOS 26, *)
struct P384EphemeralKey: EphemeralPrivateKey {
    typealias T = P384.KeyAgreement.PrivateKey
    var privateKey: P384.KeyAgreement.PrivateKey

    init() {
        self.privateKey = P384.KeyAgreement.PrivateKey()
    }

    var namedGroup: NamedGroup {
        get {
            return .secp384
        }
    }

    var publicKeyData: Data {
        get {
            return self.privateKey.publicKey.x963Representation
        }
    }

    func encap(publicKeyData: Data) throws(TLSError) -> (Data, SymmetricKey) {
        let key = try decap(ciphertextData: publicKeyData)
        return (self.publicKeyData, key)
    }

    func decap(ciphertextData: Data) throws(TLSError) -> SymmetricKey {
        let peerPublicKey = try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try P384.KeyAgreement.PublicKey(x963Representation: ciphertextData) }
        let secret = try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in try self.privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey) }
        return SymmetricKey.init(data: secret)
    }
}

@available(anyAppleOS 26, *)
struct X25519MLKEM768EphemeralKey: EphemeralPrivateKey {
    var privateKeyA: Curve25519.KeyAgreement.PrivateKey
    var privateKeyB: MLKEM768.PrivateKey
    var publicKeyData: Data

    let curve25519PublicKeySize = 32
    let mlkemPublicKeySize = 1184
    let mlkemCiphertextSize = 1088

    init() throws(TLSError) {
        self.privateKeyA = Curve25519.KeyAgreement.PrivateKey()
        self.privateKeyB = try TLSError.wrappingCryptoError { try MLKEM768.PrivateKey.generate() }
        self.publicKeyData = self.privateKeyB.publicKey.rawRepresentation + self.privateKeyA.publicKey.rawRepresentation
    }

    var namedGroup: NamedGroup {
        get {
            return .x25519MLKEM768
        }
    }

    func encap(publicKeyData: Data) throws(TLSError) -> (Data, SymmetricKey) {
        if publicKeyData.count < curve25519PublicKeySize+mlkemPublicKeySize {
            throw TLSError.insufficientBytes
        }
        let peerMLKEMKeyBytes = publicKeyData.prefix(mlkemPublicKeySize)
        let peerX25519KeyBytes = publicKeyData.dropFirst(mlkemPublicKeySize)

        let peerPublicKeyA = try TLSError.wrappingCryptoError { try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerX25519KeyBytes) }
        let sharedSecretA = try TLSError.wrappingCryptoError { try self.privateKeyA.sharedSecretFromKeyAgreement(with: peerPublicKeyA) }
        let secretA = SymmetricKey(data:sharedSecretA)

        let peerPublicKeyB = try TLSError.wrappingCryptoError { try MLKEM768.PublicKey(rawRepresentation: peerMLKEMKeyBytes) }
        let encapResult = try TLSError.wrappingCryptoError { try peerPublicKeyB.encapsulate() }
        let secretB = encapResult.sharedSecret

        var buffer = ByteBuffer()
        secretB.withUnsafeBytes { _ = buffer.writeBytes($0) }
        secretA.withUnsafeBytes { _ = buffer.writeBytes($0) }
        let bytes = buffer.readableBytesView

        let ciphertext = encapResult.encapsulated + self.privateKeyA.publicKey.rawRepresentation

        return (ciphertext, SymmetricKey.init(data: bytes))
    }

    func decap(ciphertextData: Data) throws(TLSError) -> SymmetricKey {
        if ciphertextData.count < curve25519PublicKeySize+mlkemCiphertextSize {
            throw TLSError.insufficientBytes
        }
        let peerMLKEMKeyBytes = ciphertextData.prefix(mlkemCiphertextSize)
        let peerX25519KeyBytes = ciphertextData.dropFirst(mlkemCiphertextSize)

        let peerPublicKeyA = try TLSError.wrappingCryptoError { try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerX25519KeyBytes) }
        let sharedSecretA = try TLSError.wrappingCryptoError { try self.privateKeyA.sharedSecretFromKeyAgreement(with: peerPublicKeyA) }
        let secretA = SymmetricKey(data:sharedSecretA)
        let secretB = try TLSError.wrappingCryptoError { try self.privateKeyB.decapsulate(peerMLKEMKeyBytes) }

        var buffer = ByteBuffer()
        secretB.withUnsafeBytes { _ = buffer.writeBytes($0) }
        secretA.withUnsafeBytes { _ = buffer.writeBytes($0) }
        let bytes = buffer.readableBytesView

        return SymmetricKey.init(data: bytes)
    }
}

@available(anyAppleOS 26, *)
func generateEphemeralKeyForNamedGroup(_ group: NamedGroup) -> GeneratedEphemeralPrivateKey? {
    switch group {
    case .secp384:
        return .p384(P384EphemeralKey())
    case .x25519:
        return .curve25519(Curve25519EphemeralKey())
    case .x25519MLKEM768:
        guard let key = try? X25519MLKEM768EphemeralKey() else {
            return nil
        }
        return .X25519MLKEM768(key)
    default:
        return nil
    }
}

@available(anyAppleOS 26, *)
extension SymmetricKey {
    init(_copying bytes: RawSpan) {
        self = bytes.withUnsafeBytes { buffer in
            SymmetricKey(data: buffer)
        }
    }
}
