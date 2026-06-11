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

@available(anyAppleOS 26, *)
struct EPSK {
    let externalIdentity: ByteBuffer
    let epsk: SymmetricKey
    let context: ByteBuffer?

    init(externalIdentity: ByteBuffer, epsk: SymmetricKey, context: ByteBuffer?) throws(TLSError) {
        guard epsk.bitCount >= 128 else {
            throw TLSError.insufficientLengthForEPSK
        }

        self.externalIdentity = externalIdentity
        self.epsk = epsk
        self.context = context
    }

    internal func generateImportedIdentity(for targetKDF: TLSKDFIdentifier) throws(TLSError) -> ImportedIdentity {
        return try ImportedIdentity(externalIdentity: externalIdentity, context: context, targetProtocol: 0x0304, targetKDF: targetKDF.rawValue)
    }

    func deriveImportedPSKs(for targetKDFs: [TLSKDFIdentifier]) throws(TLSError) -> [ImportedPSK] {
        guard !targetKDFs.isEmpty else {
            throw TLSError.missingTargetKDFs
        }
        var importedPSKs: [ImportedPSK] = []
        let zeros = Array(repeating: UInt8(0), count: SHA256.Digest.byteCount)
        // SHA256 is default specified by RFC 9258:
        // "The hash function used for HMAC-based Key Derivation Function (HKDF) [RFC5869] is that which is associated with the EPSK.
        // It is not the hash function associated with ImportedIdentity.target_kdf. If the EPSK does not have such an associated hash
        // function, SHA-256 [SHA2] SHOULD be used."
        let epskx = HKDF<SHA256>.extract(inputKeyMaterial: epsk, salt: zeros)
        for targetKDF in targetKDFs {
            let importedIdentity = try generateImportedIdentity(for: targetKDF)
            let ipskx = HKDF<SHA256>.expandLabel(secret: epskx, label: "derived psk", context: SHA256.hash(data: importedIdentity.serialize()), length: targetKDF.outputLength)
            importedPSKs.append(ImportedPSK(importedIdentity: importedIdentity, ipskx: ipskx))
        }
        return importedPSKs
    }
}

@available(anyAppleOS 26, *)
struct TLSKDFIdentifier: Sendable {
    public let rawValue: UInt16
    public let outputLength: Int

    init(rawValue: UInt16,  outputLength: Int) {
        self.rawValue = rawValue
        self.outputLength = outputLength
    }

    static func cipherSuiteToKDFIdentifier(cipherSuite: CipherSuite) throws(TLSError) -> TLSKDFIdentifier {
        if cipherSuite == .TLS_AES_256_GCM_SHA384 {
            return TLSKDFIdentifier.HKDF_SHA384
        } else if cipherSuite == .TLS_AES_128_GCM_SHA256 ||
                    cipherSuite == .TLS_CHACHA20_POLY1305_SHA256 {
            return TLSKDFIdentifier.HKDF_SHA256
        } else {
            throw TLSError.unknownCiphersuite
        }
    }
}

@available(anyAppleOS 26, *)
extension TLSKDFIdentifier: Hashable { }

@available(anyAppleOS 26, *)
extension TLSKDFIdentifier {
    static let HKDF_SHA256 = TLSKDFIdentifier(rawValue: 0x0001, outputLength: 32)
    static let HKDF_SHA384 = TLSKDFIdentifier(rawValue: 0x0002, outputLength: 48)
}

@available(anyAppleOS 26, *)
protocol PSKProtocol {
    var identity: ByteBuffer { get }
    var key: SymmetricKey { get }
}

@available(anyAppleOS 26, *)
enum PSK: Equatable {
    case imported(ImportedPSK)
    case rawEPSK(RawEPSK)
}

@available(anyAppleOS 26, *)
struct GeneralEPSK: Equatable, PSKProtocol {
    let innerPSK: PSK

    var identity: ByteBuffer {
        switch innerPSK {
        case .imported(let psk):
            return psk.identity
        case .rawEPSK(let psk):
            return psk.identity
        }
    }

    var key: SymmetricKey {
        switch innerPSK {
        case .imported(let psk):
            return psk.key
        case .rawEPSK(let psk):
            return psk.key
        }
    }

    var isImported: Bool {
        switch innerPSK {
        case .imported:
            return true
        case .rawEPSK:
            return false
        }
    }

    var targetKDF: UInt16? {
        switch innerPSK {
        case .imported(let importedPSK):
            return importedPSK.importedIdentity.targetKDF
        case .rawEPSK(_):
            return nil
        }
    }

    init(_ importedPSK: ImportedPSK) {
        self.innerPSK = .imported(importedPSK)
    }

    init(_ rawEPSK: RawEPSK) {
        self.innerPSK = .rawEPSK(rawEPSK)
    }
}

@available(anyAppleOS 26, *)
struct ImportedPSK: Equatable, PSKProtocol {
    let importedIdentity: ImportedIdentity
    let ipskx: SymmetricKey

    var identity : ByteBuffer { ByteBuffer(data: importedIdentity.serialize()) }
    var key: SymmetricKey { ipskx }
}

@available(anyAppleOS 26, *)
struct RawEPSK: Equatable, PSKProtocol {
    let identity: ByteBuffer
    let epsk: SymmetricKey
    var key: SymmetricKey { epsk }
}

@available(anyAppleOS 26, *)
struct ImportedIdentity: Hashable {
    let externalIdentity: ByteBuffer
    let context: ByteBuffer?
    let targetProtocol: UInt16 // 0x0304 for TLS 1.3
    let targetKDF: UInt16

    init(externalIdentity: ByteBuffer, context: ByteBuffer?, targetProtocol: UInt16, targetKDF: UInt16) throws(TLSError) {
        // reject any ImportedIdentity that exceeds 2^16 - 1 octets (max size of PSK extension)
        guard externalIdentity.readableBytes + (context?.readableBytes ?? 0) + 8 <= UInt16.max else {
            throw TLSError.importedIdentityTooLong
        }

        self.externalIdentity = externalIdentity
        self.context = context
        self.targetProtocol = targetProtocol
        self.targetKDF = targetKDF
    }

    func serialize() -> Data {
        var buffer = ByteBuffer()
        buffer.writeUInt16LengthPrefixedImmutableBuffer(self.externalIdentity)
        if let context {
            buffer.writeUInt16LengthPrefixedImmutableBuffer(context)
        } else {
            buffer.writeInteger(0, as: UInt16.self)
        }
        buffer.writeInteger(self.targetProtocol, as: UInt16.self)
        buffer.writeInteger(self.targetKDF)

        return buffer.readableBytesView
    }

    init(serialized: RawSpan) throws(TLSError) {
        var buffer = InputBuffer(storage: serialized)
        guard let externalIdentity = buffer.readLengthPrefixed(lengthAs: UInt16.self, { ByteBuffer(copying: $0.bytes) }),
              let context = buffer.readLengthPrefixed(lengthAs: UInt16.self, { ByteBuffer(copying: $0.bytes) }),
              let targetProtocol = buffer.readInteger(as: UInt16.self),
              let targetKDF = buffer.readInteger(as: UInt16.self) else {
            throw TLSError.invalidSerializedImportedIdentity
        }

        self.externalIdentity = externalIdentity
        self.context = context.readableBytes > 0 ? context : nil
        self.targetProtocol = targetProtocol
        self.targetKDF = targetKDF
    }

    static func getImportedIdentity(serialized: RawSpan) -> ImportedIdentity? {
        do {
            return try ImportedIdentity(serialized: serialized)
        } catch {
            return nil
        }
    }
}

@available(anyAppleOS 26, *)
extension ByteBuffer {
    mutating func writeUInt16LengthPrefixedImmutableBuffer(_ byteBuffer: ByteBuffer) {
        self.writeInteger(UInt16(byteBuffer.readableBytes))
        self.writeImmutableBuffer(byteBuffer)
    }
}
