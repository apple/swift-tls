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
#elseif canImport(SwiftSystem)
import SwiftSystem
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
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "RecordLayer")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.RecordLayer")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.RecordLayer")
#endif

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
struct Nonce {
    let array: [12 of UInt8]

    var bytes: RawSpan {
        @_lifetime(borrow self)
        get {
            array.span.bytes
        }
    }

    init(_ span: RawSpan) {
        self.array = [12 of UInt8](copying: span)
    }
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension Nonce: Hashable {
    static func == (lhs: Nonce, rhs: Nonce) -> Bool {
        return lhs.array == rhs.array
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(bytes: self.bytes)
    }
}

// RFC 9846 §5.2: "additional_data = TLSCiphertext.opaque_type ||
// TLSCiphertext.legacy_record_version || TLSCiphertext.length"
//
// The defaults are only correct on the send path; receivers must pass the
// header as it arrived (RFC 9846 Appendix E).
//
// Availability due to `Swift`'s `InlineArray`
@available(SwiftTLS 0.1.0, *)
func additionalData(
    contentType: ContentType = TLSCiphertext.opaqueType,
    protocolVersion: ProtocolVersion = TLSCiphertext.pv,
    ciphertextLength: Int
) -> InlineArray<5, UInt8> {
    let length = UInt16(ciphertextLength)
    let ad: InlineArray<5, UInt8> = [
        contentType.rawValue,
        protocolVersion.major,
        protocolVersion.minor,
        UInt8(truncatingIfNeeded: length >> 8),
        UInt8(truncatingIfNeeded: length),
    ]
    #if SWIFTTLS_EXCLAVECORE
    logger.debug("additional data: content type = \(String(describing: contentType)), protocol version = \(String(describing: protocolVersion)), length = \(ciphertextLength)")
    #else
    logger.debug("additional data: content type = \(contentType), protocol version = \(protocolVersion), length = \(ciphertextLength)")
    #endif
    return ad
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
func calculateTLSRecordNonce(iv: [UInt8], seqno: UInt64) -> Nonce {
    var nonce = [12 of UInt8](repeating: 0)
    // 64-bit seq number is encoded in network byte order and padded to the left with zeros to iv_length
    // Set the 8-right bytes to the packet number.
    // Note that we take assume the packet number is in little-endian and
    // convert it to big-endian.
    nonce[4] |= UInt8((seqno >> 56) & 0xFF)
    nonce[5] |= UInt8((seqno >> 48) & 0xFF)
    nonce[6] |= UInt8((seqno >> 40) & 0xFF)
    nonce[7] |= UInt8((seqno >> 32) & 0xFF)
    nonce[8] |= UInt8((seqno >> 24) & 0xFF)
    nonce[9] |= UInt8((seqno >> 16) & 0xFF)
    nonce[10] |= UInt8((seqno >> 8) & 0xFF)
    nonce[11] |= UInt8((seqno >> 0) & 0xFF)

    // XOR with the IV
    for i in 0..<iv.count {
        nonce[i] ^= iv[i]
    }
    return Nonce(nonce.span.bytes)
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
struct TLSRecordProtector: ~Copyable {
    static let writeAES256KeyLengthBytes = 32
    static let writeAES128KeyLengthBytes = 16

    static let IVlengthBytes = 12
    static let aesTagLengthBytes = 16

    private var writeKey: SymmetricKey?
    private var writeIV: [UInt8]?

    private var readKey: SymmetricKey?
    private var readIV: [UInt8]?

    private var writeSequenceNumber: UInt64 = 0
    private var readSequenceNumber: UInt64 = 0

    private var ciphersuite: UInt16?

    // helper to check key lengths
    func checkKeyAndIVLengths(key: SymmetricKey, iv: [UInt8]) throws(TLSError) {
        guard let ciphersuite = self.ciphersuite else {
            throw TLSError.internalError(reason: "can't check key length without ciphersuite set")
        }
        if ciphersuite == CipherSuite.TLS_AES_256_GCM_SHA384.rawValue {
            guard key.bitCount == TLSRecordProtector.writeAES256KeyLengthBytes * 8 else {
                throw TLSError.internalError(reason: "Invalid symmetric key size for TLS_AES_256_GCM_SHA384: key has \(key.bitCount) bits, needs 256.")
            }
        } else {
            guard key.bitCount == TLSRecordProtector.writeAES128KeyLengthBytes * 8 ||
                key.bitCount == TLSRecordProtector.writeAES256KeyLengthBytes * 8 else {
                throw TLSError.internalError(reason: "Invalid symmetric key size for AES. key has \(key.bitCount) bits, needs 128 OR 256.")
            }
        }

        guard iv.count == TLSRecordProtector.IVlengthBytes else {
            throw TLSError.internalError(reason: "Invalid IV size: writeIV has \(iv.count) bytes, needs \(TLSRecordProtector.IVlengthBytes).")
        }
    }

    // RFC 9846 §5.5: "For AES-GCM, up to 2^24.5 full-size records (about 24 million) may be
    // encrypted under a given set of keys while keeping a safety margin of approximately 2^-57
    // for Authenticated Encryption (AE) security. For ChaCha20/Poly1305, the record sequence
    // number would wrap before the safety limit is reached."
    func aeadRecordLimit() throws(TLSError) -> UInt64 {
        guard let ciphersuite = self.ciphersuite else {
            throw TLSError.internalError(reason: "can't check key usage limit without ciphersuite set")
        }
        if ciphersuite == CipherSuite.TLS_AES_256_GCM_SHA384.rawValue
            || ciphersuite == CipherSuite.TLS_AES_128_GCM_SHA256.rawValue {
            return 23_726_566 // floor(2^24.5)
        }
        throw TLSError.unknownCiphersuite
    }

    init() {
        self.writeKey = nil
        self.writeIV = nil
        self.readKey = nil
        self.readIV = nil
        self.ciphersuite = nil
    }

    init(writeKey: SymmetricKey? = nil, writeIV: [UInt8]? = nil, readKey: SymmetricKey? = nil, readIV: [UInt8]? = nil, ciphersuite: CipherSuite) throws {
        self.ciphersuite = ciphersuite.rawValue
        if let writeKey = writeKey, let writeIV = writeIV {
            try checkKeyAndIVLengths(key: writeKey, iv: writeIV)
        }
        if let readKey = readKey, let readIV = readIV {
            try checkKeyAndIVLengths(key: readKey, iv: readIV)
        }
        self.writeKey = writeKey
        self.writeIV = writeIV
        self.readKey = readKey
        self.readIV = readIV
    }

    mutating func updateWriteKeyAndIV(_ newWriteKey: SymmetricKey, _ newWriteIV: [UInt8]) throws(TLSError) {
        try checkKeyAndIVLengths(key: newWriteKey, iv: newWriteIV)
        self.writeKey = newWriteKey
        self.writeIV = newWriteIV
        self.writeSequenceNumber = 0
    }

    mutating func updateReadKeyAndIV(_ newReadKey: SymmetricKey, _ newReadIV: [UInt8]) throws(TLSError) {
        try checkKeyAndIVLengths(key: newReadKey, iv: newReadIV)
        self.readKey = newReadKey
        self.readIV = newReadIV
        self.readSequenceNumber = 0
    }

    mutating func setCiphersuite(ciphersuite: UInt16) {
        self.ciphersuite = ciphersuite
    }

    mutating func setSequenceNumbersForTesting(write: UInt64? = nil, read: UInt64? = nil) {
        if let write { self.writeSequenceNumber = write }
        if let read { self.readSequenceNumber = read }
    }

    mutating func protect(plaintext: RawSpan, actualContentType: ContentType, paddingLength: Int = 0) throws(TLSError) -> TLSCiphertext {
        guard let writeIV = self.writeIV, let writeKey = self.writeKey else {
            throw TLSError.internalError(reason: "write key and iv not set when protect called")
        }
        // Alerts are exempt from this guard so a terminating alert can still be sent under a key
        // that has just hit the limit
        if actualContentType != .alert {
            guard self.writeSequenceNumber < (try aeadRecordLimit()) else {
                throw TLSError.keyUsageLimitExceeded
            }
        }
        let plaintextByteCount = plaintext.byteCount
        guard plaintextByteCount <= maxPlaintextFragmentLength else {
            throw TLSError.internalError(reason: "plaintext exceeds max plaintext fragment length.")
        }
        let nonce = calculateTLSRecordNonce(iv: writeIV, seqno: self.writeSequenceNumber)
        let innerPlaintext = TLSInnerPlaintext(content: plaintext, contentType: actualContentType, paddingLength: paddingLength)
        guard innerPlaintext.length <= maxPlaintextFragmentLength + 1 else {
            throw TLSError.internalError(reason: "inner plaintext exceeds max plaintext fragment length + 1.")
        }

        let ciphertextLength = innerPlaintext.length + TLSRecordProtector.aesTagLengthBytes
        guard ciphertextLength <= maxCiphertextEncryptedRecordLength else {
            throw TLSError.internalError(reason: "record exceeds max ciphertext encrypted record length.")
        }

        #if !SWIFTTLS_EMBEDDED
        // This comment needs to be reworked to be compatible with EmbeddedSwift. Probably by printing nonce directly instead of indirecting through the dataToString helper function
        logger.debug("creating ciphertext record: paddingLength: \(paddingLength), pt len: \(plaintextByteCount), ct len: \(ciphertextLength)")
        #endif

        // additional_data = TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
        let ad = additionalData(ciphertextLength: ciphertextLength)

        let protectedRecord = try TLSCiphertext(
            writeKey: writeKey,
            nonce: nonce,
            innerPlaintext: innerPlaintext,
            additionalData: ad.span.bytes
        )

        guard UInt64.max - 1 >= self.writeSequenceNumber else {
            throw TLSError.internalError(reason: "write sequence number overflow")
        }
        self.writeSequenceNumber += 1
        return protectedRecord
    }

    mutating func deprotect(ciphertext: TLSCiphertext) throws(TLSError) -> DeprotectedRecord {
        guard let readIV = self.readIV, let readKey = self.readKey else {
            throw TLSError.internalError(reason: "read key and iv not set when deprotect called")
        }

        // Receiving implementations SHOULD NOT enforce limits on key usage, as future analyses may
        // result in updated values, so the AEAD record limit is intentionally not enforced here.'

        let nonce = calculateTLSRecordNonce(iv: readIV, seqno: self.readSequenceNumber)

        let ciphertextLength = ciphertext.encryptedRecord.count
        guard ciphertextLength <= maxCiphertextEncryptedRecordLength else {
            throw TLSError.internalError(reason: "record exceeds max ciphertext encrypted record length.")
        }
        // the plaintext length is checked in TLSCiphertext.deprotect after deprotecting. This matches boringssl.
        let plaintextLength = ciphertextLength - TLSRecordProtector.aesTagLengthBytes - 1 /* ContentType length */

        #if !SWIFTTLS_EMBEDDED
        logger.debug("deprotecting ciphertext record: pt len: \(plaintextLength), ct len: \(ciphertextLength)")
        #endif

        let deprotectedRecord = try ciphertext.deprotect(peerWriteKey: readKey, nonce: nonce, aeadExpansionLength: TLSRecordProtector.aesTagLengthBytes)

        guard UInt64.max - 1 >= self.readSequenceNumber else {
            throw TLSError.internalError(reason: "read sequence number overflow")
        }
        self.readSequenceNumber += 1
        return deprotectedRecord
    }
}
