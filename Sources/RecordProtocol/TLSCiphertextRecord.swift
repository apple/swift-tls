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

#if !canImport(CryptoKit) && canImport(Crypto)
@preconcurrency import Crypto
#else
import CryptoKit
#endif

#if canImport(Foundation) && !SWIFTTLS_EMBEDDED
import Foundation
#elseif canImport(SwiftSystem)
import SwiftSystem
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

#if !SWIFTTLS_EMBEDDED && !SWIFTTLS_DRIVERKIT
// EmbeddedSwift doesn't support String(format:)
func dataToString(data: any DataProtocol) -> String {
    return data.map { String(format: "%02hhx", $0)}.joined()
}
#endif

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
struct TLSCiphertext: TLSRecordProtocol, Hashable {
    let contentType: ContentType
    let protocolVersion: ProtocolVersion
    var content: [UInt8] { self.encryptedRecord }

    // The record header for a ciphertext record always has content type of application data
    // The actual content type is in the encrypted record.
    static var opaqueType: ContentType { .applicationData }
    static var pv: ProtocolVersion { .tlsv12 }
    let encryptedRecord: [UInt8]

    init(
        encryptedRecord: [UInt8],
        contentType: ContentType = TLSCiphertext.opaqueType,
        protocolVersion: ProtocolVersion = TLSCiphertext.pv
    ) {
        self.encryptedRecord = encryptedRecord
        self.contentType = contentType
        self.protocolVersion = protocolVersion
    }

    init(
        encryptedRecord: RawSpan,
        contentType: ContentType = TLSCiphertext.opaqueType,
        protocolVersion: ProtocolVersion = TLSCiphertext.pv
    ) {
        self.encryptedRecord = [UInt8](copying: encryptedRecord)
        self.contentType = contentType
        self.protocolVersion = protocolVersion
    }

    init(writeKey: SymmetricKey, nonce: Nonce, innerPlaintext: borrowing TLSInnerPlaintext, additionalData: RawSpan) throws(TLSError) {
        self.encryptedRecord = try innerPlaintext.protect(writeKey: writeKey, nonce: nonce, additionalData: additionalData)
        self.contentType = TLSCiphertext.opaqueType
        self.protocolVersion = TLSCiphertext.pv
    }

    func deprotect(peerWriteKey: SymmetricKey, nonce: Nonce, aeadExpansionLength: Int) throws(TLSError) -> DeprotectedRecord {
        try Self.deprotect(
            encryptedRecord: self.encryptedRecord.span.bytes,
            contentType: self.contentType,
            protocolVersion: self.protocolVersion,
            peerWriteKey: peerWriteKey,
            nonce: nonce,
            aeadExpansionLength: aeadExpansionLength
        )
    }

    static func deprotect(
        encryptedRecord: RawSpan,
        contentType: ContentType,
        protocolVersion: ProtocolVersion,
        peerWriteKey: SymmetricKey,
        nonce: Nonce,
        aeadExpansionLength: Int
    ) throws(TLSError) -> DeprotectedRecord {
        // needs to at least be the length of the aead expansion and 1 byte for the content type
        guard encryptedRecord.byteCount > aeadExpansionLength else {
            throw TLSError.ciphertextRecordTooShort
        }

        // RFC 9846 §5.2: the additional data is this record's header, using
        // the content type and legacy record version as received.
        let ad = additionalData(
            contentType: contentType,
            protocolVersion: protocolVersion,
            ciphertextLength: encryptedRecord.byteCount
        )

        /// Copy the ciphertext and tag into a new array.
        var message = [UInt8](unsafeUninitializedCapacity: encryptedRecord.byteCount) { buffer, initializedCount in
            encryptedRecord.withUnsafeBytes { encryptedBuffer in
                UnsafeMutableRawBufferPointer(buffer).copyMemory(from: encryptedBuffer)
            }
            initializedCount = encryptedRecord.byteCount
        }

        // Decrypt in-place.
        let ciphertextLength = encryptedRecord.byteCount - aeadExpansionLength
        do {
            try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in
                try message.withUnsafeMutableBytes { (messageBuffer) -> Result<(), CryptoKitMetaError> in
                    var ciphertextSpan = UnsafeMutableRawBufferPointer(
                        rebasing: messageBuffer[0..<ciphertextLength]
                    ).mutableBytes
                    let tagSpan = UnsafeMutableRawBufferPointer(
                        rebasing: messageBuffer[ciphertextLength..<encryptedRecord.byteCount]
                    ).mutableBytes

                    return ad.withUnsafeBytes { (adBytes) -> Result<(), CryptoKitMetaError> in
                        do throws(CryptoKitMetaError) {
                            try AES.GCM.open(inPlace: &ciphertextSpan, using: peerWriteKey, nonce: .init(copying: nonce.bytes), authenticating: adBytes.bytes, tag: tagSpan.bytes)
                            return .success(())
                        } catch {
                            return .failure(error)
                        }
                    }
                }.get()
            }
        } catch {
            // RFC 9846 §5.2: "If decryption fails, the receiver MUST terminate
            // the connection with a 'bad_record_mac' alert."
            throw TLSError.badRecordMac
        }

        // RFC 9846 §5: "If a TLS implementation receives an unexpected record
        // type, it MUST terminate the connection with an 'unexpected_message'
        // alert." TLSCiphertext.opaque_type is always application_data, so any
        // other outer type is unexpected. Checked after decryption so a header
        // modified in transit still reports bad_record_mac.
        guard contentType == TLSCiphertext.opaqueType else {
            logger.error("received a protected record whose outer content type is not application data")
            throw TLSError.handshakeUnexpectedMessage
        }

        // result is the encoded TLSInnerPlaintext (content || content type (1 byte) || padding)
        // the length must not exceed the max plaintext length (2^14) + 1
        guard ciphertextLength <= maxPlaintextFragmentLength + 1 else {
            throw TLSError.recordOverflow
        }

        let (contentTypeIndex, actualContentType) = extractContentType(
            message.span.bytes,
            ciphertextLength: ciphertextLength
        )

        // Shrink the message down to just the plaintext (without the content type).
        message.removeSubrange(contentTypeIndex...)
        return DeprotectedRecord(fragment: message, actualContentType: actualContentType)
    }

    static func extractContentType(_ message: RawSpan, ciphertextLength: Int) -> (Int, ContentType) {
        let plaintext = message.extracting(0..<ciphertextLength)
        var contentTypeIndex = plaintext.byteCount - 1

        // skip over all padding
        while contentTypeIndex > 0 && plaintext[contentTypeIndex] == 0 {
            contentTypeIndex -= 1
        }
        if contentTypeIndex != ciphertextLength - 1 {
            logger.debug("contentTypeIndex is: \(contentTypeIndex). Last index is: \(ciphertextLength - 1). Padding length = \(ciphertextLength - 1 - contentTypeIndex)")
        }

        return (contentTypeIndex, ContentType(rawValue: plaintext[contentTypeIndex]))
    }
}

struct DeprotectedRecord: Hashable {
    var fragment: [UInt8]
    let actualContentType: ContentType
}

// This struct is encoded and used as the plaintext input to the protect function.
// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
struct TLSInnerPlaintext: ~Escapable {
    let content: RawSpan
    let contentType: ContentType
    let paddingLength: Int

    @_lifetime(copy content)
    init(content: RawSpan, contentType: ContentType, paddingLength: Int) {
        self.content = content
        self.contentType = contentType
        self.paddingLength = paddingLength
    }

    var length: Int {
        get {
            return content.byteCount + 1  /* Content Type length */ + paddingLength
        }
    }

    func protect(writeKey: SymmetricKey, nonce: Nonce, additionalData: RawSpan) throws(TLSError) -> [UInt8] {
        // Allocate storage for the ciphertext + content + padding + tag.
        let tagSize = TLSRecordProtector.aesTagLengthBytes
        var storage = [UInt8](unsafeUninitializedCapacity: length + tagSize) { buffer, initializedCount in
            self.content.withUnsafeBytes { contentBuffer in
                UnsafeMutableRawBufferPointer(buffer).copyMemory(from: contentBuffer)
            }
            buffer[content.byteCount] = self.contentType.rawValue
            buffer[(content.byteCount + 1)...].initialize(repeating: 0)
            initializedCount = length + tagSize
        }

        try TLSError.wrappingCryptoError { () throws(CryptoKitMetaError) in
            try storage.withUnsafeMutableBytes { (storageBuffer) -> Result<(), CryptoKitMetaError> in
                let messageStorage = UnsafeMutableRawBufferPointer(rebasing: storageBuffer[..<length])
                var messageBytes = messageStorage.mutableBytes
                let tagStorage = UnsafeMutableRawBufferPointer(rebasing: storageBuffer[length...])
                var tagSpan = tagStorage.mutableBytes
                precondition(tagStorage.count == tagSize)
                do throws (CryptoKitMetaError) {
                    try tagSpan.withUnsafeMutableBytes { tagBuffer throws(CryptoKitMetaError) in
                        var tagBytes = OutputRawSpan(buffer: tagBuffer, initializedCount: 0)
                        try AES.GCM
                            .seal(
                                inPlace: &messageBytes,
                                using: writeKey,
                                nonce: .init(copying: nonce.bytes),
                                authenticating: additionalData,
                                tag: &tagBytes
                            )
                        _ = tagBytes.finalize(for: tagBuffer)
                    }
                    return .success(())
                } catch {
                    return .failure(error)
                }
            }.get()
        }

        return storage
    }
}
