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
struct TLSRecordParser: ~Copyable {
    private var bufferedBytes: ByteBuffer?
    var numberOfBytesBuffered: Int { self.bufferedBytes?.readableBytes ?? 0 }
    var numberOfBytesToReadNext: Int = 5

    init() {}

    mutating func clearBufferedBytes() {
        self.bufferedBytes = nil
    }

    mutating func appendBytes(_ buffer: inout ByteBuffer) {
        if self.bufferedBytes == nil {
            self.bufferedBytes = buffer.readSlice(length: buffer.readableBytes)
        } else {
            self.bufferedBytes!.writeBuffer(&buffer)
        }
    }

    mutating func appendBytes(_ buffer: [UInt8]) {
        if self.bufferedBytes == nil {
            self.bufferedBytes = ByteBuffer(bytes: buffer)
        } else {
            self.bufferedBytes!.writeBytes(buffer)
        }
    }

    mutating func parsePlaintextRecord(changeCipherSpecPermitted: Bool = true) throws(TLSError) -> TLSPlaintext? {
        guard let record = try self.parseRecord(recordProtectionEnabled: false, changeCipherSpecPermitted: changeCipherSpecPermitted) else {
            return nil
        }
        switch record {
        case let .plaintext(plaintext):
            return plaintext
        case .ciphertext(_):
            // Currently unreachable, as parseSingleRecord will only classify a record
            // with recordProtectionEnabled: false as plaintext, but fail closed here
            // anyways.
            logger.error("unexpectedly parsed ciphertext when expecting plaintext")
            throw TLSError.internalError(reason: "Unexpectedly parsed ciphertext when expecting plaintext")
        }
    }

    mutating func parseCiphertextRecord(changeCipherSpecPermitted: Bool = true) throws(TLSError) -> TLSCiphertext? {
        guard let record = try self.parseRecord(recordProtectionEnabled: true, changeCipherSpecPermitted: changeCipherSpecPermitted) else {
            return nil
        }
        switch record {
        case let .ciphertext(ciphertext):
            return ciphertext
        case .plaintext(_):
            // Currently unreachable, as parseSingleRecord will only classify a record
            // with recordProtectionEnabled: true as ciphertext (non-CCS path), but fail
            // closed here anyways.
            logger.error("unexpectedly parsed plaintext when expecting ciphertext")
            throw TLSError.internalError(reason: "Unexpectedly parsed plaintext when expecting ciphertext")
        }
    }

    /// Parse a single record, noting whether it changed the cipher
    /// specification.
    private static func parseSingleRecord(
        from buffer: inout InputBuffer,
        recordProtectionEnabled: Bool,
        changeCipherSpecPermitted: Bool,
        numberOfBytesToReadNext: inout Int,
        changeCipherSpecParsed: inout Bool
    ) throws(TLSError) -> TLSRecord? {
        guard let contentType = buffer.readContentType(),
            let protocolVersion = buffer.readProtocolVersion() else {
            logger.error("failed to parse contentType and protocolVersion")
            throw TLSError.decodeError
        }

        // it is never acceptable for application data to be sent in a
        // plaintext message
        if !recordProtectionEnabled && contentType == .applicationData {
            logger.error("record protection not enabled and received record with content type application data")
            throw TLSError.decodeError
        }

        //   The value of TLSPlaintext.legacy_record_version MUST be ignored by all
        //   implementations.  The value of TLSCiphertext.legacy_record_version is
        //   included in the additional data for deprotection but MAY otherwise be
        //   ignored or MAY be validated to match the fixed constant value.
        #if SWIFTTLS_EXCLAVECORE
        logger.info("protocolVersion is \(String(describing:protocolVersion))")
        logger.info("content type is \(String(describing:contentType))")
        #else
        logger.info("protocolVersion is \(protocolVersion)")
        logger.info("content type is \(contentType)")
        #endif

        guard let contentLength = buffer.readInteger(as: UInt16.self) else {
            logger.error("unable to read content length")
            throw TLSError.decodeError
        }
        logger.info("content length is: \(contentLength)")

        let maxContentLength = recordProtectionEnabled ? maxCiphertextEncryptedRecordLength : maxPlaintextFragmentLength
        guard contentLength <= maxContentLength else {
            logger.error("contentLength (\(contentLength) bytes) exceeds maximum length of \(maxContentLength) bytes for \(recordProtectionEnabled ? "ciphertext" : "plaintext") messages")
            throw TLSError.recordOverflow
        }

        guard let content = buffer.read(length: Int(contentLength)) else {
            logger.info("unable to read full content, waiting for more data")
            numberOfBytesToReadNext = Int(contentLength) - buffer.byteCount
            return nil
        }
        numberOfBytesToReadNext = 5
        if contentType == .changeCipherSpec {
            // RFC 9846 §5: a change_cipher_spec is only ever valid after the first
            // ClientHello has been sent or received and before the peer's Finished
            // has been received. Outside that window it MUST be treated as an
            // unexpected record type, regardless of its value.
            guard changeCipherSpecPermitted else {
                logger.debug("received change cipher spec message outside the permitted window (before first ClientHello or after peer's Finished)")
                throw TLSError.handshakeUnexpectedMessage
            }
            if contentLength == 1 {
                let byte = content.bytes.unsafeLoad(as: UInt8.self)
                if byte == 1 {
                    logger.info("got a change cipher spec message with value 0x01, ignoring")
                    changeCipherSpecParsed = true
                    // This record is discarded
                    return TLSRecord.plaintext(TLSPlaintext(contentType: .changeCipherSpec, fragment: content.bytes))
                }
            }
            logger.debug("received unexpected change cipher spec message")
            throw TLSError.handshakeUnexpectedMessage
        } else {
            changeCipherSpecParsed = false
        }

        if !recordProtectionEnabled {
            return TLSRecord.plaintext(TLSPlaintext(contentType: contentType, fragment: content.bytes))
        } else if recordProtectionEnabled && contentLength >= 16 {
            // The received content type and legacy record version are used as
            // part of the additional data this record is deprotected against.
            return TLSRecord.ciphertext(
                TLSCiphertext(
                    encryptedRecord: content.bytes,
                    contentType: contentType,
                    protocolVersion: protocolVersion
                )
            )
        } else {
            throw TLSError.ciphertextRecordTooShort
        }
    }

    private mutating func parseRecord(recordProtectionEnabled: Bool, changeCipherSpecPermitted: Bool) throws(TLSError) -> TLSRecord? {
        var changeCipherSpecParsed = false
        var result: TLSRecord?

        repeat {
            // check that there are at least enough bytes for valid record with length 0 content
            // shortest valid record (5 bytes) = contentType (1) + protocol version (2) + content length (2)
            guard self.numberOfBytesBuffered >= 5 else {
                logger.debug("less than 5 bytes to parse, need at least 5 for any valid record, waiting for more data")
                return nil
            }

            // Form an input buffer to consume from the buffered bytes. If we
            // successfully parse a record, then we'll update the buffered
            // bytes.
            var buffer = InputBuffer(storage: self.bufferedBytes!.readableBytesSpan)

            // Make a local copy of numberOfBytesToReadNext that
            // parseSingleRecord can modify, then write it back. This avoids
            // an overlapping access to self with the input buffer above.
            var numberOfBytesToReadNext = self.numberOfBytesToReadNext
            defer {
                self.numberOfBytesToReadNext = numberOfBytesToReadNext
            }

            // Try to parse a single record.
            result = try Self.parseSingleRecord(
                from: &buffer,
                recordProtectionEnabled: recordProtectionEnabled,
                changeCipherSpecPermitted: changeCipherSpecPermitted,
                numberOfBytesToReadNext: &numberOfBytesToReadNext,
                changeCipherSpecParsed: &changeCipherSpecParsed
            )

            if result != nil {
                _ = self.bufferedBytes!.readSlice(length: buffer.position)
            }
        } while changeCipherSpecParsed && result != nil
        if self.numberOfBytesBuffered == 0 {
            // hard reset buffer when all bytes have been read.
            self.bufferedBytes = ByteBuffer()
        }
        return result
    }
}
