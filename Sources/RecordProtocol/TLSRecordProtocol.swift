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


let maxPlaintextFragmentLength: UInt16 = 16384 /* 2^14 bytes */
let maxCiphertextEncryptedRecordLength: UInt16 = maxPlaintextFragmentLength + 256 /* 255 bytes (max AEAD expansion) + 1 bytes (content type)*/

protocol TLSRecordProtocol {
    var contentType: ContentType { get }
    var protocolVersion: ProtocolVersion { get }
    var content: [UInt8] { get }
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeRecord<Record: TLSRecordProtocol>(_ record: Record) -> Int {
        let contentTypeLength = self.writeContentType(record.contentType)
        let protocolVersionLength = self.writeProtocolVersion(record.protocolVersion)
        let lengthLength = self.writeInteger(UInt16(record.content.count), as: UInt16.self)
        let contentLength = self.writeBytes(record.content)
        logger.debug("wrote contentlength: \(contentLength)")

        let totalLength = contentTypeLength + protocolVersionLength + lengthLength + contentLength

        #if SWIFTTLS_EXCLAVECORE
        logger.debug("wrote record with contentType: \(String(describing:record.contentType)), protocolVersion: \(String(describing:record.protocolVersion)), contentLength: \(record.content.count), total: \(totalLength)")
        #else
        logger.debug("wrote record with contentType: \(record.contentType), protocolVersion: \(record.protocolVersion), contentLength: \(record.content.count), total: \(totalLength)")
        #endif
        return totalLength
    }
}
