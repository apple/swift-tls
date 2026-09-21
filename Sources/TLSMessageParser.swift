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

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
struct TLSMessageParser {
    private var bufferedBytes: ByteBuffer?

    init() { }

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

    mutating func parseHandshakeMessage() throws(TLSError) -> HandshakeMessage? {
        // Form an input buffer that we will consume from. If we successfully parse
        // a result, consume from the bytes we've buffered.
        var buffer = InputBuffer(storage: self.bufferedBytes!.readableBytesSpan)

        guard let type = buffer.readHandshakeType(), let length = buffer.readUInt24(), var message = buffer.read(length: length) else {
            return nil
        }

        let result: HandshakeMessage

        switch type {
        case .clientHello:
            result = try .clientHello(ClientHello(bytes: &message))
        case .serverHello:
            result = try .serverHello(ServerHello(bytes: &message))
        case .encryptedExtensions:
            result = try .encryptedExtensions(EncryptedExtensions(bytes: &message))
        case .certificateRequest:
            result = try .certificateRequest(CertificateRequest(bytes: &message))
        case .certificate:
            result = try .certificate(CertificateMessage(bytes: &message))
        case .certificateVerify:
            result = try .certificateVerify(CertificateVerify(bytes: &message))
        case.finished:
            result = try .finished(FinishedMessage(bytes: &message))
        default:
            #if SWIFTTLS_EXCLAVECORE
            logger.error("Unsupported handshake message: \(String(describing: type))")
            #else
            logger.error("Unsupported handshake message: \(type)")
            #endif
            throw TLSError.handshakeUnexpectedMessage
        }

        guard message.byteCount == 0 else {
            logger.error("excess bytes after reading message")
            throw TLSError.excessBytes
        }

        _ = self.bufferedBytes!.readSlice(length: buffer.position)
        return result
    }
}
