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
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "HandshakeMessageParser")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeMessageParser")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.HandshakeMessageParser")
#endif

struct HandshakeMessageParser {
    private var bufferedBytes: ByteBuffer?
    var readClientHello: Bool = false

    var bytesToParse: Int {
        return self.bufferedBytes?.readableBytes ?? 0
    }

    init() { }

    mutating func appendBytes(_ bytes: RawSpan) {
        if self.bufferedBytes == nil {
            self.bufferedBytes = ByteBuffer(copying: bytes)
        } else {
            self.bufferedBytes!.writeBytes(bytes)
        }
    }

    mutating func appendBytes(_ buffer: inout ByteBuffer) {
        if self.bufferedBytes == nil {
            self.bufferedBytes = buffer.readSlice(length: buffer.readableBytes)
        } else {
            self.bufferedBytes!.writeBuffer(&buffer)
        }
    }

    mutating func parseHandshakeMessage() throws(TLSError) -> ParseResult? {
        try self.bufferedBytes?.withInputBuffer { inputBuffer throws(TLSError) in
            try HandshakeMessageParser
                .parseHandshakeMessage(
                    from: &inputBuffer,
                    readClientHello: &readClientHello
                )
        }
    }

    /// Parse a handshake message using the bytes we've buffered already plus the
    /// provided `incomingBytes`. On exit, any bytes the parser doesn't consume
    /// remain buffered for the next call.
    mutating func parseHandshakeMessage(incomingBytes: inout InputBuffer) throws(TLSError) -> ParseResult? {
        // If we didn't buffer any bytes, we can parse directly from the input buffer
        // without copying anything.
        if bytesToParse == 0 {
            // On exit, append the remaining incoming bytes to the buffer;
            // we'll parse them again once we receive more data.
            defer {
                self.appendBytes(incomingBytes.readAll())
            }

            return try Self.parseHandshakeMessage(from: &incomingBytes, readClientHello: &readClientHello)
        }


        self.appendBytes(incomingBytes.readAll())
        return try self.parseHandshakeMessage()
    }

    static func parseHandshakeMessage(
        from buffer: inout InputBuffer,
        readClientHello: inout Bool
    ) throws(TLSError) -> ParseResult? {
        // The original position, which we will rewind to if it remains non-nil.
        // When we successfully parse a message, this will be set to nil to consume
        // the bytes read.
        let originalPosition: Int = buffer.position
        var successfullyParsed = false
        defer {
            if !successfullyParsed {
                buffer.seek(to: originalPosition)
            }
        }

        guard let type = buffer.readHandshakeType(),
              let length = buffer.readUInt24() else {
            return nil
        }

        // NOTE: this length limit is not RFC specified. The length field is a uint24, so can be larger.
        // Boringssl sets a max length of 2^14 unless peer cert validation is supported then it
        // allows the max length to be 2^24.
        // Guard against erroneous handshake length values causing large memory allocations.
        guard length <= 0xFFFF else {
            if type == .clientHello {
                // if we can at least tell that we were sent a client hello, but
                // it is just too large
                // we will send an alert on error
                readClientHello = true
            }
            throw TLSError.handshakeInvalidMessage
        }

        guard var message = buffer.read(length: length),
              let result = try parseHandshakeMessage(from: &message, readClientHello: &readClientHello, afterType: type) else {
            return nil
        }

        // We're committed now; don't roll back.
        successfullyParsed = true

        // Ok, got the message. Let's grab a slice of the readable bytes. This force-unwrap is safe,
        // we cannot possibly have read more bytes than there were in the buffer.
        let readBytes = buffer.position - originalPosition
        buffer.seek(to: originalPosition)
        let readBytesSlice = buffer.read(length: readBytes)!
        return ParseResult(messageBytes: ByteBuffer(copying: readBytesSlice), message: result)
    }

    static func parseHandshakeMessage(from message: inout InputBuffer, readClientHello: inout Bool, afterType type: HandshakeType) throws(TLSError) -> HandshakeMessage? {
        if type == .clientHello {
            // if we have read a full client hello
            // we will now send an alert on error
            readClientHello = true
        }

        let result: HandshakeMessage
        switch type {
        case .clientHello:
            logger.debug("clientHello")
            result = try .clientHello(ClientHello(bytes: &message))
        case .serverHello:
            logger.debug("serverHello")
            result = try .serverHello(ServerHello(bytes: &message))
        case .encryptedExtensions:
            logger.debug("encryptedExtensions")
            result = try .encryptedExtensions(EncryptedExtensions(bytes: &message))
        case .certificateRequest:
            logger.debug("certificateRequest")
            result = try .certificateRequest(CertificateRequest(bytes: &message))
        case .certificate:
            logger.debug("certificate")
            result = try .certificate(CertificateMessage(bytes: &message))
        case .certificateVerify:
            logger.debug("certificateVerify")
            result = try .certificateVerify(CertificateVerify(bytes: &message))
        case .finished:
            logger.debug("finished")
            result = try .finished(FinishedMessage(bytes: &message))
        case .newSessionTicket:
            logger.debug("newSessionTicket")
            result = try .newSessionTicket(NewSessionTicket(bytes: &message))
        default:
            #if SWIFTTLS_EXCLAVECORE
            logger.debug("Unsupported handshake message: \(String(describing: type))")
            #else
            logger.debug("Unsupported handshake message: \(type)")
            #endif
            throw TLSError.handshakeInvalidMessage
        }

        guard message.byteCount == 0 else {
            let messageLength = message.byteCount
            logger.debug("ExcessBytes: \(messageLength)")
            throw TLSError.excessBytes
        }

        return result
    }
}

extension HandshakeMessageParser {
    struct ParseResult {
        var messageBytes: ByteBuffer
        var message: HandshakeMessage
    }
}
