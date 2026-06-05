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

struct NewSessionTicket {
    var ticketLifetime: UInt32
    var ticketAgeAdd: UInt32
    var ticketNonce: ByteBuffer
    var ticket: ByteBuffer
    var extensions: Array<Extension>

    init(ticketLifetime: UInt32,
         ticketAgeAdd: UInt32,
         ticketNonce: ByteBuffer,
         ticket: ByteBuffer,
         extensions: [Extension]) {
        self.ticketLifetime = ticketLifetime
        self.ticketAgeAdd = ticketAgeAdd
        self.ticketNonce = ticketNonce
        self.ticket = ticket
        self.extensions = extensions
    }
}

extension NewSessionTicket: Hashable { }

extension NewSessionTicket: HandshakeMessageProtocol {
    static var handshakeType: HandshakeType {
        .newSessionTicket
    }

    func write(into buffer: inout ByteBuffer) -> Int {
        var written = buffer.writeInteger(self.ticketLifetime)
        written += buffer.writeInteger(self.ticketAgeAdd)
        written += buffer.writeVariableLengthVector(lengthFieldType: UInt8.self) {
            $0.writeImmutableBuffer(self.ticketNonce)
        }
        written += buffer.writeVariableLengthVector(lengthFieldType: UInt16.self) {
            $0.writeImmutableBuffer(self.ticket)
        }
        written += buffer.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return self.extensions.reduce(into: 0) { count, ext in
                count += buffer.writeExtension(ext)
            }
        }

        return written
    }

    init(bytes: inout InputBuffer) throws(TLSError) {
        guard let ticketLifetime = bytes.readInteger(as: UInt32.self),
              let ticketAgeAdd = bytes.readInteger(as: UInt32.self),
              let ticketNonce = try bytes.readVariableLengthVector(lengthFieldType: UInt8.self, { buffer in
                  ByteBuffer(copying: buffer.readAll())
              }),
              let ticket = try bytes.readVariableLengthVector(lengthFieldType: UInt16.self, { buffer in
                  ByteBuffer(copying: buffer.readAll())
              }),
              let extensions = try bytes.readExtensions(messageType: .newSessionTicket, helloRetryRequest: false) else {
            throw TLSError.truncatedMessage
        }

        self = NewSessionTicket(ticketLifetime: ticketLifetime, ticketAgeAdd: ticketAgeAdd, ticketNonce: ticketNonce, ticket: ticket, extensions: extensions)
    }
}
