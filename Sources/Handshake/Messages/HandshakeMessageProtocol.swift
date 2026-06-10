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

/// A protocol adopted by all handshake messages.
@available(SwiftTLS 0.1.0, *)
protocol HandshakeMessageProtocol {
    static var handshakeType: HandshakeType { get }

    @discardableResult
    func write(into: inout ByteBuffer) -> Int

    init(bytes: inout InputBuffer) throws(TLSError)
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeHandshakeMessage<Message: HandshakeMessageProtocol>(_ message: Message) -> Int {
        let typeLength = self.writeHandshakeType(Message.handshakeType)

        let lengthOffset = self.writerIndex
        let lengthLength = self.writeUInt24(0)

        let contentLength = message.write(into: &self)
        self.setUInt24(contentLength, at: lengthOffset)

        return typeLength + lengthLength + contentLength
    }
}


