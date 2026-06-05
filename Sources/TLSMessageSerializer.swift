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

struct TLSMessageSerializer {
    init() { }

    @discardableResult
    func writeHandshakeMessage(_ message: HandshakeMessage, into buffer: inout ByteBuffer) -> Int {
        switch message {
        case .clientHello(let hello):
            return buffer.writeHandshakeMessage(hello)
        case .serverHello(let hello):
            return buffer.writeHandshakeMessage(hello)
        case .encryptedExtensions(let ee):
            return buffer.writeHandshakeMessage(ee)
        case .certificateRequest(let certRequest):
            return buffer.writeHandshakeMessage(certRequest)
        case .certificate(let certificate):
            return buffer.writeHandshakeMessage(certificate)
        case .certificateVerify(let certVerify):
            return buffer.writeHandshakeMessage(certVerify)
        case .finished(let finished):
            return buffer.writeHandshakeMessage(finished)
        case .newSessionTicket(let ticket):
            return buffer.writeHandshakeMessage(ticket)
        }
    }
}
