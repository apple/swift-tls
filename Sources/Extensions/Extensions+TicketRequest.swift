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

extension Extension {
    enum TicketRequest {
        case clientHello(ClientTicketRequest)
        case encryptedExtensions(ServerTicketRequestHint)
    }
}

extension Extension.TicketRequest: Hashable { }

struct ClientTicketRequest: Hashable, CustomStringConvertible {
    var newSessionCount: UInt8
    var resumptionCount: UInt8

    init(newSessionCount: UInt8, resumptionCount: UInt8) {
        self.newSessionCount = newSessionCount
        self.resumptionCount = resumptionCount
    }

    var description: String {
        return "TicketRequest(newSessionCount: \(self.newSessionCount), resumptionCount: \(self.resumptionCount))"
    }
}

extension Extension.TicketRequest {
    struct ServerTicketRequestHint {
        var expectedCount: UInt8

        init (expectedCount: UInt8) {
            self.expectedCount = expectedCount
        }
    }
}

extension Extension.TicketRequest.ServerTicketRequestHint: Hashable { }

extension Extension.TicketRequest.ServerTicketRequestHint: CustomStringConvertible {
    var description: String {
        return "TicketRequest(newSessionCount: \(self.expectedCount))"
    }
}

extension InputBuffer {
    mutating func readTicketRequestExtension(messageType: HandshakeType) throws(TLSError) -> Extension.TicketRequest {
        switch messageType {
        case .clientHello:
            guard let newSessionCount = self.readInteger(as: UInt8.self),
                  let resumedSessionCount = self.readInteger(as: UInt8.self) else {
                throw TLSError.truncatedMessage
            }
            return .clientHello(ClientTicketRequest(newSessionCount: newSessionCount, resumptionCount: resumedSessionCount))
        case .encryptedExtensions:
            guard let expectedCount = self.readInteger(as: UInt8.self) else {
                throw TLSError.truncatedMessage
            }
            return .encryptedExtensions(Extension.TicketRequest.ServerTicketRequestHint(expectedCount: expectedCount))
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .ticketRequest)
        }
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeTicketRequestExtension(_ ticketRequest: Extension.TicketRequest) -> Int {
        switch ticketRequest {
        case .clientHello(let request):
            return self.writeInteger(request.newSessionCount) + self.writeInteger(request.resumptionCount)
        case .encryptedExtensions(let response):
            return self.writeInteger(response.expectedCount)
        }
    }
}
