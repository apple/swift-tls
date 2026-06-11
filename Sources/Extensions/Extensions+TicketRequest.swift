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

@available(SwiftTLS 0.1.0, *)
extension Extension {
    enum TicketRequest {
        case clientHello(ClientTicketRequest)
        case encryptedExtensions(ServerTicketRequestHint)
    }
}

@available(SwiftTLS 0.1.0, *)
extension Extension.TicketRequest: Hashable { }

@available(SwiftTLS 0.1.0, *)
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

@available(SwiftTLS 0.1.0, *)
extension Extension.TicketRequest {
    struct ServerTicketRequestHint {
        var expectedCount: UInt8

        init (expectedCount: UInt8) {
            self.expectedCount = expectedCount
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension Extension.TicketRequest.ServerTicketRequestHint: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension Extension.TicketRequest.ServerTicketRequestHint: CustomStringConvertible {
    var description: String {
        return "TicketRequest(newSessionCount: \(self.expectedCount))"
    }
}

@available(SwiftTLS 0.1.0, *)
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

@available(SwiftTLS 0.1.0, *)
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
