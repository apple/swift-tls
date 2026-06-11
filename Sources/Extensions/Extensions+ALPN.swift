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
#endif

@available(SwiftTLS 0.1.0, *)
extension Extension {
    enum ApplicationLayerProtocolNegotiation {
        case offer([String])
        case selection(ApplicationLayerProtocol)
    }
}

@available(SwiftTLS 0.1.0, *)
extension Extension.ApplicationLayerProtocolNegotiation: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeALPN(_ alpn: Extension.ApplicationLayerProtocolNegotiation) -> Int {
        var buffer = ByteBuffer()
        switch alpn {
        case .offer(let offers):
            for offer in offers {
                buffer.writeApplicationLayerProtocol(offer)
            }
        case .selection(let selection):
            buffer.writeApplicationLayerProtocol(selection)
        }

        return self.writeVariableLengthVector(lengthFieldType: UInt16.self) {
            $0.writeImmutableBuffer(buffer)
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readALPN(messageType: HandshakeType) throws(TLSError) -> Extension.ApplicationLayerProtocolNegotiation {
        switch messageType {
        case .clientHello, .encryptedExtensions:
            if messageType == .clientHello {
                let protocols = try self.readVariableLengthVector(
                    lengthFieldType: UInt16.self
                ) { opaqueOffer throws(TLSError) in
                    var protocols: [ApplicationLayerProtocol] = []
                    while opaqueOffer.byteCount > 0 {
                        guard let proto = opaqueOffer.readApplicationLayerProtocol() else {
                            throw TLSError.invalidApplicationProtocol
                        }
                        protocols.append(proto)
                    }
                    return protocols
                }

                guard let protocols else {
                    throw TLSError.truncatedMessage
                }
                return Extension.ApplicationLayerProtocolNegotiation.offer(protocols)
            } else {
                let proto = try self.readVariableLengthVector(
                    lengthFieldType: UInt16.self
                ) { opaqueOffer throws(TLSError) in
                    guard let proto = opaqueOffer.readApplicationLayerProtocol(), opaqueOffer.byteCount <= 0 else {
                        throw TLSError.invalidApplicationProtocol
                    }
                    return proto
                }

                guard let proto else {
                    throw TLSError.truncatedMessage
                }

                return Extension.ApplicationLayerProtocolNegotiation.selection(proto)
            }
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .applicationLayerProtocolNegotiation)
        }
    }
}
