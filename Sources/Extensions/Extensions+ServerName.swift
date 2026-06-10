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
    enum ServerName {
        case clientHello(Names)
        case encryptedExtensions
    }

}

@available(SwiftTLS 0.1.0, *)
extension Extension.ServerName {
    struct Names {
        var hostName: ByteBuffer

        fileprivate static let hostNameNameType = UInt8(0)
    }
}

@available(SwiftTLS 0.1.0, *)
extension Extension.ServerName: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension Extension.ServerName.Names: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readServerName(messageType: HandshakeType) throws(TLSError) -> Extension.ServerName {
        switch messageType {
        case .clientHello:
            // nil is an error here. We only support host_name for now.
            let possibleResult: ByteBuffer? = try self.readVariableLengthVector(lengthFieldType: UInt16.self) { buffer throws(TLSError) in
                var hostName: ByteBuffer? = nil

                // Even though we only support host_name, we consume the entire buffer to police for violations of the RFC.
                while buffer.byteCount > 0 {
                    guard let nameType = buffer.readInteger(as: UInt8.self) else {
                        throw TLSError.truncatedMessage
                    }

                    if nameType == Extension.ServerName.Names.hostNameNameType {
                        let innerResult: ByteBuffer? = try buffer.readVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
                            // Convert the InputBuffer bytes to ByteBuffer
                            return ByteBuffer(copying: buffer.readAll())
                        }

                        guard let actualResult = innerResult else {
                            throw TLSError.truncatedMessage
                        }

                        guard hostName == nil else {
                            throw TLSError.handshakeInvalidMessage
                        }

#if !SWIFTTLS_EMBEDDED
                        // RFC 6066: "The hostname is represented as a byte string using ASCII encoding without a trailing dot."
                        guard actualResult.readableBytesView.allSatisfy ({ (0..<128).contains($0) }) else {
                            throw TLSError.illegalParameter
                        }
#endif

                        hostName = actualResult
                    } else {
                        // Ok, we don't support this, but we can consume the bytes and skip over it.
                        try buffer.readVariableLengthVector(lengthFieldType: UInt16.self) { innerBuffer throws(TLSError) in
                            // Skip all bytes by reading to the end
                            _ = innerBuffer.readAll()
                        }
                    }
                }

                guard let unwrapped = hostName else {
                    throw TLSError.handshakeInvalidMessage
                }

                return unwrapped
            }

            guard let result = possibleResult else {
                throw TLSError.truncatedMessage
            }

            return .clientHello(.init(hostName: result))
        case .encryptedExtensions:
            guard self.byteCount == 0 else {
                throw TLSError.handshakeInvalidMessage
            }
            return .encryptedExtensions
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .serverName)
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeServerName(_ serverName: Extension.ServerName) -> Int {
        switch serverName {
        case .clientHello(let names):
            return self.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
                var count = buffer.writeInteger(Extension.ServerName.Names.hostNameNameType)

                count += buffer.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
                    buffer.writeImmutableBuffer(names.hostName)
                }

                return count
            }
        case .encryptedExtensions:
            return 0
        }
    }
}
