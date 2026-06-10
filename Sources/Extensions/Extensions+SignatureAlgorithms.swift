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
    struct SignatureAlgorithms {
        var schemes: [SignatureScheme]

        init(schemes: [SignatureScheme]) {
            self.schemes = schemes
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension Extension.SignatureAlgorithms: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readSignatureAlgorithms(messageType: HandshakeType) throws(TLSError) -> Extension.SignatureAlgorithms {
        switch messageType {
        case .clientHello, .certificateRequest:
            // nil is an error here.
            let possibleResult: [SignatureScheme]? = try self.readVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
                var schemes = Array<SignatureScheme>()
                schemes.reserveCapacity(buffer.byteCount / 2)

                while let scheme = buffer.readSignatureScheme() {
                    schemes.append(scheme)
                }

                return schemes
            }

            guard let result = possibleResult else {
                throw TLSError.truncatedMessage
            }

            return Extension.SignatureAlgorithms(schemes: result)
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .signatureAlgorithms)
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeSignatureAlgorithms(_ algorithms: Extension.SignatureAlgorithms) -> Int {
        return self.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return algorithms.schemes.reduce(into: 0) { length, scheme in
                length += buffer.writeSignatureScheme(scheme)
            }
        }
    }
}
