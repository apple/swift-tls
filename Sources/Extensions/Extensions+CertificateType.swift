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
    enum CertificateTypeExt {
        case offer([CertificateType])
        case selection(CertificateType)
    }
}

@available(SwiftTLS 0.1.0, *)
extension Extension.CertificateTypeExt: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeCertificateType(_ certificateType: Extension.CertificateTypeExt) -> Int {
        switch certificateType {
        case .offer(let offers):
            return self.writeVariableLengthVector(lengthFieldType: UInt8.self) { buffer in
                return offers.reduce(into: 0) { length, offer in
                    length += buffer.writeCertificateType(offer)
                }
            }

        case .selection(let selection):
            return self.writeCertificateType(selection)
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readCertificateType(messageType: HandshakeType) throws(TLSError) -> Extension.CertificateTypeExt {
        switch messageType {
        case .encryptedExtensions:
            // We expect the server only version. nil is an error here.
            guard let version = self.readCertificateType() else {
                throw TLSError.truncatedMessage
            }
            return .selection(version)
        case .clientHello:
            // nil is an error here.
            let possibleResult: [CertificateType]? = try self.readVariableLengthVector(lengthFieldType: UInt8.self) { buffer in
                var types = Array<CertificateType>()
                types.reserveCapacity(buffer.byteCount)

                while let type = buffer.readCertificateType() {
                    types.append(type)
                }

                return types
            }

            guard let result = possibleResult else {
                throw TLSError.truncatedMessage
            }

            return .offer(result)
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .serverCertificateType)
        }
    }
}
