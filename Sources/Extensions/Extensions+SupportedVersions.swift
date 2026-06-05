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
    enum SupportedVersions {
        case offer([ProtocolVersion])
        case selection(ProtocolVersion)
    }
}

extension Extension.SupportedVersions: Hashable { }

extension InputBuffer {
    mutating func readSupportedVersions(messageType: HandshakeType) throws(TLSError) -> Extension.SupportedVersions {
        switch messageType {
        case .serverHello:
            // We expect the server only version. nil is an error here.
            guard let version = self.readProtocolVersion() else {
                throw TLSError.truncatedMessage
            }
            return .selection(version)
        case .clientHello:
            // nil is an error here.
            let possibleResult: [ProtocolVersion]? = try self.readVariableLengthVector(lengthFieldType: UInt8.self) { buffer in
                var versions = Array<ProtocolVersion>()
                versions.reserveCapacity(buffer.byteCount / 2)

                while let version = buffer.readProtocolVersion() {
                    versions.append(version)
                }

                return versions
            }

            guard let result = possibleResult else {
                throw TLSError.truncatedMessage
            }

            return .offer(result)
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .supportedVersions)
        }
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeSupportedVersions(_ versions: Extension.SupportedVersions) -> Int {
        switch versions {
        case .offer(let offers):
            return self.writeVariableLengthVector(lengthFieldType: UInt8.self) { buffer in
                return offers.reduce(into: 0) { length, offer in
                    length += buffer.writeProtocolVersion(offer)
                }
            }

        case .selection(let version):
            return self.writeProtocolVersion(version)
        }
    }
}
