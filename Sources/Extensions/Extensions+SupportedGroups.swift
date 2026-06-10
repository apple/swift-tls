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
    struct SupportedGroups {
        var groups: [NamedGroup]

        init(groups: [NamedGroup]) {
            self.groups = groups
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension Extension.SupportedGroups: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readSupportedGroups(messageType: HandshakeType) throws(TLSError) -> Extension.SupportedGroups {
        switch messageType {
        case .clientHello, .encryptedExtensions:
            // nil is an error here.
            let possibleResult: [NamedGroup]? = try self.readVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
                var groups = Array<NamedGroup>()
                groups.reserveCapacity(buffer.byteCount / 2)

                while let group = buffer.readNamedGroup() {
                    groups.append(group)
                }

                return groups
            }

            guard let result = possibleResult else {
                throw TLSError.truncatedMessage
            }

            return Extension.SupportedGroups(groups: result)
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .supportedGroups)
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeSupportedGroups(_ groups: Extension.SupportedGroups) -> Int {
        return self.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return groups.groups.reduce(into: 0) { length, group in
                length += buffer.writeNamedGroup(group)
            }
        }
    }
}
