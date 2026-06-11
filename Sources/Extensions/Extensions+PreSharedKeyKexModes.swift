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

@available(anyAppleOS 26, *)
extension Extension {
    struct PreSharedKeyKexModes {
        var modes: [Mode]
    }
}

@available(anyAppleOS 26, *)
extension Extension.PreSharedKeyKexModes {
    struct Mode: RawRepresentable, Hashable {
        var rawValue: UInt8

        init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        static let pskOnly = Mode(rawValue: 0)
        static let pskAndDHE = Mode(rawValue: 1)
    }
}

@available(anyAppleOS 26, *)
extension Extension.PreSharedKeyKexModes: Hashable { }

@available(anyAppleOS 26, *)
extension InputBuffer {
    mutating func readPreSharedKeyKexModes(messageType: HandshakeType) throws(TLSError) -> Extension.PreSharedKeyKexModes {
        switch messageType {
        case .clientHello:
            guard let modes = try self.readVariableLengthVector(lengthFieldType: UInt8.self, { buffer in
                var modes: [Extension.PreSharedKeyKexModes.Mode] = []

                while let mode = buffer.readInteger().map({ Extension.PreSharedKeyKexModes.Mode(rawValue: $0) }) {
                    modes.append(mode)
                }

                return modes
            }) else {
                throw TLSError.truncatedMessage
            }

            return Extension.PreSharedKeyKexModes(modes: modes)
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .preSharedKeyKexModes)
        }
    }
}

@available(anyAppleOS 26, *)
extension ByteBuffer {
    @discardableResult
    mutating func writePreSharedKeyKexModes(_ modes: Extension.PreSharedKeyKexModes) -> Int {
        return self.writeVariableLengthVector(lengthFieldType: UInt8.self) { buffer in
            return modes.modes.reduce(into: 0) { $0 += buffer.writeInteger($1.rawValue) }
        }
    }
}
