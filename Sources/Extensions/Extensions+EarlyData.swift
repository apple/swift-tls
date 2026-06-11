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
    struct EarlyData {
        // Will be `nil` when used in ClientHello/EncryptedExtensions, will not be zero otherwise.
        var maxEarlyDataSize: UInt32?
    }
}

@available(anyAppleOS 26, *)
extension Extension.EarlyData: Hashable { }

@available(anyAppleOS 26, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeEarlyDataExtension(_ earlyData: Extension.EarlyData) -> Int {
        if let maxEarlyDataSize = earlyData.maxEarlyDataSize {
            return self.writeInteger(maxEarlyDataSize)
        } else {
            return 0
        }
    }
}

@available(anyAppleOS 26, *)
extension InputBuffer {
    mutating func readEarlyDataExtension(messageType: HandshakeType) throws(TLSError) -> Extension.EarlyData {
        switch messageType {
        case .clientHello, .encryptedExtensions:
            return Extension.EarlyData(maxEarlyDataSize: nil)
        case .newSessionTicket:
            guard let maxEarlyDataSize = self.readInteger(as: UInt32.self) else {
                throw TLSError.truncatedMessage
            }
            return Extension.EarlyData(maxEarlyDataSize: maxEarlyDataSize)
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .keyShare)
        }
    }
}
