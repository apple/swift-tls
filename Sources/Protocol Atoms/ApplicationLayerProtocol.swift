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

typealias ApplicationLayerProtocol = String

@available(anyAppleOS 26, *)
extension InputBuffer {
    mutating func readApplicationLayerProtocol() -> ApplicationLayerProtocol? {
        guard let length = self.readInteger(as: UInt8.self) else {
            return nil
        }
        guard let slice = self.read(length: Int(length)) else {
            return nil
        }
        // Convert RawSpan bytes to String
        return slice.bytes.withUnsafeBytes { buffer in
            ApplicationLayerProtocol(decoding: buffer, as: UTF8.self)
        }
    }
}

@available(anyAppleOS 26, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeApplicationLayerProtocol(_ appProtocol: ApplicationLayerProtocol) -> Int {
        let appProtocolUTF8 = appProtocol.utf8
        if appProtocolUTF8.count > UInt8.max {
            return 0
        }
        return self.writeInteger(UInt8(appProtocolUTF8.count)) + self.writeBytes(appProtocolUTF8)
    }
}
