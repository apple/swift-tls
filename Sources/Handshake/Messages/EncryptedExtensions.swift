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
struct EncryptedExtensions {
    // TODO: enforcement on this value, only allow well-formed EncryptedExtensions.
    var extensions: Array<Extension>

    init(extensions: [Extension]) {
        self.extensions = extensions
    }
}

@available(anyAppleOS 26, *)
extension EncryptedExtensions: Hashable { }

@available(anyAppleOS 26, *)
extension EncryptedExtensions: HandshakeMessageProtocol {
    static var handshakeType: HandshakeType {
        .encryptedExtensions
    }

    func write(into buffer: inout ByteBuffer) -> Int {
        return buffer.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return self.extensions.reduce(into: 0) { count, ext in
                count += buffer.writeExtension(ext)
            }
        }
    }

    init(bytes: inout InputBuffer) throws(TLSError) {
        guard let extensions = try bytes.readExtensions(messageType: .encryptedExtensions, helloRetryRequest: false) else {
            throw TLSError.truncatedMessage
        }

        self = EncryptedExtensions(extensions: extensions)
    }
}
