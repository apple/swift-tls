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
struct CertificateRequest {
    var certificateRequestContext: ByteBuffer

    var extensions: Array<Extension>

    init(certificateRequestContext: ByteBuffer, extensions: [Extension]) {
        self.certificateRequestContext = certificateRequestContext
        self.extensions = extensions
    }
}

@available(SwiftTLS 0.1.0, *)
extension CertificateRequest: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension CertificateRequest: HandshakeMessageProtocol {
    static var handshakeType: HandshakeType {
        .certificateRequest
    }

    func write(into buffer: inout ByteBuffer) -> Int {
        var written = buffer.writeVariableLengthVector(lengthFieldType: UInt8.self) { buffer in
            buffer.writeImmutableBuffer(self.certificateRequestContext)
        }
        written += buffer.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return self.extensions.reduce(into: 0) { count, ext in
                count += buffer.writeExtension(ext)
            }
        }
        return written
    }

    init(bytes: inout InputBuffer) throws(TLSError) {
        guard let certificateRequestContext = try bytes.readVariableLengthVector(lengthFieldType: UInt8.self, { buffer in
            ByteBuffer(copying: buffer.readAll())
        }) else {
            throw TLSError.truncatedMessage
        }

        guard let extensions = try bytes.readExtensions(messageType: .certificateRequest, helloRetryRequest: false) else {
            throw TLSError.truncatedMessage
        }

        self = CertificateRequest(certificateRequestContext: certificateRequestContext, extensions: extensions)
    }
}
