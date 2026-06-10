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
struct CertificateVerify {
    var algorithm: SignatureScheme

    var signature: ByteBuffer

    init(algorithm: SignatureScheme, signature: ByteBuffer) {
        self.algorithm = algorithm
        self.signature = signature
    }
}

@available(SwiftTLS 0.1.0, *)
extension CertificateVerify: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension CertificateVerify: HandshakeMessageProtocol {
    static var handshakeType: HandshakeType {
        .certificateVerify
    }

    func write(into buffer: inout ByteBuffer) -> Int {
        var written = buffer.writeSignatureScheme(self.algorithm)
        written += buffer.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            buffer.writeImmutableBuffer(self.signature)
        }
        return written
    }

    init(bytes: inout InputBuffer) throws(TLSError) {
        guard let signatureScheme = bytes.readSignatureScheme(),
              let signature = try bytes.readVariableLengthVector(lengthFieldType: UInt16.self, { buffer in
                  ByteBuffer(copying: buffer.readAll())
              }) else {
            throw TLSError.truncatedMessage
        }

        self = CertificateVerify(algorithm: signatureScheme, signature: signature)
    }
}
