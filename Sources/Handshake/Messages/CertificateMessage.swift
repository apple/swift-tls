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

struct CertificateMessage {
    var certificateRequestContext: ByteBuffer

    var certificateList: [CertificateEntry]

    init(certificateRequestContext: ByteBuffer, certificateList: [CertificateEntry]) {
        self.certificateRequestContext = certificateRequestContext
        self.certificateList = certificateList
    }
}

extension CertificateMessage: Hashable { }

extension CertificateMessage {
    struct CertificateEntry {
        var opaqueCertificateData: ByteBuffer

        // TODO: enforcement on this value, only allow well-formed CertificateEntry.
        var extensions: Array<Extension>

        init(opaqueCertificateData: ByteBuffer, extensions: [Extension]) {
            self.opaqueCertificateData = opaqueCertificateData
            self.extensions = extensions
        }
    }
}

extension CertificateMessage.CertificateEntry: Hashable { }

extension CertificateMessage: HandshakeMessageProtocol {
    static var handshakeType: HandshakeType {
        .certificate
    }

    func write(into buffer: inout ByteBuffer) -> Int {
        var written = buffer.writeVariableLengthVector(lengthFieldType: UInt8.self) { buffer in
            buffer.writeImmutableBuffer(self.certificateRequestContext)
        }
        written += buffer.writeVariableLengthVectorUInt24 { buffer in
            return self.certificateList.reduce(into: 0) { count, certificateEntry in
                count += buffer.writeCertificateEntry(certificateEntry)
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

        guard let certificateEntries = try bytes.readVariableLengthVectorUInt24({ buffer throws(TLSError) in
            var extensions = Array<CertificateEntry>()

            while let ext = try buffer.readCertificateEntry() {
                extensions.append(ext)
            }

            return extensions
        }) else {
            throw TLSError.truncatedMessage
        }

        self = CertificateMessage(certificateRequestContext: certificateRequestContext, certificateList: certificateEntries)
    }
}

extension InputBuffer {
    mutating func readCertificateEntry() throws(TLSError) -> CertificateMessage.CertificateEntry? {
        guard let certificateData = try self.readVariableLengthVectorUInt24({ buffer in
            ByteBuffer(copying: buffer.readAll())
        }) else {
            return nil
        }

        guard let extensions = try self.readExtensions(messageType: .certificate, helloRetryRequest: false) else {
            return nil
        }

        return CertificateMessage.CertificateEntry(opaqueCertificateData: certificateData, extensions: extensions)
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeCertificateEntry(_ entry: CertificateMessage.CertificateEntry) -> Int {
        var written = self.writeVariableLengthVectorUInt24 { buffer in
            buffer.writeImmutableBuffer(entry.opaqueCertificateData)
        }
        written += self.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return entry.extensions.reduce(into: 0) { count, ext in
                count += buffer.writeExtension(ext)
            }
        }
        return written
    }
}
