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
struct ServerHello {
    var legacyVersion: ProtocolVersion
    var random: Random
    var legacySessionIDEcho: LegacySessionID
    var cipherSuite: CipherSuite
    var legacyCompressionMethod: UInt8
    var extensions: Array<Extension>
}

@available(SwiftTLS 0.1.0, *)
extension ServerHello {
    var isHelloRetryRequest: Bool {
        return self.random == .helloRetryRequest
    }

    var supportedVersion: ProtocolVersion? {
        for ext in self.extensions {
            if case .supportedVersions(.selection(let version)) = ext {
                return version
            }
        }

        return nil
    }
}

@available(SwiftTLS 0.1.0, *)
extension ServerHello: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension ServerHello: HandshakeMessageProtocol {
    static var handshakeType: HandshakeType {
        .serverHello
    }

    func write(into buffer: inout ByteBuffer) -> Int {
        var written = buffer.writeProtocolVersion(self.legacyVersion)
        written += buffer.writeRandom(self.random)
        written += buffer.writeLegacySessionID(self.legacySessionIDEcho)
        written += buffer.writeCipherSuite(self.cipherSuite)
        written += buffer.writeInteger(self.legacyCompressionMethod)
        written += buffer.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return self.extensions.reduce(into: 0) { count, ext in
                count += buffer.writeExtension(ext)
            }
        }
        return written
    }

    init(bytes: inout InputBuffer) throws(TLSError) {
        guard let version = bytes.readProtocolVersion(),
              let random = bytes.readRandom(),
              let legacySessionID = try bytes.readLegacySessionID(),
              let cipherSuite = bytes.readCipherSuite(),
              let legacyCompressionMethod = bytes.readInteger(as: UInt8.self) else {
            throw TLSError.truncatedMessage
        }

        // We can't read the extensions until we know if this is a hello retry request or not.
        let isHelloRetryRequest = random == .helloRetryRequest
        guard let extensions = try bytes.readExtensions(messageType: .serverHello, helloRetryRequest: isHelloRetryRequest) else {
            throw TLSError.truncatedMessage
        }

        self = ServerHello(legacyVersion: version, random: random, legacySessionIDEcho: legacySessionID, cipherSuite: cipherSuite, legacyCompressionMethod: legacyCompressionMethod, extensions: extensions)
    }
}
