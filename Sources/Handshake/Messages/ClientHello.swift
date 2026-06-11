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
struct ClientHello {
    var legacyVersion: ProtocolVersion
    var random: Random
    var legacySessionID: LegacySessionID

    // TODO: Enforcement on this value, only allow well-formed ClientHellos
    var cipherSuites: Array<CipherSuite>

    // TODO: enforcement on this value, only allow well-formed ClientHellos, but tolerate non
    // TLS 1.3 ones.
    var legacyCompressionMethods: Array<UInt8>

    // TODO: enforcement on this value, only allow well-formed ClientHellos.
    var extensions: Array<Extension>

    init(legacyVersion: ProtocolVersion,
         random: Random,
         legacySessionID: LegacySessionID,
         cipherSuites: [CipherSuite],
         legacyCompressionMethods: [UInt8],
         extensions: [Extension]) {
        self.legacyVersion = legacyVersion
        self.random = random
        self.legacySessionID = legacySessionID
        self.cipherSuites = cipherSuites
        self.legacyCompressionMethods = legacyCompressionMethods
        self.extensions = extensions
    }
}

@available(anyAppleOS 26, *)
extension ClientHello {
    var serverCertificateTypes: [CertificateType] {
        for ext in self.extensions {
            if case .serverCertificateType(.offer(let types)) = ext {
                return types
            }
        }

        // The default value is x509.
        return [.x509]
    }

    var clientCertificateTypes: [CertificateType] {
        for ext in self.extensions {
            if case .clientCertificateType(.offer(let types)) = ext {
                return types
            }
        }

        // The default value is x509.
        return [.x509]
    }
}

@available(anyAppleOS 26, *)
extension ClientHello {
    var signatureAlgorithms: [UInt16] {
        for ext in self.extensions {
            if case .signatureAlgorithms(let schemes) = ext {
                return schemes.schemes.map { $0.rawValue }
            }
        }
        return []
    }
}

@available(anyAppleOS 26, *)
extension ClientHello {
    var serverName: String? {
        for ext in self.extensions {
            if case .serverName(let serverName) = ext {
                switch serverName {
                case .clientHello(let names):
                    // This is a safe conversion.
                    // Parsing the extension checks that this is ASCII, see `readServerName(messageType:)`.
                    return String(validating: names.hostName.readableBytesView, as: UTF8.self)
                case .encryptedExtensions:
                    return nil
                }
            }
        }
        return nil
    }
}

@available(anyAppleOS 26, *)
extension ClientHello {
    var alpns: [String] {
        for ext in self.extensions {
            if case .alpn(let alpn) = ext {
                switch alpn {
                case .offer(let alpns):
                    return alpns
                case .selection(let alpn):
                    return [alpn]
                }
            }
        }
        return []
    }
}

@available(anyAppleOS 26, *)
extension ClientHello: Hashable { }

@available(anyAppleOS 26, *)
extension ClientHello: HandshakeMessageProtocol {
    static var handshakeType: HandshakeType {
        .clientHello
    }

    func write(into buffer: inout ByteBuffer) -> Int {
        var written = buffer.writeProtocolVersion(self.legacyVersion)
        written += buffer.writeRandom(self.random)
        written += buffer.writeLegacySessionID(self.legacySessionID)
        written += buffer.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return self.cipherSuites.reduce(into: 0) { count, cipherSuite in
                count += buffer.writeCipherSuite(cipherSuite)
            }
        }
        written += buffer.writeVariableLengthVector(lengthFieldType: UInt8.self) { buffer in
            return self.legacyCompressionMethods.reduce(into: 0) { count, compressionMethod in
                count += buffer.writeInteger(compressionMethod)
            }
        }
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
              let legacySessionID = try bytes.readLegacySessionID() else {
            throw TLSError.truncatedMessage
        }

        guard let cipherSuites = try bytes.readVariableLengthVector(lengthFieldType: UInt16.self, { buffer throws(TLSError) in
            var suites = Array<CipherSuite>()
            suites.reserveCapacity(buffer.byteCount / MemoryLayout<CipherSuite>.size)

            while let cipherSuite = buffer.readCipherSuite() {
                suites.append(cipherSuite)
            }

            return suites
        }) else {
            throw TLSError.truncatedMessage
        }

        guard let legacyCompressionMethods = try bytes.readVariableLengthVector(lengthFieldType: UInt8.self, { buffer throws(TLSError) in
            [UInt8](copying: buffer.readAll())
        }) else {
            throw TLSError.truncatedMessage
        }

        guard let extensions = try bytes.readExtensions(messageType: .clientHello, helloRetryRequest: false) else {
            throw TLSError.truncatedMessage
        }

        self = ClientHello(legacyVersion: version, random: random, legacySessionID: legacySessionID, cipherSuites: cipherSuites, legacyCompressionMethods: legacyCompressionMethods, extensions: extensions)
    }
}
