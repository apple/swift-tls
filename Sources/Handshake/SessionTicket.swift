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
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
@preconcurrency import Crypto
#endif

#if canImport(Darwin) || SWIFTTLS_EXCLAVEKIT
import os.log
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "SessionTicket")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.SessionTicket")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.SessionTicket")
#endif

/// A TLS session ticket.
///
/// This structure encodes all the information needed to resume a session. This means it includes ticket data,
/// ticket age information, and details about the underlying handshake so that resumption can be validated.
///
/// Critically, you can serialize and deserialize session tickets.
@available(SwiftTLS 0.1.0, *)
struct SessionTicket {
    var issued: Date

    var lifetime: UInt32

    var ticketAgeAdd: UInt32

    var nonce: ByteBuffer

    var ticket: ByteBuffer

    var psk: SymmetricKey

    var maxEarlyDataSize: UInt32

    var cipherSuite: CipherSuite

    var group: NamedGroup

    var alpn: ApplicationLayerProtocol?

    var certificateBundle: PeerCertificateBundle

    init(message: NewSessionTicket,
         psk: SymmetricKey,
         cipherSuite: CipherSuite,
         group: NamedGroup,
         alpn: ApplicationLayerProtocol?,
         certificateBundle: PeerCertificateBundle,
         currentTime: Date) throws(TLSError) {
        self.issued = currentTime
        self.lifetime = min(message.ticketLifetime, Self.maxLifetime)
        self.ticketAgeAdd = message.ticketAgeAdd
        self.ticket = message.ticket
        self.nonce = message.ticketNonce
        self.psk = psk
        self.cipherSuite = cipherSuite
        self.group = group
        self.alpn = alpn
        self.certificateBundle = certificateBundle

        // Max early data size is an extension.
        var maxEarlyDataSize: UInt32?

        var observedExtensionTypes = Set<ExtensionType>()

        for ext in message.extensions {
            let (inserted, _) = observedExtensionTypes.insert(ext.type)

            if !inserted {
                #if SWIFTTLS_EXCLAVECORE
                logger.error("server offered duplicate extension of type \(String(describing: ext.type)) on new session ticket")
                #else
                logger.error("server offered duplicate extension of type \(ext.type) on new session ticket")
                #endif
                throw TLSError.handshakeInvalidMessage
            }

            switch ext {
            case .earlyData(let earlyData):
                // Max early data size must be non-nil, and unique
                guard maxEarlyDataSize == nil, let earlyData = earlyData.maxEarlyDataSize else {
                    logger.error("invalid early data extension: old value \(maxEarlyDataSize?.description ?? "nil") new value \(earlyData.maxEarlyDataSize?.description ?? "nil")")
                    throw TLSError.handshakeInvalidMessage
                }

                maxEarlyDataSize = earlyData
            default:
                // Unknown extensions MUST be ignored.
                continue
            }
        }

        self.maxEarlyDataSize = maxEarlyDataSize ?? 0
    }

    func serialize() -> Data {
        var buffer = ByteBuffer()
        buffer.writeInteger(self.issued.timeIntervalSinceReferenceDate.bitPattern, as: UInt64.self)
        buffer.writeInteger(self.lifetime)
        buffer.writeInteger(self.ticketAgeAdd)
        buffer.writeLengthPrefixedImmutableBuffer(self.nonce)
        buffer.writeLengthPrefixedImmutableBuffer(self.ticket)

        self.psk.withUnsafeBytes {
            buffer.writeLengthPrefixedBytes($0)
        }

        buffer.writeInteger(self.maxEarlyDataSize)
        buffer.writeCipherSuite(self.cipherSuite)
        buffer.writeNamedGroup(self.group)
        buffer.writeOptional(self.alpn) { $0.writeApplicationLayerProtocol($1) }
        buffer.writePeerCertificateBundle(self.certificateBundle)

        return buffer.readableBytesView
    }

    init(serialized: RawSpan) throws(TLSError) {
        var buffer = InputBuffer(storage: serialized)

        guard let dateInterval = buffer.readInteger(as: UInt64.self),
              let lifetime = buffer.readInteger(as: UInt32.self),
              let ticketAgeAdd = buffer.readInteger(as: UInt32.self),
              let nonce = buffer.readLengthPrefixed({ ByteBuffer(copying: $0.bytes) }),
              let ticket = buffer.readLengthPrefixed({ ByteBuffer(copying: $0.bytes) }),
              let psk = buffer.readLengthPrefixed({ SymmetricKey(_copying: $0.bytes) }),
              let maxEarlyDataSize = buffer.readInteger(as: UInt32.self),
              let cipherSuite = buffer.readCipherSuite(),
              let group = buffer.readNamedGroup(),
              let alpn = buffer.readOptional({ buffer in buffer.readApplicationLayerProtocol() }),
              let certificateBundle = try buffer.readPeerCertificateBundle() else {
            logger.error("Unable to parse decrypted session ticket")
            throw TLSError.invalidSerializedSession
        }

        self.issued = Date(timeIntervalSinceReferenceDate: Double(bitPattern: dateInterval))
        self.lifetime = lifetime
        self.ticketAgeAdd = ticketAgeAdd
        self.nonce = nonce
        self.ticket = ticket
        self.psk = psk
        self.maxEarlyDataSize = maxEarlyDataSize
        self.cipherSuite = cipherSuite
        self.group = group
        self.alpn = alpn
        self.certificateBundle = certificateBundle
    }

    /// Reports whether this `SessionTicket` can resume with the provided client hello.
    ///
    /// Note: This always returns `false` when using certificate callbacks for peer verification, because resumption requires peer public keys to be set on the configuration.
    func isCompatibleWith(_ clientHello: ClientHello, configuration: HandshakeStateMachine.Configuration, currentTime: Date) -> Bool {
        // Gotta confirm this session is suitable. Start with the cheap ones: do the algorithms line up?
        // For now we only resume if this matches the _first_ outcomes, because it avoids needing to deal with
        // sorting the sessions.
        guard self.cipherSuite == clientHello.cipherSuites.first else {
            return false
        }

        for ext in clientHello.extensions {
            switch ext {
            case .alpn(.offer(let alpns)):
                if let alpn = self.alpn {
                    guard alpns.contains(alpn) else {
                        return false
                    }
                }

            default:
                continue
            }
        }

        // Now validate that the peer certificate bundle would be trusted.
        guard let validPeerPublicKeys = configuration.validPeerPublicKeys,
              self.certificateBundle.wouldBeTrusted(forKeys: validPeerPublicKeys) else {
            return false
        }

        // Ok, now confirm we can still re-use this session. Lifetime is seconds in a UInt32,
        // TimeInterval is seconds in a Double, so we have to do a bit of a dance here.
        let expiry = self.issued.addingTimeInterval(TimeInterval(self.lifetime))
        guard currentTime < expiry && self.issued <= currentTime else {
            return false
        }

        return true
    }

    func obfuscatedTicketAge(currentTime: Date) -> UInt32 {
        let age = currentTime.timeIntervalSince(self.issued)

        // We need to get the age in milliseconds, and add the obfuscation value modulo 2^32.
        let ageInMillis = UInt32(age * 1000)
        return ageInMillis &+ self.ticketAgeAdd
    }
}

@available(SwiftTLS 0.1.0, *)
extension SessionTicket {
    /// The maximum cache lifetime allowed by RFC 8446.
    static fileprivate let maxLifetime = UInt32(604800)
}

@available(SwiftTLS 0.1.0, *)
extension SessionTicket: Equatable { }

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    mutating func writeLengthPrefixedString(_ string: String) {
        self.writeLengthPrefixedBytes(string.utf8)
    }

    mutating func writeLengthPrefixedImmutableBuffer(_ byteBuffer: ByteBuffer) {
        self.writeInteger(UInt64(byteBuffer.readableBytes))
        self.writeImmutableBuffer(byteBuffer)
    }

    mutating func writeLengthPrefixedBytes<C: Collection>(_ collection: C) where C.Element == UInt8 {
        self.writeInteger(UInt64(collection.count))
        self.writeBytes(collection)
    }

    mutating func writeOptional<DataType>(_ value: Optional<DataType>, _ writeFunction: (inout ByteBuffer, DataType) -> Void) {
        if let value = value {
            self.writeInteger(UInt8(0xff)) // Weird bool marker.
            writeFunction(&self, value)
        } else {
            self.writeInteger(UInt8(0)) // Weird bool marker
        }
    }
}
