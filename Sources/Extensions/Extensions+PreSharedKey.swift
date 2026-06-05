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

extension Extension {
    enum PreSharedKey {
        case clientHello(OfferedPSKs)
        case serverHello(UInt16)
    }
}

extension Extension.PreSharedKey {
    struct OfferedPSKs {
        var identities: [PSKIdentity]

        var binders: [PSKBinderEntry]
    }
}

extension Extension.PreSharedKey.OfferedPSKs {
    struct PSKIdentity {
        var identity: ByteBuffer

        var obfuscatedTicketAge: UInt32
    }
}

extension Extension.PreSharedKey.OfferedPSKs {
    struct PSKBinderEntry {
        var serializedBinder: ByteBuffer
    }
}

extension Extension.PreSharedKey: Hashable { }

extension Extension.PreSharedKey.OfferedPSKs: Hashable { }

extension Extension.PreSharedKey.OfferedPSKs.PSKIdentity: Hashable { }

extension Extension.PreSharedKey.OfferedPSKs.PSKBinderEntry: Hashable { }

extension InputBuffer {
    mutating func readPSKIdentity() throws(TLSError) -> Extension.PreSharedKey.OfferedPSKs.PSKIdentity? {
        guard let identity: ByteBuffer = try? self.readVariableLengthVector(lengthFieldType: UInt16.self, { buffer in
            return ByteBuffer(copying: buffer.readAll())
        }) else {
            return nil
        }

        guard let obfuscatedTicketAge = self.readInteger(as: UInt32.self) else {
            return nil
        }

        guard identity.readableBytes > 0 else {
            throw TLSError.insufficientBytes
        }

        return .init(identity: identity, obfuscatedTicketAge: obfuscatedTicketAge)
    }

    mutating func readPSKBinderEntry() throws(TLSError) -> Extension.PreSharedKey.OfferedPSKs.PSKBinderEntry? {
        let bytes: ByteBuffer? = try? self.readVariableLengthVector(lengthFieldType: UInt8.self, { buffer in
            return ByteBuffer(copying: buffer.readAll())
        })

        guard let serializedBinder = bytes else { return nil }

        guard serializedBinder.readableBytes >= 32 else {
            throw TLSError.insufficientBytes
        }

        return .init(serializedBinder: serializedBinder)
    }

    mutating func readOfferedPSKs() throws(TLSError) -> Extension.PreSharedKey.OfferedPSKs? {
        guard let identities = try self.readVariableLengthVector(lengthFieldType: UInt16.self, { buffer throws(TLSError) in
            var identities: [Extension.PreSharedKey.OfferedPSKs.PSKIdentity] = []

            while let identity = try buffer.readPSKIdentity() {
                identities.append(identity)
            }

            return identities
        }),
        let binders = try self.readVariableLengthVector(lengthFieldType: UInt16.self, { buffer throws(TLSError) in
            var binderEntries: [Extension.PreSharedKey.OfferedPSKs.PSKBinderEntry] = []

            while let binderEntry = try buffer.readPSKBinderEntry() {
                binderEntries.append(binderEntry)
            }

            return binderEntries
        }) else {
            return nil
        }

        return Extension.PreSharedKey.OfferedPSKs(identities: identities, binders: binders)
    }

    mutating func readPreSharedKey(messageType: HandshakeType, helloRetryRequest: Bool) throws(TLSError) -> Extension.PreSharedKey {
        switch messageType {
        case .clientHello:
            guard let psks = try self.readOfferedPSKs() else {
                throw TLSError.truncatedMessage
            }

            return .clientHello(psks)

        case .serverHello where !helloRetryRequest:
            guard let selectedIdentity = self.readInteger(as: UInt16.self) else {
                throw TLSError.truncatedMessage
            }

            return .serverHello(selectedIdentity)

        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .preSharedKey)
        }
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writePreSharedKey(_ psk: Extension.PreSharedKey) -> Int {
        switch psk {
        case .clientHello(let offeredPSKs):
            return self.writeOfferedPSKs(offeredPSKs)
        case .serverHello(let selectedIdentity):
            return self.writeInteger(selectedIdentity)
        }
    }

    @discardableResult
    private mutating func writeOfferedPSKs(_ psks: Extension.PreSharedKey.OfferedPSKs) -> Int {
        var written = 0
        written += self.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return psks.identities.reduce(into: 0) { $0 += buffer.writePSKIdentity($1) }
        }
        written += self.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
            return psks.binders.reduce(into: 0) { $0 += buffer.writePSKBinder($1) }
        }
        return written
    }

    @discardableResult
    private mutating func writePSKIdentity(_ identity: Extension.PreSharedKey.OfferedPSKs.PSKIdentity) -> Int {
        var written = 0
        written += self.writeVariableLengthVector(lengthFieldType: UInt16.self) { $0.writeImmutableBuffer(identity.identity) }
        written += self.writeInteger(identity.obfuscatedTicketAge)
        return written
    }

    @discardableResult
    private mutating func writePSKBinder(_ binder: Extension.PreSharedKey.OfferedPSKs.PSKBinderEntry) -> Int {
        return self.writeVariableLengthVector(lengthFieldType: UInt8.self) { $0.writeImmutableBuffer(binder.serializedBinder) }
    }
}
