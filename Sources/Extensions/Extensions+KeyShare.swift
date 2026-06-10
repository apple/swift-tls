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
extension Extension {
    enum KeyShare {
        case clientHello([KeyShareEntry])
        case serverHello(KeyShareEntry)
        case helloRetryRequest(NamedGroup)
    }
}

@available(SwiftTLS 0.1.0, *)
extension Extension.KeyShare: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension Extension.KeyShare {
    struct KeyShareEntry {
        var group: NamedGroup
        var keyExchange: ByteBuffer

        init(group: NamedGroup, keyExchange: ByteBuffer) {
            self.group = group
            self.keyExchange = keyExchange
        }
    }
}

@available(SwiftTLS 0.1.0, *)
extension Extension.KeyShare.KeyShareEntry: Hashable { }

@available(SwiftTLS 0.1.0, *)
extension Extension.KeyShare.KeyShareEntry: CustomStringConvertible {
    var description: String {
        "KeyShareEntry(group: \(self.group), keyExchange: \(self.keyExchange.readableBytes) bytes)"
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeKeyShare(_ versions: Extension.KeyShare) -> Int {
        switch versions {
        case .clientHello(let shares):
            return self.writeVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
                return shares.reduce(into: 0) { length, share in
                    length += buffer.writeKeyShareEntry(share)
                }
            }

        case .serverHello(let share):
            return self.writeKeyShareEntry(share)

        case .helloRetryRequest(let namedGroup):
            return self.writeNamedGroup(namedGroup)
        }
    }

    @discardableResult
    mutating func writeKeyShareEntry(_ entry: Extension.KeyShare.KeyShareEntry) -> Int {
        var written = self.writeNamedGroup(entry.group)
        written += self.writeInteger(UInt16(entry.keyExchange.readableBytes))
        written += self.writeImmutableBuffer(entry.keyExchange)
        return written
    }
}

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readKeyShareEntry() -> Extension.KeyShare.KeyShareEntry? {
        guard let group = self.readNamedGroup() else {
            return nil
        }

        // Read the key exchange data as a variable-length vector
        guard let keyExchangeBuffer: ByteBuffer = try? self.readVariableLengthVector(lengthFieldType: UInt16.self, { buffer in
            return ByteBuffer(copying: buffer.readAll())
        }) else {
            return nil
        }

        return Extension.KeyShare.KeyShareEntry(group: group, keyExchange: keyExchangeBuffer)
    }

    mutating func readKeyShare(messageType: HandshakeType, helloRetryRequest: Bool) throws(TLSError) -> Extension.KeyShare {
        switch messageType {
        case .serverHello where !helloRetryRequest:
            // We expect the server only version. nil is an error here.
            guard let keyShareEntry = self.readKeyShareEntry() else {
                throw TLSError.truncatedMessage
            }
            return .serverHello(keyShareEntry)
        case .serverHello where helloRetryRequest:
            // nil is an error here
            guard let namedGroup = self.readNamedGroup() else {
                throw TLSError.truncatedMessage
            }
            return .helloRetryRequest(namedGroup)
        case .clientHello:
            // nil is an error here.
            let possibleResult: [Extension.KeyShare.KeyShareEntry]? = try self.readVariableLengthVector(lengthFieldType: UInt16.self) { buffer in
                var shares = Array<Extension.KeyShare.KeyShareEntry>()
                shares.reserveCapacity(buffer.byteCount / 32)  // This will tend to overcommit, but that's ok

                while let share = buffer.readKeyShareEntry() {
                    shares.append(share)
                }

                return shares
            }

            guard let result = possibleResult else {
                throw TLSError.truncatedMessage
            }

            return .clientHello(result)
        default:
            throw TLSError.invalidMessageForExtension(messageType: messageType, extensionType: .keyShare)
        }
    }
}
