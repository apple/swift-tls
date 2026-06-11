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

#if canImport(Darwin) || SWIFTTLS_EXCLAVEKIT
import os.log
@available(macOS 11, iOS 14, tvOS 14, watchOS 7, *)
private let logger = Logger(subsystem: "com.apple.security.swifttls", category: "Handshake")
#elseif SWIFTTLS_EMBEDDED || SWIFTTLS_DRIVERKIT
private let logger = Logger(label: "com.apple.security.swifttls.Handshake")
#elseif canImport(Logging)
// Linux Logging
import Logging
private let logger = Logger(label: "com.apple.security.swifttls.Handshake")
#endif

@available(anyAppleOS 26, *)
struct LegacySessionID {
    fileprivate var bytes: (UInt64, UInt64, UInt64, UInt64)
    fileprivate var length: Int

    private init(_ bytes: (UInt64, UInt64, UInt64, UInt64), length: Int) {
        precondition((0...32).contains(length), "LegacySessionID must be between zero and 32 bytes in size")
        self.bytes = bytes
        self.length = length
    }

    /// Initialize the legacy session ID from the given bytes, padding any
    /// remaining bytes with zero.
    init(_ bytes: borrowing RawSpan) {
        precondition(bytes.byteCount <= MemoryLayout<Random>.size)
        self.bytes = (0, 0, 0, 0)
        withUnsafeMutableBytes(of: &self.bytes) { outputBuffer in
            bytes.withUnsafeBytes { inputBuffer in
                outputBuffer.copyBytes(from: inputBuffer)
            }
        }
        self.length = bytes.byteCount
    }

    static func random() -> LegacySessionID {
        var rng = SystemRandomNumberGenerator()
        return LegacySessionID((rng.next(), rng.next(), rng.next(), rng.next()), length: 32)  // My kingdom for a better interface
    }

    static var zero: LegacySessionID {
        return LegacySessionID((0, 0, 0, 0), length: 0)
    }
}

@available(anyAppleOS 26, *)
extension LegacySessionID: Hashable {
    static func ==(lhs: LegacySessionID, rhs: LegacySessionID) -> Bool {
        // Right now this can just check every byte unconditionally because we zero-initialize the other bytes.
        return lhs.bytes.0 == rhs.bytes.0 && lhs.bytes.1 == rhs.bytes.1 && lhs.bytes.2 == rhs.bytes.2 && lhs.bytes.3 == rhs.bytes.3 && lhs.length == rhs.length
    }

    func hash(into hasher: inout Hasher) {
        // Right now this can just check every byte unconditionally because we zero-initialize the other bytes.
        hasher.combine(self.length)
        hasher.combine(self.bytes.0)
        hasher.combine(self.bytes.1)
        hasher.combine(self.bytes.2)
        hasher.combine(self.bytes.3)
    }
}

@available(anyAppleOS 26, *)
extension InputBuffer {
    mutating func readLegacySessionID() throws(TLSError) -> LegacySessionID? {
        return try self.readVariableLengthVector(lengthFieldType: UInt8.self) { buffer throws(TLSError) in
            let numBytes = buffer.byteCount
            guard numBytes <= 32 else {
                logger.error("reading legacy session id: too many bytes \(numBytes), but expected <= 32")
                throw TLSError.excessBytes
            }

            let sessionIDBytes = buffer.readAll()
            return LegacySessionID(sessionIDBytes)
        }
    }
}

@available(anyAppleOS 26, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeLegacySessionID(_ sessionID: LegacySessionID) -> Int {
        return self.writeVariableLengthVector(lengthFieldType: UInt8.self) { buffer in
            return withUnsafeBytes(of: sessionID.bytes) {
                buffer.writeBytes($0.prefix(sessionID.length))
            }
        }
    }
}
