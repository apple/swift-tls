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

struct Random {
    fileprivate var bytes: (UInt64, UInt64, UInt64, UInt64)

    init() {
        var rng = SystemRandomNumberGenerator()
        self.bytes = (rng.next(), rng.next(), rng.next(), rng.next())  // My kingdom for a better interface
    }

    init<Bytes: RandomAccessCollection>(_ bytes: Bytes) where Bytes.Element == UInt8 {
        precondition(bytes.count == MemoryLayout<Random>.size)
        self.bytes = (0, 0, 0, 0)
        withUnsafeMutableBytes(of: &self.bytes) {
            $0.copyBytes(from: bytes)
        }
    }
}

extension Random {
    static let helloRetryRequest = Random(
        [0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
         0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C]
    )
}

extension Random: Hashable {
    static func ==(lhs: Random, rhs: Random) -> Bool {
        return lhs.bytes.0 == rhs.bytes.0 && lhs.bytes.1 == rhs.bytes.1 && lhs.bytes.2 == rhs.bytes.2 && lhs.bytes.3 == rhs.bytes.3
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(self.bytes.0)
        hasher.combine(self.bytes.1)
        hasher.combine(self.bytes.2)
        hasher.combine(self.bytes.3)
    }
}

@available(SwiftTLS 0.1.0, *)
extension InputBuffer {
    mutating func readRandom() -> Random? {
        self.read(as: Random.self)
    }
}

@available(SwiftTLS 0.1.0, *)
extension ByteBuffer {
    @discardableResult
    mutating func writeRandom(_ random: Random) -> Int {
        return withUnsafeBytes(of: random.bytes) {
            assert($0.count == 32)
            return self.writeBytes($0)
        }
    }
}
