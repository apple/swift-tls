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

import XCTest
#if canImport(SwiftTLS) && !SWIFTTLS_BUILTIN_TESTS
@testable @_spi(SwiftTLSProtocol) import SwiftTLS
#endif

/// Checks that `OutputRawSpan.append(contentsOf:)` over a `Sequence<UInt8>` writes the same bytes whether or not
/// the sequence has contiguous storage.
// Availability due to `Swift`'s `OutputRawSpan`
@available(SwiftTLS 0.1.0, *)
final class OutputRawSpanAppendTests: XCTestCase {
    /// Writes `prefix` and then `bytes` into a buffer of exactly their combined size, through the helper
    /// that production code uses to fill stack buffers.
    private func writtenBytes<Bytes: Sequence<UInt8>>(prefix: [UInt8] = [], appending bytes: Bytes) -> [UInt8] {
        let count = prefix.count + bytes.underestimatedCount
        return withTemporaryAllocationOfBytes(
            capacity: count,
            fill: { outputSpan in
                for byte in prefix {
                    outputSpan.append(byte)
                }
                outputSpan.append(contentsOf: bytes)
            },
            use: { Array(copying: $0) }
        )
    }

    func testAppendsAnArray() {
        XCTAssertEqual(self.writtenBytes(appending: [1, 2, 3] as [UInt8]), [1, 2, 3])
    }

    func testAppendsTheUTF8ViewOfAString() {
        let string = "tls13 héllo"
        XCTAssertEqual(self.writtenBytes(appending: string.utf8), Array(string.utf8))
    }

    func testAppendsASequenceWithoutContiguousStorage() {
        let sequence = (0..<5).lazy.map { UInt8($0) }
        // The premise of this test is that the sequence takes the byte-by-byte path.
        XCTAssertNil(sequence.withContiguousStorageIfAvailable { $0.count })

        XCTAssertEqual(self.writtenBytes(appending: sequence), [0, 1, 2, 3, 4])
    }

    func testAppendsAfterExistingBytes() {
        XCTAssertEqual(self.writtenBytes(prefix: [9], appending: [1, 2] as [UInt8]), [9, 1, 2])
        XCTAssertEqual(self.writtenBytes(prefix: [9], appending: (1...2).lazy.map { UInt8($0) }), [9, 1, 2])
    }

    func testAppendsAnEmptySequence() {
        XCTAssertEqual(self.writtenBytes(appending: [UInt8]()), [])
        XCTAssertEqual(self.writtenBytes(appending: "".utf8), [])
        XCTAssertEqual(self.writtenBytes(appending: (0..<0).lazy.map { UInt8($0) }), [])
    }
}
