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
@testable import SwiftTLS
#endif

@available(anyAppleOS 26, *)
class InputBufferTests: XCTestCase {
    // MARK: - Basic properties

    func testEmptyBuffer() {
        var buffer = ByteBuffer()
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.byteCount, 0)
            XCTAssertEqual(input.position, 0)
            XCTAssertEqual(input.bytes.byteCount, 0)
        }
    }

    func testByteCountReflectsRemaining() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04, 0x05])
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.byteCount, 5)
            XCTAssertEqual(input.position, 0)

            _ = input.read(length: 2)
            XCTAssertEqual(input.byteCount, 3)
            XCTAssertEqual(input.position, 2)

            _ = input.read(length: 3)
            XCTAssertEqual(input.byteCount, 0)
            XCTAssertEqual(input.position, 5)
        }
    }

    // MARK: - read(length:)

    func testReadLength() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04, 0x05])
        buffer.withInputBuffer { input in
            guard var slice = input.read(length: 3) else {
                XCTFail("expected to read 3 bytes")
                return
            }
            XCTAssertEqual(slice.byteCount, 3)
            XCTAssertEqual(slice.readInteger(as: UInt8.self), 0x01)
            XCTAssertEqual(slice.readInteger(as: UInt8.self), 0x02)
            XCTAssertEqual(slice.readInteger(as: UInt8.self), 0x03)
            XCTAssertEqual(slice.byteCount, 0)

            // The original buffer advanced by 3 bytes.
            XCTAssertEqual(input.byteCount, 2)
            XCTAssertEqual(input.readInteger(as: UInt8.self), 0x04)
            XCTAssertEqual(input.readInteger(as: UInt8.self), 0x05)
        }
    }

    func testReadLengthZero() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02])
        buffer.withInputBuffer { input in
            guard let slice = input.read(length: 0) else {
                XCTFail("expected to read zero-length slice")
                return
            }
            XCTAssertEqual(slice.byteCount, 0)
            XCTAssertEqual(input.byteCount, 2)
            XCTAssertEqual(input.position, 0)
        }
    }

    func testReadLengthInsufficient() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02])
        buffer.withInputBuffer { input in
            // InputBuffer is non-copyable, so we can't use XCTAssertNil directly.
            if let _ = input.read(length: 3) {
                XCTFail("expected nil for read beyond buffer")
            }
            // Position did not advance.
            XCTAssertEqual(input.position, 0)
            XCTAssertEqual(input.byteCount, 2)
        }
    }

    // MARK: - readAll

    func testReadAll() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0xAA, 0xBB, 0xCC, 0xDD])
        buffer.withInputBuffer { input in
            let all = input.readAll()
            XCTAssertEqual(all.byteCount, 4)
            XCTAssertEqual(input.byteCount, 0)
            XCTAssertEqual(input.position, 4)

            // Copy bytes out and compare to the source.
            let bytes = ByteBuffer(copying: all)
            XCTAssertEqual(Array(bytes.readableBytesView), [0xAA, 0xBB, 0xCC, 0xDD])
        }
    }

    func testReadAllEmpty() {
        var buffer = ByteBuffer()
        buffer.withInputBuffer { input in
            let all = input.readAll()
            XCTAssertEqual(all.byteCount, 0)
            XCTAssertEqual(input.byteCount, 0)
        }
    }

    func testReadAllAfterPartialRead() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04])
        buffer.withInputBuffer { input in
            _ = input.read(length: 2)
            let all = input.readAll()
            XCTAssertEqual(all.byteCount, 2)
            let bytes = ByteBuffer(copying: all)
            XCTAssertEqual(Array(bytes.readableBytesView), [0x03, 0x04])
        }
    }

    // MARK: - readInteger

    func testReadIntegerUInt8() {
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt8(0x42))
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.readInteger(as: UInt8.self), 0x42)
            XCTAssertEqual(input.byteCount, 0)
        }
    }

    func testReadIntegerUInt16BigEndian() {
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt16(0x1234))
        // Confirm wire format is big-endian.
        XCTAssertEqual(Array(buffer.readableBytesView), [0x12, 0x34])
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.readInteger(as: UInt16.self), 0x1234)
        }
    }

    func testReadIntegerUInt32BigEndian() {
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt32(0xDEADBEEF))
        XCTAssertEqual(Array(buffer.readableBytesView), [0xDE, 0xAD, 0xBE, 0xEF])
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.readInteger(as: UInt32.self), 0xDEADBEEF)
        }
    }

    func testReadIntegerUInt64BigEndian() {
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt64(0x0123456789ABCDEF))
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.readInteger(as: UInt64.self), 0x0123456789ABCDEF)
        }
    }

    func testReadIntegerInsufficient() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x12])
        buffer.withInputBuffer { input in
            // Not enough bytes for a UInt16.
            XCTAssertNil(input.readInteger(as: UInt16.self))
            // Since read(length:) bails early, the position must not have advanced.
            XCTAssertEqual(input.position, 0)
        }
    }

    func testReadMultipleIntegers() {
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt8(0x01))
        buffer.writeInteger(UInt16(0x0203))
        buffer.writeInteger(UInt32(0x04050607))
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.readInteger(as: UInt8.self), 0x01)
            XCTAssertEqual(input.readInteger(as: UInt16.self), 0x0203)
            XCTAssertEqual(input.readInteger(as: UInt32.self), 0x04050607)
            XCTAssertEqual(input.byteCount, 0)
        }
    }

    // MARK: - readUInt24

    func testReadUInt24() {
        var buffer = ByteBuffer()
        buffer.writeUInt24(0x123456)
        XCTAssertEqual(Array(buffer.readableBytesView), [0x12, 0x34, 0x56])
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.readUInt24(), 0x123456)
            XCTAssertEqual(input.byteCount, 0)
        }
    }

    func testReadUInt24Zero() {
        var buffer = ByteBuffer()
        buffer.writeUInt24(0)
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.readUInt24(), 0)
        }
    }

    func testReadUInt24Max() {
        var buffer = ByteBuffer()
        buffer.writeUInt24(0xFFFFFF)
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.readUInt24(), 0xFFFFFF)
        }
    }

    func testReadUInt24Insufficient() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x12, 0x34])
        buffer.withInputBuffer { input in
            XCTAssertNil(input.readUInt24())
            // rewindOnNilOrError should have rewound position.
            XCTAssertEqual(input.position, 0)
        }
    }

    // MARK: - read(as:) for BitwiseCopyable

    func testReadAsBitwiseCopyable() {
        var buffer = ByteBuffer()
        // Use UInt8 which is byte-order-agnostic.
        buffer.writeBytes([0x7F])
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.read(as: UInt8.self), 0x7F)
            XCTAssertEqual(input.byteCount, 0)
        }
    }

    func testReadAsBitwiseCopyableInsufficient() {
        var buffer = ByteBuffer()
        buffer.withInputBuffer { input in
            XCTAssertNil(input.read(as: UInt32.self))
            XCTAssertEqual(input.position, 0)
        }
    }

    // MARK: - bytes property

    func testBytesReflectsRemaining() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04])
        buffer.withInputBuffer { input in
            XCTAssertEqual(input.bytes.byteCount, 4)
            _ = input.read(length: 2)
            XCTAssertEqual(input.bytes.byteCount, 2)

            // Remaining bytes start with 0x03.
            let remaining = ByteBuffer(copying: input.bytes)
            XCTAssertEqual(Array(remaining.readableBytesView), [0x03, 0x04])
        }
    }

    // MARK: - seek

    func testSeekForward() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04, 0x05])
        buffer.withInputBuffer { input in
            input.seek(to: 3)
            XCTAssertEqual(input.position, 3)
            XCTAssertEqual(input.byteCount, 2)
            XCTAssertEqual(input.readInteger(as: UInt8.self), 0x04)
        }
    }

    func testSeekBackward() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04])
        buffer.withInputBuffer { input in
            _ = input.read(length: 3)
            XCTAssertEqual(input.position, 3)

            input.seek(to: 1)
            XCTAssertEqual(input.position, 1)
            XCTAssertEqual(input.readInteger(as: UInt8.self), 0x02)
        }
    }

    func testSeekToEnd() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03])
        buffer.withInputBuffer { input in
            input.seek(to: 3)
            XCTAssertEqual(input.byteCount, 0)
        }
    }

    // MARK: - readLengthPrefixed

    func testReadLengthPrefixed() throws {
        var buffer = ByteBuffer()
        buffer.writeInteger(UInt16(3))
        buffer.writeBytes([0xAA, 0xBB, 0xCC])
        buffer.writeBytes([0xDD]) // Trailing byte left after the prefixed region.

        try buffer.withInputBuffer { input in
            let result: UInt32? = input.readLengthPrefixed(lengthAs: UInt16.self) { slice in
                XCTAssertEqual(slice.byteCount, 3)
                return UInt32(slice.readInteger(as: UInt8.self)!) << 16
                    | UInt32(slice.readInteger(as: UInt8.self)!) << 8
                    | UInt32(slice.readInteger(as: UInt8.self)!)
            }
            XCTAssertEqual(result, 0xAABBCC)
            XCTAssertEqual(input.byteCount, 1)
            XCTAssertEqual(input.readInteger(as: UInt8.self), 0xDD)
        }
    }

    func testReadLengthPrefixedInsufficientLength() {
        var buffer = ByteBuffer()
        // Only 1 byte — not enough for a UInt16 length prefix.
        buffer.writeBytes([0x01])
        buffer.withInputBuffer { input in
            let result: Int? = input.readLengthPrefixed(lengthAs: UInt16.self) { _ in 0 }
            XCTAssertNil(result)
        }
    }

    func testReadLengthPrefixedInsufficientBody() {
        var buffer = ByteBuffer()
        // Length says 10 bytes, but only 3 bytes of payload are present.
        buffer.writeInteger(UInt16(10))
        buffer.writeBytes([0x01, 0x02, 0x03])
        buffer.withInputBuffer { input in
            let result: Int? = input.readLengthPrefixed(lengthAs: UInt16.self) { _ in 0 }
            XCTAssertNil(result)
        }
    }

    // MARK: - readVariableLengthVector

    func testReadVariableLengthVector() throws {
        var buffer = ByteBuffer()
        buffer.writeVariableLengthVector(lengthFieldType: UInt8.self) { inner in
            inner.writeInteger(UInt16(0x1234))
            inner.writeInteger(UInt16(0x5678))
            return 4
        }
        buffer.writeBytes([0xFF]) // Trailing byte.

        try buffer.withInputBuffer { input in
            let values: [UInt16]? = try input.readVariableLengthVector(lengthFieldType: UInt8.self) { slice in
                var out: [UInt16] = []
                while let value = slice.readInteger(as: UInt16.self) {
                    out.append(value)
                }
                return out
            }
            XCTAssertEqual(values, [0x1234, 0x5678])
            XCTAssertEqual(input.byteCount, 1)
        }
    }

    func testReadVariableLengthVectorExcessBytes() throws {
        var buffer = ByteBuffer()
        // Length is 4 bytes; reader only consumes 2.
        buffer.writeInteger(UInt8(4))
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04])

        try buffer.withInputBuffer { input in
            XCTAssertThrowsError(try input.readVariableLengthVector(lengthFieldType: UInt8.self) { slice -> UInt16? in
                return slice.readInteger(as: UInt16.self)
            }) { error in
                XCTAssertEqual(error as? TLSError, TLSError.excessBytes)
            }
        }
    }

    func testReadVariableLengthVectorInsufficient() {
        var buffer = ByteBuffer()
        // Length says 5 bytes, but only 2 are present.
        buffer.writeInteger(UInt8(5))
        buffer.writeBytes([0x01, 0x02])
        buffer.withInputBuffer { input in
            do {
                let result: Int? = try input.readVariableLengthVector(lengthFieldType: UInt8.self) { _ in 0 }
                XCTAssertNil(result)
                // rewindOnNilOrError should have rewound position.
                XCTAssertEqual(input.position, 0)
            } catch {
                XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testReadVariableLengthVectorUInt24() throws {
        var buffer = ByteBuffer()
        buffer.writeVariableLengthVectorUInt24 { inner in
            inner.writeBytes([0xDE, 0xAD, 0xBE, 0xEF])
            return 4
        }

        try buffer.withInputBuffer { input in
            let bytes: [UInt8]? = try input.readVariableLengthVectorUInt24 { slice in
                var out: [UInt8] = []
                while let b = slice.readInteger(as: UInt8.self) {
                    out.append(b)
                }
                return out
            }
            XCTAssertEqual(bytes, [0xDE, 0xAD, 0xBE, 0xEF])
            XCTAssertEqual(input.byteCount, 0)
        }
    }

    // MARK: - readOptional

    func testReadOptionalNil() throws {
        var buffer = ByteBuffer()
        // Nil is encoded as discriminator byte 0x00.
        buffer.writeInteger(UInt8(0x00))
        buffer.withInputBuffer { input in
            let outer: UInt16?? = input.readOptional { inner in
                inner.readInteger(as: UInt16.self)
            }
            XCTAssertNotNil(outer)
            XCTAssertNil(outer!)
            // Only the discriminator byte was consumed.
            XCTAssertEqual(input.position, 1)
        }
    }

    func testReadOptionalValue() throws {
        var buffer = ByteBuffer()
        // Non-nil encoding: any nonzero discriminator + payload.
        buffer.writeInteger(UInt8(0xFF))
        buffer.writeInteger(UInt16(0xBEEF))
        buffer.withInputBuffer { input in
            let outer: UInt16?? = input.readOptional { inner in
                inner.readInteger(as: UInt16.self)
            }
            XCTAssertEqual(outer, .some(.some(0xBEEF)))
            XCTAssertEqual(input.byteCount, 0)
        }
    }

    func testReadOptionalNoDiscriminator() {
        var buffer = ByteBuffer()
        buffer.withInputBuffer { input in
            let outer: UInt16?? = input.readOptional { inner in
                inner.readInteger(as: UInt16.self)
            }
            // Couldn't even read the discriminator.
            XCTAssertNil(outer)
        }
    }

    func testReadOptionalValueTooShort() {
        var buffer = ByteBuffer()
        // Discriminator says there's a value, but only 1 byte of payload for a UInt16.
        buffer.writeInteger(UInt8(0xFF))
        buffer.writeInteger(UInt8(0x00))
        buffer.withInputBuffer { input in
            let outer: UInt16?? = input.readOptional { inner in
                inner.readInteger(as: UInt16.self)
            }
            // Outer optional is nil (couldn't read a complete value).
            XCTAssertNil(outer)
        }
    }

    // MARK: - rewindOnNilOrError

    func testRewindOnNilRewinds() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04])
        buffer.withInputBuffer { input in
            let result: UInt16? = input.rewindOnNilOrError { inner in
                _ = inner.readInteger(as: UInt8.self)
                _ = inner.readInteger(as: UInt8.self)
                return nil
            }
            XCTAssertNil(result)
            // Position is rewound.
            XCTAssertEqual(input.position, 0)
            XCTAssertEqual(input.byteCount, 4)
        }
    }

    func testRewindOnErrorRewinds() throws {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04])
        try buffer.withInputBuffer { input in
            XCTAssertThrowsError(try input.rewindOnNilOrError { inner throws(TLSError) -> UInt16? in
                _ = inner.readInteger(as: UInt8.self)
                throw TLSError.decodeError
            }) { error in
                XCTAssertEqual(error as? TLSError, TLSError.decodeError)
            }
            XCTAssertEqual(input.position, 0)
            XCTAssertEqual(input.byteCount, 4)
        }
    }

    func testRewindOnSuccessKeepsPosition() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04])
        buffer.withInputBuffer { input in
            let result: UInt16? = input.rewindOnNilOrError { inner in
                inner.readInteger(as: UInt16.self)
            }
            XCTAssertEqual(result, 0x0102)
            // Position was NOT rewound on success.
            XCTAssertEqual(input.position, 2)
            XCTAssertEqual(input.byteCount, 2)
        }
    }

    // MARK: - copy(to:)

    func testCopy() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x10, 0x20, 0x30, 0x40])
        buffer.withInputBuffer { input in
            _ = input.read(length: 1) // advance past 0x10

            withUnsafeTemporaryAllocation(byteCount: 8, alignment: 1) { raw in
                var output = OutputRawSpan(buffer: raw, initializedCount: 0)
                let written = input.copy(to: &output)
                XCTAssertEqual(written, 3)

                // copy() does not consume bytes from the input buffer.
                XCTAssertEqual(input.byteCount, 3)
                XCTAssertEqual(input.position, 1)

                let finalized = output.finalize(for: raw)
                XCTAssertEqual(finalized, 3)

                let copied = Array(UnsafeBufferPointer(start: raw.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 3))
                XCTAssertEqual(copied, [0x20, 0x30, 0x40])
            }
        }
    }

    func testCopyLimitedByOutputCapacity() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04, 0x05])
        buffer.withInputBuffer { input in
            withUnsafeTemporaryAllocation(byteCount: 2, alignment: 1) { raw in
                var output = OutputRawSpan(buffer: raw, initializedCount: 0)
                let written = input.copy(to: &output)
                // Capped at the output's free capacity.
                XCTAssertEqual(written, 2)
                // Input position is not advanced.
                XCTAssertEqual(input.position, 0)

                let finalized = output.finalize(for: raw)
                XCTAssertEqual(finalized, 2)

                let copied = Array(UnsafeBufferPointer(start: raw.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 2))
                XCTAssertEqual(copied, [0x01, 0x02])
            }
        }
    }

    // MARK: - Direct construction from RawSpan

    func testDirectConstructionFromReadableBytesSpan() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0xAA, 0xBB, 0xCC])
        var input = InputBuffer(storage: buffer.readableBytesSpan)
        XCTAssertEqual(input.byteCount, 3)
        XCTAssertEqual(input.readInteger(as: UInt8.self), 0xAA)
        XCTAssertEqual(input.readInteger(as: UInt8.self), 0xBB)
        XCTAssertEqual(input.readInteger(as: UInt8.self), 0xCC)
        XCTAssertEqual(input.byteCount, 0)
    }

    // MARK: - withInputBuffer advancing the reader index

    func testWithInputBufferAdvancesReaderIndexOnSuccess() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04])
        buffer.withInputBuffer { input in
            _ = input.read(length: 2)
        }
        // The ByteBuffer's reader index advanced by 2.
        XCTAssertEqual(buffer.readableBytes, 2)
        XCTAssertEqual(Array(buffer.readableBytesView), [0x03, 0x04])
    }

    func testWithInputBufferAdvancesReaderIndexOnThrow() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x01, 0x02, 0x03, 0x04])
        XCTAssertThrowsError(try buffer.withInputBuffer { input throws(TLSError) -> Void in
            _ = input.read(length: 1)
            throw TLSError.decodeError
        })
        // Even when the body throws, bytes that were consumed are still consumed.
        XCTAssertEqual(buffer.readableBytes, 3)
        XCTAssertEqual(Array(buffer.readableBytesView), [0x02, 0x03, 0x04])
    }
}
