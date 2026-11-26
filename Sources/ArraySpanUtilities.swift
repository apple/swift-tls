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

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension Array where Element == UInt8 {
    /// Creates an array by copying the bytes of the given raw span.
    ///
    /// The span must contain exactly `count` bytes.
    init(copying bytes: RawSpan) {
        self.init(capacity: bytes.byteCount) { output in
            output.append(contentsOf: bytes)
        }
    }

    /// Splits this array's storage at `index`, yielding the prefix as a
    /// `MutableRawSpan` to be updated in place and the suffix as an
    /// `OutputRawSpan` to be written into.
    ///
    /// Two disjoint mutable views into one allocation can't be expressed with
    /// the safe span APIs, so this helper splits the storage into a prefix and
    /// a suffix through pointers.
    ///
    /// The suffix is already-initialized storage, but `OutputRawSpan` can only
    /// model it as empty free capacity, so it is presented with an initialized
    /// count of zero. `body` must therefore write the suffix in full.
    mutating func withUnsafeMutableOutputSplit(
        at index: Int,
        _ body: (inout MutableRawSpan, inout OutputRawSpan) throws -> Void
    ) rethrows {
        precondition(index >= 0 && index <= self.count)
        try self.withUnsafeMutableBytes { buffer in
            let prefix = UnsafeMutableRawBufferPointer(rebasing: buffer[..<index])
            let suffix = UnsafeMutableRawBufferPointer(rebasing: buffer[index...])
            var prefixSpan = prefix.mutableBytes
            var suffixSpan = OutputRawSpan(buffer: suffix, initializedCount: 0)
            try body(&prefixSpan, &suffixSpan)
            let written = suffixSpan.finalize(for: suffix)
            precondition(
                written == suffix.count,
                "output span left \(suffix.count - written) of \(suffix.count) bytes unwritten"
            )
        }
    }
}

// Availability due to `Swift`'s `InlineArray`
@available(SwiftTLS 0.1.0, *)
extension InlineArray where Element == UInt8 {
    /// Creates an inline array by copying the bytes of the given raw span.
    ///
    /// The span must contain exactly `count` bytes.
    init(copying bytes: RawSpan) {
        precondition(count == bytes.byteCount)
        self.init { outputSpan in
            outputSpan.append(contentsOf: bytes)
        }
    }
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension Hasher {
    mutating func combine(bytes: RawSpan) {
        bytes.withUnsafeBytes { buffer in
            self.combine(bytes: buffer)
        }
    }
}

// Availability due to `Swift`'s `InlineArray`
@available(SwiftTLS 0.1.0, *)
extension InlineArray where Element: Equatable {
    static func ==(lhs: Self, rhs: Self) -> Bool {
        for i in lhs.indices {
            if lhs[i] != rhs[i] {
                return false
            }
        }

        return true
    }
}

// Availability due to `Swift`'s `OutputRawSpan`
@available(SwiftTLS 0.1.0, *)
extension OutputRawSpan {
    /// Appends the contents of the given raw span to this output span.
    ///
    /// The standard library has no bulk append on `OutputRawSpan`, so this
    /// reaches for a pointer to get a single `memcpy`. We could append byte-by-byte
    /// with a manual for loop which gets vectorized in release builds; however,
    /// in debug builds it leads to orders of magnitude slower performance.
    mutating func append(contentsOf bytes: RawSpan) {
        precondition(
            bytes.byteCount <= self.freeCapacity,
            "append(contentsOf:) would write \(bytes.byteCount) bytes into \(self.freeCapacity) bytes of free capacity"
        )
        guard !bytes.isEmpty else { return }
        self.withUnsafeMutableBytes { buffer, initializedCount in
            bytes.withUnsafeBytes { input in
                UnsafeMutableRawBufferPointer(rebasing: buffer[initializedCount...])
                    .copyMemory(from: input)
            }
            initializedCount += bytes.byteCount
        }
    }

    /// Appends the bytes of `bytes` to this output span.
    ///
    /// Traps if `bytes` has more elements than `freeCapacity`. This copies in one operation when
    /// `bytes` has contiguous storage, as a native `String.UTF8View` does, and appends one byte at
    /// a time otherwise. Use it to append a `String`'s UTF-8 bytes where `String.UTF8View.span` is
    /// unavailable, such as on watchOS.
    mutating func append<Bytes: Sequence<UInt8>>(contentsOf bytes: Bytes) {
        let copiedFromContiguousStorage: Void? = bytes.withContiguousStorageIfAvailable { buffer in
            let rawBuffer = UnsafeRawBufferPointer(buffer)
            self.append(contentsOf: rawBuffer.bytes)
        }
        if copiedFromContiguousStorage != nil {
            return
        }

        for byte in bytes {
            self.append(byte)
        }
    }
}

// Availability due to `Swift`'s `OutputSpan`
@available(SwiftTLS 0.1.0, *)
extension OutputSpan where Element == UInt8 {
    /// Appends the contents of the given raw span to this output span.
    ///
    /// See `OutputRawSpan.append(contentsOf:)` for why this copies through a
    /// pointer rather than appending byte by byte.
    mutating func append(contentsOf bytes: RawSpan) {
        precondition(
            bytes.byteCount <= self.freeCapacity,
            "append(contentsOf:) would write \(bytes.byteCount) bytes into \(self.freeCapacity) bytes of free capacity"
        )
        guard !bytes.isEmpty else { return }
        self.withUnsafeMutableBufferPointer { buffer, initializedCount in
            bytes.withUnsafeBytes { input in
                UnsafeMutableRawBufferPointer(
                    rebasing: UnsafeMutableRawBufferPointer(buffer)[initializedCount...]
                ).copyMemory(from: input)
            }
            initializedCount += bytes.byteCount
        }
    }
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension RawSpan {
    subscript(index: Int) -> UInt8 {
        unsafeLoad(fromByteOffset: index, as: UInt8.self)
    }
}

/// Fills a stack buffer of exactly `capacity` bytes through a bounds-checked `OutputRawSpan`, then
/// passes the finished bytes to `use`.
///
/// `fill` must write every byte; otherwise this traps rather than expose uninitialized memory to `use`.
/// The bytes passed to `use` are only valid for the duration of that call.
///
/// Every unsafe operation of this pattern is confined to this function.
// Availability due to `Swift`'s `OutputRawSpan`
@available(SwiftTLS 0.1.0, *)
func withTemporaryAllocationOfBytes<Result>(
    capacity: Int,
    fill: (inout OutputRawSpan) -> Void,
    use: (RawSpan) -> Result
) -> Result {
    // The temporary allocation is `capacity` bytes and lives until this closure returns, and it is
    // not used for anything but the `OutputRawSpan` and `use`.
    return withUnsafeTemporaryAllocation(byteCount: capacity, alignment: 1) { buffer in
        // `buffer` is the whole of the allocation and `initializedCount` is 0, so the span starts
        // empty with `capacity` bytes free; its `append` traps when asked to write past that.
        var outputSpan = OutputRawSpan(buffer: buffer, initializedCount: 0)
        fill(&outputSpan)
        // Finalizing checks that `outputSpan` was built over `buffer`, and the count check below ensures
        // that every byte has been initialized before `use` can read them.
        let initializedCount = outputSpan.finalize(for: buffer)
        precondition(
            initializedCount == capacity,
            "output span left \(capacity - initializedCount) of \(capacity) bytes unwritten"
        )
        let initializedBytes = UnsafeRawBufferPointer(buffer)
        return use(initializedBytes.bytes)
    }
}
